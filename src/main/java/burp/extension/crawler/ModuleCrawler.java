package burp.extension.crawler;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.extension.ExtensionConfig;
import burp.extension.auth.AuthManager;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;

/**
 * ModuleCrawler systematically visits every SugarCRM module and action,
 * discovers URLs/forms, and returns a list of HttpRequests ready for scanning.
 *
 * SugarCRM URL pattern:  /index.php?module=<M>&action=<A>[&record=<ID>]
 * REST API pattern:      /api/v8/<resource>
 */
public class ModuleCrawler {

    private final MontoyaApi      api;
    private final ExtensionConfig config;
    private final AuthManager     authManager;

    // All discovered requests (deduped by URL+body)
    private final Set<String>        visited    = ConcurrentHashMap.newKeySet();
    private final List<HttpRequest>  discovered = Collections.synchronizedList(new ArrayList<>());

    // ─── SugarCRM module/action matrix ───────────────────────────────────────
    // Pair of module → list of actions to test
    private static final Map<String, List<String>> MODULE_ACTIONS = new LinkedHashMap<>();
    static {
        // Core CRM modules
        addModule("Accounts",       "index","DetailView","EditView","list","search","vcard","Subpanel-list");
        addModule("Contacts",       "index","DetailView","EditView","list","search","vcard","Subpanel-list");
        addModule("Leads",          "index","DetailView","EditView","list","search","ConvertLead");
        addModule("Opportunities",  "index","DetailView","EditView","list","search");
        addModule("Cases",          "index","DetailView","EditView","list","search");
        addModule("Bugs",           "index","DetailView","EditView","list","search");
        addModule("Calls",          "index","DetailView","EditView","list","search","Save","CallUI");
        addModule("Meetings",       "index","DetailView","EditView","list","search","Save");
        addModule("Tasks",          "index","DetailView","EditView","list","search");
        addModule("Notes",          "index","DetailView","EditView","list","search");
        addModule("Documents",      "index","DetailView","EditView","list","search","Download");
        addModule("Emails",         "index","DetailView","list","Popup","compose");
        addModule("EmailTemplates",  "index","DetailView","EditView","list","search");
        addModule("Campaigns",      "index","DetailView","EditView","list","WizardMarketing");
        addModule("Quotes",         "index","DetailView","EditView","list","search");
        addModule("Products",       "index","DetailView","EditView","list","search");
        addModule("Contracts",      "index","DetailView","EditView","list","search");
        addModule("RevenueLineItems","index","DetailView","EditView","list","search");
        // Users / ACL
        addModule("Users",          "index","DetailView","EditView","list","search","ChangePassword","ResetToDefault");
        addModule("ACLRoles",       "index","DetailView","EditView","list");
        addModule("Teams",          "index","DetailView","EditView","list");
        // Reporting
        addModule("Reports",        "index","DetailView","EditView","list","chart","export");
        addModule("AOS_PDF_Templates","index","DetailView","EditView","list");
        // Workflow / Process
        addModule("AOW_WorkFlow",   "index","DetailView","EditView","list");
        addModule("AOW_Processed",  "index","list");
        // Admin — tested only when testAdmin flag is enabled
        addModule("Administration", "index","DiagnosticRun","UpgradeWizard","PasswordManager",
                "Currencies","BackupNow","RepairQueueJobsAudit","DisplayModules","UnifiedSearch",
                "config","DropdownEditor","ModuleLoader","ImportCustomFields","HistoryContactRelationship");
        addModule("ModuleBuilder",  "index","refreshPackage","addLayout","editLayout","deployPackage");
        addModule("Configurator",   "index","EditView","Save");
        addModule("Schedulers",     "index","EditView","list","Save");
        addModule("UpgradeWizard",  "index","step1","step4");
        // REST probe modules
        addModule("_REST_V8", "modules","metadata","current_user"); // handled separately
    }

    private static void addModule(String module, String... actions) {
        MODULE_ACTIONS.put(module, Arrays.asList(actions));
    }

    // SugarCRM REST API v8 endpoints
    private static final List<String> REST_V8_ENDPOINTS = Arrays.asList(
        "/api/v8/",
        "/api/v8/metadata",
        "/api/v8/me",
        "/api/v8/Accounts",
        "/api/v8/Contacts",
        "/api/v8/Leads",
        "/api/v8/Opportunities",
        "/api/v8/Cases",
        "/api/v8/Users",
        "/api/v8/Documents",
        "/api/v8/Reports",
        "/api/v8/Quotes",
        "/api/v8/Teams",
        "/api/v8/ACLRoles",
        "/api/v8/Emails",
        "/api/v8/Campaigns",
        "/api/v8/Administration",
        "/api/v8/Accounts/filter",
        "/api/v8/Contacts/filter",
        "/api/v8/search?q=test",
        "/api/v8/bulk"
    );

    public ModuleCrawler(MontoyaApi api, ExtensionConfig config, AuthManager authManager) {
        this.api         = api;
        this.config      = config;
        this.authManager = authManager;
    }

    /**
     * Main crawl entry point.
     * Returns all discovered HttpRequests (web + REST).
     */
    public List<HttpRequest> crawl(Consumer<String> logger) {
        visited.clear();
        discovered.clear();

        logger.accept("[Crawler] Starting module crawl on " + config.getTargetUrl());

        // 1. Classic web UI modules
        crawlWebModules(logger);

        // 2. SugarCRM REST API v8
        if (config.isTestRestApi()) {
            crawlRestApi(logger);
        }

        logger.accept("[Crawler] Crawl complete. Discovered " + discovered.size() + " unique requests.");
        return Collections.unmodifiableList(discovered);
    }

    // ─── Web module crawl ─────────────────────────────────────────────────────

    private void crawlWebModules(Consumer<String> logger) {
        for (Map.Entry<String, List<String>> entry : MODULE_ACTIONS.entrySet()) {
            String module = entry.getKey();
            if (module.equals("_REST_V8")) continue;
            if (module.equals("Administration") && !config.isTestAdminEndpoints()) continue;
            if (module.equals("ModuleBuilder")  && !config.isTestAdminEndpoints()) continue;

            for (String action : entry.getValue()) {
                String url = config.getTargetUrl() + "/index.php?module=" + module + "&action=" + action;
                HttpRequest req = buildAuthenticatedGet(url);
                if (markVisited(url)) {
                    discovered.add(req);
                    // Crawl the response for embedded links and forms
                    if (config.getCrawlDepth() >= 2) {
                        try {
                            HttpRequestResponse resp = api.http().sendRequest(req);
                            if (resp.response() != null && resp.response().statusCode() == 200) {
                                logger.accept("[Crawler] " + module + "/" + action + " -> HTTP 200");
                                extractLinksAndForms(resp.response().bodyToString(), logger);
                            }
                        } catch (Exception e) {
                            logger.accept("[Crawler] Error fetching " + url + ": " + e.getMessage());
                        }
                    } else {
                        logger.accept("[Crawler] Queued: " + module + "/" + action);
                    }
                }
            }
        }

        // Enumerate record IDs 1..20 for IDOR checks on critical modules
        String[] idorModules = {"Accounts","Contacts","Users","Documents","Reports"};
        for (String module : idorModules) {
            for (int id = 1; id <= 20; id++) {
                // SugarCRM uses UUIDs but older installs may use sequential IDs; test both
                String urlDetail = config.getTargetUrl() + "/index.php?module=" + module + "&action=DetailView&record=" + id;
                String urlEdit   = config.getTargetUrl() + "/index.php?module=" + module + "&action=EditView&record=" + id;
                if (markVisited(urlDetail)) discovered.add(buildAuthenticatedGet(urlDetail));
                if (markVisited(urlEdit))   discovered.add(buildAuthenticatedGet(urlEdit));
            }
        }
    }

    // ─── REST API crawl ───────────────────────────────────────────────────────

    private void crawlRestApi(Consumer<String> logger) {
        logger.accept("[Crawler] Crawling REST API v8 endpoints...");
        for (String endpoint : REST_V8_ENDPOINTS) {
            String url = config.getTargetUrl() + endpoint;
            if (!markVisited("REST:" + url)) continue;

            // GET
            HttpRequest getReq = buildRestGet(url);
            discovered.add(getReq);

            // POST with empty body (discover error messages / schema leakage)
            HttpRequest postReq = buildRestPost(url, "{}");
            discovered.add(postReq);

            logger.accept("[Crawler] REST: " + endpoint);
        }

        // PATCH/DELETE on individual records
        String[] restModules = {"Accounts","Contacts","Users","Documents"};
        for (String mod : restModules) {
            for (int i = 1; i <= 5; i++) {
                String url = config.getTargetUrl() + "/api/v8/" + mod + "/" + i;
                if (markVisited("REST:PATCH:" + url)) {
                    discovered.add(buildRestPatch(url, "{}"));
                }
                if (markVisited("REST:DELETE:" + url)) {
                    discovered.add(buildRestDelete(url));
                }
            }
        }
    }

    // ─── HTML link/form extraction ────────────────────────────────────────────

    private void extractLinksAndForms(String html, Consumer<String> logger) {
        try {
            Document doc = Jsoup.parse(html);
            String base  = config.getTargetUrl();

            // Extract <a href> links
            for (Element link : doc.select("a[href]")) {
                String href = link.attr("abs:href");
                if (href.startsWith(base) && markVisited(href)) {
                    discovered.add(buildAuthenticatedGet(href));
                }
            }

            // Extract <form> elements — build POST requests
            for (Element form : doc.select("form")) {
                String action = form.attr("abs:action");
                if (action.isBlank()) action = base + "/index.php";
                if (!action.startsWith(base)) continue;

                String method = form.attr("method").equalsIgnoreCase("post") ? "POST" : "GET";
                StringBuilder bodyBuilder = new StringBuilder();
                for (Element input : form.select("input, select, textarea")) {
                    String name  = input.attr("name");
                    String value = input.attr("value");
                    if (name.isBlank()) continue;
                    if (!bodyBuilder.isEmpty()) bodyBuilder.append("&");
                    bodyBuilder.append(urlEncode(name)).append("=").append(urlEncode(value));
                }

                String key = method + ":" + action + "?" + bodyBuilder;
                if (markVisited(key)) {
                    HttpRequest formReq;
                    if ("POST".equals(method)) {
                        formReq = buildAuthenticatedPost(action, bodyBuilder.toString());
                    } else {
                        formReq = buildAuthenticatedGet(action + (bodyBuilder.isEmpty() ? "" : "?" + bodyBuilder));
                    }
                    discovered.add(formReq);
                    logger.accept("[Crawler]   Found form: " + method + " " + action);
                }
            }
        } catch (Exception e) {
            api.logging().logToError("[Crawler] extractLinksAndForms error: " + e.getMessage());
        }
    }

    // ─── Request builders ─────────────────────────────────────────────────────

    private HttpRequest buildAuthenticatedGet(String url) {
        return HttpRequest.httpRequestFromUrl(url)
                .withMethod("GET")
                .withHeader("Cookie", config.getSessionCookie())
                .withHeader("User-Agent", "Mozilla/5.0 (SugarCRM-BurpScanner/1.0)")
                .withHeader("Accept", "text/html,application/xhtml+xml,*/*");
    }

    private HttpRequest buildAuthenticatedPost(String url, String body) {
        return HttpRequest.httpRequestFromUrl(url)
                .withMethod("POST")
                .withHeader("Cookie", config.getSessionCookie())
                .withHeader("User-Agent", "Mozilla/5.0 (SugarCRM-BurpScanner/1.0)")
                .withHeader("Content-Type", "application/x-www-form-urlencoded")
                .withBody(body);
    }

    private HttpRequest buildRestGet(String url) {
        HttpRequest r = HttpRequest.httpRequestFromUrl(url)
                .withMethod("GET")
                .withHeader("User-Agent", "Mozilla/5.0 (SugarCRM-BurpScanner/1.0)")
                .withHeader("Accept", "application/json");
        if (!config.getOauthToken().isBlank()) {
            r = r.withHeader("Authorization", "Bearer " + config.getOauthToken());
        }
        return r;
    }

    private HttpRequest buildRestPost(String url, String body) {
        HttpRequest r = HttpRequest.httpRequestFromUrl(url)
                .withMethod("POST")
                .withHeader("User-Agent", "Mozilla/5.0 (SugarCRM-BurpScanner/1.0)")
                .withHeader("Content-Type", "application/json")
                .withHeader("Accept", "application/json")
                .withBody(body);
        if (!config.getOauthToken().isBlank()) {
            r = r.withHeader("Authorization", "Bearer " + config.getOauthToken());
        }
        return r;
    }

    private HttpRequest buildRestPatch(String url, String body) {
        HttpRequest r = HttpRequest.httpRequestFromUrl(url)
                .withMethod("PATCH")
                .withHeader("User-Agent", "Mozilla/5.0 (SugarCRM-BurpScanner/1.0)")
                .withHeader("Content-Type", "application/json")
                .withHeader("Accept", "application/json")
                .withBody(body);
        if (!config.getOauthToken().isBlank()) {
            r = r.withHeader("Authorization", "Bearer " + config.getOauthToken());
        }
        return r;
    }

    private HttpRequest buildRestDelete(String url) {
        HttpRequest r = HttpRequest.httpRequestFromUrl(url)
                .withMethod("DELETE")
                .withHeader("User-Agent", "Mozilla/5.0 (SugarCRM-BurpScanner/1.0)");
        if (!config.getOauthToken().isBlank()) {
            r = r.withHeader("Authorization", "Bearer " + config.getOauthToken());
        }
        return r;
    }

    // ─── Helpers ──────────────────────────────────────────────────────────────

    private boolean markVisited(String key) {
        return visited.add(key);
    }

    private String urlEncode(String s) {
        try { return java.net.URLEncoder.encode(s, "UTF-8"); }
        catch (Exception e) { return s; }
    }
}
