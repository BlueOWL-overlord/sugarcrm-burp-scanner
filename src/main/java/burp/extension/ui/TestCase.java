package burp.extension.ui;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Registry of all test cases the scanner can execute.
 *
 * Each TestCase carries:
 *  - id           : unique key used in config / persistence
 *  - displayName  : human-readable label shown in the UI
 *  - description  : tooltip / detail text explaining what the test does
 *  - category     : logical grouping for the checkbox panel
 *  - intrusive    : true  → user must explicitly approve before execution
 *                   false → safe / read-only, runs without confirmation
 *  - enabledByDefault
 */
public enum TestCase {

    // ── Crawl & Enumeration ──────────────────────────────────────────────────
    CRAWL_WEB_MODULES(
        "crawl_web", "Web Module Crawl",
        "Visits every SugarCRM module + action combination (40+ modules × up to 20 actions).\n"
        + "Generates ~200–400 authenticated GET requests to map the full web-UI attack surface.",
        Category.CRAWL, false, true),

    CRAWL_REST_API(
        "crawl_rest", "REST API v8 Crawl",
        "Enumerates all REST API v8 endpoints including /api/v8/Accounts, /api/v8/Users, "
        + "/api/v8/bulk, /api/v8/search, and module-level CRUD endpoints.\n"
        + "Tests GET / POST / PATCH / DELETE verbs.",
        Category.CRAWL, false, true),

    CRAWL_EXTRACT_LINKS(
        "crawl_links", "Extract Links & Forms from Responses",
        "Parses HTML responses for <a href> links and <form> elements, then queues those "
        + "for scanning (requires Crawl Depth ≥ 2).",
        Category.CRAWL, false, true),

    CRAWL_IDOR_ENUM(
        "crawl_idor_enum", "Record ID Enumeration (sequential + UUID)",
        "Requests DetailView and EditView for record IDs 1–20 on Accounts, Contacts, Users, "
        + "Documents, and Reports — a prerequisite for IDOR detection.",
        Category.CRAWL, false, true),

    // ── Authentication & Session ─────────────────────────────────────────────
    AUTH_CSRF_BYPASS(
        "auth_csrf", "CSRF Token Bypass (sugar_token validation)",
        "Posts authenticated state-changing forms without the sugar_token and with a forged "
        + "static token. Flags the endpoint if the server still processes the request.",
        Category.AUTH, false, true),

    AUTH_SESSION_EXPIRY(
        "auth_session_expiry", "Session Expiry & Re-authentication",
        "Verifies that expired/invalid sessions are properly rejected and that re-login "
        + "is required. Attempts requests with an empty or malformed PHPSESSID.",
        Category.AUTH, false, true),

    AUTH_WEAK_PASSWORD_POLICY(
        "auth_weak_pwd", "Weak Password / Lockout Policy",
        "Attempts login with common weak passwords and verifies account lockout after "
        + "repeated failures. Non-destructive (uses a dedicated probe account).",
        Category.AUTH, false, false),

    // ── Injection Tests ──────────────────────────────────────────────────────
    INJ_SQL(
        "inj_sql", "SQL Injection",
        "Tests all insertion points with 10 SQLi payloads including UNION, OR 1=1, "
        + "SLEEP timing, and error-based patterns. Detects MySQL / PostgreSQL / Oracle errors.",
        Category.INJECTION, false, true),

    INJ_XSS(
        "inj_xss", "Reflected XSS",
        "Tests 8 XSS payloads (<script>, img/onerror, svg/onload, iframe) and checks "
        + "whether the payload appears unencoded in the response.",
        Category.INJECTION, false, true),

    INJ_STORED_XSS(
        "inj_stored_xss", "Stored XSS via Record Create/Edit",
        "Injects XSS payloads into CRM record fields (name, description, notes) during "
        + "the user-action simulation phase, then checks if they are reflected in list/detail views.\n"
        + "⚠ INTRUSIVE: creates test records in the target CRM.",
        Category.INJECTION, true, true),

    INJ_SSRF(
        "inj_ssrf", "Server-Side Request Forgery (SSRF)",
        "Tests URL/host/smtp/callback parameters with 7 payloads targeting localhost, "
        + "AWS/GCP/Alibaba metadata endpoints, and internal IP ranges.",
        Category.INJECTION, false, true),

    INJ_PATH_TRAVERSAL(
        "inj_path", "Path Traversal / Local File Inclusion",
        "Tests file/path/record/download/filename parameters with 5 traversal payloads "
        + "(../, URL-encoded, double-encoded). Detects /etc/passwd and win.ini content.",
        Category.INJECTION, false, true),

    INJ_XXE(
        "inj_xxe", "XXE via vCard / XML Import",
        "Uploads a crafted vCard (VCF) file containing an XML External Entity declaration "
        + "to test for XXE vulnerabilities in SugarCRM's import parser.",
        Category.INJECTION, true, true),

    INJ_SSTI(
        "inj_ssti", "Server-Side Template Injection (Smarty/Twig)",
        "Tests Smarty template injection payloads ({{7*7}}, {php}...{/php}) in fields "
        + "rendered by SugarCRM's Smarty engine (email templates, PDF templates, workflows).\n"
        + "⚠ INTRUSIVE: may execute server-side expressions.",
        Category.INJECTION, true, true),

    INJ_OPEN_REDIRECT(
        "inj_redirect", "Open Redirect",
        "Tests return/redirect/url/next parameters with 4 redirect payloads targeting "
        + "external domains. Flags endpoints that issue 3xx redirects to attacker-controlled URLs.",
        Category.INJECTION, false, true),

    // ── Access Control ───────────────────────────────────────────────────────
    AC_IDOR(
        "ac_idor", "IDOR — Unauthorised Record Access",
        "Attempts to access other users' records by manipulating the 'record' / 'id' parameter. "
        + "Flags endpoints that return data without ACL restriction errors.",
        Category.ACCESS_CONTROL, false, true),

    AC_PRIV_ESC(
        "ac_priv_esc", "Privilege Escalation via Parameter Tampering",
        "Injects is_admin=1 / user_type=Administrator into POST requests. Checks whether "
        + "the server silently elevates the user's privileges.\n"
        + "⚠ INTRUSIVE: may modify user attributes if the vulnerability exists.",
        Category.ACCESS_CONTROL, true, true),

    AC_UNAUTH_REST(
        "ac_unauth_rest", "Unauthenticated REST API Access",
        "Sends GET requests to all REST API v8 endpoints without an Authorization header. "
        + "Flags any endpoint that returns data with HTTP 200.",
        Category.ACCESS_CONTROL, false, true),

    AC_ADMIN_ENDPOINTS(
        "ac_admin_ep", "Admin Endpoint Access Control",
        "Tests whether non-admin sessions can access Administration, ModuleBuilder, "
        + "UpgradeWizard, and Configurator endpoints.",
        Category.ACCESS_CONTROL, false, true),

    // ── Business Logic ───────────────────────────────────────────────────────
    BL_FILE_UPLOAD(
        "bl_file_upload", "Malicious File Upload (PHP Extension Bypass)",
        "Attempts to upload a .php file disguised as a document. Verifies that the server "
        + "rejects dangerous file extensions.\n"
        + "⚠ INTRUSIVE: uploads files to the target instance.",
        Category.BUSINESS_LOGIC, true, true),

    BL_CSV_INJECTION(
        "bl_csv", "CSV Injection via Import",
        "Imports a CSV file containing formula-injection payloads (=CMD|' /C calc'!A0) "
        + "into the Contacts module to test for unsafe handling.",
        Category.BUSINESS_LOGIC, true, true),

    BL_REST_MASS_ASSIGN(
        "bl_mass_assign", "REST API Mass Assignment",
        "Sends PATCH requests to /api/v8/Users with extra fields (is_admin, user_type, status) "
        + "to test if the server properly filters writable attributes.\n"
        + "⚠ INTRUSIVE: may modify user data if vulnerability exists.",
        Category.BUSINESS_LOGIC, true, true),

    BL_EXPORT_ALL(
        "bl_export", "Bulk Data Export",
        "Tests export endpoints on 7 modules. Checks whether unrestricted data export is "
        + "possible and whether exports are scope/ACL-limited.",
        Category.BUSINESS_LOGIC, false, true),

    // ── User Action Simulation ───────────────────────────────────────────────
    SIM_CRUD_RECORDS(
        "sim_crud", "Create / Edit / Delete Records",
        "Creates test Accounts, Contacts, Leads, Opportunities, and Cases. Edits and then "
        + "deletes them. Generates rich AJAX traffic for scanner analysis.\n"
        + "⚠ INTRUSIVE: creates and deletes records in the target CRM. Cleanup is automatic.",
        Category.SIMULATION, true, true),

    SIM_SEARCH(
        "sim_search", "Search & Quick-Search Operations",
        "Runs basic search, advanced search, and unified global search on 6 modules. "
        + "Also exercises the REST /api/v8/search endpoint.",
        Category.SIMULATION, false, true),

    SIM_IMPORT_VCARD(
        "sim_import_vcard", "vCard Import",
        "Imports a standard vCard (VCF) file via the Contacts module. Exercises the "
        + "parser for injection and XXE vulnerabilities.",
        Category.SIMULATION, true, true),

    SIM_IMPORT_CSV(
        "sim_import_csv", "CSV Import",
        "Performs a two-step CSV import into the Contacts module to surface CSV injection "
        + "and file parser vulnerabilities.",
        Category.SIMULATION, true, true),

    SIM_PASSWORD_CHANGE(
        "sim_pwd_change", "Password Change Workflow",
        "Tests the Users/ChangePassword action using the same old and new password "
        + "(no actual change). Checks for CSRF and authorization gaps.",
        Category.SIMULATION, false, true),

    SIM_EMAIL_COMPOSE(
        "sim_email", "Email Compose & Send",
        "Exercises the Emails module compose action. Tests for SSRF via mail relay "
        + "and email header injection.",
        Category.SIMULATION, false, true),

    SIM_ADMIN_ACTIONS(
        "sim_admin", "Admin Action Simulation",
        "Exercises administrative actions: cache clear, repair, module loader page, "
        + "diagnostic download, system configuration.\n"
        + "⚠ INTRUSIVE: may trigger server-side operations (cache clear, rebuild).",
        Category.SIMULATION, true, true),

    // ── CVE / Targeted Probes ────────────────────────────────────────────────
    CVE_UNAUTH_ADMIN(
        "cve_unauth", "Unauthenticated Admin / REST Access Probe",
        "Checks whether /index.php?module=Administration and /api/v8/Accounts return "
        + "sensitive data without authentication.",
        Category.CVE_PROBES, false, true),

    CVE_2023_22952(
        "cve_2023_22952", "CVE-2023-22952 — Pre-Auth RCE via EmailTemplate",
        "Sends a crafted EmailTemplate save request containing a PHP eval payload in "
        + "the body_html field. Checks for RCE indicators (phpinfo, uid=).\n"
        + "⚠ INTRUSIVE: sends a potential RCE payload to the server.",
        Category.CVE_PROBES, true, true),

    CVE_2021_45229(
        "cve_2021_45229", "CVE-2021-45229 — Auth Bypass via Token Parameter",
        "Requests a User DetailView with a crafted token= parameter to test for "
        + "authentication bypass.",
        Category.CVE_PROBES, false, true),

    CVE_2020_15301(
        "cve_2020_15301", "CVE-2020-15301 — SSRF via Email Transport Config",
        "Posts an Admin/Save request with smtp_host=http://127.0.0.1 to test for "
        + "SSRF via the email transport configuration.\n"
        + "⚠ INTRUSIVE: may modify SMTP server settings.",
        Category.CVE_PROBES, true, true),

    CVE_LFI_MODULE(
        "cve_lfi", "LFI via module / action Parameters",
        "Tests the module and action GET parameters with directory traversal sequences "
        + "to attempt local file inclusion (../../etc/passwd).",
        Category.CVE_PROBES, false, true),

    CVE_OBJECT_INJECTION(
        "cve_obj_inject", "PHP Object Injection via Cookie",
        "Sends a request with a serialised PHP stdClass object in the sugar_user_theme "
        + "cookie to test for PHP object injection.\n"
        + "⚠ INTRUSIVE: sends a serialised payload.",
        Category.CVE_PROBES, true, true),

    CVE_2022_21712(
        "cve_2022_21712", "CVE-2022-21712 — XSS in QuickSearch",
        "Sends an XSS payload via the UnifiedSearch action to test for reflected XSS "
        + "in the quick-search functionality.",
        Category.CVE_PROBES, false, true),

    CVE_CONFIG_EXPOSURE(
        "cve_config", "Config File Exposure (config.php / config_override.php)",
        "Checks whether config.php and config_override.php are directly accessible "
        + "from the web root (should return 403 / 404).",
        Category.CVE_PROBES, false, true),

    CVE_LOG_EXPOSURE(
        "cve_log", "Log File Web Access (sugarcrm.log)",
        "Attempts to fetch sugarcrm.log from the web root.",
        Category.CVE_PROBES, false, true),

    CVE_GIT_EXPOSURE(
        "cve_git", ".git Directory Exposed",
        "Checks whether /.git/config is accessible, indicating the source repository "
        + "was deployed without removing the .git directory.",
        Category.CVE_PROBES, false, true),

    CVE_WORKFLOW_SSTI(
        "cve_workflow_ssti", "Workflow / Process Audit SSTI",
        "Tests Smarty template injection via the workflow condition/action fields "
        + "(AOW_WorkFlow module).\n"
        + "⚠ INTRUSIVE: may execute server-side template expressions.",
        Category.CVE_PROBES, true, true),

    CVE_MODULE_LOADER(
        "cve_module_loader", "Module Loader Upload (Admin RCE Vector)",
        "Checks whether the ModuleLoader upload endpoint is accessible and accepts ZIP "
        + "uploads without proper validation.\n"
        + "⚠ INTRUSIVE: uploads a probe ZIP archive.",
        Category.CVE_PROBES, true, false),

    // ── Passive Analysis ─────────────────────────────────────────────────────
    PASSIVE_VERSION(
        "passive_version", "Version Disclosure Detection",
        "Passively detects SugarCRM version strings in all responses.",
        Category.PASSIVE, false, true),

    PASSIVE_SECURITY_HEADERS(
        "passive_headers", "Missing Security Headers",
        "Flags responses missing X-Frame-Options, X-Content-Type-Options, CSP, or HSTS.",
        Category.PASSIVE, false, true),

    PASSIVE_COOKIE_FLAGS(
        "passive_cookies", "Session Cookie Security Flags",
        "Checks that PHPSESSID and sugar_* cookies carry HttpOnly, Secure, and SameSite attributes.",
        Category.PASSIVE, false, true),

    PASSIVE_SENSITIVE_DATA(
        "passive_sensitive", "Sensitive Data in Responses (hashes, keys, PII)",
        "Detects MD5 password hashes, API keys, JWT tokens, SSNs, and credit card numbers "
        + "in response bodies.",
        Category.PASSIVE, false, true),

    PASSIVE_DEBUG_OUTPUT(
        "passive_debug", "Debug / Stack Trace / SQL Error Disclosure",
        "Flags PHP fatal errors, Xdebug output, stack traces, and raw SQL error messages.",
        Category.PASSIVE, false, true);

    // ── Fields ───────────────────────────────────────────────────────────────

    public final String   id;
    public final String   displayName;
    public final String   description;
    public final Category category;
    /** True = user will be prompted to approve before the test runs. */
    public final boolean  intrusive;
    public final boolean  enabledByDefault;

    TestCase(String id, String displayName, String description,
             Category category, boolean intrusive, boolean enabledByDefault) {
        this.id               = id;
        this.displayName      = displayName;
        this.description      = description;
        this.category         = category;
        this.intrusive        = intrusive;
        this.enabledByDefault = enabledByDefault;
    }

    // ── Category ─────────────────────────────────────────────────────────────

    public enum Category {
        CRAWL          ("Crawl & Enumeration"),
        AUTH           ("Authentication & Session"),
        INJECTION      ("Injection Tests"),
        ACCESS_CONTROL ("Access Control"),
        BUSINESS_LOGIC ("Business Logic"),
        SIMULATION     ("User Action Simulation"),
        CVE_PROBES     ("CVE / Targeted Probes"),
        PASSIVE        ("Passive Analysis");

        public final String label;
        Category(String label) { this.label = label; }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    public static List<TestCase> byCategory(Category cat) {
        return Arrays.stream(values())
                     .filter(tc -> tc.category == cat)
                     .collect(Collectors.toList());
    }
}
