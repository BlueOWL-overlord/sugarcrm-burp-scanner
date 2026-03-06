package burp.extension.scanner;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.ScanCheck;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.extension.ExtensionConfig;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * SugarCRM-specific PASSIVE scan checks.
 *
 * These checks analyse each response that passes through Burp Proxy without
 * sending any additional requests.
 *
 * Checks performed:
 *  1.  Sensitive data in HTTP responses (API keys, passwords, PII)
 *  2.  Missing / weak security headers
 *  3.  Session cookie security flags (HttpOnly, Secure, SameSite)
 *  4.  SugarCRM version disclosure
 *  5.  Debug / stack-trace leakage
 *  6.  Verbose error messages (SQL errors, PHP warnings)
 *  7.  Directory listing enabled
 *  8.  Backup / temp files accessible
 *  9.  Unauthenticated API access (REST v8 without token)
 * 10.  Weak password hash disclosure (md5 visible in response)
 * 11.  Cleartext credentials in URL query string
 * 12.  JWT / OAuth token leakage in response bodies
 */
public class PassiveScanChecks implements ScanCheck {

    private final MontoyaApi      api;
    private final ExtensionConfig config;

    // ─── Detection patterns ───────────────────────────────────────────────────

    // Version disclosure
    private static final Pattern VERSION_PATTERN = Pattern.compile(
        "(SugarCRM|SugarEnterprise|SugarPro|Sugar\\s+CE)\\s+(?:Version\\s+)?([0-9]+\\.[0-9]+[^\\s<\"']*)",
        Pattern.CASE_INSENSITIVE
    );

    // Stack traces / debug output
    private static final Pattern STACK_TRACE_PATTERN = Pattern.compile(
        "(Fatal error|Call Stack|Stack trace|Uncaught Exception|\\bPHP Warning\\b|\\bPHP Notice\\b"
        + "|\\bXdebug\\b|\\bTraceback \\(most recent call\\)|SugarException)",
        Pattern.CASE_INSENSITIVE
    );

    // SQL error patterns
    private static final Pattern SQL_ERROR_PATTERN = Pattern.compile(
        "(SQL syntax.*MySQL|Warning.*mysql_|ORA-[0-9]{4,}|SQLSTATE\\[[A-Z0-9]+\\]"
        + "|pg_query\\(\\):|sqlite3\\.OperationalError)",
        Pattern.CASE_INSENSITIVE
    );

    // MD5 password hash (32 hex chars — common in Sugar user responses)
    private static final Pattern MD5_HASH_PATTERN = Pattern.compile(
        "\"user_hash\"\\s*:\\s*\"([a-f0-9]{32})\"", Pattern.CASE_INSENSITIVE
    );

    // Credentials in URL
    private static final Pattern CREDS_IN_URL_PATTERN = Pattern.compile(
        "[?&](password|passwd|pass|pwd|secret|api_key|token)=[^&\\s]+",
        Pattern.CASE_INSENSITIVE
    );

    // API key / secret patterns in response body
    private static final Pattern API_KEY_PATTERN = Pattern.compile(
        "(\"api_key\"|\"client_secret\"|\"access_token\"|\"private_key\")\\s*:\\s*\"([^\"]{8,})\""
    );

    // JWT
    private static final Pattern JWT_PATTERN = Pattern.compile(
        "eyJ[A-Za-z0-9-_=]+\\.[A-Za-z0-9-_=]+\\.[A-Za-z0-9-_.+/=]*"
    );

    // Directory listing
    private static final Pattern DIR_LISTING_PATTERN = Pattern.compile(
        "<title>Index of /|Directory listing for /", Pattern.CASE_INSENSITIVE
    );

    // Backup / temp file paths in HTML
    private static final Pattern BACKUP_FILE_PATTERN = Pattern.compile(
        "(?i)(backup|\\.bak|\\.old|\\.tmp|\\.orig|dump\\.sql|\\.sql\\.gz|config\\.php\\.bak)"
    );

    // PII disclosure
    private static final Pattern PII_SSN_PATTERN = Pattern.compile(
        "\\b\\d{3}-\\d{2}-\\d{4}\\b"    // US SSN
    );
    private static final Pattern PII_CC_PATTERN = Pattern.compile(
        "\\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\\b" // Visa/MC/Amex
    );

    public PassiveScanChecks(MontoyaApi api, ExtensionConfig config) {
        this.api    = api;
        this.config = config;
    }

    @Override
    public AuditResult passiveAudit(HttpRequestResponse reqResp) {
        List<AuditIssue> issues = new ArrayList<>();

        String url = reqResp.request().url();
        if (!url.startsWith(config.getTargetUrl())) return AuditResult.auditResult(issues);

        HttpResponse response = reqResp.response();
        if (response == null) return AuditResult.auditResult(issues);

        String body    = response.bodyToString();
        String headers = response.toString();   // full response including headers

        issues.addAll(checkVersionDisclosure(reqResp, body));
        issues.addAll(checkStackTrace(reqResp, body));
        issues.addAll(checkSqlErrors(reqResp, body));
        issues.addAll(checkSecurityHeaders(reqResp, headers));
        issues.addAll(checkCookieFlags(reqResp, headers));
        issues.addAll(checkSensitiveDataInResponse(reqResp, body));
        issues.addAll(checkCredsInUrl(reqResp, url));
        issues.addAll(checkDirectoryListing(reqResp, body));
        issues.addAll(checkBackupFiles(reqResp, body));
        issues.addAll(checkUnauthenticatedRestAccess(reqResp, body));

        return AuditResult.auditResult(issues);
    }

    @Override
    public AuditResult activeAudit(HttpRequestResponse base, AuditInsertionPoint ip) {
        return AuditResult.auditResult(List.of()); // Active handled in ActiveScanChecks
    }

    @Override
    public ConsolidationAction consolidateIssues(AuditIssue newIssue, AuditIssue existingIssue) {
        return newIssue.name().equals(existingIssue.name())
                ? ConsolidationAction.KEEP_EXISTING
                : ConsolidationAction.KEEP_BOTH;
    }

    // ─── Individual passive checks ────────────────────────────────────────────

    private List<AuditIssue> checkVersionDisclosure(HttpRequestResponse reqResp, String body) {
        List<AuditIssue> found = new ArrayList<>();
        var m = VERSION_PATTERN.matcher(body);
        if (m.find()) {
            found.add(issue(
                "SugarCRM Version Disclosure",
                "The response reveals the SugarCRM version: " + m.group(0),
                "Remove version strings from HTML, HTTP headers, and JavaScript files. "
                + "Check config_override.php for output buffering options.",
                reqResp, AuditIssueSeverity.INFORMATION, AuditIssueConfidence.CERTAIN
            ));
        }
        return found;
    }

    private List<AuditIssue> checkStackTrace(HttpRequestResponse reqResp, String body) {
        List<AuditIssue> found = new ArrayList<>();
        var m = STACK_TRACE_PATTERN.matcher(body);
        if (m.find()) {
            found.add(issue(
                "SugarCRM Debug / Stack Trace Information Disclosure",
                "A stack trace or debug message was found in the response: \"" + m.group(0) + "\"",
                "Disable PHP display_errors and Xdebug in production. Set "
                + "'sugar_config[display_action_menu_items]' to false and ensure "
                + "PHP error_reporting does not include E_WARNING/E_NOTICE.",
                reqResp, AuditIssueSeverity.MEDIUM, AuditIssueConfidence.CERTAIN
            ));
        }
        return found;
    }

    private List<AuditIssue> checkSqlErrors(HttpRequestResponse reqResp, String body) {
        List<AuditIssue> found = new ArrayList<>();
        var m = SQL_ERROR_PATTERN.matcher(body);
        if (m.find()) {
            found.add(issue(
                "SugarCRM SQL Error Message Disclosure",
                "A raw SQL error was found in the response, indicating a potential injection point "
                + "or misconfiguration: \"" + m.group(0) + "\"",
                "Suppress SQL error output in production. Centralise error handling through "
                + "SugarCRM's LoggerManager and never echo database exceptions to the browser.",
                reqResp, AuditIssueSeverity.MEDIUM, AuditIssueConfidence.CERTAIN
            ));
        }
        return found;
    }

    private List<AuditIssue> checkSecurityHeaders(HttpRequestResponse reqResp, String headers) {
        List<AuditIssue> found = new ArrayList<>();

        if (!headers.contains("X-Frame-Options") && !headers.contains("frame-ancestors")) {
            found.add(issue(
                "Missing X-Frame-Options / CSP frame-ancestors (Clickjacking Risk)",
                "The response for " + reqResp.request().url() + " does not set X-Frame-Options or "
                + "a CSP frame-ancestors directive, leaving it vulnerable to clickjacking.",
                "Add 'X-Frame-Options: SAMEORIGIN' and/or 'Content-Security-Policy: frame-ancestors "
                + "'self'' to all authenticated responses.",
                reqResp, AuditIssueSeverity.MEDIUM, AuditIssueConfidence.CERTAIN
            ));
        }

        if (!headers.contains("X-Content-Type-Options")) {
            found.add(issue(
                "Missing X-Content-Type-Options Header",
                "The response lacks X-Content-Type-Options: nosniff, enabling MIME sniffing attacks.",
                "Set 'X-Content-Type-Options: nosniff' in .htaccess or web server config.",
                reqResp, AuditIssueSeverity.LOW, AuditIssueConfidence.CERTAIN
            ));
        }

        if (!headers.contains("Content-Security-Policy")) {
            found.add(issue(
                "Missing Content-Security-Policy Header",
                "No CSP header was found. This increases XSS risk.",
                "Implement a Content-Security-Policy header. Start with "
                + "'default-src 'self'; script-src 'self'' and iterate.",
                reqResp, AuditIssueSeverity.LOW, AuditIssueConfidence.CERTAIN
            ));
        }

        if (!headers.contains("Strict-Transport-Security")) {
            found.add(issue(
                "Missing Strict-Transport-Security (HSTS)",
                "The response does not include an HSTS header.",
                "Set 'Strict-Transport-Security: max-age=31536000; includeSubDomains' on all HTTPS responses.",
                reqResp, AuditIssueSeverity.LOW, AuditIssueConfidence.CERTAIN
            ));
        }

        return found;
    }

    private List<AuditIssue> checkCookieFlags(HttpRequestResponse reqResp, String headers) {
        List<AuditIssue> found = new ArrayList<>();
        // Parse each Set-Cookie header
        String[] lines = headers.split("\r?\n");
        for (String line : lines) {
            if (!line.toLowerCase().startsWith("set-cookie:")) continue;

            if (line.contains("PHPSESSID") || line.contains("sugar")) {
                if (!line.contains("HttpOnly")) {
                    found.add(issue(
                        "SugarCRM Session Cookie Missing HttpOnly Flag",
                        "The session cookie is accessible via JavaScript (no HttpOnly flag). "
                        + "Cookie header: " + line.trim(),
                        "Set HttpOnly on all session cookies in PHP: "
                        + "session_set_cookie_params(['httponly' => true]).",
                        reqResp, AuditIssueSeverity.MEDIUM, AuditIssueConfidence.CERTAIN
                    ));
                }
                if (!line.contains("Secure")) {
                    found.add(issue(
                        "SugarCRM Session Cookie Missing Secure Flag",
                        "The session cookie can be sent over plain HTTP. Cookie: " + line.trim(),
                        "Set Secure flag on all session cookies. Enforce HTTPS site-wide.",
                        reqResp, AuditIssueSeverity.MEDIUM, AuditIssueConfidence.CERTAIN
                    ));
                }
                if (!line.contains("SameSite")) {
                    found.add(issue(
                        "SugarCRM Session Cookie Missing SameSite Attribute",
                        "The cookie lacks SameSite=Strict/Lax, making it easier to exploit CSRF.",
                        "Add SameSite=Strict (or Lax) to session cookies.",
                        reqResp, AuditIssueSeverity.LOW, AuditIssueConfidence.CERTAIN
                    ));
                }
            }
        }
        return found;
    }

    private List<AuditIssue> checkSensitiveDataInResponse(HttpRequestResponse reqResp, String body) {
        List<AuditIssue> found = new ArrayList<>();

        // MD5 password hash
        var m1 = MD5_HASH_PATTERN.matcher(body);
        if (m1.find()) {
            found.add(issue(
                "SugarCRM User Password Hash Disclosure",
                "An MD5 password hash was found in the response: " + m1.group(0).substring(0, Math.min(60, m1.group(0).length())),
                "Never expose password hashes in API responses. Filter the user_hash field from "
                + "all API output in SugarCRM's vardefs / ACL filters.",
                reqResp, AuditIssueSeverity.HIGH, AuditIssueConfidence.CERTAIN
            ));
        }

        // API keys / secrets
        var m2 = API_KEY_PATTERN.matcher(body);
        if (m2.find()) {
            found.add(issue(
                "SugarCRM API Key / Secret Disclosure",
                "A sensitive key was found in the response: " + m2.group(1),
                "Ensure API credentials are not included in REST responses. "
                + "Revoke and rotate any exposed keys immediately.",
                reqResp, AuditIssueSeverity.HIGH, AuditIssueConfidence.FIRM
            ));
        }

        // JWT
        var m3 = JWT_PATTERN.matcher(body);
        if (m3.find()) {
            found.add(issue(
                "JWT Token Found in Response Body",
                "A JWT was found in the response body. Verify it is intentionally returned and "
                + "is not leaking beyond its intended scope.",
                "Return JWTs only in dedicated authentication endpoints. "
                + "Use short expiry times and token rotation.",
                reqResp, AuditIssueSeverity.INFORMATION, AuditIssueConfidence.FIRM
            ));
        }

        // PII
        if (PII_SSN_PATTERN.matcher(body).find()) {
            found.add(issue(
                "PII — Social Security Number in Response",
                "A pattern matching a US SSN was found in the response.",
                "Mask or omit PII from API responses where not strictly required.",
                reqResp, AuditIssueSeverity.HIGH, AuditIssueConfidence.FIRM
            ));
        }
        if (PII_CC_PATTERN.matcher(body).find()) {
            found.add(issue(
                "PII — Credit Card Number in Response",
                "A pattern matching a credit/debit card number was found in the response.",
                "Mask PAN data; do not store or transmit full card numbers. Ensure PCI-DSS compliance.",
                reqResp, AuditIssueSeverity.HIGH, AuditIssueConfidence.FIRM
            ));
        }

        return found;
    }

    private List<AuditIssue> checkCredsInUrl(HttpRequestResponse reqResp, String url) {
        List<AuditIssue> found = new ArrayList<>();
        var m = CREDS_IN_URL_PATTERN.matcher(url);
        if (m.find()) {
            found.add(issue(
                "Credentials Transmitted in URL Query String",
                "A sensitive parameter (" + m.group(1) + ") was found in the URL. "
                + "Query string parameters are logged by web servers, proxies, and browser history.",
                "Move sensitive parameters to the POST body or Authorization header.",
                reqResp, AuditIssueSeverity.MEDIUM, AuditIssueConfidence.CERTAIN
            ));
        }
        return found;
    }

    private List<AuditIssue> checkDirectoryListing(HttpRequestResponse reqResp, String body) {
        List<AuditIssue> found = new ArrayList<>();
        if (DIR_LISTING_PATTERN.matcher(body).find()) {
            found.add(issue(
                "Directory Listing Enabled",
                "A directory listing was returned. This reveals file/folder names to attackers.",
                "Add 'Options -Indexes' to .htaccess or set DirectoryBrowse Off in IIS.",
                reqResp, AuditIssueSeverity.MEDIUM, AuditIssueConfidence.CERTAIN
            ));
        }
        return found;
    }

    private List<AuditIssue> checkBackupFiles(HttpRequestResponse reqResp, String body) {
        List<AuditIssue> found = new ArrayList<>();
        if (BACKUP_FILE_PATTERN.matcher(body).find() && reqResp.response().statusCode() == 200) {
            found.add(issue(
                "Backup / Temporary File Accessible",
                "A backup or temporary file appears to be accessible. These may contain "
                + "database credentials or source code.",
                "Remove backup files from the web root. Use automated CI/CD deployment to "
                + "prevent accidental file exposure.",
                reqResp, AuditIssueSeverity.HIGH, AuditIssueConfidence.FIRM
            ));
        }
        return found;
    }

    private List<AuditIssue> checkUnauthenticatedRestAccess(HttpRequestResponse reqResp, String body) {
        List<AuditIssue> found = new ArrayList<>();
        String url = reqResp.request().url();
        if (!url.contains("/api/v8/")) return found;

        String authHeader = reqResp.request().headerValue("Authorization");
        if ((authHeader == null || authHeader.isBlank()) && reqResp.response().statusCode() == 200
                && body.contains("\"id\"")) {
            found.add(issue(
                "SugarCRM REST API Unauthenticated Access",
                "An API v8 endpoint returned data without an Authorization header. "
                + "URL: " + url,
                "Ensure all REST API endpoints enforce OAuth2 authentication. Check the "
                + "app/routes.php and platform configuration.",
                reqResp, AuditIssueSeverity.HIGH, AuditIssueConfidence.CERTAIN
            ));
        }
        return found;
    }

    // ─── Helper ───────────────────────────────────────────────────────────────

    private AuditIssue issue(String name, String detail, String remediation,
                              HttpRequestResponse reqResp,
                              AuditIssueSeverity severity, AuditIssueConfidence confidence) {
        return AuditIssue.auditIssue(
            name, detail, remediation,
            reqResp.request().url(),
            severity, confidence,
            null, null, severity,
            reqResp
        );
    }
}
