package burp.extension.auth;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.extension.ExtensionConfig;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * AuthManager handles:
 *  1. Fresh login via SugarCRM's web form (classic UI)
 *  2. OAuth2 token acquisition via REST API v8
 *  3. Extraction of session from Burp Proxy history (recorded login mode)
 *  4. HTTP handler: injects the live session cookie into all in-scope requests
 */
public class AuthManager implements HttpHandler {

    private final MontoyaApi api;
    private final ExtensionConfig config;

    // Patterns for extracting tokens from HTML
    private static final Pattern CSRF_PATTERN   = Pattern.compile("name=['\"]sugar_token['\"]\\s+value=['\"]([^'\"]+)['\"]");
    private static final Pattern SESSION_PATTERN = Pattern.compile("PHPSESSID=([^;\\s]+)");

    public AuthManager(MontoyaApi api, ExtensionConfig config) {
        this.api    = api;
        this.config = config;
    }

    // ─── Public API ───────────────────────────────────────────────────────────

    /**
     * Performs login based on config:
     *  - If useRecordedSession=true, scans Burp Proxy history for a valid session.
     *  - Otherwise, performs a fresh web-form login + REST OAuth2 login.
     *
     * @return true if authentication succeeded
     */
    public boolean login() {
        if (config.isUseRecordedSession() && !config.getSessionCookie().isBlank()) {
            // Caller pre-filled session cookie from the UI — verify it works
            return verifySession();
        }

        if (config.isUseRecordedSession()) {
            // Extract session from Burp Proxy history
            return extractSessionFromProxyHistory();
        }

        // Fresh login
        return performWebLogin() && performOAuthLogin();
    }

    /**
     * Scans Burp Proxy history for a SugarCRM POST /index.php login request and
     * extracts the session cookie from its response.
     */
    public boolean extractSessionFromProxyHistory() {
        List<ProxyHttpRequestResponse> history = api.proxy().history();
        String target = config.getTargetUrl();

        for (int i = history.size() - 1; i >= 0; i--) {
            ProxyHttpRequestResponse entry = history.get(i);
            HttpRequest  req  = entry.request();
            HttpResponse resp = entry.response();

            if (resp == null) continue;

            String url = req.url();
            if (!url.startsWith(target)) continue;

            // Find login POST: module=Users&action=Authenticate
            if (req.method().equalsIgnoreCase("POST")
                    && req.bodyToString().contains("action=Authenticate")) {

                String setCookie = resp.headerValue("Set-Cookie");
                if (setCookie == null) continue;

                Matcher m = SESSION_PATTERN.matcher(setCookie);
                if (m.find()) {
                    config.setSessionCookie("PHPSESSID=" + m.group(1));
                    api.logging().logToOutput("[Auth] Extracted PHPSESSID from Proxy history.");
                    // Also try to grab sugar_token from a subsequent response
                    extractTokenFromHistory(history, i + 1);
                    return verifySession();
                }
            }
        }

        api.logging().logToError("[Auth] No SugarCRM login found in Proxy history.");
        return false;
    }

    // ─── Private methods ──────────────────────────────────────────────────────

    /**
     * Two-step web login:
     *  Step 1 – GET /index.php  -> parse sugar_token (CSRF)
     *  Step 2 – POST /index.php?module=Users&action=Authenticate
     */
    private boolean performWebLogin() {
        try {
            // Step 1: GET the login page to retrieve the CSRF token
            HttpRequest getLogin = HttpRequest.httpRequestFromUrl(config.getTargetUrl() + "/index.php")
                    .withMethod("GET")
                    .withHeader("User-Agent", "Mozilla/5.0 (SugarCRM-BurpScanner/1.0)");

            HttpRequestResponse getResp = api.http().sendRequest(getLogin);
            if (getResp.response() == null) {
                api.logging().logToError("[Auth] No response to login page GET");
                return false;
            }

            // Parse sugar_token from HTML
            String html = getResp.response().bodyToString();
            String csrfToken = parseCsrfToken(html);

            // Extract session cookie from the GET response
            String setCookieGet = getResp.response().headerValue("Set-Cookie");
            if (setCookieGet != null) {
                Matcher m = SESSION_PATTERN.matcher(setCookieGet);
                if (m.find()) {
                    config.setSessionCookie("PHPSESSID=" + m.group(1));
                }
            }

            // Step 2: POST credentials
            String body = "module=Users"
                    + "&action=Authenticate"
                    + "&user_name=" + urlEncode(config.getUsername())
                    + "&user_password=" + urlEncode(md5Hex(config.getPassword()))
                    + "&sugar_token=" + urlEncode(csrfToken)
                    + "&login_module=Users"
                    + "&login_action=DetailView";

            HttpRequest postLogin = HttpRequest.httpRequestFromUrl(config.getTargetUrl() + "/index.php")
                    .withMethod("POST")
                    .withHeader("Content-Type", "application/x-www-form-urlencoded")
                    .withHeader("Cookie", config.getSessionCookie())
                    .withHeader("User-Agent", "Mozilla/5.0 (SugarCRM-BurpScanner/1.0)")
                    .withBody(body);

            HttpRequestResponse postResp = api.http().sendRequest(postLogin);
            if (postResp.response() == null) {
                api.logging().logToError("[Auth] No response to login POST");
                return false;
            }

            // Grab updated session cookie from login response
            String setCookiePost = postResp.response().headerValue("Set-Cookie");
            if (setCookiePost != null) {
                Matcher m = SESSION_PATTERN.matcher(setCookiePost);
                if (m.find()) {
                    config.setSessionCookie("PHPSESSID=" + m.group(1));
                }
            }

            // Store CSRF token
            if (!csrfToken.isEmpty()) {
                config.setSugarToken(csrfToken);
            }

            // Verify redirect to home (successful login)
            int status = postResp.response().statusCode();
            String location = postResp.response().headerValue("Location");
            boolean ok = (status == 302 && location != null && !location.contains("action=Login"))
                      || (status == 200 && postResp.response().bodyToString().contains("Home"));

            api.logging().logToOutput("[Auth] Web login " + (ok ? "succeeded" : "FAILED") + " (HTTP " + status + ")");
            return ok;

        } catch (Exception e) {
            api.logging().logToError("[Auth] Web login exception: " + e.getMessage());
            return false;
        }
    }

    /**
     * Acquire a REST API OAuth2 bearer token via /api/v8/oauth2/token
     * This is used for REST API scan coverage.
     */
    private boolean performOAuthLogin() {
        try {
            String body = "{"
                    + "\"grant_type\":\"password\","
                    + "\"client_id\":\"sugar\","
                    + "\"client_secret\":\"\","
                    + "\"username\":\"" + jsonEscape(config.getUsername()) + "\","
                    + "\"password\":\"" + jsonEscape(config.getPassword()) + "\","
                    + "\"platform\":\"base\""
                    + "}";

            HttpRequest req = HttpRequest.httpRequestFromUrl(config.getTargetUrl() + "/api/v8/oauth2/token")
                    .withMethod("POST")
                    .withHeader("Content-Type", "application/json")
                    .withHeader("User-Agent", "Mozilla/5.0 (SugarCRM-BurpScanner/1.0)")
                    .withBody(body);

            HttpRequestResponse resp = api.http().sendRequest(req);
            if (resp.response() == null) return false;

            if (resp.response().statusCode() == 200) {
                JsonObject json = JsonParser.parseString(resp.response().bodyToString()).getAsJsonObject();
                if (json.has("access_token")) {
                    config.setOauthToken(json.get("access_token").getAsString());
                    api.logging().logToOutput("[Auth] OAuth2 token acquired.");
                    return true;
                }
            }

            api.logging().logToOutput("[Auth] OAuth2 login failed (HTTP " + resp.response().statusCode() + ")");
            return false;

        } catch (Exception e) {
            api.logging().logToError("[Auth] OAuth2 login exception: " + e.getMessage());
            return false;
        }
    }

    /**
     * Makes a lightweight authenticated request to verify the current session.
     */
    private boolean verifySession() {
        try {
            HttpRequest req = HttpRequest.httpRequestFromUrl(config.getTargetUrl() + "/index.php?module=Home&action=index")
                    .withMethod("GET")
                    .withHeader("Cookie", config.getSessionCookie())
                    .withHeader("User-Agent", "Mozilla/5.0 (SugarCRM-BurpScanner/1.0)");

            HttpRequestResponse resp = api.http().sendRequest(req);
            if (resp.response() == null) return false;

            String body = resp.response().bodyToString();
            // If we see the login form, session is dead
            boolean valid = !body.contains("action=Login") && !body.contains("user_name");
            api.logging().logToOutput("[Auth] Session verification: " + (valid ? "VALID" : "INVALID"));
            return valid;

        } catch (Exception e) {
            api.logging().logToError("[Auth] Session verify exception: " + e.getMessage());
            return false;
        }
    }

    /** Scans proxy history entries after `startIdx` to find a sugar_token in HTML. */
    private void extractTokenFromHistory(List<ProxyHttpRequestResponse> history, int startIdx) {
        for (int i = startIdx; i < Math.min(history.size(), startIdx + 20); i++) {
            HttpResponse resp = history.get(i).response();
            if (resp == null) continue;
            String html = resp.bodyToString();
            if (html.contains("sugar_token")) {
                String token = parseCsrfToken(html);
                if (!token.isEmpty()) {
                    config.setSugarToken(token);
                    return;
                }
            }
        }
    }

    // ─── HttpHandler: inject session into all in-scope requests ──────────────

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent req) {
        // Only inject into requests targeting our configured SugarCRM host
        if (!config.isAuthenticated()) return RequestToBeSentAction.continueWith(req);
        if (!req.url().startsWith(config.getTargetUrl())) return RequestToBeSentAction.continueWith(req);

        HttpRequest modified = req;

        // Inject web session cookie
        if (!config.getSessionCookie().isBlank()) {
            String existing = req.headerValue("Cookie");
            if (existing == null || !existing.contains("PHPSESSID=")) {
                String newCookie = existing == null
                        ? config.getSessionCookie()
                        : config.getSessionCookie() + "; " + existing;
                modified = modified.withHeader("Cookie", newCookie);
            }
        }

        return RequestToBeSentAction.continueWith(modified);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived resp) {
        // Capture refreshed session cookies proactively
        String setCookie = resp.headerValue("Set-Cookie");
        if (setCookie != null && setCookie.contains("PHPSESSID=")) {
            Matcher m = SESSION_PATTERN.matcher(setCookie);
            if (m.find()) {
                config.setSessionCookie("PHPSESSID=" + m.group(1));
            }
        }
        return ResponseReceivedAction.continueWith(resp);
    }

    // ─── Utility helpers ──────────────────────────────────────────────────────

    private String parseCsrfToken(String html) {
        // Try regex first (faster)
        Matcher m = CSRF_PATTERN.matcher(html);
        if (m.find()) return m.group(1);

        // Fall back to Jsoup DOM parsing
        try {
            Document doc = Jsoup.parse(html);
            Element el = doc.selectFirst("input[name=sugar_token]");
            if (el != null) return el.val();
        } catch (Exception ignored) {}
        return "";
    }

    private String urlEncode(String s) {
        try {
            return java.net.URLEncoder.encode(s, "UTF-8");
        } catch (Exception e) {
            return s;
        }
    }

    private String jsonEscape(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    /**
     * SugarCRM stores the password as MD5(password).
     * In some versions it is MD5(password) hex-encoded.
     */
    private String md5Hex(String input) {
        try {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("MD5");
            byte[] digest = md.digest(input.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) {
            return input; // fallback — some Sugar versions accept plain text
        }
    }
}
