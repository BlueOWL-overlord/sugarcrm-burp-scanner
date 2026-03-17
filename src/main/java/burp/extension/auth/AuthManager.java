package burp.extension.auth;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.extension.ExtensionConfig;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;

import java.util.List;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * AuthManager handles:
 *  1. Fresh login via SugarCRM's web form (classic UI)
 *  2. OAuth2 token acquisition via REST API v8
 *  3. Extraction of session from Burp Proxy history (recorded session mode)
 *  4. Replay of a Burp Navigation-Recorder JSON sequence for automated re-login
 *  5. HTTP handler: injects the live session cookie into all in-scope requests
 */
public class AuthManager implements HttpHandler {

    private final MontoyaApi      api;
    private final ExtensionConfig config;

    private static final Pattern CSRF_PATTERN    = Pattern.compile(
        "name=['\"]sugar_token['\"]\\s+value=['\"]([^'\"]+)['\"]");
    private static final Pattern SESSION_PATTERN = Pattern.compile(
        "PHPSESSID=([^;\\s]+)");

    public AuthManager(MontoyaApi api, ExtensionConfig config) {
        this.api    = api;
        this.config = config;
    }

    // ─── Public API ───────────────────────────────────────────────────────────

    /**
     * Performs login based on config:
     *  a) Navigation-Recorder JSON is set  → replay the recorded sequence
     *  b) useRecordedSession=true + cookie  → verify existing session
     *  c) useRecordedSession=true (no cookie) → scan Burp Proxy history
     *  d) default                           → fresh web + OAuth2 login
     *
     * @return true if authentication succeeded
     */
    public boolean login() {
        return login(msg -> api.logging().logToOutput(msg));
    }

    public boolean login(Consumer<String> logger) {
        // Navigation-Recorder JSON takes highest priority
        if (config.isUseNavigationRecorderJson()
                && !config.getRecordedLoginJson().isBlank()) {
            logger.accept("[Auth] Using Navigation-Recorder JSON for login.");
            return loginFromRecordedJson(config.getRecordedLoginJson(), logger);
        }

        if (config.isUseRecordedSession() && !config.getSessionCookie().isBlank()) {
            logger.accept("[Auth] Verifying existing recorded session.");
            return verifySession(logger);
        }

        if (config.isUseRecordedSession()) {
            logger.accept("[Auth] Extracting session from Burp Proxy history.");
            return extractSessionFromProxyHistory(logger);
        }

        logger.accept("[Auth] Performing fresh web + OAuth2 login.");
        return performWebLogin(logger) && performOAuthLogin(logger);
    }

    /**
     * Parses a Burp Navigation-Recorder JSON (or any compatible HTTP-steps JSON)
     * and replays each HTTP request in sequence, capturing the session cookie.
     *
     * Supported formats:
     *
     * 1. Array of step objects (Burp navigation recorder / custom):
     *    [ { "method":"GET",  "url":"...", "headers":{}, "body":"" },
     *      { "method":"POST", "url":"...", "headers":{"Content-Type":"..."}, "body":"..." } ]
     *
     * 2. Single object with a "steps" or "requests" key containing the above array.
     *
     * 3. Array of Burp macro-style request objects:
     *    [ { "request": { "method":"POST", "url":"...", "body":"..." } } ]
     *
     * The method extracts PHPSESSID from Set-Cookie headers and sugar_token
     * from response HTML after the sequence completes.
     */
    public boolean loginFromRecordedJson(String json, Consumer<String> logger) {
        try {
            JsonElement root = JsonParser.parseString(json.trim());
            JsonArray steps;

            if (root.isJsonArray()) {
                steps = root.getAsJsonArray();
            } else if (root.isJsonObject()) {
                JsonObject obj = root.getAsJsonObject();
                // Try "steps", "requests", or "macro" keys
                if      (obj.has("steps"))    steps = obj.getAsJsonArray("steps");
                else if (obj.has("requests")) steps = obj.getAsJsonArray("requests");
                else if (obj.has("macro"))    steps = obj.getAsJsonArray("macro");
                else {
                    // Treat the whole object as a single request step
                    steps = new JsonArray();
                    steps.add(obj);
                }
            } else {
                logger.accept("[Auth] Recorded JSON is neither an object nor an array.");
                return false;
            }

            logger.accept("[Auth] Replaying " + steps.size() + " recorded step(s)...");

            for (int i = 0; i < steps.size(); i++) {
                JsonElement el = steps.get(i);
                if (!el.isJsonObject()) continue;
                JsonObject step = el.getAsJsonObject();

                // Unwrap Burp macro-style { "request": {...} }
                if (step.has("request") && step.get("request").isJsonObject()) {
                    step = step.getAsJsonObject("request");
                }

                String method = getStr(step, "method", "GET").toUpperCase();
                String url    = getStr(step, "url", "");
                String body   = getStr(step, "body", "");

                if (url.isBlank()) {
                    logger.accept("[Auth] Step " + (i + 1) + ": no URL — skipping.");
                    continue;
                }

                // Build request
                HttpRequest req = HttpRequest.httpRequestFromUrl(url)
                        .withMethod(method)
                        .withHeader("User-Agent", "Mozilla/5.0 (SugarCRM-BurpScanner/2.0)");

                // Inject current session cookie if we have one
                if (!config.getSessionCookie().isBlank()) {
                    req = req.withHeader("Cookie", config.getSessionCookie());
                }

                // Apply custom headers from the recorded step
                if (step.has("headers") && step.get("headers").isJsonObject()) {
                    for (var entry : step.getAsJsonObject("headers").entrySet()) {
                        String hName  = entry.getKey();
                        String hValue = entry.getValue().getAsString();
                        req = req.withHeader(hName, hValue);
                    }
                } else if (step.has("headers") && step.get("headers").isJsonArray()) {
                    // Array of { "name":..., "value":... }
                    for (JsonElement hEl : step.getAsJsonArray("headers")) {
                        if (!hEl.isJsonObject()) continue;
                        JsonObject h = hEl.getAsJsonObject();
                        String hName  = getStr(h, "name",  "");
                        String hValue = getStr(h, "value", "");
                        if (!hName.isBlank()) req = req.withHeader(hName, hValue);
                    }
                }

                // Set body for POST/PUT/PATCH
                if (!body.isBlank() && (method.equals("POST") || method.equals("PUT") || method.equals("PATCH"))) {
                    if (req.headerValue("Content-Type") == null) {
                        req = req.withHeader("Content-Type", "application/x-www-form-urlencoded");
                    }
                    req = req.withBody(body);
                }

                logger.accept("[Auth] Step " + (i + 1) + ": " + method + " " + url);
                HttpRequestResponse rr = api.http().sendRequest(req);
                if (rr.response() == null) {
                    logger.accept("[Auth]   → No response.");
                    continue;
                }

                int status = rr.response().statusCode();
                logger.accept("[Auth]   → HTTP " + status);

                // Capture PHPSESSID from Set-Cookie
                String setCookie = rr.response().headerValue("Set-Cookie");
                if (setCookie != null) {
                    Matcher m = SESSION_PATTERN.matcher(setCookie);
                    if (m.find()) {
                        config.setSessionCookie("PHPSESSID=" + m.group(1));
                        logger.accept("[Auth]   → Captured PHPSESSID from Set-Cookie.");
                    }
                }

                // Try to extract sugar_token from HTML response
                if (rr.response().bodyToString().contains("sugar_token")) {
                    String token = parseCsrfToken(rr.response().bodyToString());
                    if (!token.isEmpty()) {
                        config.setSugarToken(token);
                        logger.accept("[Auth]   → Captured sugar_token.");
                    }
                }
            }

            // Also acquire OAuth2 token if we now have credentials
            if (!config.getSessionCookie().isBlank()) {
                performOAuthLogin(logger);
            }

            boolean valid = verifySession(logger);
            logger.accept("[Auth] Navigation-Recorder replay " + (valid ? "SUCCEEDED" : "FAILED") + ".");
            return valid;

        } catch (Exception e) {
            logger.accept("[Auth] Navigation-Recorder JSON parse/replay error: " + e.getMessage());
            api.logging().logToError("[Auth] recordedJson error: " + e.getMessage());
            return false;
        }
    }

    /**
     * Scans Burp Proxy history for a SugarCRM POST /index.php login request and
     * extracts the session cookie from its response.
     */
    public boolean extractSessionFromProxyHistory() {
        return extractSessionFromProxyHistory(msg -> api.logging().logToOutput(msg));
    }

    public boolean extractSessionFromProxyHistory(Consumer<String> logger) {
        List<ProxyHttpRequestResponse> history = api.proxy().history();
        String target = config.getTargetUrl();

        for (int i = history.size() - 1; i >= 0; i--) {
            ProxyHttpRequestResponse entry = history.get(i);
            HttpRequest  req  = entry.request();
            HttpResponse resp = entry.response();

            if (resp == null) continue;

            String url = req.url();
            if (!url.startsWith(target)) continue;

            if (req.method().equalsIgnoreCase("POST")
                    && req.bodyToString().contains("action=Authenticate")) {

                String setCookie = resp.headerValue("Set-Cookie");
                if (setCookie == null) continue;

                Matcher m = SESSION_PATTERN.matcher(setCookie);
                if (m.find()) {
                    config.setSessionCookie("PHPSESSID=" + m.group(1));
                    logger.accept("[Auth] Extracted PHPSESSID from Proxy history.");
                    extractTokenFromHistory(history, i + 1);
                    return verifySession(logger);
                }
            }
        }

        logger.accept("[Auth] No SugarCRM login found in Proxy history.");
        return false;
    }

    // ─── Private login methods ────────────────────────────────────────────────

    private boolean performWebLogin(Consumer<String> logger) {
        try {
            HttpRequest getLogin = HttpRequest.httpRequestFromUrl(config.getTargetUrl() + "/index.php")
                    .withMethod("GET")
                    .withHeader("User-Agent", "Mozilla/5.0 (SugarCRM-BurpScanner/2.0)");

            HttpRequestResponse getResp = api.http().sendRequest(getLogin);
            if (getResp.response() == null) {
                logger.accept("[Auth] No response to login page GET");
                return false;
            }

            String html      = getResp.response().bodyToString();
            String csrfToken = parseCsrfToken(html);

            String setCookieGet = getResp.response().headerValue("Set-Cookie");
            if (setCookieGet != null) {
                Matcher m = SESSION_PATTERN.matcher(setCookieGet);
                if (m.find()) config.setSessionCookie("PHPSESSID=" + m.group(1));
            }

            String body = "module=Users"
                    + "&action=Authenticate"
                    + "&user_name="     + urlEncode(config.getUsername())
                    + "&user_password=" + urlEncode(md5Hex(config.getPassword()))
                    + "&sugar_token="   + urlEncode(csrfToken)
                    + "&login_module=Users"
                    + "&login_action=DetailView";

            HttpRequest postLogin = HttpRequest.httpRequestFromUrl(config.getTargetUrl() + "/index.php")
                    .withMethod("POST")
                    .withHeader("Content-Type", "application/x-www-form-urlencoded")
                    .withHeader("Cookie",       config.getSessionCookie())
                    .withHeader("User-Agent",   "Mozilla/5.0 (SugarCRM-BurpScanner/2.0)")
                    .withBody(body);

            HttpRequestResponse postResp = api.http().sendRequest(postLogin);
            if (postResp.response() == null) {
                logger.accept("[Auth] No response to login POST");
                return false;
            }

            String setCookiePost = postResp.response().headerValue("Set-Cookie");
            if (setCookiePost != null) {
                Matcher m = SESSION_PATTERN.matcher(setCookiePost);
                if (m.find()) config.setSessionCookie("PHPSESSID=" + m.group(1));
            }

            if (!csrfToken.isEmpty()) config.setSugarToken(csrfToken);

            int    status   = postResp.response().statusCode();
            String location = postResp.response().headerValue("Location");
            boolean ok = (status == 302 && location != null && !location.contains("action=Login"))
                      || (status == 200 && postResp.response().bodyToString().contains("Home"));

            logger.accept("[Auth] Web login " + (ok ? "succeeded" : "FAILED") + " (HTTP " + status + ")");
            return ok;

        } catch (Exception e) {
            logger.accept("[Auth] Web login exception: " + e.getMessage());
            return false;
        }
    }

    private boolean performOAuthLogin(Consumer<String> logger) {
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
                    .withHeader("User-Agent",   "Mozilla/5.0 (SugarCRM-BurpScanner/2.0)")
                    .withBody(body);

            HttpRequestResponse resp = api.http().sendRequest(req);
            if (resp.response() == null) return false;

            if (resp.response().statusCode() == 200) {
                JsonObject json = JsonParser.parseString(resp.response().bodyToString()).getAsJsonObject();
                if (json.has("access_token")) {
                    config.setOauthToken(json.get("access_token").getAsString());
                    logger.accept("[Auth] OAuth2 token acquired.");
                    return true;
                }
            }

            logger.accept("[Auth] OAuth2 login failed (HTTP " + resp.response().statusCode() + ")");
            return false;

        } catch (Exception e) {
            logger.accept("[Auth] OAuth2 login exception: " + e.getMessage());
            return false;
        }
    }

    private boolean performOAuthLogin() {
        return performOAuthLogin(msg -> api.logging().logToOutput(msg));
    }

    // ─── Session verification ─────────────────────────────────────────────────

    public boolean verifySession() {
        return verifySession(msg -> api.logging().logToOutput(msg));
    }

    public boolean verifySession(Consumer<String> logger) {
        try {
            HttpRequest req = HttpRequest.httpRequestFromUrl(
                        config.getTargetUrl() + "/index.php?module=Home&action=index")
                    .withMethod("GET")
                    .withHeader("Cookie",     config.getSessionCookie())
                    .withHeader("User-Agent", "Mozilla/5.0 (SugarCRM-BurpScanner/2.0)");

            HttpRequestResponse resp = api.http().sendRequest(req);
            if (resp.response() == null) return false;

            String body  = resp.response().bodyToString();
            boolean valid = !body.contains("action=Login") && !body.contains("\"user_name\"");
            logger.accept("[Auth] Session verification: " + (valid ? "VALID" : "INVALID"));
            return valid;

        } catch (Exception e) {
            logger.accept("[Auth] Session verify exception: " + e.getMessage());
            return false;
        }
    }

    // ─── Utility helpers ──────────────────────────────────────────────────────

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
        if (!config.isAuthenticated()) return RequestToBeSentAction.continueWith(req);
        if (!req.url().startsWith(config.getTargetUrl())) return RequestToBeSentAction.continueWith(req);

        HttpRequest modified = req;
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
        String setCookie = resp.headerValue("Set-Cookie");
        if (setCookie != null && setCookie.contains("PHPSESSID=")) {
            Matcher m = SESSION_PATTERN.matcher(setCookie);
            if (m.find()) config.setSessionCookie("PHPSESSID=" + m.group(1));
        }
        return ResponseReceivedAction.continueWith(resp);
    }

    // ─── Parsing helpers ──────────────────────────────────────────────────────

    private String parseCsrfToken(String html) {
        Matcher m = CSRF_PATTERN.matcher(html);
        if (m.find()) return m.group(1);
        try {
            Document doc = Jsoup.parse(html);
            Element el   = doc.selectFirst("input[name=sugar_token]");
            if (el != null) return el.val();
        } catch (Exception ignored) {}
        return "";
    }

    private String urlEncode(String s) {
        try { return java.net.URLEncoder.encode(s, "UTF-8"); }
        catch (Exception e) { return s; }
    }

    private String jsonEscape(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private String md5Hex(String input) {
        try {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("MD5");
            byte[] digest = md.digest(input.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) { return input; }
    }

    private String getStr(JsonObject obj, String key, String defaultVal) {
        if (!obj.has(key) || obj.get(key).isJsonNull()) return defaultVal;
        return obj.get(key).getAsString();
    }
}
