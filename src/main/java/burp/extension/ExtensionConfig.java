package burp.extension;

import burp.extension.ui.TestCase;

import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Shared configuration state for the extension.
 * All fields are thread-safe for concurrent access by crawler and scanner threads.
 */
public class ExtensionConfig {

    // ── Target ────────────────────────────────────────────────────────────────
    private final AtomicReference<String> targetUrl  = new AtomicReference<>("http://sugarcrm.local");
    private final AtomicReference<String> username   = new AtomicReference<>("admin");
    private final AtomicReference<String> password   = new AtomicReference<>("");

    // ── Session (populated after login or from recorded session) ─────────────
    private final AtomicReference<String> sessionCookie = new AtomicReference<>("");
    private final AtomicReference<String> sugarToken    = new AtomicReference<>("");   // sugar_token CSRF
    private final AtomicReference<String> oauthToken    = new AtomicReference<>("");   // REST API bearer

    // ── Navigation Recorder JSON ─────────────────────────────────────────────
    // User pastes JSON exported from Burp's navigation recorder (or a plain
    // array of HTTP-step objects) here.  AuthManager.loginFromRecordedJson()
    // replays this sequence to obtain a fresh session when the current one
    // expires.
    private final AtomicReference<String> recordedLoginJson = new AtomicReference<>("");

    // ── Behaviour flags ───────────────────────────────────────────────────────
    private final AtomicBoolean useRecordedSession        = new AtomicBoolean(false);
    private final AtomicBoolean useNavigationRecorderJson = new AtomicBoolean(false);
    private final AtomicBoolean simulateUserActions       = new AtomicBoolean(true);
    private final AtomicBoolean activelyPassToBurpScanner = new AtomicBoolean(true);
    private final AtomicBoolean testAdminEndpoints        = new AtomicBoolean(true);
    private final AtomicBoolean testRestApi               = new AtomicBoolean(true);
    /** When true the browser simulation steps are logged verbosely (Chromium-like narration). */
    private final AtomicBoolean showBrowserSimulation     = new AtomicBoolean(true);
    /** When true all intrusive tests are automatically approved (no confirmation dialog). */
    private final AtomicBoolean autoApproveIntrusive      = new AtomicBoolean(false);

    // ── Scan depth ────────────────────────────────────────────────────────────
    private volatile int crawlDepth = 2;

    // ── Selected test cases ───────────────────────────────────────────────────
    // Populated from the TestCase selection panel in the UI.
    // Initialised to the default-enabled set so scans work without opening UI.
    private final Set<String> enabledTestCases = Collections.synchronizedSet(buildDefaultSet());

    private static Set<String> buildDefaultSet() {
        Set<String> s = new java.util.HashSet<>();
        for (TestCase tc : TestCase.values()) {
            if (tc.enabledByDefault) s.add(tc.id);
        }
        return s;
    }

    // ── Getters / Setters ─────────────────────────────────────────────────────

    public String getTargetUrl()   { return targetUrl.get(); }
    public void setTargetUrl(String v) {
        targetUrl.set(v.endsWith("/") ? v.substring(0, v.length() - 1) : v);
    }

    public String getUsername()  { return username.get(); }
    public void setUsername(String v) { username.set(v); }

    public String getPassword()  { return password.get(); }
    public void setPassword(String v) { password.set(v); }

    public String getSessionCookie()   { return sessionCookie.get(); }
    public void setSessionCookie(String v) { sessionCookie.set(v); }

    public String getSugarToken()  { return sugarToken.get(); }
    public void setSugarToken(String v)    { sugarToken.set(v); }

    public String getOauthToken()  { return oauthToken.get(); }
    public void setOauthToken(String v)    { oauthToken.set(v); }

    public String getRecordedLoginJson()   { return recordedLoginJson.get(); }
    public void setRecordedLoginJson(String v) { recordedLoginJson.set(v == null ? "" : v.trim()); }

    public boolean isUseRecordedSession()        { return useRecordedSession.get(); }
    public void setUseRecordedSession(boolean v) { useRecordedSession.set(v); }

    public boolean isUseNavigationRecorderJson()        { return useNavigationRecorderJson.get(); }
    public void setUseNavigationRecorderJson(boolean v) { useNavigationRecorderJson.set(v); }

    public boolean isSimulateUserActions()        { return simulateUserActions.get(); }
    public void setSimulateUserActions(boolean v) { simulateUserActions.set(v); }

    public boolean isActivelyPassToBurpScanner()        { return activelyPassToBurpScanner.get(); }
    public void setActivelyPassToBurpScanner(boolean v) { activelyPassToBurpScanner.set(v); }

    public boolean isTestAdminEndpoints()        { return testAdminEndpoints.get(); }
    public void setTestAdminEndpoints(boolean v) { testAdminEndpoints.set(v); }

    public boolean isTestRestApi()        { return testRestApi.get(); }
    public void setTestRestApi(boolean v) { testRestApi.set(v); }

    public boolean isShowBrowserSimulation()        { return showBrowserSimulation.get(); }
    public void setShowBrowserSimulation(boolean v) { showBrowserSimulation.set(v); }

    public boolean isAutoApproveIntrusive()        { return autoApproveIntrusive.get(); }
    public void setAutoApproveIntrusive(boolean v) { autoApproveIntrusive.set(v); }

    public int getCrawlDepth()        { return crawlDepth; }
    public void setCrawlDepth(int v)  { crawlDepth = Math.max(1, Math.min(v, 5)); }

    // ── Test case selection ───────────────────────────────────────────────────

    public boolean isTestCaseEnabled(TestCase tc) {
        return enabledTestCases.contains(tc.id);
    }

    public boolean isTestCaseEnabled(String id) {
        return enabledTestCases.contains(id);
    }

    public void setTestCaseEnabled(TestCase tc, boolean enabled) {
        if (enabled) enabledTestCases.add(tc.id);
        else         enabledTestCases.remove(tc.id);
    }

    public void setAllTestCasesEnabled(boolean enabled) {
        enabledTestCases.clear();
        if (enabled) {
            for (TestCase tc : TestCase.values()) enabledTestCases.add(tc.id);
        }
    }

    public Set<String> getEnabledTestCases() {
        return Collections.unmodifiableSet(enabledTestCases);
    }

    /** Returns true if we have a usable authenticated session. */
    public boolean isAuthenticated() {
        return !sessionCookie.get().isBlank() || !oauthToken.get().isBlank();
    }
}
