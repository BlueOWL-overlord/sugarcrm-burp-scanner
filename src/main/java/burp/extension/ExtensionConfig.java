package burp.extension;

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Shared configuration state for the extension.
 * All fields are thread-safe for concurrent access by crawler and scanner threads.
 */
public class ExtensionConfig {

    // -- Target --
    private final AtomicReference<String> targetUrl      = new AtomicReference<>("http://sugarcrm.local");
    private final AtomicReference<String> username       = new AtomicReference<>("admin");
    private final AtomicReference<String> password       = new AtomicReference<>("");

    // -- Session (populated after login or from recorded session) --
    private final AtomicReference<String> sessionCookie  = new AtomicReference<>("");
    private final AtomicReference<String> sugarToken     = new AtomicReference<>("");  // sugar_token CSRF
    private final AtomicReference<String> oauthToken     = new AtomicReference<>("");  // REST API bearer

    // -- Behaviour flags --
    private final AtomicBoolean useRecordedSession       = new AtomicBoolean(false);
    private final AtomicBoolean simulateUserActions      = new AtomicBoolean(true);
    private final AtomicBoolean activelyPassToBurpScanner = new AtomicBoolean(true);
    private final AtomicBoolean testAdminEndpoints       = new AtomicBoolean(true);
    private final AtomicBoolean testRestApi              = new AtomicBoolean(true);

    // -- Scan depth --
    private volatile int crawlDepth = 2;

    // Getters / setters

    public String getTargetUrl()   { return targetUrl.get(); }
    public void setTargetUrl(String v) { targetUrl.set(v.endsWith("/") ? v.substring(0, v.length()-1) : v); }

    public String getUsername()    { return username.get(); }
    public void setUsername(String v)  { username.set(v); }

    public String getPassword()    { return password.get(); }
    public void setPassword(String v)  { password.set(v); }

    public String getSessionCookie()   { return sessionCookie.get(); }
    public void setSessionCookie(String v) { sessionCookie.set(v); }

    public String getSugarToken()  { return sugarToken.get(); }
    public void setSugarToken(String v)    { sugarToken.set(v); }

    public String getOauthToken()  { return oauthToken.get(); }
    public void setOauthToken(String v)    { oauthToken.set(v); }

    public boolean isUseRecordedSession()        { return useRecordedSession.get(); }
    public void setUseRecordedSession(boolean v) { useRecordedSession.set(v); }

    public boolean isSimulateUserActions()        { return simulateUserActions.get(); }
    public void setSimulateUserActions(boolean v) { simulateUserActions.set(v); }

    public boolean isActivelyPassToBurpScanner()        { return activelyPassToBurpScanner.get(); }
    public void setActivelyPassToBurpScanner(boolean v) { activelyPassToBurpScanner.set(v); }

    public boolean isTestAdminEndpoints()        { return testAdminEndpoints.get(); }
    public void setTestAdminEndpoints(boolean v) { testAdminEndpoints.set(v); }

    public boolean isTestRestApi()        { return testRestApi.get(); }
    public void setTestRestApi(boolean v) { testRestApi.set(v); }

    public int getCrawlDepth()        { return crawlDepth; }
    public void setCrawlDepth(int v)  { crawlDepth = Math.max(1, Math.min(v, 5)); }

    /** Returns true if we have a usable authenticated session. */
    public boolean isAuthenticated() {
        return !sessionCookie.get().isBlank() || !oauthToken.get().isBlank();
    }
}
