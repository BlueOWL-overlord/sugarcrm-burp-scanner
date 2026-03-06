package burp.extension;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import burp.extension.auth.AuthManager;
import burp.extension.crawler.ModuleCrawler;
import burp.extension.scanner.ActiveScanChecks;
import burp.extension.scanner.PassiveScanChecks;
import burp.extension.orchestrator.ScanOrchestrator;
import burp.extension.ui.ConfigPanel;

/**
 * SugarCRM Burp Suite Pro Extension
 *
 * Automates security testing of SugarCRM instances by:
 *  - Replaying a recorded login or performing fresh authentication
 *  - Crawling all SugarCRM modules and REST API endpoints
 *  - Simulating user interactions (create/edit/delete/search/upload)
 *  - Submitting discovered URLs to Burp's active scanner
 *  - Running custom SugarCRM-specific active and passive scan checks
 */
public class SugarCRMExtension implements BurpExtension {

    public static MontoyaApi api;

    @Override
    public void initialize(MontoyaApi montoyaApi) {
        api = montoyaApi;
        api.extension().setName("SugarCRM Auto Scanner");

        // Shared config (target URL, credentials, session cookie)
        ExtensionConfig config = new ExtensionConfig();

        // Core components
        AuthManager authManager           = new AuthManager(api, config);
        ModuleCrawler crawler             = new ModuleCrawler(api, config, authManager);
        ActiveScanChecks activeScan       = new ActiveScanChecks(api, config);
        PassiveScanChecks passiveScan     = new PassiveScanChecks(api, config);
        ScanOrchestrator orchestrator     = new ScanOrchestrator(api, config, authManager, crawler);

        // Register scan checks with Burp
        api.scanner().registerScanCheck(activeScan);
        api.scanner().registerScanCheck(passiveScan);

        // Register HTTP handler to inject session into all in-scope requests
        api.http().registerHttpHandler(authManager);

        // Register the UI tab
        ConfigPanel configPanel = new ConfigPanel(config, orchestrator, authManager);
        api.userInterface().registerSuiteTab("SugarCRM Scanner", configPanel.getPanel());

        api.extension().registerUnloadingHandler(new ExtensionUnloadingHandler() {
            @Override
            public void extensionUnloaded() {
                orchestrator.shutdown();
                api.logging().logToOutput("SugarCRM Scanner unloaded.");
            }
        });

        api.logging().logToOutput("[SugarCRM Scanner] Extension loaded. Open the 'SugarCRM Scanner' tab to configure.");
    }
}
