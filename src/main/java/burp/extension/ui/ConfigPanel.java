package burp.extension.ui;

import burp.extension.ExtensionConfig;
import burp.extension.SugarCRMExtension;
import burp.extension.auth.AuthManager;
import burp.extension.orchestrator.ScanOrchestrator;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Main UI tab for the SugarCRM Scanner extension.
 *
 * Layout — JTabbedPane with three tabs:
 *   1. "Configuration"   — Target / Session / Scan Options / Log / Buttons
 *   2. "Test Cases"      — Checkbox list organised by category; Select-All / Deselect-All
 *   3. "Recorded Login"  — Textarea for Burp Navigation-Recorder JSON + replay controls
 */
public class ConfigPanel {

    private final ExtensionConfig config;
    private final ScanOrchestrator orchestrator;
    private final AuthManager authManager;

    // ── Tab 1 – Configuration ─────────────────────────────────────────────────
    private JTextField   tfTargetUrl;
    private JTextField   tfUsername;
    private JPasswordField pfPassword;
    private JCheckBox    cbUseRecordedSession;
    private JTextField   tfSessionCookie;
    private JTextField   tfSugarToken;
    private JCheckBox    cbSimulateActions;
    private JCheckBox    cbPassToScanner;
    private JCheckBox    cbTestAdmin;
    private JCheckBox    cbTestRestApi;
    private JCheckBox    cbShowBrowserSim;
    private JCheckBox    cbAutoApproveIntrusive;
    private JSpinner     spCrawlDepth;
    private JTextArea    taLog;
    private JLabel       lblStatus;

    // ── Tab 2 – Test Cases ────────────────────────────────────────────────────
    /** Map from TestCase → its checkbox widget */
    private final Map<TestCase, JCheckBox> testCaseCheckboxes = new LinkedHashMap<>();

    // ── Tab 3 – Recorded Login ────────────────────────────────────────────────
    private JTextArea  taRecordedJson;
    private JLabel     lblJsonStatus;
    private JCheckBox  cbUseNavRecorder;

    private JPanel rootPanel;

    public ConfigPanel(ExtensionConfig config, ScanOrchestrator orchestrator,
                       AuthManager authManager) {
        this.config       = config;
        this.orchestrator = orchestrator;
        this.authManager  = authManager;
        buildUI();
    }

    // ─── UI construction ──────────────────────────────────────────────────────

    private void buildUI() {
        rootPanel = new JPanel(new BorderLayout());

        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("Configuration",   buildConfigTab());
        tabs.addTab("Test Cases",      buildTestCasesTab());
        tabs.addTab("Recorded Login",  buildRecordedLoginTab());

        rootPanel.add(tabs, BorderLayout.CENTER);
    }

    // ── Tab 1: Configuration ──────────────────────────────────────────────────

    private JPanel buildConfigTab() {
        JPanel tab = new JPanel(new BorderLayout(8, 8));
        tab.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // Top row: three config panels
        JPanel topRow = new JPanel(new GridLayout(1, 3, 8, 0));
        topRow.add(buildTargetPanel());
        topRow.add(buildAuthPanel());
        topRow.add(buildOptionsPanel());
        tab.add(topRow, BorderLayout.NORTH);

        // Centre: log area
        taLog = new JTextArea();
        taLog.setEditable(false);
        taLog.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        taLog.setBackground(new Color(20, 20, 20));
        taLog.setForeground(new Color(0, 220, 0));
        JScrollPane logScroll = new JScrollPane(taLog);
        logScroll.setBorder(new TitledBorder("Scan Log"));
        logScroll.setPreferredSize(new Dimension(0, 320));
        tab.add(logScroll, BorderLayout.CENTER);

        // Bottom: status + action buttons
        tab.add(buildButtonBar(), BorderLayout.SOUTH);
        return tab;
    }

    private JPanel buildTargetPanel() {
        JPanel p = new JPanel(new GridBagLayout());
        p.setBorder(new TitledBorder("Target"));
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(4, 4, 4, 4);
        c.fill   = GridBagConstraints.HORIZONTAL;

        c.gridx = 0; c.gridy = 0; c.weightx = 0; p.add(new JLabel("URL:"), c);
        c.gridx = 1; c.weightx = 1;
        tfTargetUrl = new JTextField(config.getTargetUrl(), 20);
        p.add(tfTargetUrl, c);

        c.gridx = 0; c.gridy = 1; c.weightx = 0; p.add(new JLabel("Username:"), c);
        c.gridx = 1; c.weightx = 1;
        tfUsername = new JTextField(config.getUsername(), 20);
        p.add(tfUsername, c);

        c.gridx = 0; c.gridy = 2; c.weightx = 0; p.add(new JLabel("Password:"), c);
        c.gridx = 1; c.weightx = 1;
        pfPassword = new JPasswordField(20);
        p.add(pfPassword, c);

        return p;
    }

    private JPanel buildAuthPanel() {
        JPanel p = new JPanel(new GridBagLayout());
        p.setBorder(new TitledBorder("Session / Auth"));
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(4, 4, 4, 4);
        c.fill   = GridBagConstraints.HORIZONTAL;

        cbUseRecordedSession = new JCheckBox("Use Burp proxy-history session");
        cbUseRecordedSession.setToolTipText(
            "Scan Burp Proxy history backwards for a SugarCRM login POST and\n" +
            "extract the PHPSESSID from the response Set-Cookie header.");
        cbUseRecordedSession.addActionListener(e -> {
            boolean use = cbUseRecordedSession.isSelected();
            tfUsername.setEnabled(!use);
            pfPassword.setEnabled(!use);
        });
        c.gridx = 0; c.gridy = 0; c.gridwidth = 2;
        p.add(cbUseRecordedSession, c);

        c.gridy = 1; c.gridwidth = 1; c.weightx = 0;
        p.add(new JLabel("Session Cookie:"), c);
        c.gridx = 1; c.weightx = 1;
        tfSessionCookie = new JTextField(20);
        tfSessionCookie.setToolTipText("Paste PHPSESSID=<value> here if using a recorded session");
        p.add(tfSessionCookie, c);

        c.gridx = 0; c.gridy = 2; c.weightx = 0;
        p.add(new JLabel("Sugar Token (CSRF):"), c);
        c.gridx = 1; c.weightx = 1;
        tfSugarToken = new JTextField(20);
        tfSugarToken.setToolTipText("sugar_token value from a recorded POST request");
        p.add(tfSugarToken, c);

        return p;
    }

    private JPanel buildOptionsPanel() {
        JPanel p = new JPanel(new GridBagLayout());
        p.setBorder(new TitledBorder("Scan Options"));
        GridBagConstraints c = new GridBagConstraints();
        c.insets  = new Insets(3, 4, 3, 4);
        c.anchor  = GridBagConstraints.WEST;

        cbSimulateActions = new JCheckBox("Simulate user actions (CRUD, search, upload)", true);
        cbSimulateActions.setToolTipText("Creates/edits/deletes sample records to surface more attack surface");
        c.gridx = 0; c.gridy = 0; p.add(cbSimulateActions, c);

        cbPassToScanner = new JCheckBox("Pass discovered URLs to Burp Scanner", true);
        cbPassToScanner.setToolTipText("Sends every discovered endpoint to Burp's active scanner");
        c.gridy = 1; p.add(cbPassToScanner, c);

        cbTestAdmin = new JCheckBox("Test admin endpoints", true);
        c.gridy = 2; p.add(cbTestAdmin, c);

        cbTestRestApi = new JCheckBox("Test REST API v8", true);
        c.gridy = 3; p.add(cbTestRestApi, c);

        cbShowBrowserSim = new JCheckBox("Show browser simulation in log", true);
        cbShowBrowserSim.setToolTipText(
            "Narrate each simulated user interaction step-by-step in the scan log,\n" +
            "mimicking what a real user would click in a browser.");
        c.gridy = 4; p.add(cbShowBrowserSim, c);

        cbAutoApproveIntrusive = new JCheckBox("Auto-approve all intrusive tests", false);
        cbAutoApproveIntrusive.setForeground(new Color(180, 0, 0));
        cbAutoApproveIntrusive.setToolTipText(
            "WARNING: When checked, no confirmation dialogs are shown before intrusive tests.\n" +
            "Only enable this if you have explicit written authorisation for all test types.");
        c.gridy = 5; p.add(cbAutoApproveIntrusive, c);

        c.gridy = 6;
        JPanel depthRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        depthRow.add(new JLabel("Crawl depth:"));
        spCrawlDepth = new JSpinner(new SpinnerNumberModel(2, 1, 5, 1));
        depthRow.add(spCrawlDepth);
        p.add(depthRow, c);

        return p;
    }

    private JPanel buildButtonBar() {
        JPanel p = new JPanel(new BorderLayout(8, 4));
        p.setBorder(BorderFactory.createEmptyBorder(6, 0, 0, 0));

        lblStatus = new JLabel("Status: Idle");
        lblStatus.setFont(lblStatus.getFont().deriveFont(Font.BOLD));
        p.add(lblStatus, BorderLayout.WEST);

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));

        JButton btnClear  = new JButton("Clear Log");
        btnClear.addActionListener(e -> taLog.setText(""));

        JButton btnStop   = new JButton("■ Stop");
        btnStop.setForeground(Color.RED);
        btnStop.addActionListener(e -> doStop());

        JButton btnLogin  = new JButton("1. Login / Refresh Session");
        btnLogin.setToolTipText("Authenticate to SugarCRM and store the session cookie");
        btnLogin.addActionListener(e -> doLogin());

        JButton btnScan   = new JButton("2. Start Full Scan");
        btnScan.setToolTipText("Crawl all modules, simulate user actions, and pass to Burp Scanner");
        btnScan.addActionListener(e -> doStartScan());

        buttons.add(btnClear);
        buttons.add(btnStop);
        buttons.add(btnLogin);
        buttons.add(btnScan);
        p.add(buttons, BorderLayout.EAST);
        return p;
    }

    // ── Tab 2: Test Cases ─────────────────────────────────────────────────────

    private JPanel buildTestCasesTab() {
        JPanel tab = new JPanel(new BorderLayout(8, 8));
        tab.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // Header info
        JLabel header = new JLabel("<html><b>Select the test cases to run.</b> "
            + "Tests marked <font color='#cc0000'>[INTRUSIVE]</font> will prompt "
            + "for approval before executing unless auto-approve is enabled.</html>");
        header.setBorder(BorderFactory.createEmptyBorder(0, 0, 8, 0));
        tab.add(header, BorderLayout.NORTH);

        // Scrollable panel of grouped checkboxes
        JPanel listPanel = new JPanel();
        listPanel.setLayout(new BoxLayout(listPanel, BoxLayout.Y_AXIS));
        listPanel.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4));

        for (TestCase.Category cat : TestCase.Category.values()) {
            java.util.List<TestCase> cases = TestCase.byCategory(cat);
            if (cases.isEmpty()) continue;

            JPanel catPanel = new JPanel(new GridBagLayout());
            catPanel.setBorder(new TitledBorder(cat.label));
            catPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
            GridBagConstraints c = new GridBagConstraints();
            c.insets  = new Insets(1, 4, 1, 4);
            c.anchor  = GridBagConstraints.WEST;
            c.fill    = GridBagConstraints.HORIZONTAL;
            c.weightx = 1;
            c.gridx   = 0;

            for (int i = 0; i < cases.size(); i++) {
                TestCase tc = cases.get(i);
                String label = (tc.intrusive ? "[INTRUSIVE] " : "") + tc.displayName;
                JCheckBox cb = new JCheckBox(label, config.isTestCaseEnabled(tc));
                if (tc.intrusive) cb.setForeground(new Color(180, 0, 0));
                cb.setToolTipText("<html><pre style='width:420px'>" + tc.description + "</pre></html>");
                cb.addActionListener(e -> config.setTestCaseEnabled(tc, cb.isSelected()));
                testCaseCheckboxes.put(tc, cb);
                c.gridy = i;
                catPanel.add(cb, c);
            }
            listPanel.add(catPanel);
            listPanel.add(Box.createRigidArea(new Dimension(0, 4)));
        }

        JScrollPane scroll = new JScrollPane(listPanel);
        scroll.getVerticalScrollBar().setUnitIncrement(16);
        tab.add(scroll, BorderLayout.CENTER);

        // Bottom: Select All / Deselect All / Intrusive Only buttons
        JPanel bottom = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        JButton btnAll      = new JButton("Select All");
        JButton btnNone     = new JButton("Deselect All");
        JButton btnSafeOnly = new JButton("Safe Tests Only");
        JButton btnDefault  = new JButton("Reset to Defaults");

        btnAll.addActionListener(e -> setAllCheckboxes(true));
        btnNone.addActionListener(e -> setAllCheckboxes(false));
        btnSafeOnly.addActionListener(e -> {
            for (Map.Entry<TestCase, JCheckBox> entry : testCaseCheckboxes.entrySet()) {
                boolean safe = !entry.getKey().intrusive;
                entry.getValue().setSelected(safe);
                config.setTestCaseEnabled(entry.getKey(), safe);
            }
        });
        btnDefault.addActionListener(e -> {
            for (Map.Entry<TestCase, JCheckBox> entry : testCaseCheckboxes.entrySet()) {
                boolean def = entry.getKey().enabledByDefault;
                entry.getValue().setSelected(def);
                config.setTestCaseEnabled(entry.getKey(), def);
            }
        });

        bottom.add(btnAll);
        bottom.add(btnNone);
        bottom.add(btnSafeOnly);
        bottom.add(btnDefault);
        tab.add(bottom, BorderLayout.SOUTH);
        return tab;
    }

    private void setAllCheckboxes(boolean selected) {
        for (Map.Entry<TestCase, JCheckBox> entry : testCaseCheckboxes.entrySet()) {
            entry.getValue().setSelected(selected);
            config.setTestCaseEnabled(entry.getKey(), selected);
        }
    }

    // ── Tab 3: Recorded Login ─────────────────────────────────────────────────

    private JPanel buildRecordedLoginTab() {
        JPanel tab = new JPanel(new BorderLayout(8, 8));
        tab.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // Instructions
        JTextArea instructions = new JTextArea(
            "Paste the JSON from Burp's Navigation Recorder (or a hand-crafted HTTP steps array) here.\n\n"
            + "Supported formats:\n"
            + "  [{ \"method\":\"GET\",  \"url\":\"https://target/index.php\", \"headers\":{}, \"body\":\"\" },\n"
            + "   { \"method\":\"POST\", \"url\":\"https://target/index.php\",\n"
            + "     \"headers\":{\"Content-Type\":\"application/x-www-form-urlencoded\"},\n"
            + "     \"body\":\"module=Users&action=Authenticate&user_name=admin&user_password=...\" }]\n\n"
            + "The extension will replay these steps in sequence, capture the PHPSESSID from\n"
            + "Set-Cookie headers, and extract the sugar_token from the response HTML.\n"
            + "This sequence is also used for automatic re-login if the session expires during a scan.\n\n"
            + "To export from Burp Pro: Proxy -> HTTP History -> right-click a login request\n"
            + "-> 'Copy as JSON' or use Session Handling -> Macros and export the macro.");
        instructions.setEditable(false);
        instructions.setBackground(new Color(245, 245, 245));
        instructions.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        instructions.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6));
        JScrollPane instrScroll = new JScrollPane(instructions);
        instrScroll.setPreferredSize(new Dimension(0, 160));
        instrScroll.setBorder(new TitledBorder("Instructions"));

        // JSON text area
        taRecordedJson = new JTextArea(12, 60);
        taRecordedJson.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        taRecordedJson.setLineWrap(true);
        taRecordedJson.setWrapStyleWord(false);
        taRecordedJson.setToolTipText("Paste your Navigation Recorder JSON here");
        JScrollPane jsonScroll = new JScrollPane(taRecordedJson);
        jsonScroll.setBorder(new TitledBorder("Navigation Recorder JSON"));

        // Use-this-JSON checkbox
        cbUseNavRecorder = new JCheckBox(
            "Use this Navigation Recorder JSON for login (overrides username/password login)",
            config.isUseNavigationRecorderJson());
        cbUseNavRecorder.addActionListener(e ->
            config.setUseNavigationRecorderJson(cbUseNavRecorder.isSelected()));

        // Status label
        lblJsonStatus = new JLabel("Status: Not yet tested");
        lblJsonStatus.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4));

        // Buttons
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));

        JButton btnTest = new JButton("Test Recorded Login");
        btnTest.setToolTipText("Replay the JSON sequence and verify the resulting session");
        btnTest.addActionListener(e -> doTestRecordedLogin());

        JButton btnCopy = new JButton("Copy JSON Template");
        btnCopy.setToolTipText("Copy a SugarCRM login JSON template to the clipboard");
        btnCopy.addActionListener(e -> {
            String template = buildJsonTemplate();
            Toolkit.getDefaultToolkit().getSystemClipboard()
                   .setContents(new StringSelection(template), null);
            JOptionPane.showMessageDialog(rootPanel,
                "SugarCRM login JSON template copied to clipboard.",
                "Template Copied", JOptionPane.INFORMATION_MESSAGE);
        });

        JButton btnClear = new JButton("Clear");
        btnClear.addActionListener(e -> {
            taRecordedJson.setText("");
            lblJsonStatus.setText("Status: Cleared");
            lblJsonStatus.setForeground(Color.GRAY);
        });

        buttons.add(cbUseNavRecorder);
        buttons.add(Box.createHorizontalStrut(16));
        buttons.add(btnTest);
        buttons.add(btnCopy);
        buttons.add(btnClear);

        // Centre layout
        JPanel centre = new JPanel(new BorderLayout(4, 4));
        centre.add(jsonScroll, BorderLayout.CENTER);

        JPanel bottom = new JPanel(new BorderLayout());
        bottom.add(buttons,      BorderLayout.NORTH);
        bottom.add(lblJsonStatus, BorderLayout.SOUTH);

        tab.add(instrScroll, BorderLayout.NORTH);
        tab.add(centre,       BorderLayout.CENTER);
        tab.add(bottom,       BorderLayout.SOUTH);
        return tab;
    }

    // ─── Actions ─────────────────────────────────────────────────────────────

    private void applyConfigFromUI() {
        config.setTargetUrl(tfTargetUrl.getText().trim());
        config.setUsername(tfUsername.getText().trim());
        config.setPassword(new String(pfPassword.getPassword()));
        config.setUseRecordedSession(cbUseRecordedSession.isSelected());
        config.setSessionCookie(tfSessionCookie.getText().trim());
        config.setSugarToken(tfSugarToken.getText().trim());
        config.setSimulateUserActions(cbSimulateActions.isSelected());
        config.setActivelyPassToBurpScanner(cbPassToScanner.isSelected());
        config.setTestAdminEndpoints(cbTestAdmin.isSelected());
        config.setTestRestApi(cbTestRestApi.isSelected());
        config.setShowBrowserSimulation(cbShowBrowserSim.isSelected());
        config.setAutoApproveIntrusive(cbAutoApproveIntrusive.isSelected());
        config.setCrawlDepth((Integer) spCrawlDepth.getValue());
        // Sync Navigation Recorder JSON from Tab 3
        config.setRecordedLoginJson(taRecordedJson.getText().trim());
        config.setUseNavigationRecorderJson(cbUseNavRecorder.isSelected());
    }

    private void doLogin() {
        applyConfigFromUI();
        setStatus("Authenticating...", Color.ORANGE);
        log("[*] Starting login to " + config.getTargetUrl());
        new Thread(() -> {
            try {
                boolean ok = authManager.login(this::log);
                SwingUtilities.invokeLater(() -> {
                    if (ok) {
                        setStatus("Authenticated ✓", Color.GREEN);
                        tfSessionCookie.setText(config.getSessionCookie());
                        tfSugarToken.setText(config.getSugarToken());
                        String preview = config.getSessionCookie();
                        if (preview.length() > 30) preview = preview.substring(0, 30) + "...";
                        log("[+] Login successful. Session: " + preview);
                    } else {
                        setStatus("Login FAILED", Color.RED);
                        log("[!] Login failed. Check credentials and target URL.");
                    }
                });
            } catch (Exception ex) {
                SwingUtilities.invokeLater(() -> {
                    setStatus("Error: " + ex.getMessage(), Color.RED);
                    log("[!] Exception during login: " + ex.getMessage());
                });
            }
        }, "SugarCRM-Login").start();
    }

    private void doStartScan() {
        applyConfigFromUI();

        // If a session was captured by "Test Recorded Login" on Tab 3, tfSessionCookie
        // is already populated and applyConfigFromUI() will have restored it into config.
        // Only block if we genuinely have nothing to work with.
        if (!config.isAuthenticated()) {
            // Auto-login attempt using the best available method before giving up
            log("[*] No active session — attempting auto-login before scan...");
            boolean ok = authManager.login(this::log);
            if (ok || !config.getSessionCookie().isBlank()) {
                SwingUtilities.invokeLater(() -> {
                    tfSessionCookie.setText(config.getSessionCookie());
                    tfSugarToken.setText(config.getSugarToken());
                });
            }
            if (!config.isAuthenticated()) {
                log("[!] Authentication failed. Use '1. Login / Refresh Session' or "
                    + "paste a Navigation Recorder JSON on the 'Recorded Login' tab.");
                setStatus("Not authenticated", Color.RED);
                return;
            }
        }

        setStatus("Scanning...", Color.ORANGE);
        log("[*] Starting automated SugarCRM scan...");

        // Build the intrusive-approval callback (shows Swing dialog on EDT)
        IntrusiveApprovalCallback approvalCallback = buildApprovalCallback();

        new Thread(() -> {
            orchestrator.startScan(this::log, approvalCallback);
            SwingUtilities.invokeLater(() -> setStatus("Scan Complete", Color.GREEN));
        }, "SugarCRM-Scan").start();
    }

    private void doStop() {
        orchestrator.shutdown();
        setStatus("Stopped", Color.GRAY);
        log("[*] Scan stopped by user.");
    }

    private void doTestRecordedLogin() {
        String json = taRecordedJson.getText().trim();
        if (json.isEmpty()) {
            lblJsonStatus.setText("Status: No JSON entered.");
            lblJsonStatus.setForeground(Color.RED);
            return;
        }
        applyConfigFromUI();
        lblJsonStatus.setText("Status: Replaying recorded steps...");
        lblJsonStatus.setForeground(Color.ORANGE);

        new Thread(() -> {
            boolean ok = authManager.loginFromRecordedJson(json, this::log);
            SwingUtilities.invokeLater(() -> {
                String cookie = config.getSessionCookie();
                boolean hasCookie = !cookie.isBlank();

                // Always populate the cookie fields with whatever was captured,
                // regardless of whether full verification succeeded.
                if (hasCookie) {
                    tfSessionCookie.setText(cookie);
                    tfSugarToken.setText(config.getSugarToken());
                }

                if (ok && hasCookie) {
                    String preview = cookie.length() > 40 ? cookie.substring(0, 40) + "..." : cookie;
                    lblJsonStatus.setText("Status: SUCCESS — " + preview);
                    lblJsonStatus.setForeground(new Color(0, 140, 0));
                    setStatus("Authenticated ✓", Color.GREEN);
                } else if (hasCookie) {
                    // Cookie captured but verification uncertain (e.g. SugarCRM 25.x JSON heuristic)
                    lblJsonStatus.setText("Status: Cookie captured — verification inconclusive. "
                        + "Try 'Start Full Scan' to proceed.");
                    lblJsonStatus.setForeground(new Color(180, 100, 0));
                    setStatus("Session captured (check log)", Color.ORANGE);
                } else {
                    lblJsonStatus.setText("Status: FAILED — No PHPSESSID captured. "
                        + "Check the JSON steps and target URL in the scan log.");
                    lblJsonStatus.setForeground(Color.RED);
                    setStatus("Login FAILED", Color.RED);
                }
            });
        }, "SugarCRM-RecordedLogin").start();
    }

    // ─── Intrusive approval dialog ────────────────────────────────────────────

    private IntrusiveApprovalCallback buildApprovalCallback() {
        return tc -> {
            if (config.isAutoApproveIntrusive()) {
                log("[Intrusive] Auto-approved: " + tc.displayName);
                return IntrusiveApprovalCallback.Decision.APPROVE;
            }

            // Build a detailed dialog
            String[] options = {"Run This Test", "Skip This Test", "Skip All Intrusive Tests"};
            String message = "<html><body style='width:480px'>"
                + "<h3 style='color:#cc0000'>⚠ Intrusive Test Confirmation</h3>"
                + "<b>Test:</b> " + escapeHtml(tc.displayName) + "<br>"
                + "<b>Category:</b> " + escapeHtml(tc.category.label) + "<br><br>"
                + "<b>Description:</b><br>"
                + "<pre style='width:460px;font-size:10px'>" + escapeHtml(tc.description) + "</pre>"
                + "<br><hr>"
                + "<b>This test may:</b><ul>"
                + "<li>Create, modify, or delete data on the target system</li>"
                + "<li>Send potentially malicious payloads to the server</li>"
                + "<li>Trigger server-side execution of code or system commands</li>"
                + "</ul>"
                + "<b>Only proceed if you have explicit written authorisation to perform "
                + "intrusive testing on this system.</b>"
                + "</body></html>";

            // Must run on EDT and block
            int[] result = {0};
            try {
                SwingUtilities.invokeAndWait(() -> {
                    result[0] = JOptionPane.showOptionDialog(
                        rootPanel, new JLabel(message),
                        "Intrusive Test Approval Required",
                        JOptionPane.DEFAULT_OPTION, JOptionPane.WARNING_MESSAGE,
                        null, options, options[0]);
                });
            } catch (Exception e) {
                return IntrusiveApprovalCallback.Decision.SKIP;
            }

            return switch (result[0]) {
                case 0  -> IntrusiveApprovalCallback.Decision.APPROVE;
                case 2  -> IntrusiveApprovalCallback.Decision.SKIP_ALL;
                default -> IntrusiveApprovalCallback.Decision.SKIP;
            };
        };
    }

    // ─── Helpers ─────────────────────────────────────────────────────────────

    public void log(String msg) {
        SwingUtilities.invokeLater(() -> {
            taLog.append(msg + "\n");
            taLog.setCaretPosition(taLog.getDocument().getLength());
        });
        SugarCRMExtension.api.logging().logToOutput(msg);
    }

    private void setStatus(String text, Color color) {
        lblStatus.setText("Status: " + text);
        lblStatus.setForeground(color);
    }

    public JPanel getPanel() { return rootPanel; }

    private String buildJsonTemplate() {
        return "[\n"
            + "  {\n"
            + "    \"method\": \"GET\",\n"
            + "    \"url\": \"" + config.getTargetUrl() + "/index.php\",\n"
            + "    \"headers\": {},\n"
            + "    \"body\": \"\"\n"
            + "  },\n"
            + "  {\n"
            + "    \"method\": \"POST\",\n"
            + "    \"url\": \"" + config.getTargetUrl() + "/index.php\",\n"
            + "    \"headers\": {\n"
            + "      \"Content-Type\": \"application/x-www-form-urlencoded\"\n"
            + "    },\n"
            + "    \"body\": \"module=Users&action=Authenticate&user_name="
            + config.getUsername()
            + "&user_password=PASTE_MD5_PASSWORD_HASH_HERE&sugar_token=PASTE_TOKEN_HERE"
            + "&login_module=Users&login_action=DetailView\"\n"
            + "  }\n"
            + "]\n";
    }

    private static String escapeHtml(String s) {
        return s.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\n", "<br>");
    }
}
