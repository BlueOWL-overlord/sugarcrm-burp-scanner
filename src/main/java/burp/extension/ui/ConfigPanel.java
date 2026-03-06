package burp.extension.ui;

import burp.extension.ExtensionConfig;
import burp.extension.SugarCRMExtension;
import burp.extension.auth.AuthManager;
import burp.extension.orchestrator.ScanOrchestrator;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;

/**
 * Swing UI tab displayed in Burp Suite's suite tab bar.
 *
 * Layout:
 *  [Target Config]  [Auth Config]  [Scan Options]
 *  [Status log]
 *  [Action buttons: Login | Start Scan | Stop]
 */
public class ConfigPanel {

    private final ExtensionConfig config;
    private final ScanOrchestrator orchestrator;
    private final AuthManager authManager;

    // Target fields
    private JTextField tfTargetUrl;
    private JTextField tfUsername;
    private JPasswordField pfPassword;

    // Session fields
    private JCheckBox cbUseRecordedSession;
    private JTextField tfSessionCookie;
    private JTextField tfSugarToken;

    // Options
    private JCheckBox cbSimulateActions;
    private JCheckBox cbPassToScanner;
    private JCheckBox cbTestAdmin;
    private JCheckBox cbTestRestApi;
    private JSpinner spCrawlDepth;

    // Log area
    private JTextArea taLog;

    // Status indicator
    private JLabel lblStatus;

    private JPanel rootPanel;

    public ConfigPanel(ExtensionConfig config, ScanOrchestrator orchestrator, AuthManager authManager) {
        this.config       = config;
        this.orchestrator = orchestrator;
        this.authManager  = authManager;
        buildUI();
    }

    private void buildUI() {
        rootPanel = new JPanel(new BorderLayout(8, 8));
        rootPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // ── Top: config panels in a row ──────────────────────────────────────
        JPanel topRow = new JPanel(new GridLayout(1, 3, 8, 0));
        topRow.add(buildTargetPanel());
        topRow.add(buildAuthPanel());
        topRow.add(buildOptionsPanel());
        rootPanel.add(topRow, BorderLayout.NORTH);

        // ── Centre: log ──────────────────────────────────────────────────────
        taLog = new JTextArea();
        taLog.setEditable(false);
        taLog.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        taLog.setBackground(Color.BLACK);
        taLog.setForeground(Color.GREEN);
        JScrollPane logScroll = new JScrollPane(taLog);
        logScroll.setBorder(new TitledBorder("Scan Log"));
        logScroll.setPreferredSize(new Dimension(0, 300));
        rootPanel.add(logScroll, BorderLayout.CENTER);

        // ── Bottom: status + action buttons ─────────────────────────────────
        rootPanel.add(buildButtonBar(), BorderLayout.SOUTH);
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

        cbUseRecordedSession = new JCheckBox("Use Burp-recorded session");
        cbUseRecordedSession.setToolTipText(
            "When checked, the extension reads the PHPSESSID cookie from\n" +
            "Burp Proxy history instead of logging in itself.");
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
        c.insets = new Insets(4, 4, 4, 4);
        c.anchor = GridBagConstraints.WEST;

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

        c.gridy = 4;
        JPanel depthRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        depthRow.add(new JLabel("Crawl depth:"));
        spCrawlDepth = new JSpinner(new SpinnerNumberModel(2, 1, 5, 1));
        depthRow.add(spCrawlDepth);
        p.add(depthRow, c);

        return p;
    }

    private JPanel buildButtonBar() {
        JPanel p = new JPanel(new BorderLayout(8, 4));

        lblStatus = new JLabel("Status: Idle");
        lblStatus.setFont(lblStatus.getFont().deriveFont(Font.BOLD));
        p.add(lblStatus, BorderLayout.WEST);

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));

        JButton btnLogin = new JButton("1. Login / Refresh Session");
        btnLogin.setToolTipText("Authenticate to SugarCRM and store the session cookie");
        btnLogin.addActionListener(e -> doLogin());

        JButton btnScan = new JButton("2. Start Full Scan");
        btnScan.setToolTipText("Crawl all modules, simulate user actions, and pass to Burp Scanner");
        btnScan.addActionListener(e -> doStartScan());

        JButton btnStop = new JButton("Stop");
        btnStop.setForeground(Color.RED);
        btnStop.addActionListener(e -> doStop());

        JButton btnClear = new JButton("Clear Log");
        btnClear.addActionListener(e -> taLog.setText(""));

        buttons.add(btnClear);
        buttons.add(btnStop);
        buttons.add(btnLogin);
        buttons.add(btnScan);
        p.add(buttons, BorderLayout.EAST);
        return p;
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
        config.setCrawlDepth((Integer) spCrawlDepth.getValue());
    }

    private void doLogin() {
        applyConfigFromUI();
        setStatus("Authenticating...", Color.ORANGE);
        log("[*] Starting login to " + config.getTargetUrl());
        new Thread(() -> {
            try {
                boolean ok = authManager.login();
                SwingUtilities.invokeLater(() -> {
                    if (ok) {
                        setStatus("Authenticated ✓", Color.GREEN);
                        tfSessionCookie.setText(config.getSessionCookie());
                        tfSugarToken.setText(config.getSugarToken());
                        log("[+] Login successful. Session: " + config.getSessionCookie().substring(0, Math.min(30, config.getSessionCookie().length())) + "...");
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
        if (!config.isAuthenticated()) {
            log("[!] Not authenticated. Run 'Login / Refresh Session' first.");
            return;
        }
        setStatus("Scanning...", Color.ORANGE);
        log("[*] Starting automated SugarCRM scan...");
        new Thread(() -> {
            orchestrator.startScan(this::log);
            SwingUtilities.invokeLater(() -> setStatus("Scan Complete", Color.GREEN));
        }, "SugarCRM-Scan").start();
    }

    private void doStop() {
        orchestrator.shutdown();
        setStatus("Stopped", Color.GRAY);
        log("[*] Scan stopped by user.");
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

    public JPanel getPanel() {
        return rootPanel;
    }
}
