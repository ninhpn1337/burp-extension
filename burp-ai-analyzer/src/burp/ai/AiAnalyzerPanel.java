package burp.ai;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;

import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Single "AI Analyzer" suite tab: connection + model picker, prompt loader/selector,
 * and a results log that fills in as "Send to AI Analyzer" context-menu actions complete.
 */
public class AiAnalyzerPanel {

    private final MontoyaApi api;
    private final Settings settings;
    private final AiClient client;
    private final ExecutorService executor = Executors.newFixedThreadPool(2);
    private final Map<String, String> loadedPrompts = new LinkedHashMap<>();

    private final JPanel root = new JPanel(new BorderLayout(8, 8));
    private final JTextField baseUrlField = new JTextField();
    private final JPasswordField apiKeyField = new JPasswordField();
    private final JComboBox<String> modelCombo = new JComboBox<>();
    private final JButton connectButton = new JButton("Connect");
    private final JLabel statusLabel = new JLabel("Not connected");

    private final JComboBox<String> promptSelector = new JComboBox<>();
    private final JButton loadPromptButton = new JButton("Load prompt.txt...");
    private final JTextArea promptArea = new JTextArea();

    private static final Pattern SUGGESTED_TEST_PATTERN = Pattern.compile(
            "SUGGESTED TEST:\\s*(.*?)\\r?\\n```[a-zA-Z]*\\r?\\n([\\s\\S]*?)```", Pattern.MULTILINE);

    private final JPanel resultsContainer = new JPanel();

    public AiAnalyzerPanel(MontoyaApi api, Settings settings, AiClient client) {
        this.api = api;
        this.settings = settings;
        this.client = client;
        build();
        loadFromSettings();
    }

    public Component getUiComponent() {
        return root;
    }

    private void build() {
        JPanel connectionPanel = new JPanel(new GridBagLayout());
        connectionPanel.setBorder(BorderFactory.createTitledBorder("AI backend"));
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(4, 4, 4, 4);
        c.fill = GridBagConstraints.HORIZONTAL;

        c.gridx = 0; c.gridy = 0; c.weightx = 0;
        connectionPanel.add(new JLabel("Base URL:"), c);
        c.gridx = 1; c.weightx = 1;
        connectionPanel.add(baseUrlField, c);

        c.gridx = 0; c.gridy = 1; c.weightx = 0;
        connectionPanel.add(new JLabel("API key (optional):"), c);
        c.gridx = 1; c.weightx = 1;
        connectionPanel.add(apiKeyField, c);

        c.gridx = 0; c.gridy = 2; c.weightx = 0;
        connectionPanel.add(new JLabel("Model:"), c);
        c.gridx = 1; c.weightx = 1;
        modelCombo.setEditable(true);
        connectionPanel.add(modelCombo, c);

        c.gridx = 0; c.gridy = 3; c.gridwidth = 1; c.weightx = 0;
        connectionPanel.add(connectButton, c);
        c.gridx = 1; c.weightx = 1;
        connectionPanel.add(statusLabel, c);

        connectButton.addActionListener(e -> onConnect());

        JPanel promptPanel = new JPanel(new BorderLayout(4, 4));
        promptPanel.setBorder(BorderFactory.createTitledBorder("Prompt"));
        JPanel promptTop = new JPanel(new BorderLayout(4, 4));
        promptSelector.setPrototypeDisplayValue("default");
        promptTop.add(promptSelector, BorderLayout.CENTER);
        promptTop.add(loadPromptButton, BorderLayout.EAST);
        promptPanel.add(promptTop, BorderLayout.NORTH);
        promptArea.setLineWrap(true);
        promptArea.setWrapStyleWord(true);
        promptPanel.add(new JScrollPane(promptArea), BorderLayout.CENTER);

        loadedPrompts.put("default", Settings.DEFAULT_PROMPT);
        promptSelector.addItem("default");
        loadedPrompts.put("flow (multi-step)", Settings.DEFAULT_FLOW_PROMPT);
        promptSelector.addItem("flow (multi-step)");
        loadPromptButton.addActionListener(e -> onLoadPrompt());
        promptSelector.addActionListener(e -> {
            String name = (String) promptSelector.getSelectedItem();
            if (name != null && loadedPrompts.containsKey(name)) {
                promptArea.setText(loadedPrompts.get(name));
            }
        });

        JPanel top = new JPanel(new BorderLayout(8, 8));
        top.add(connectionPanel, BorderLayout.NORTH);
        top.add(promptPanel, BorderLayout.CENTER);

        resultsContainer.setLayout(new BoxLayout(resultsContainer, BoxLayout.Y_AXIS));
        JScrollPane resultsScroll = new JScrollPane(resultsContainer);
        resultsScroll.getVerticalScrollBar().setUnitIncrement(16);
        JPanel resultsPanel = new JPanel(new BorderLayout(4, 4));
        resultsPanel.setBorder(BorderFactory.createTitledBorder(
                "Results  (right-click request(s) -> \"Send to AI Analyzer\", or select several in order "
                        + "and use \"Send flow to AI Analyzer\". Any \"SUGGESTED TEST\" the AI proposes gets "
                        + "a Send/Repeater button below its answer.)"));
        resultsPanel.add(resultsScroll, BorderLayout.CENTER);
        JButton clearButton = new JButton("Clear");
        clearButton.addActionListener(e -> {
            resultsContainer.removeAll();
            resultsContainer.revalidate();
            resultsContainer.repaint();
        });
        JPanel resultsButtons = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        resultsButtons.add(clearButton);
        resultsPanel.add(resultsButtons, BorderLayout.SOUTH);

        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, top, resultsPanel);
        split.setResizeWeight(0.45);

        JButton saveButton = new JButton("Save settings");
        saveButton.addActionListener(e -> saveToSettings());
        JPanel bottomBar = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        bottomBar.add(saveButton);

        root.add(split, BorderLayout.CENTER);
        root.add(bottomBar, BorderLayout.SOUTH);
    }

    private void loadFromSettings() {
        baseUrlField.setText(settings.getBaseUrl());
        apiKeyField.setText(settings.getApiKey());
        String model = settings.getModel();
        if (model != null && !model.isBlank()) {
            modelCombo.addItem(model);
            modelCombo.setSelectedItem(model);
        }
        String savedPrompt = settings.getPrompt();
        if (savedPrompt != null && !savedPrompt.isBlank()) {
            loadedPrompts.put("default", savedPrompt);
        }
        promptArea.setText(loadedPrompts.get("default"));
    }

    private void saveToSettings() {
        settings.setBaseUrl(baseUrlField.getText().trim());
        settings.setApiKey(new String(apiKeyField.getPassword()));
        Object selectedModel = modelCombo.getSelectedItem();
        settings.setModel(selectedModel != null ? selectedModel.toString() : "");
        settings.setPrompt(promptArea.getText());
        statusLabel.setText("Settings saved.");
    }

    private void onConnect() {
        String baseUrl = baseUrlField.getText().trim();
        String apiKey = new String(apiKeyField.getPassword());
        statusLabel.setText("Connecting...");
        connectButton.setEnabled(false);
        executor.submit(() -> {
            AiClient.ConnectResult result = client.listModels(baseUrl, apiKey);
            SwingUtilities.invokeLater(() -> {
                connectButton.setEnabled(true);
                if (result.ok) {
                    String previous = (String) modelCombo.getSelectedItem();
                    modelCombo.removeAllItems();
                    for (String m : result.models) {
                        modelCombo.addItem(m);
                    }
                    if (previous != null && result.models.contains(previous)) {
                        modelCombo.setSelectedItem(previous);
                    }
                    statusLabel.setText("Connected - " + result.models.size() + " model(s) found.");
                } else {
                    statusLabel.setText("Connection failed: " + result.error);
                }
            });
        });
    }

    private void onLoadPrompt() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Load prompt file");
        chooser.setFileFilter(new FileNameExtensionFilter("Text files (*.txt)", "txt"));
        int res = chooser.showOpenDialog(root);
        if (res != JFileChooser.APPROVE_OPTION) {
            return;
        }
        File file = chooser.getSelectedFile();
        try {
            String content = Files.readString(file.toPath(), StandardCharsets.UTF_8);
            String name = file.getName();
            loadedPrompts.put(name, content);
            if (((DefaultComboBoxModel<String>) promptSelector.getModel()).getIndexOf(name) < 0) {
                promptSelector.addItem(name);
            }
            promptSelector.setSelectedItem(name);
            promptArea.setText(content);
        } catch (IOException ex) {
            JOptionPane.showMessageDialog(root, "Could not read file: " + ex.getMessage(),
                    "Load prompt", JOptionPane.ERROR_MESSAGE);
        }
    }

    /** Invoked from the context menu for each selected request/response, analyzed independently. */
    public void analyzeAsync(List<HttpRequestResponse> items) {
        Connection conn = currentConnection();
        if (conn == null) {
            return;
        }
        for (HttpRequestResponse item : items) {
            executor.submit(() -> runAnalysis(conn, item));
        }
    }

    private String buildFlowText(List<HttpRequestResponse> items) {
        StringBuilder flow = new StringBuilder();
        for (int i = 0; i < items.size(); i++) {
            HttpRequestResponse item = items.get(i);
            String method = item.request() != null ? item.request().method() : "?";
            String url = item.request() != null ? item.request().url() : "?";
            flow.append("--- Step ").append(i + 1).append(": ").append(method).append(" ").append(url).append(" ---\n");
            flow.append("[REQUEST]\n").append(item.request() != null ? item.request().toString() : "").append("\n\n");
            flow.append("[RESPONSE]\n")
                    .append(item.hasResponse() ? item.response().toString() : "(no response captured)")
                    .append("\n\n");
        }
        return flow.toString();
    }

    /** Invoked from the context menu for several selected request/response pairs, analyzed as one chained flow. */
    public void analyzeFlowAsync(List<HttpRequestResponse> items) {
        Connection conn = currentConnection();
        if (conn == null) {
            return;
        }
        if (items.size() < 2) {
            JOptionPane.showMessageDialog(root,
                    "Select two or more requests (in order) first, then \"Send flow to AI Analyzer\".",
                    "AI Analyzer", JOptionPane.WARNING_MESSAGE);
            return;
        }
        executor.submit(() -> runFlowAnalysis(conn, items));
    }

    private void runAnalysis(Connection conn, HttpRequestResponse item) {
        String requestText = item.request() != null ? item.request().toString() : "";
        String responseText = item.hasResponse() ? item.response().toString() : "(no response captured)";
        String prompt = conn.template.replace("{{REQUEST}}", requestText).replace("{{RESPONSE}}", responseText);

        String label = (item.request() != null ? item.request().method() + " " + item.request().url() : "request");
        HttpService defaultService = item.request() != null ? item.request().httpService() : null;
        ResultCard card = createResultCard(label, defaultService);

        try {
            String answer = client.chat(conn.baseUrl, conn.apiKey, conn.model, prompt);
            updateResultCard(card, answer);
        } catch (Exception e) {
            updateResultCard(card, "ERROR: " + e.getMessage());
            api.logging().logToError("AI Analyzer request failed", e);
        }
    }

    private void runFlowAnalysis(Connection conn, List<HttpRequestResponse> items) {
        String flow = buildFlowText(items);
        String prompt = conn.template.contains("{{FLOW}}")
                ? conn.template.replace("{{FLOW}}", flow)
                : conn.template.replace("{{REQUEST}}", flow).replace("{{RESPONSE}}", "(see steps above)");

        String label = "FLOW (" + items.size() + " steps): "
                + (items.get(0).request() != null ? items.get(0).request().method() + " " + items.get(0).request().url() : "?")
                + "  ->  ...  ->  "
                + (items.get(items.size() - 1).request() != null
                        ? items.get(items.size() - 1).request().method() + " " + items.get(items.size() - 1).request().url()
                        : "?");
        // Suggested tests for a flow default to the first step's host - most flows (login, checkout...)
        // stay on the same origin throughout.
        HttpService defaultService = items.get(0).request() != null ? items.get(0).request().httpService() : null;
        ResultCard card = createResultCard(label, defaultService);

        try {
            String answer = client.chat(conn.baseUrl, conn.apiKey, conn.model, prompt);
            updateResultCard(card, answer);
        } catch (Exception e) {
            updateResultCard(card, "ERROR: " + e.getMessage());
            api.logging().logToError("AI Analyzer flow request failed", e);
        }
    }

    private static final class Connection {
        final String baseUrl;
        final String apiKey;
        final String model;
        final String template;

        Connection(String baseUrl, String apiKey, String model, String template) {
            this.baseUrl = baseUrl;
            this.apiKey = apiKey;
            this.model = model;
            this.template = template;
        }
    }

    private Connection currentConnection() {
        String baseUrl = baseUrlField.getText().trim();
        String apiKey = new String(apiKeyField.getPassword());
        Object modelObj = modelCombo.getSelectedItem();
        String model = modelObj != null ? modelObj.toString().trim() : "";
        String template = promptArea.getText();

        if (baseUrl.isBlank() || model.isBlank()) {
            JOptionPane.showMessageDialog(root,
                    "Set a base URL and model in the AI Analyzer tab first, then Connect.",
                    "AI Analyzer", JOptionPane.WARNING_MESSAGE);
            return null;
        }
        return new Connection(baseUrl, apiKey, model, template);
    }

    /** One analysis result: a title, the AI's answer text, and any suggested-test sub-cards below it. */
    private static final class ResultCard {
        final JPanel panel;
        final JTextArea answerArea;
        final JPanel testsContainer;
        final HttpService defaultService;

        ResultCard(JPanel panel, JTextArea answerArea, JPanel testsContainer, HttpService defaultService) {
            this.panel = panel;
            this.answerArea = answerArea;
            this.testsContainer = testsContainer;
            this.defaultService = defaultService;
        }
    }

    /** Must be called off the EDT (from an executor task); blocks until the empty card is visible. */
    private ResultCard createResultCard(String label, HttpService defaultService) {
        String timestamp = new SimpleDateFormat("HH:mm:ss").format(new Date());
        ResultCard[] holder = new ResultCard[1];
        Runnable build = () -> holder[0] = buildResultCard(timestamp, label, defaultService);
        if (SwingUtilities.isEventDispatchThread()) {
            build.run();
        } else {
            try {
                SwingUtilities.invokeAndWait(build);
            } catch (Exception e) {
                build.run();
            }
        }
        return holder[0];
    }

    private ResultCard buildResultCard(String timestamp, String label, HttpService defaultService) {
        JPanel card = new JPanel(new BorderLayout(4, 4));
        card.setAlignmentX(Component.LEFT_ALIGNMENT);
        card.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createTitledBorder("[" + timestamp + "] " + label),
                BorderFactory.createEmptyBorder(4, 4, 4, 4)));

        JTextArea answerArea = new JTextArea("(analyzing...)");
        answerArea.setEditable(false);
        answerArea.setLineWrap(true);
        answerArea.setWrapStyleWord(true);
        card.add(answerArea, BorderLayout.CENTER);

        JPanel testsContainer = new JPanel();
        testsContainer.setLayout(new BoxLayout(testsContainer, BoxLayout.Y_AXIS));
        card.add(testsContainer, BorderLayout.SOUTH);

        resultsContainer.add(card);
        resultsContainer.add(Box.createVerticalStrut(6));
        resultsContainer.revalidate();
        resultsContainer.repaint();

        return new ResultCard(card, answerArea, testsContainer, defaultService);
    }

    private void updateResultCard(ResultCard card, String content) {
        SwingUtilities.invokeLater(() -> {
            card.answerArea.setText(content);
            card.testsContainer.removeAll();
            for (Matcher m = SUGGESTED_TEST_PATTERN.matcher(content); m.find(); ) {
                String description = m.group(1).trim();
                String rawRequest = m.group(2);
                card.testsContainer.add(buildSuggestedTestPanel(description, rawRequest, card.defaultService));
            }
            card.testsContainer.revalidate();
            card.panel.revalidate();
            card.panel.repaint();
        });
    }

    /**
     * One collapsed line by default: "[toggle] description [Send]". Clicking the toggle (or
     * Send) reveals the editable raw request + response below it. Keeps the results list scannable
     * instead of dumping a full request/response box per suggested test up front.
     */
    private JPanel buildSuggestedTestPanel(String description, String rawRequest, HttpService defaultService) {
        JPanel panel = new JPanel(new BorderLayout(2, 2));
        panel.setAlignmentX(Component.LEFT_ALIGNMENT);

        JButton toggleButton = new JButton("▸"); // collapsed triangle
        toggleButton.setMargin(new Insets(0, 4, 0, 4));
        JLabel descLabel = new JLabel(description);
        JButton sendButton = new JButton("Send");

        JPanel header = new JPanel(new BorderLayout(4, 0));
        JPanel left = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        left.add(toggleButton);
        left.add(descLabel);
        header.add(left, BorderLayout.CENTER);
        JPanel right = new JPanel(new FlowLayout(FlowLayout.RIGHT, 0, 0));
        right.add(sendButton);
        header.add(right, BorderLayout.EAST);
        panel.add(header, BorderLayout.NORTH);

        JTextArea reqArea = new JTextArea(rawRequest.strip(), 6, 60);
        reqArea.setLineWrap(true);
        JTextArea respArea = new JTextArea("(not sent yet)", 6, 60);
        respArea.setEditable(false);
        respArea.setLineWrap(true);

        JPanel detail = new JPanel(new GridLayout(1, 2, 4, 0));
        detail.add(new JScrollPane(reqArea));
        detail.add(new JScrollPane(respArea));
        detail.setVisible(false);
        panel.add(detail, BorderLayout.CENTER);

        Runnable toggle = () -> {
            boolean show = !detail.isVisible();
            detail.setVisible(show);
            toggleButton.setText(show ? "▾" : "▸");
            panel.revalidate();
        };
        toggleButton.addActionListener(e -> toggle.run());

        if (defaultService == null) {
            sendButton.setEnabled(false);
            descLabel.setText(description + "  (no target host captured - can't send)");
        } else {
            sendButton.addActionListener(e -> {
                if (!detail.isVisible()) {
                    toggle.run();
                }
                respArea.setText("(sending...)");
                String raw = reqArea.getText();
                executor.submit(() -> {
                    try {
                        HttpRequest req = HttpRequest.httpRequest(defaultService, normalizeLineEndings(raw));
                        HttpRequestResponse result = api.http().sendRequest(req);
                        String respText = result.hasResponse() ? result.response().toString() : "(no response)";
                        SwingUtilities.invokeLater(() -> respArea.setText(respText));
                    } catch (Exception ex) {
                        SwingUtilities.invokeLater(() -> respArea.setText("ERROR: " + ex.getMessage()));
                        api.logging().logToError("AI Analyzer suggested-test send failed", ex);
                    }
                });
            });
        }

        return panel;
    }

    private static String normalizeLineEndings(String raw) {
        return raw.replace("\r\n", "\n").replace("\n", "\r\n");
    }
}
