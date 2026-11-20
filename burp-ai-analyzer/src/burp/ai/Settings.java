package burp.ai;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.persistence.Preferences;

public class Settings {
    private static final String KEY_BASE_URL = "ai.baseUrl";
    private static final String KEY_API_KEY = "ai.apiKey";
    private static final String KEY_MODEL = "ai.model";
    private static final String KEY_PROMPT = "ai.prompt";

    /**
     * Shared instructions appended to both default prompts: ask the model to propose concrete,
     * runnable follow-up tests in a fixed, parseable format. AiAnalyzerPanel looks for exactly
     * this "SUGGESTED TEST:" + fenced block pattern to turn each suggestion into a Send/Repeater
     * button right in the Results panel.
     */
    private static final String SUGGESTED_TEST_INSTRUCTIONS =
            "\n\nIf, and only if, you spot something concretely worth testing, propose one or more follow-up " +
            "tests so they can be run directly. For each one, output exactly this format (one block per test):\n" +
            "SUGGESTED TEST: <short description of what it checks>\n" +
            "```http\n" +
            "<METHOD> <path-or-url> HTTP/1.1\n" +
            "<Header-Name: value>\n" +
            "\n" +
            "<body, if any>\n" +
            "```\n" +
            "Use a path relative to the same host as the original request unless you need a different host " +
            "(a full URL also works). You do not need to include the Host header, it is filled in " +
            "automatically. Only suggest safe, non-destructive tests appropriate for an authorized security " +
            "test. If there is nothing worth testing further, omit this section entirely.\n";

    public static final String DEFAULT_PROMPT =
            "You are a web application security analyst. Analyze the HTTP request and response below " +
            "and report any security issues you find (e.g. injection, auth/session flaws, sensitive data " +
            "exposure, misconfiguration, information disclosure). Be concise and specific, reference the " +
            "exact header/parameter/value involved.\n\n" +
            "=== REQUEST ===\n{{REQUEST}}\n\n=== RESPONSE ===\n{{RESPONSE}}\n"
            + SUGGESTED_TEST_INSTRUCTIONS;

    public static final String DEFAULT_FLOW_PROMPT =
            "You are a web application security analyst. Below is a multi-step HTTP flow (e.g. login, " +
            "checkout, password reset, invite/onboarding...) captured in order, step by step. Analyze the " +
            "flow AS A WHOLE, not just each request in isolation. Look specifically for: broken " +
            "authentication/session handling across steps, CSRF or anti-automation tokens that are missing, " +
            "reused or predictable between steps, authorization/state transitions that could be skipped or " +
            "replayed out of order, IDOR or privilege issues that only show up when steps are chained, race " +
            "conditions, and business-logic flaws (e.g. price/quantity/role manipulated at one step and " +
            "trusted at a later step). Reference the exact step number and header/parameter/value involved.\n\n" +
            "{{FLOW}}\n"
            + SUGGESTED_TEST_INSTRUCTIONS;

    private final Preferences prefs;

    public Settings(MontoyaApi api) {
        this.prefs = api.persistence().preferences();
    }

    public String getBaseUrl() {
        String v = prefs.getString(KEY_BASE_URL);
        return v != null ? v : "http://localhost:11434";
    }

    public void setBaseUrl(String v) {
        prefs.setString(KEY_BASE_URL, v);
    }

    public String getApiKey() {
        String v = prefs.getString(KEY_API_KEY);
        return v != null ? v : "";
    }

    public void setApiKey(String v) {
        prefs.setString(KEY_API_KEY, v);
    }

    public String getModel() {
        String v = prefs.getString(KEY_MODEL);
        return v != null ? v : "";
    }

    public void setModel(String v) {
        prefs.setString(KEY_MODEL, v);
    }

    public String getPrompt() {
        String v = prefs.getString(KEY_PROMPT);
        return v != null ? v : DEFAULT_PROMPT;
    }

    public void setPrompt(String v) {
        prefs.setString(KEY_PROMPT, v);
    }
}
