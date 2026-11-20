package burp.ai;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

public class AiAnalyzerExtension implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("AI Analyzer");

        Settings settings = new Settings(api);
        AiClient client = new AiClient(line -> api.logging().logToOutput("[AI Analyzer] " + line));
        AiAnalyzerPanel panel = new AiAnalyzerPanel(api, settings, client);

        api.userInterface().registerSuiteTab("AI Analyzer", panel.getUiComponent());
        api.userInterface().registerContextMenuItemsProvider(new AnalyzeContextMenu(panel));

        api.logging().logToOutput("AI Analyzer loaded. Open the \"AI Analyzer\" tab to set a base URL and model, "
                + "then right-click any request and choose \"Send to AI Analyzer\".");
    }
}
