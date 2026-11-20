package burp.ai;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.util.ArrayList;
import java.util.List;

public class AnalyzeContextMenu implements ContextMenuItemsProvider {

    private final AiAnalyzerPanel panel;

    public AnalyzeContextMenu(AiAnalyzerPanel panel) {
        this.panel = panel;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<HttpRequestResponse> targets = new ArrayList<>(event.selectedRequestResponses());
        if (targets.isEmpty()) {
            event.messageEditorRequestResponse()
                    .ifPresent(editor -> targets.add(editor.requestResponse()));
        }
        if (targets.isEmpty()) {
            return List.of();
        }

        List<Component> items = new ArrayList<>();

        JMenuItem single = new JMenuItem(targets.size() > 1
                ? "Send to AI Analyzer (" + targets.size() + " requests, analyzed separately)"
                : "Send to AI Analyzer");
        single.addActionListener(e -> panel.analyzeAsync(targets));
        items.add(single);

        if (targets.size() > 1) {
            JMenuItem flow = new JMenuItem("Send flow to AI Analyzer (" + targets.size() + " steps, as one chain)");
            flow.addActionListener(e -> panel.analyzeFlowAsync(targets));
            items.add(flow);
        }

        String copyLabel = targets.size() > 1
                ? "Copy for another AI (" + targets.size() + ")"
                : "Copy for another AI";
        JMenu copyMenu = new JMenu(copyLabel);
        JMenuItem copyRequest = new JMenuItem("Request only");
        copyRequest.addActionListener(e -> copyToClipboard(targets, CopyMode.REQUEST));
        JMenuItem copyResponse = new JMenuItem("Response only");
        copyResponse.addActionListener(e -> copyToClipboard(targets, CopyMode.RESPONSE));
        JMenuItem copyBoth = new JMenuItem("Both");
        copyBoth.addActionListener(e -> copyToClipboard(targets, CopyMode.BOTH));
        copyMenu.add(copyRequest);
        copyMenu.add(copyResponse);
        copyMenu.add(copyBoth);
        items.add(copyMenu);

        return items;
    }

    private enum CopyMode { REQUEST, RESPONSE, BOTH }

    private static final String COPY_PROMPT_PREFIX =
            "Luồng gói tin này đội pentest đang thông báo có lỗ hổng bảo mật, chạy và verify đến khi nào "
                    + "ra hết các lỗ hổng bảo mật.\n\n";

    /** Formats the selected request(s) and/or response(s) as plain text (prefixed with a
     *  ready-to-use instruction prompt) and puts it on the clipboard, so it can be pasted
     *  straight into any external AI chat/agent. */
    private void copyToClipboard(List<HttpRequestResponse> targets, CopyMode mode) {
        StringBuilder sb = new StringBuilder(COPY_PROMPT_PREFIX);
        boolean numbered = targets.size() > 1;
        for (int i = 0; i < targets.size(); i++) {
            HttpRequestResponse item = targets.get(i);
            String method = item.request() != null ? item.request().method() : "?";
            String url = item.request() != null ? item.request().url() : "?";
            if (numbered) {
                sb.append("=== Request ").append(i + 1).append(": ").append(method).append(" ").append(url)
                        .append(" ===\n");
            }
            if (mode != CopyMode.RESPONSE) {
                sb.append("[REQUEST]\n").append(item.request() != null ? item.request().toString() : "").append("\n\n");
            }
            if (mode != CopyMode.REQUEST) {
                sb.append("[RESPONSE]\n")
                        .append(item.hasResponse() ? item.response().toString() : "(no response captured)")
                        .append("\n\n");
            }
        }
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(sb.toString()), null);
    }
}
