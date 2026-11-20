# -*- coding: utf-8 -*-
# Report Repeater - Burp Suite extension (Jython)
#
# Lets you capture/edit a request & response using Burp's own message editors
# (same look & feel as Repeater), then save the response as a "report response"
# rule. Any live traffic through Burp (Proxy/Repeater/Scanner/Intruder...)
# whose method+URL matches an enabled rule gets its real response replaced
# with your report one, before it reaches the client.
#
# Load: Burp > Extensions > Add > Extension type: Python, select this file.
# Requires a Jython standalone jar configured under Extensions > Settings >
# Python Environment.

import json

from burp import IBurpExtender, ITab, IHttpListener, IContextMenuFactory, IMessageEditorController

from javax.swing import (JPanel, JSplitPane, JList, DefaultListModel, JButton, JScrollPane,
                          JTextField, JLabel, JComboBox, JCheckBox, JDialog, JTextArea,
                          JOptionPane, ListSelectionModel, BorderFactory, SwingUtilities,
                          BoxLayout)
from java.awt import BorderLayout, GridLayout, FlowLayout, Dimension
from java.util import ArrayList

EXT_NAME = "Report Repeater"
SETTING_KEY = "report_repeater_rules_v1"


class ReportRule(object):
    def __init__(self, method, url_contains, status_line, headers, body, enabled=True):
        self.method = method              # "ANY" or e.g. "GET"
        self.url_contains = url_contains
        self.status_line = status_line    # e.g. "HTTP/1.1 200 OK"
        self.headers = headers            # list[str], without the status line
        self.body = body                  # python str, 1 char == 1 byte (via helpers.bytesToString)
        self.enabled = enabled

    def label(self):
        state = "ON " if self.enabled else "OFF"
        try:
            code = self.status_line.split(" ", 2)[1]
        except Exception:
            code = "?"
        return "[%s] %s %s -> %s" % (state, self.method, self.url_contains, code)

    def to_dict(self):
        return {
            "method": self.method,
            "url_contains": self.url_contains,
            "status_line": self.status_line,
            "headers": self.headers,
            "body": self.body,
            "enabled": self.enabled,
        }

    @staticmethod
    def from_dict(d):
        return ReportRule(d["method"], d["url_contains"], d["status_line"],
                         d["headers"], d["body"], d.get("enabled", True))


class BurpExtender(IBurpExtender, ITab, IHttpListener, IContextMenuFactory, IMessageEditorController):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName(EXT_NAME)

        self.rules = []
        self._currentService = None
        self._history = []
        self._historyIndex = -1

        self._buildUi()

        callbacks.addSuiteTab(self)
        callbacks.registerHttpListener(self)
        callbacks.registerContextMenuFactory(self)

        self._loadRules()
        callbacks.printOutput("%s loaded." % EXT_NAME)

    # ---------------- UI ----------------

    def _buildUi(self):
        self._mainPanel = JPanel(BorderLayout())

        self._ruleListModel = DefaultListModel()
        self._ruleList = JList(self._ruleListModel)
        self._ruleList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)

        leftPanel = JPanel(BorderLayout())
        leftPanel.setPreferredSize(Dimension(280, 0))
        leftPanel.setBorder(BorderFactory.createTitledBorder("Report response rules"))
        leftPanel.add(JScrollPane(self._ruleList), BorderLayout.CENTER)

        btnPanel = JPanel(GridLayout(0, 1, 2, 2))
        btnToggle = JButton("Enable/Disable", actionPerformed=self._toggleSelectedRule)
        btnDelete = JButton("Delete", actionPerformed=self._deleteSelectedRule)
        btnEdit = JButton("Load into editor", actionPerformed=self._loadSelectedRule)
        btnPanel.add(btnToggle)
        btnPanel.add(btnEdit)
        btnPanel.add(btnDelete)
        leftPanel.add(btnPanel, BorderLayout.SOUTH)

        # ---- top toolbar (full width, always visible regardless of split orientation) ----
        # Host/Port/HTTPS/Method/URL-contains are edited via the "Target..." dialog
        # instead of sitting in the main toolbar, so the screen above Request/Response
        # stays as clean as a real Repeater tab.
        self._hostField = JTextField("example.com", 14)
        self._portField = JTextField("443", 4)
        self._httpsBox = JCheckBox("HTTPS", True)
        self._methodBox = JComboBox(["ANY", "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
        self._urlField = JTextField("/api/", 20)

        sendBtn = JButton("Send >", actionPerformed=self._sendRequest)
        saveBtn = JButton("Save as Report Response", actionPerformed=self._saveRule)
        self._layoutBtn = JButton("Layout: Vertical", actionPerformed=self._toggleLayout)
        targetBtn = JButton("Target...", actionPerformed=self._openTargetDialog)
        pasteBtn = JButton("Paste raw response", actionPerformed=self._pasteRawResponse)
        self._prevBtn = JButton("< Prev", actionPerformed=self._historyPrev)
        self._nextBtn = JButton("Next >", actionPerformed=self._historyNext)
        self._historyLabel = JLabel("History: 0/0")
        self._prevBtn.setEnabled(False)
        self._nextBtn.setEnabled(False)

        toolbarLeft = JPanel(FlowLayout(FlowLayout.LEFT))
        toolbarLeft.add(sendBtn)
        toolbarLeft.add(saveBtn)
        toolbarLeft.add(targetBtn)
        toolbarLeft.add(self._layoutBtn)

        # History/paste controls live on their own, pushed to the right edge of
        # the toolbar so the primary Send/Save/Target/Layout buttons stand out
        # on the left and the row doesn't look cluttered.
        toolbarRight = JPanel(FlowLayout(FlowLayout.RIGHT))
        toolbarRight.add(pasteBtn)
        toolbarRight.add(self._prevBtn)
        toolbarRight.add(self._nextBtn)
        toolbarRight.add(self._historyLabel)

        topToolbar = JPanel(BorderLayout())
        topToolbar.add(toolbarLeft, BorderLayout.WEST)
        topToolbar.add(toolbarRight, BorderLayout.EAST)
        self._mainPanel.add(topToolbar, BorderLayout.NORTH)

        self._requestEditor = self._callbacks.createMessageEditor(self, True)
        self._responseEditor = self._callbacks.createMessageEditor(self, True)

        from java.awt import Font
        headerFont = Font("Dialog", Font.BOLD, 13)

        reqPanel = JPanel(BorderLayout())
        reqLabel = JLabel("Request")
        reqLabel.setFont(headerFont)
        reqLabel.setBorder(BorderFactory.createEmptyBorder(6, 8, 6, 8))
        reqPanel.add(reqLabel, BorderLayout.NORTH)
        reqPanel.add(self._requestEditor.getComponent(), BorderLayout.CENTER)

        respPanel = JPanel(BorderLayout())
        respLabel = JLabel("Response")
        respLabel.setFont(headerFont)
        respLabel.setBorder(BorderFactory.createEmptyBorder(6, 8, 6, 8))
        respPanel.add(respLabel, BorderLayout.NORTH)
        respPanel.add(self._responseEditor.getComponent(), BorderLayout.CENTER)

        # A GridLayout with one row / two equal columns always keeps the two
        # panes exactly 50/50 (unlike a JSplitPane, whose divider can drift
        # off-center depending on initial sizing), matching a real Repeater
        # tab's side-by-side look for a screenshot.
        self._reqRespSplit = JPanel(GridLayout(1, 2, 4, 0))
        self._reqRespSplit.add(reqPanel)
        self._reqRespSplit.add(respPanel)

        mainSplit = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, leftPanel, self._reqRespSplit)
        mainSplit.setResizeWeight(0.0)

        self._mainPanel.add(mainSplit, BorderLayout.CENTER)
        self._vertical = False

    def _toggleLayout(self, event):
        self._vertical = not self._vertical
        if self._vertical:
            rows, cols = 2, 1
            self._layoutBtn.setText("Layout: Horizontal")
        else:
            rows, cols = 1, 2
            self._layoutBtn.setText("Layout: Vertical")
        self._reqRespSplit.setLayout(GridLayout(rows, cols, 4, 4))
        self._reqRespSplit.revalidate()
        self._reqRespSplit.repaint()

    # ---------------- ITab ----------------

    def getTabCaption(self):
        return EXT_NAME

    def getUiComponent(self):
        return self._mainPanel

    # ---------------- IMessageEditorController ----------------

    def getHttpService(self):
        return self._currentService

    def getRequest(self):
        return self._requestEditor.getMessage()

    def getResponse(self):
        return self._responseEditor.getMessage()

    # ---------------- Context menu: "send to Report Repeater" ----------------

    def createMenuItems(self, invocation):
        from javax.swing import JMenuItem
        items = ArrayList()
        messages = invocation.getSelectedMessages()
        if messages and len(messages) > 0:
            item = JMenuItem("Send to Report Repeater",
                              actionPerformed=lambda e: self._loadMessageIntoEditor(messages[0]))
            items.add(item)
        return items

    def _loadMessageIntoEditor(self, messageInfo):
        service = messageInfo.getHttpService()
        self._currentService = service
        self._hostField.setText(service.getHost())
        self._portField.setText(str(service.getPort()))
        self._httpsBox.setSelected(service.getProtocol() == "https")

        reqBytes = messageInfo.getRequest()
        self._requestEditor.setMessage(reqBytes, True)

        try:
            analyzed = self._helpers.analyzeRequest(service, reqBytes)
            self._methodBox.setSelectedItem(analyzed.getMethod())
            path = analyzed.getUrl().getPath()
            self._urlField.setText(path if path else "/")
        except Exception:
            pass

        respBytes = messageInfo.getResponse()
        if respBytes:
            self._responseEditor.setMessage(respBytes, False)
        else:
            self._responseEditor.setMessage(self._helpers.stringToBytes(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}"), False)

    # ---------------- Target dialog (Host/Port/HTTPS/Method/URL contains) ----------------

    def _openTargetDialog(self, event):
        dialog = JDialog()
        dialog.setTitle("Target")
        dialog.setModal(True)

        form = JPanel(GridLayout(0, 2, 6, 6))
        form.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
        form.add(JLabel("Host:"))
        form.add(self._hostField)
        form.add(JLabel("Port:"))
        form.add(self._portField)
        form.add(JLabel("HTTPS:"))
        form.add(self._httpsBox)
        form.add(JLabel("Method (for saved rule):"))
        form.add(self._methodBox)
        form.add(JLabel("URL contains (for saved rule):"))
        form.add(self._urlField)

        closeBtn = JButton("Close", actionPerformed=lambda e: dialog.dispose())
        btnRow = JPanel(FlowLayout(FlowLayout.RIGHT))
        btnRow.add(closeBtn)

        content = JPanel(BorderLayout())
        content.add(form, BorderLayout.CENTER)
        content.add(btnRow, BorderLayout.SOUTH)
        dialog.setContentPane(content)
        dialog.pack()
        dialog.setLocationRelativeTo(self._mainPanel)
        dialog.setVisible(True)

    # ---------------- Send button: replay the (possibly edited) request ----------------

    def _sendRequest(self, event):
        try:
            host = self._hostField.getText().strip()
            port = int(self._portField.getText().strip())
            https = self._httpsBox.isSelected()
            service = self._helpers.buildHttpService(host, port, https)
            self._currentService = service
            reqBytes = self._requestEditor.getMessage()
            result = self._callbacks.makeHttpRequest(service, reqBytes)
            respBytes = result.getResponse()
            if respBytes:
                self._responseEditor.setMessage(respBytes, False)
                self._recordHistory(reqBytes, respBytes)
            else:
                JOptionPane.showMessageDialog(self._mainPanel, "No response received.")
        except Exception as e:
            JOptionPane.showMessageDialog(self._mainPanel, "Send failed: %s" % str(e))

    # ---------------- Send/response history (back/forward through real traffic) ----------------

    def _recordHistory(self, reqBytes, respBytes):
        self._history = self._history[:self._historyIndex + 1]
        self._history.append((reqBytes, respBytes))
        if len(self._history) > 200:
            self._history = self._history[-200:]
        self._historyIndex = len(self._history) - 1
        self._updateHistoryUi()

    def _updateHistoryUi(self):
        total = len(self._history)
        pos = self._historyIndex + 1 if total else 0
        self._historyLabel.setText("History: %d/%d" % (pos, total))
        self._prevBtn.setEnabled(self._historyIndex > 0)
        self._nextBtn.setEnabled(0 <= self._historyIndex < total - 1)

    def _historyPrev(self, event):
        if self._historyIndex > 0:
            self._historyIndex -= 1
            self._loadHistoryEntry()

    def _historyNext(self, event):
        if self._historyIndex < len(self._history) - 1:
            self._historyIndex += 1
            self._loadHistoryEntry()

    def _loadHistoryEntry(self):
        reqBytes, respBytes = self._history[self._historyIndex]
        self._requestEditor.setMessage(reqBytes, True)
        self._responseEditor.setMessage(respBytes, False)
        self._updateHistoryUi()

    # ---------------- Paste raw response ----------------

    def _pasteRawResponse(self, event):
        dialog = JDialog()
        dialog.setTitle("Paste raw HTTP response")
        dialog.setModal(True)
        dialog.setSize(700, 500)

        area = JTextArea()
        area.setText("HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\"ok\": true}")

        applyBtn = JButton("Apply")
        cancelBtn = JButton("Cancel")

        def onApply(e):
            text = area.getText().replace("\r\n", "\n").replace("\n", "\r\n")
            raw = self._helpers.stringToBytes(text)
            self._responseEditor.setMessage(raw, False)
            dialog.dispose()

        def onCancel(e):
            dialog.dispose()

        applyBtn.actionPerformed = onApply
        cancelBtn.actionPerformed = onCancel

        btnRow = JPanel(FlowLayout(FlowLayout.RIGHT))
        btnRow.add(cancelBtn)
        btnRow.add(applyBtn)

        content = JPanel(BorderLayout())
        content.add(JScrollPane(area), BorderLayout.CENTER)
        content.add(btnRow, BorderLayout.SOUTH)
        dialog.setContentPane(content)
        dialog.setLocationRelativeTo(self._mainPanel)
        dialog.setVisible(True)

    # ---------------- Save current response editor content as a rule ----------------

    def _saveRule(self, event):
        try:
            respBytes = self._responseEditor.getMessage()
            if not respBytes:
                JOptionPane.showMessageDialog(self._mainPanel, "Response editor is empty.")
                return
            info = self._helpers.analyzeResponse(respBytes)
            headers = list(info.getHeaders())
            statusLine = headers[0]
            otherHeaders = headers[1:]
            bodyBytes = respBytes[info.getBodyOffset():]
            bodyStr = self._helpers.bytesToString(bodyBytes)

            method = self._methodBox.getSelectedItem()
            urlContains = self._urlField.getText().strip()
            if not urlContains:
                JOptionPane.showMessageDialog(self._mainPanel, "Set a 'URL contains' match first.")
                return

            rule = ReportRule(method, urlContains, statusLine, otherHeaders, bodyStr, True)
            self.rules.append(rule)
            self._ruleListModel.addElement(rule.label())
            self._saveRules()
            JOptionPane.showMessageDialog(self._mainPanel, "Rule saved.")
        except Exception as e:
            JOptionPane.showMessageDialog(self._mainPanel, "Could not save rule: %s" % str(e))

    def _toggleSelectedRule(self, event):
        idx = self._ruleList.getSelectedIndex()
        if idx < 0:
            return
        rule = self.rules[idx]
        rule.enabled = not rule.enabled
        self._ruleListModel.set(idx, rule.label())
        self._saveRules()

    def _deleteSelectedRule(self, event):
        idx = self._ruleList.getSelectedIndex()
        if idx < 0:
            return
        del self.rules[idx]
        self._ruleListModel.remove(idx)
        self._saveRules()

    def _loadSelectedRule(self, event):
        idx = self._ruleList.getSelectedIndex()
        if idx < 0:
            return
        rule = self.rules[idx]
        self._methodBox.setSelectedItem(rule.method)
        self._urlField.setText(rule.url_contains)
        headerBlock = "\r\n".join([rule.status_line] + rule.headers)
        raw = self._helpers.stringToBytes(headerBlock + "\r\n\r\n" + rule.body)
        self._responseEditor.setMessage(raw, False)

    # ---------------- persistence ----------------

    def _saveRules(self):
        try:
            data = json.dumps([r.to_dict() for r in self.rules])
            self._callbacks.saveExtensionSetting(SETTING_KEY, data)
        except Exception as e:
            self._callbacks.printError("Failed to save rules: %s" % str(e))

    def _loadRules(self):
        try:
            data = self._callbacks.loadExtensionSetting(SETTING_KEY)
            if not data:
                return
            items = json.loads(data)
            self.rules = [ReportRule.from_dict(d) for d in items]
            for r in self.rules:
                self._ruleListModel.addElement(r.label())
        except Exception as e:
            self._callbacks.printError("Failed to load rules: %s" % str(e))

    # ---------------- IHttpListener: enforce rules on live traffic ----------------

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            return
        if not self.rules:
            return
        try:
            service = messageInfo.getHttpService()
            reqInfo = self._helpers.analyzeRequest(service, messageInfo.getRequest())
            method = reqInfo.getMethod()
            url = str(reqInfo.getUrl())
        except Exception:
            return

        for rule in self.rules:
            if not rule.enabled:
                continue
            if rule.method != "ANY" and rule.method.upper() != method.upper():
                continue
            if rule.url_contains not in url:
                continue

            cleanHeaders = []
            for h in rule.headers:
                low = h.lower()
                if low.startswith("content-length:") or low.startswith("transfer-encoding:") or low.startswith("content-encoding:"):
                    continue
                cleanHeaders.append(h)

            bodyBytes = self._helpers.stringToBytes(rule.body)
            cleanHeaders.append("Content-Length: %d" % len(bodyBytes))

            fullHeaders = ArrayList()
            fullHeaders.add(rule.status_line)
            for h in cleanHeaders:
                fullHeaders.add(h)

            newResponse = self._helpers.buildHttpMessage(fullHeaders, bodyBytes)
            messageInfo.setResponse(newResponse)
            return
