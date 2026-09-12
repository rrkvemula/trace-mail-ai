/**
 * TraceMail AI — Background Service Worker
 */

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: "tracemail-scan-selection",
    title: "⚡ Inspect Selection with TraceMail AI",
    contexts: ["selection", "link"]
  });
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId === "tracemail-scan-selection") {
    const textToScan = info.selectionText || info.linkUrl || "";
    if (textToScan && tab && tab.id) {
      chrome.tabs.sendMessage(tab.id, {
        action: "scan_snippet",
        snippet: textToScan
      }).catch(() => {
        // Tab might not have content script loaded
      });
    }
  }
});
