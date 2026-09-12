const DEFAULT_SERVER_URL = "http://localhost:8899";

document.addEventListener("DOMContentLoaded", () => {
  const statusBadge = document.getElementById("serverStatusBadge");
  const serverUrlInput = document.getElementById("serverUrlInput");
  const saveUrlBtn = document.getElementById("saveUrlBtn");
  const dashboardLink = document.getElementById("dashboardLink");
  const auditTabBtn = document.getElementById("auditTabBtn");

  // Load saved server URL
  chrome.storage.sync.get(["tracemail_server_url"], (res) => {
    const url = res.tracemail_server_url || DEFAULT_SERVER_URL;
    serverUrlInput.value = url;
    dashboardLink.href = url;
    checkEngineHealth(url, statusBadge);
  });

  // Save server URL
  saveUrlBtn.addEventListener("click", () => {
    const newUrl = serverUrlInput.value.trim().replace(/\/$/, "");
    chrome.storage.sync.set({ tracemail_server_url: newUrl }, () => {
      dashboardLink.href = newUrl;
      checkEngineHealth(newUrl, statusBadge);
      alert("TraceMail Endpoint Saved!");
    });
  });

  // Audit Tab Button
  auditTabBtn.addEventListener("click", () => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs[0] && tabs[0].id) {
        chrome.scripting.executeScript({
          target: { tabId: tabs[0].id },
          func: () => {
            if (typeof extractAndAuditCurrentEmail === "function") {
              extractAndAuditCurrentEmail();
            } else {
              alert("Open a Gmail or Outlook email thread first, then click Audit.");
            }
          }
        }).catch(() => {
          alert("Could not inject into this tab. Please open Gmail or Outlook first.");
        });
      }
    });
  });
});

function checkEngineHealth(url, badge) {
  badge.innerText = "PINGING...";
  badge.className = "status-badge";

  fetch(`${url}/health`, { method: "GET" })
    .then((res) => {
      if (res.ok) {
        badge.innerText = "ONLINE";
        badge.className = "status-badge";
      } else {
        throw new Error();
      }
    })
    .catch(() => {
      badge.innerText = "OFFLINE";
      badge.className = "status-badge offline";
    });
}
