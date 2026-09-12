/**
 * TraceMail AI — Webmail Sentry Content Script
 * Injects 1-click forensic auditing directly into Gmail and Outlook webmail interfaces.
 */

const DEFAULT_SERVER_URL = "http://localhost:8899";

function getServerUrl(callback) {
  if (chrome.storage && chrome.storage.sync) {
    chrome.storage.sync.get(["tracemail_server_url"], (result) => {
      callback(result.tracemail_server_url || DEFAULT_SERVER_URL);
    });
  } else {
    callback(DEFAULT_SERVER_URL);
  }
}

// Injects the audit button into Gmail email thread view
function injectGmailAuditButton() {
  // Check if button already injected
  if (document.getElementById("tracemail-gmail-btn")) return;

  // Candidate toolbar locations in Gmail
  const toolbars = document.querySelectorAll(".G-Ni.J-J5-Ji, .amn, .bzn");
  if (!toolbars || toolbars.length === 0) return;

  const targetToolbar = toolbars[0];
  if (!targetToolbar) return;

  const btn = document.createElement("button");
  btn.id = "tracemail-gmail-btn";
  btn.type = "button";
  btn.className = "tracemail-audit-btn";
  btn.innerHTML = `<span>🛡️</span><span>Audit with TraceMail</span>`;
  btn.title = "Run Deep RFC 5322 Invariant & Threat Analysis with TraceMail AI";

  btn.addEventListener("click", (e) => {
    e.preventDefault();
    e.stopPropagation();
    extractAndAuditCurrentEmail();
  });

  targetToolbar.appendChild(btn);
}

// Injects the audit button into Outlook web view
function injectOutlookAuditButton() {
  if (document.getElementById("tracemail-outlook-btn")) return;

  const toolbar = document.querySelector("[aria-label='Command bar'], .ms-CommandBar");
  if (!toolbar) return;

  const btn = document.createElement("button");
  btn.id = "tracemail-outlook-btn";
  btn.type = "button";
  btn.className = "tracemail-audit-btn";
  btn.innerHTML = `<span>🛡️</span><span>Audit with TraceMail</span>`;
  btn.title = "Run Deep Forensic Analysis with TraceMail AI";

  btn.addEventListener("click", (e) => {
    e.preventDefault();
    e.stopPropagation();
    extractAndAuditCurrentEmail();
  });

  toolbar.appendChild(btn);
}

// Scrapes the email subject, sender, and body from the DOM
function extractAndAuditCurrentEmail() {
  showFloatingHUD("ANALYZING EMAIL INVARIANTS...", "Connecting to TraceMail Forensic Engine...", "loading");

  let subject = "";
  let sender = "";
  let bodyText = "";

  // Gmail extraction heuristics
  const h2Subject = document.querySelector("h2.hP");
  if (h2Subject) subject = h2Subject.innerText.trim();

  const senderSpan = document.querySelector("span.gD");
  if (senderSpan) {
    const emailAttr = senderSpan.getAttribute("email");
    sender = emailAttr ? `${senderSpan.innerText} <${emailAttr}>` : senderSpan.innerText;
  }

  const messageBody = document.querySelector(".a3s.aiL, .ii.gt");
  if (messageBody) {
    bodyText = messageBody.innerText.trim();
  }

  // Outlook extraction heuristics fallback
  if (!bodyText) {
    const outlookSubj = document.querySelector("[role='heading'][aria-level='2']");
    if (outlookSubj) subject = outlookSubj.innerText.trim();

    const outlookBody = document.querySelector("[aria-label='Message body'], .ReadingPaneContainer");
    if (outlookBody) bodyText = outlookBody.innerText.trim();
  }

  // Synthetic RFC 5322 message wrapper if raw headers aren't exposed directly by webmail
  const syntheticEml = [
    `From: ${sender || "Unknown Sender <sender@unknown.com>"}`,
    `Subject: ${subject || "Inspected Email"}`,
    `Date: ${new Date().toUTCString()}`,
    `Message-ID: <${Date.now()}@webmail-client>`,
    `MIME-Version: 1.0`,
    `Content-Type: text/plain; charset=UTF-8`,
    "",
    bodyText || "No email body text found in current view."
  ].join("\r\n");

  getServerUrl((serverUrl) => {
    sendToTraceMailServer(serverUrl, syntheticEml);
  });
}

function sendToTraceMailServer(serverUrl, emlText) {
  const formData = new FormData();
  formData.append("email_body", emlText);

  fetch(`${serverUrl}/scan`, {
    method: "POST",
    body: formData,
    headers: {
      "X-Analyst-Identity": "Webmail Sentry Extension",
      "X-Analyst-Clearance": "EXTENSION_L1"
    }
  })
  .then((res) => {
    if (!res.ok) throw new Error(`HTTP Error ${res.status}`);
    return res.json();
  })
  .then((report) => {
    renderScanResultsInHUD(serverUrl, report);
  })
  .catch((err) => {
    showFloatingHUD("CONNECTION OFFLINE", `Could not connect to TraceMail engine at ${serverUrl}. Ensure 'python3 app.py' is running.`, "error");
  });
}

function showFloatingHUD(title, subtitle, state) {
  let modal = document.getElementById("tracemail-hud-modal");
  if (!modal) {
    modal = document.createElement("div");
    modal.id = "tracemail-hud-modal";
    document.body.appendChild(modal);
  }

  modal.innerHTML = `
    <div class="tracemail-hud-header">
      <div class="tracemail-hud-title">
        <span>🛡️ TRACE-MAIL AI SENTRY</span>
      </div>
      <button class="tracemail-hud-close" onclick="document.getElementById('tracemail-hud-modal').remove()">&times;</button>
    </div>
    <div style="font-size:12px; font-weight:700; color:${state === 'error' ? '#f43f5e' : '#38bdf8'}; margin-bottom:4px;">
      ${title}
    </div>
    <div style="font-size:11px; color:#94a3b8; line-height:1.4;">
      ${subtitle}
    </div>
  `;
}

function renderScanResultsInHUD(serverUrl, report) {
  let modal = document.getElementById("tracemail-hud-modal");
  if (!modal) return;

  const score = report.fraud_score || 0;
  const isHighRisk = score >= 50;
  const badgeClass = isHighRisk ? "tracemail-badge tracemail-badge-danger" : "tracemail-badge tracemail-badge-safe";
  const label = isHighRisk ? "THREAT DETECTED" : "VERIFIED SAFE";
  const geo = (report.trace && report.trace.geo) ? report.trace.geo : (report.origin_geo || {});
  const city = geo.city && geo.city !== "Unavailable" ? geo.city : "";
  const country = geo.country && geo.country !== "Unavailable" ? geo.country : "";
  let locDisplay = (city && country) ? `${city}, ${country}` : (city || country || report.origin_location || "");
  if (!locDisplay || locDisplay === "Unknown Location") {
    locDisplay = geo.is_private ? "Internal Enclave (RFC 1918)" : (geo.note || "Perimeter Gateway");
  }

  modal.innerHTML = `
    <div class="tracemail-hud-header">
      <div class="tracemail-hud-title">
        <span>🛡️ FORENSIC VERDICT</span>
      </div>
      <button class="tracemail-hud-close" onclick="document.getElementById('tracemail-hud-modal').remove()">&times;</button>
    </div>
    
    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
      <div>
        <div style="font-size:22px; font-weight:800; color:${isHighRisk ? '#f43f5e' : '#10b981'};">
          ${score} <span style="font-size:12px; color:#94a3b8;">/ 100</span>
        </div>
        <div style="font-size:10px; color:#94a3b8;">RISK FACTOR</div>
      </div>
      <span class="${badgeClass}">${label}</span>
    </div>

    <div class="tracemail-metric-row">
      <span style="color:#94a3b8;">Classification:</span>
      <span style="font-weight:600; text-transform:uppercase;">${report.label || "Legitimate"}</span>
    </div>

    <div class="tracemail-metric-row">
      <span style="color:#94a3b8;">Origin Location:</span>
      <span style="color:#38bdf8; font-weight:600;">📍 ${locDisplay}</span>
    </div>

    <div class="tracemail-metric-row">
      <span style="color:#94a3b8;">Cryptographic Evidence:</span>
      <span style="font-family:monospace; font-size:10px; color:#6ee7b7;">${(report.evidence_hash || "SEALED").substring(0, 16)}...</span>
    </div>

    <a href="${serverUrl}" target="_blank" class="tracemail-radar-btn">
      🌐 Open 3D Planetary Radar &amp; Full Evidence Dossier &rarr;
    </a>
  `;
}

// Observe page DOM for email views
const observer = new MutationObserver(() => {
  if (window.location.hostname.includes("mail.google.com")) {
    injectGmailAuditButton();
  } else if (window.location.hostname.includes("outlook.")) {
    injectOutlookAuditButton();
  }
});

observer.observe(document.body, { childList: true, subtree: true });

console.log("[TraceMail AI Sentry] Webmail Forensic Extension Active.");
