# 🛡️ ShieldCheck — Suspicious Message Inspector

A customer-facing web application built to help users identify scam messages, detect psychological manipulation patterns, and learn how to verify requests safely before acting.

Built for **Challenge 03: Help Customers Recognize a Suspicious Message**.

---

## 🚀 Quick Start

### Option 1: Direct in Browser (Zero Install)
Simply double-click or open `index.html` in any web browser (Google Chrome, Edge, Firefox, Safari).

### Option 2: Using the Included Local Server
Run the lightweight Python server:
```bash
python server.py 3000
```
Then navigate to: [http://localhost:3000](http://localhost:3000)

---

## ✨ Key Features

1. **Interactive Red-Flag Highlighter:**
   - Highlights exact suspicious phrases in the pasted text (Urgency, Credential Harvesters, Financial Traps).
   - Hover over or tap any highlighted phrase to see an educational explanation of *why* it is dangerous.

2. **Smart URL & Domain Inspector:**
   - Detects raw numerical IP addresses in links.
   - Detects URL shorteners (`bit.ly`, `tinyurl.com`, etc.) used to mask real landing pages.
   - Detects high-risk/cheap TLDs frequently used in phishing (`.xyz`, `.top`, `.click`, `.live`).
   - Flags typo-squatted brand names and deceptive lookalikes (`paypa1`, `chase-security-verify.xyz`).

3. **Multi-Factor Risk Scoring (0–100):**
   - 🟢 **Appears Safe (0–25):** No suspicious red flags detected.
   - 🟡 **Moderate Caution (26–59):** Triggers caution indicators (pressure tactics, vague greetings).
   - 🔴 **High Risk / Likely Scam (60–100):** Multiple critical phishing/social engineering indicators.

4. **Interactive "Safe Action Plan" Checklist:**
   - Context-aware action items generated specifically for the detected threats.
   - Interactive checkboxes allowing the user to track their verification steps before taking action.

5. **1-Click Test Scenarios:**
   - Includes 6 real-world presets:
     - 💳 *Chase Bank SMS Alert* (High Risk Phishing)
     - 📦 *USPS Delivery Address Trap* (Smishing & Shortened Link)
     - 💻 *Microsoft Tech Support Scam* (Fake Virus Alert & Phone Trap)
     - 🎁 *Boss Needs Gift Cards* (Executive Impersonation / CEO Fraud)
     - 📧 *Fake PayPal Refund / Invoice* (Cryptocurrency / Dispute Phishing)
     - 🛍️ *Legitimate Order Confirmation* (Baseline Safe Verification)

6. **100% Client-Side Privacy:**
   - All heuristics, link parsing, and text analysis happen strictly inside the customer's browser. No private customer communications are ever transmitted to external servers.

---

## 📁 File Structure

```text
VibeCode/
├── index.html           # Main semantic HTML structure & layout
├── style.css            # Highlight formatting, tooltips, and gauge animations
├── app.bundle.js        # Self-contained bundle (engine + sample data + UI controller)
├── detector.js          # Modular ES6 core detection logic & rule definitions
├── sample-messages.js   # Preloaded test presets
├── app.js               # Modular ES6 UI controller
├── server.py            # Local HTTP server with explicit MIME types
└── README.md            # Documentation & project guide
```

---

## 🔒 Security Best Practices Emphasized
- **Never share OTPs:** Real customer support agents never request your one-time passwords.
- **Inspect actual domains:** Check the address bar domain rather than the sender's display name.
- **Out-of-band verification:** Always use the phone number printed on the back of your official card or your authentic banking app.
