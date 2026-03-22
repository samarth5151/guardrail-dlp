# Barclays DLP Guardian — Browser Extension

A Chrome/Edge browser extension that **intercepts every prompt** typed into ChatGPT, Gemini, DeepSeek, and Claude, scans it through the Barclays DLP Gateway, and **blocks it in real-time** if sensitive data is detected.

## How It Works

```
Employee types prompt
        │
        ▼
[Browser Extension captures submit]
        │
        ▼
[Calls http://localhost:8001/gateway/analyze]
        │
        ├── BLOCK  → Red overlay shown, prompt NOT sent to LLM ❌
        ├── WARN   → Yellow overlay, user can cancel or proceed ⚠️
        └── PASS   → Prompt sent normally to LLM ✅
```

## Installation (Chrome / Edge)

1. **Make sure the DLP Gateway is running:**
   ```
   cd dlp-gateway
   docker compose up
   ```

2. **Open Extension Manager:**
   - Chrome: Navigate to `chrome://extensions`
   - Edge: Navigate to `edge://extensions`

3. **Enable Developer Mode** (toggle in top-right corner)

4. **Click "Load unpacked"**

5. **Select the `browser-extension` folder** inside the `dlp-gateway` directory

6. The **🛡 Barclays DLP Guardian** icon will appear in your toolbar

## What Is Intercepted

| Sensitive Data        | Example                        | Action |
|-----------------------|--------------------------------|--------|
| Passwords/Credentials | `saA@122@`, `ssd@#dD23`       | BLOCK  |
| AWS/API Keys          | `AKIA...`                      | BLOCK  |
| Credit Card Numbers   | Luhn-validated card numbers    | BLOCK  |
| IBAN / Sort Codes     | `GB34 BARC 2000 0055 7799 11` | BLOCK  |
| PII (Email, SSN, etc) | `john@barclays.com`            | BLOCK  |
| Confidential Markers  | `STRICTLY CONFIDENTIAL`        | BLOCK  |
| High-Entropy Secrets  | Long random tokens             | BLOCK  |

## Supported LLM Platforms

- ✅ ChatGPT (`chatgpt.com`)
- ✅ Google Gemini (`gemini.google.com`)
- ✅ DeepSeek (`chat.deepseek.com`)
- ✅ Claude (`claude.ai`)

## Admin Dashboard

View all intercepted prompts, risk scores, and alerts at:
**http://localhost:3000**
