# Forge Browser Agent

Playwright-based browser automation service for screenshot evidence collection.

## Local run

1. Install dependencies

```bash
cd browser-agent
npm install
npx playwright install chromium
```

2. Start service

```bash
npm run dev
```

Default endpoint: http://127.0.0.1:8091

## Endpoints

- GET /healthz
- POST /capture

POST /capture body:

{
  "campaign_id": "cmp-123",
  "target_url": "https://example.com",
  "finding_type": "SQL Injection"
}
