# Quick Start

## Minimal flow

1. Start stack
2. Bootstrap org
3. Login
4. Run campaign
5. Retrieve findings and reports

## Get findings

```bash
curl -H "Authorization: Bearer <token>" \
  http://127.0.0.1:8081/campaigns/<campaign_id>/findings
```

## Get technical report

```bash
curl -H "Authorization: Bearer <token>" \
  http://127.0.0.1:8081/campaigns/<campaign_id>/reports/technical
```
