# Getting Started

## Prerequisites

- Docker and Docker Compose
- Optional local toolchains for development:
  - Go 1.22+
  - Python 3.12+
  - Node.js 20+

## 1. Start the platform

```bash
docker compose up --build
```

## 2. Bootstrap the first organization

```bash
curl -X POST http://127.0.0.1:8081/bootstrap \
  -H "Content-Type: application/json" \
  -H "X-Forge-Bootstrap-Token: forge-bootstrap-change-me" \
  -d '{
    "organization_name":"Acme Red Team",
    "admin_email":"admin@acme.test",
    "admin_password":"ChangeMe123!"
  }'
```

## 3. Login and get a token

```bash
curl -X POST http://127.0.0.1:8081/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@acme.test","password":"ChangeMe123!"}'
```

## 4. Run your first campaign

```bash
curl -X POST http://127.0.0.1:8081/campaigns \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{
    "name":"Client Assessment",
    "target_url":"https://example.com",
    "method":"GET",
    "concurrency":50,
    "duration_seconds":10,
    "timeout_seconds":5,
    "fuzz_ratio":0.4,
    "fuzz_param":"/search?q=FUZZ",
    "payload_file":"payloads.txt",
    "baseline":true
  }'
```
