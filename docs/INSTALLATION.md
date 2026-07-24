# Installation

This guide gives you a clear, repeatable path to run Forge AI locally.

## Installation Modes

- Mode A (recommended): Full platform with Docker Compose
- Mode B: Component development mode (Go, Python, and Node.js separately)

## Mode A: Full Platform with Docker Compose

### 1. Prerequisites

Install:

- Docker Desktop (includes Docker Compose)
- Git

Verify:

```bash
docker --version
docker compose version
git --version
```

### 2. Clone the repository

```bash
git clone https://github.com/Jina404/forge.git
cd forge
```

### 3. Start Forge services

```bash
docker compose up --build
```

Services started:

- Forge API: http://127.0.0.1:8081
- Forge AI service: http://127.0.0.1:8090
- Browser agent: http://127.0.0.1:8091
- PostgreSQL + pgvector: localhost:5432

### 4. Verify health

```bash
curl http://127.0.0.1:8081/healthz
curl http://127.0.0.1:8090/healthz
curl http://127.0.0.1:8091/healthz
```

Expected: JSON with status "ok" for each service.

### 5. Bootstrap first organization

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

### 6. Login

```bash
curl -X POST http://127.0.0.1:8081/auth/login \
	-H "Content-Type: application/json" \
	-d '{"email":"admin@acme.test","password":"ChangeMe123!"}'
```

Copy the returned token and use it as:

```text
Authorization: Bearer <token>
```

### 7. Run a first campaign

```bash
curl -X POST http://127.0.0.1:8081/campaigns \
	-H "Content-Type: application/json" \
	-H "Authorization: Bearer <token>" \
	-d '{
		"name":"API Security Test",
		"target_url":"https://example.com",
		"method":"GET",
		"concurrency":20,
		"duration_seconds":10,
		"timeout_seconds":5,
		"fuzz_ratio":0.4,
		"fuzz_param":"/search?q=FUZZ",
		"payload_file":"payloads.txt",
		"baseline":true
	}'
```

### 8. Stop services

```bash
docker compose down
```

Use `docker compose down -v` to also remove volumes.

## Mode B: Component Development Setup

Use this when developing specific components outside Docker.

### Required runtimes

- Go 1.22+
- Python 3.12+
- Node.js 20+
- npm 10+

Verify:

```bash
go version
python --version
node --version
npm --version
```

### Start browser agent only

```bash
npm --prefix browser-agent install
npx --prefix browser-agent playwright install chromium
npm --prefix browser-agent run dev
```

### Start AI service only

```bash
cd forge-ai
python service.py
```

### Start Go API locally

```bash
go build -o forge-agent ./cmd/forge-agent
./forge-agent
```

## Troubleshooting

### "docker: command not found"

Docker Desktop is not installed or not in PATH. Install Docker Desktop and restart terminal.

### "Python was not found"

Install Python 3.12+ and ensure `python` is available in PATH.

### Browser capture fails with Playwright executable missing

Run:

```bash
npx --prefix browser-agent playwright install chromium
```

### Go command missing

Install Go 1.22+ and ensure `go` is in PATH.

## Security reminder

Forge must only be used for authorized testing with explicit written permission.
