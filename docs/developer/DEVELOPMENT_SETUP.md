# Development Setup

## Toolchains

- Go 1.22+
- Python 3.12+
- Node.js 20+
- Docker

## Local services

```bash
docker compose up --build
```

## Component entry points

- Go API: cmd/forge-agent/main.go
- CLI: cmd/forge/main.go
- AI service: forge-ai/service.py
- Browser service: browser-agent/src/server.ts
