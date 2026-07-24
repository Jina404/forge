# Contributing to Forge

Thanks for improving Forge.

## Requirements

- Go 1.22+
- Python 3.12+
- Node.js 20+
- Docker + Docker Compose

## Development workflow

1. Create a branch from main.
2. Make focused changes.
3. Add or update tests.
4. Run lint/test locally.
5. Open a PR with clear context.

## Validation

```bash
go test ./...
docker compose up --build
```
