# Forge
[![Go Version](https://img.shields.io/github/go-mod/go-version/Jina404/forge)](https://github.com/Jina404/forge)
[![Issues](https://img.shields.io/github/issues/Jina404/forge)](https://github.com/Jina404/forge/issues)
[![Stars](https://img.shields.io/github/stars/Jina404/forge)](https://github.com/Jina404/forge/stargazers)

## Autonomous Security Validation Platform

Forge is an open-source AI-powered red-team platform that combines:

- autonomous security reasoning
- high-performance attack simulation
- vulnerability validation
- evidence collection
- professional reporting

## Why Forge?

Traditional scanners ask:

"Is this vulnerability present?"

Forge asks:

"Can this vulnerability actually be exploited under realistic conditions?"

## Features

- AI-driven attack planning
- Web application testing
- API security testing
- Browser automation
- Vulnerability validation
- Attack campaigns
- Professional reporting
- Enterprise multi-tenant boundaries with RBAC and audit logs

## Architecture

```text
								 User
									 |
									 v
							 Forge API
									 |
									 v
				 Campaign Controller
							/           \
						 v             v
				 AI Agent      Attack Engine
						 \             /
							v           v
						 Evidence + Reporting
```

Detailed docs:

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- [docs/architecture/OVERVIEW.md](docs/architecture/OVERVIEW.md)
- [docs/architecture/SYSTEM_DESIGN.md](docs/architecture/SYSTEM_DESIGN.md)

## Installation

Run full stack:

```bash
docker compose up --build
```

## Quick Example

```bash
forge campaign create \
	--name "Client Assessment" \
	--target https://example.com
```

Or via API:

```bash
curl -X POST http://127.0.0.1:8081/campaigns \
	-H "Authorization: Bearer <token>" \
	-H "Content-Type: application/json" \
	-d '{"name":"API Security Test","target_url":"https://example.com"}'
```

## Security Notice

Forge must only be used against systems you own or have written permission to test.

- [SECURITY.md](SECURITY.md)
- [docs/security/safe-usage.md](docs/security/safe-usage.md)

## Documentation

- [docs/README.md](docs/README.md)
- [docs/GETTING_STARTED.md](docs/GETTING_STARTED.md)
- [docs/QUICK_START.md](docs/QUICK_START.md)
- [docs/developer/API_REFERENCE.md](docs/developer/API_REFERENCE.md)

## Community

- GitHub Discussions
- [Contributing Guide](CONTRIBUTING.md)
- [Code of Conduct](CODE_OF_CONDUCT.md)

## CI

GitHub Actions workflow [compose-smoke.yml](.github/workflows/compose-smoke.yml) builds and smoke-tests the full Compose stack.
