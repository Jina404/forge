# Forge AI Usage

## Run Full Platform With Docker Compose

Start all services in one command:

```bash
docker compose up --build
```

Services:

- Forge Agent API: http://127.0.0.1:8081
- Forge AI Planner: http://127.0.0.1:8090
- Browser Agent: http://127.0.0.1:8091
- PostgreSQL + pgvector: localhost:5432

## Bootstrap First Organization

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

## Login

```bash
curl -X POST http://127.0.0.1:8081/auth/login \
	-H "Content-Type: application/json" \
	-d '{"email":"admin@acme.test","password":"ChangeMe123!"}'
```

Copy the returned token and set it as bearer token:

```bash
Authorization: Bearer <token>
```

## Enterprise Endpoints

- GET /organizations
- GET /organizations/{orgID}
- GET /organizations/{orgID}/users
- POST /organizations/{orgID}/users
- GET /organizations/{orgID}/projects
- POST /organizations/{orgID}/projects
- GET /organizations/{orgID}/audit-logs

## Campaign Endpoints

- POST /campaigns
- GET /campaigns/{id}
- GET /campaigns/{id}/findings
- GET /campaigns/{id}/evidence
- GET /campaigns/{id}/memory
- GET /campaigns/{id}/reports/executive
- GET /campaigns/{id}/reports/technical

## Example Campaign Execution

```bash
curl -X POST http://127.0.0.1:8081/campaigns \
	-H "Content-Type: application/json" \
	-H "Authorization: Bearer <token>" \
	-d '{
		"name":"Bank API Security Assessment",
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
