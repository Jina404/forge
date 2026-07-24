# API Reference

Base URL: http://127.0.0.1:8081

## Authentication

- POST /bootstrap
- POST /auth/login

## Enterprise

- GET /organizations
- GET /organizations/{id}
- GET/POST /organizations/{id}/users
- GET/POST /organizations/{id}/projects
- GET /organizations/{id}/audit-logs

## Campaigns

- POST /campaigns
- GET /campaigns/{id}
- GET /campaigns/{id}/findings
- GET /campaigns/{id}/evidence
- GET /campaigns/{id}/memory
- GET /campaigns/{id}/reports/executive
- GET /campaigns/{id}/reports/technical
