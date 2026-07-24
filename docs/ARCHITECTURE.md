# Forge AI Architecture

forge/

├── Phase 5: Platform and Operations
├── .github/
│   └── workflows/
│       └── compose-smoke.yml
├── docker-compose.yml
├── Dockerfile (planned)
├── Dockerfile.forge-agent
├── README.md
├── SECURITY.md
└── docs/USAGE.md

==================================================
PHASE 1 — Forge Core Security Engine (Go)
==================================================

cmd/
└── forge/
    └── main.go

pkg/

├── config/
│   └── config.go
│
├── core/
│   ├── orchestrator.go
│   ├── campaign.go
│   ├── workflow.go
│   └── scheduler.go (planned)
│
├── engine/
│   ├── runner.go
│   ├── worker.go
│   ├── client.go
│   └── fuzz_worker.go
│
├── detector/
│   ├── detector.go
│   ├── advanced.go
│   ├── xss.go (planned split)
│   └── sql.go (planned split)
│
├── fuzzer/
│   ├── fuzzer.go
│   ├── payloads.go (planned split)
│   ├── mutation.go (planned split)
│   └── generator.go (planned split)
│
└── metrics/
    ├── collector.go
    └── telemetry.go (planned)

==================================================
PHASE 2 — Autonomous AI Security Agent
==================================================

forge-ai/

(Python Service)

├── service.py
├── planner.py (planned root-level alias)
├── reasoning.py (planned root-level alias)
├── executor.py (planned root-level alias)
├── memory.py (planned root-level alias)
├── agent/planner.py
├── agent/reasoning.py
├── agent/executor.py
├── agent/memory.py
├── prompts/
└── models/

Responsibilities:

Planner:
"What should I test next?"

Reasoning:
"What does this discovery mean?"

Executor:
"Call Forge tools"

Memory:
"What did I learn previously?"

Communication:

Python AI Agent
        |
        |
 REST/gRPC
        |
        |
Go Forge Core

==================================================
PHASE 3 — Attack Intelligence Layer
==================================================

pkg/

├── recon/
│   ├── fingerprint.go
│   ├── endpoint.go
│   ├── technology.go
│   └── discovery.go (planned)
│
├── attack/
│   ├── sql.go
│   ├── xss.go
│   ├── jwt.go
│   ├── auth.go
│   ├── api.go
│   └── authorization.go (planned)
│
├── intelligence/
│   ├── cve.go
│   ├── owasp.go (planned)
│   └── vulnerability.go

Purpose:

Turn raw findings into:

- attack paths
- risk scores
- exploitation possibilities

==================================================
PHASE 3 — Browser Attack Agent
==================================================

browser-agent/

(TypeScript)

├── src/server.ts
├── package.json
├── Dockerfile
├── browser/chromium.ts (planned)
├── browser/session.ts (planned)
├── browser/actions.ts (planned)
└── evidence/screenshot.ts (planned)

Technology:

Node.js
TypeScript
Playwright

Responsibilities:

- login automation
- JavaScript execution
- DOM analysis
- screenshots
- session replay

==================================================
PHASE 4 — Evidence & Reporting Platform
==================================================

pkg/

├── evidence/
│   ├── collector.go
│   ├── request.go (planned)
│   ├── response.go (planned)
│   └── artifacts.go
│
└── reporting/
    ├── pdf.go
    ├── html.go (planned)
    ├── executive.go
    └── technical.go

Stores:

- payloads
- requests
- responses
- screenshots
- timestamps

Output:

Client-ready penetration test report.

==================================================
PHASE 5 — Enterprise Platform
==================================================

pkg/

├── api/
│   ├── server.go
│   ├── routes.go (planned split)
│   └── middleware.go (planned split)
│
└── storage/
    ├── database.go
    ├── models.go
    └── migrations/

Future:

frontend/ (planned)

React
TypeScript
Tailwind

Features:

- Organizations
- Teams
- Projects
- Clients
- Campaign dashboard
- Findings management

==================================================
FINAL PRODUCT FLOW
==================================================

                User

                 |
                 v

        Forge Dashboard

                 |
                 v

          Campaign Created

                 |
                 v

        Core Orchestrator

                 |
       --------------------
       |                  |
       v                  v

  Recon Agent        AI Planner

       |                  |
       --------------------
                 |
                 v

          Attack Engine

                 |
                 v

        Browser Agent

                 |
                 v

       Vulnerability Validation

                 |
                 v

        Evidence Collection

                 |
                 v

          AI Report Writer

                 |
                 v

          Pentest Report

## Notes

- Files marked as planned are architecture targets and may not yet exist.
- Current implementation status is tracked in README.md, docs/USAGE.md, and .github/workflows/compose-smoke.yml.
