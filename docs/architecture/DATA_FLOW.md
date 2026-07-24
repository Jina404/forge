# Data Flow

1. User authenticates and gets a signed bearer token.
2. User creates a campaign in an organization context.
3. Orchestrator records campaign and tenant ownership.
4. AI planner returns staged attack plan.
5. Engine runs traffic and attack probes.
6. Detector confirms candidate vulnerabilities.
7. Browser agent captures screenshot evidence when available.
8. Evidence and findings are persisted.
9. Reporting layer generates executive and technical output.
10. Audit logs capture critical operations.
