# Forge AI Service

Forge AI provides autonomous planning and reasoning capabilities for Forge campaigns.

## Initial modules

- agent/planner.py
- agent/reasoning.py
- agent/memory.py
- agent/executor.py

## Integration contract

The Go platform should communicate with this service using REST or gRPC. This initial scaffold focuses on deterministic local logic and typed data structures.

## Local run

```bash
cd forge-ai
python service.py
```

Service default bind: 127.0.0.1:8090

### Endpoints

- GET /healthz
- POST /plan
- POST /reason
