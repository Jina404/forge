# AI Agent Architecture

## Lifecycle

```text
Observation
    ↓
Understanding
    ↓
Planning
    ↓
Execution
    ↓
Validation
    ↓
Learning
```

## Responsibilities

- Planner: selects next testing stage based on objective and discoveries
- Reasoning: interprets findings and confidence signals
- Executor: maps plans to Forge attack and recon capabilities
- Memory: stores reusable context for future campaign strategy

## Integration

- API transport: REST (gRPC planned)
- Core contract: target + campaign objective -> staged plan
