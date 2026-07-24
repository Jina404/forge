from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Any

from .planner import build_plan
from .reasoning import ReasoningState, prioritize_next_action


@dataclass
class ExecutionResult:
    plan: Dict[str, Any]
    next_action: str


def execute_cycle(target: str, objective: str, previous_actions: list[str], discoveries: list[str], confidence: float) -> ExecutionResult:
    plan = build_plan(target)
    state = ReasoningState(
        objective=objective,
        previous_actions=previous_actions,
        discoveries=discoveries,
        confidence=confidence,
    )
    next_action = prioritize_next_action(state)
    return ExecutionResult(
        plan={"target": plan.target, "steps": [s.__dict__ for s in plan.steps]},
        next_action=next_action,
    )
