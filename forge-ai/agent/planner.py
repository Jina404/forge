from __future__ import annotations

from dataclasses import dataclass
from typing import List


@dataclass
class PlanStep:
    name: str
    description: str


@dataclass
class AttackPlan:
    target: str
    steps: List[PlanStep]


def build_plan(target: str) -> AttackPlan:
    steps = [
        PlanStep("technology_discovery", "Identify frameworks, servers, and cloud stack."),
        PlanStep("endpoint_discovery", "Map routes, parameters, and auth boundaries."),
        PlanStep("authentication_analysis", "Analyze sessions and token controls."),
        PlanStep("authorization_testing", "Test privilege escalation and IDOR paths."),
        PlanStep("injection_testing", "Probe SQLi, XSS, and command injection surfaces."),
        PlanStep("validation", "Confirm reproducibility and confidence levels."),
    ]
    return AttackPlan(target=target, steps=steps)
