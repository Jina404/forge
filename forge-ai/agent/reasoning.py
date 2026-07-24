from __future__ import annotations

from dataclasses import dataclass
from typing import List


@dataclass
class ReasoningState:
    objective: str
    previous_actions: List[str]
    discoveries: List[str]
    confidence: float


def prioritize_next_action(state: ReasoningState) -> str:
    if not state.previous_actions:
        return "technology_discovery"
    if any("blocked" in action.lower() for action in state.previous_actions[-2:]):
        return "adjust_strategy"
    if state.discoveries:
        return "targeted_follow_up"
    return "validation"
