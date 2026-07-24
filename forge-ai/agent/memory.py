from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class MemoryStore:
    campaigns: Dict[str, List[str]] = field(default_factory=dict)

    def append(self, campaign_id: str, item: str) -> None:
        self.campaigns.setdefault(campaign_id, []).append(item)

    def list(self, campaign_id: str) -> List[str]:
        return list(self.campaigns.get(campaign_id, []))
