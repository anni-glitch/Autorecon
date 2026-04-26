from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from abc import ABC, abstractmethod
import httpx

@dataclass
class FindingResult:
    module: str
    target: str
    category: str
    severity: str          # "info" | "low" | "medium" | "high" | "critical"
    title: str
    description: str
    data: dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())

class BaseModule(ABC):
    name: str = "base"
    description: str = ""
    phase: int = 1

    def __init__(self, client: httpx.AsyncClient | None = None):
        self.client = client

    @abstractmethod
    async def run(self, target: str) -> list[FindingResult]:
        pass
