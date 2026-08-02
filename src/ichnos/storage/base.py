"""Abstract storage interfaces for operational data.

The worker is stateless (design doc §2/§7): everything it needs is read fresh from
these stores at the start of a run and written back immediately. Two implementations
exist - `memory.InMemoryStore` for local development/tests, and `dynamodb.DynamoDBStore`
for the real deployment - so the pipeline logic never depends on which one is in use.
"""
from __future__ import annotations

from abc import ABC
from abc import abstractmethod
from typing import Iterable
from typing import List
from typing import Optional

from ..models import CurrentStateRecord
from ..models import Exclusion
from ..models import ScheduleEntry


class ExclusionStore(ABC):
    @abstractmethod
    def add(self, exclusion: Exclusion) -> None:
        """Upsert an exclusion. Called by the opt-out endpoint and the jurisdiction job."""

    @abstractmethod
    def list_all(self) -> List[Exclusion]:
        """Full table read - used to rebuild the ZMap blocklist before every scan run."""


class ScheduleStore(ABC):
    @abstractmethod
    def list_enabled(self) -> List[ScheduleEntry]:
        """Protocols due for consideration this run. MVP: http, https."""

    @abstractmethod
    def get(self, protocol: str) -> Optional[ScheduleEntry]:
        ...

    @abstractmethod
    def put(self, entry: ScheduleEntry) -> None:
        ...


class CurrentStateStore(ABC):
    @abstractmethod
    def get(self, protocol: str, ip: str, port: int) -> Optional[CurrentStateRecord]:
        ...

    @abstractmethod
    def put(self, record: CurrentStateRecord) -> None:
        ...

    @abstractmethod
    def count(self) -> int:
        """Item count - exposed as a CloudWatch metric, a proxy for storage growth."""


class Store(ABC):
    """Bundles the three stores an app needs. Concrete backends implement this once."""

    exclusions: ExclusionStore
    schedule: ScheduleStore
    current_state: CurrentStateStore
