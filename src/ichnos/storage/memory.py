"""In-memory storage backend - local development and tests, not for production use."""
from __future__ import annotations

from typing import Dict
from typing import List
from typing import Optional

from ..models import CurrentStateRecord
from ..models import Exclusion
from ..models import ScheduleEntry
from .base import CurrentStateStore
from .base import ExclusionStore
from .base import ScheduleStore
from .base import Store


class _MemoryExclusionStore(ExclusionStore):
    def __init__(self) -> None:
        self._rows: Dict[str, Exclusion] = {}

    def add(self, exclusion: Exclusion) -> None:
        self._rows[exclusion.ip_or_cidr] = exclusion

    def list_all(self) -> List[Exclusion]:
        return list(self._rows.values())


class _MemoryScheduleStore(ScheduleStore):
    def __init__(self) -> None:
        self._rows: Dict[str, ScheduleEntry] = {}

    def list_enabled(self) -> List[ScheduleEntry]:
        return [e for e in self._rows.values() if e.enabled]

    def get(self, protocol: str) -> Optional[ScheduleEntry]:
        return self._rows.get(protocol)

    def put(self, entry: ScheduleEntry) -> None:
        self._rows[entry.protocol] = entry


class _MemoryCurrentStateStore(CurrentStateStore):
    def __init__(self) -> None:
        self._rows: Dict[str, CurrentStateRecord] = {}

    def get(self, protocol: str, ip: str, port: int) -> Optional[CurrentStateRecord]:
        return self._rows.get(f"{protocol}#{ip}#{port}")

    def put(self, record: CurrentStateRecord) -> None:
        self._rows[record.key] = record

    def count(self) -> int:
        return len(self._rows)


class InMemoryStore(Store):
    def __init__(self) -> None:
        self.exclusions = _MemoryExclusionStore()
        self.schedule = _MemoryScheduleStore()
        self.current_state = _MemoryCurrentStateStore()
