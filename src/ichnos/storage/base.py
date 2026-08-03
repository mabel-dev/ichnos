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
    def list_all(self, protocol: str) -> List[CurrentStateRecord]:
        """Every known-responsive host for `protocol` - the refresh scan's target
        list, and the set discovery excludes so it doesn't keep re-finding hosts
        refresh already covers."""

    @abstractmethod
    def count(self) -> int:
        """Item count - exposed as a CloudWatch metric, a proxy for storage growth."""


class VersionIndexStore(ABC):
    @abstractmethod
    def claim(self, fingerprint_id: str) -> bool:
        """Record `fingerprint_id` as published, returning True only for the caller that
        actually inserted it - False means some earlier call already did.

        `CurrentStateStore` above answers "has *this host* changed?", which is the right
        question for emitting an Observation but the wrong one for emitting a Version:
        the fingerprint is a hash of the response payload alone, with no host in it
        (fingerprint.py), so a payload served identically by many hosts is genuinely the
        same fingerprint. Deduping per host meant every one of those hosts appended its
        own copy of the identical row to `versions` and to the protocol dataset - real
        production bug, ~23 rows for one Akamai "Invalid URL" edge page - which then
        fanned every Observation joined to it out into 23 duplicate result rows. This
        store answers the question the Version datasets actually need: "have we ever
        published this payload?", once, globally.

        Must be atomic: two hosts in the same run (or two workers in the same hour) can
        turn up the same brand-new fingerprint, and exactly one of them may emit the row.
        """


class Store(ABC):
    """Bundles the four stores an app needs. Concrete backends implement this once."""

    exclusions: ExclusionStore
    schedule: ScheduleStore
    current_state: CurrentStateStore
    version_index: VersionIndexStore
