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


class VersionIndexStore(ABC):
    @abstractmethod
    def claim(self, fingerprint_id: str) -> bool:
        """Record `fingerprint_id` as published, returning True only for the caller that
        actually inserted it - False means some earlier call already did.

        Emitting an Observation asks "what is this host serving now?", which every
        Observation records directly. This asks something different, and the two were
        conflated once:
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
    version_index: VersionIndexStore
