"""DynamoDB-backed storage - the real deployment backend (design doc §3.1, §9).

Table layout matches the design doc exactly:
    Exclusions    PK ip_or_cidr
    ScanSchedule  PK protocol
    CurrentState  PK protocol#ip#port (see CurrentStateRecord.key)

Requires the `aws` extra (`pip install ichnos[aws]`) - boto3 is not a hard dependency
so the rest of the package (blocklist building, fingerprinting, tests) works without it.
"""
from __future__ import annotations

from datetime import datetime
from datetime import timezone
from typing import Any
from typing import Dict
from typing import List
from typing import Optional

from ..models import CurrentStateRecord
from ..models import Exclusion
from ..models import ExclusionSource
from ..models import ScheduleEntry
from .base import CurrentStateStore
from .base import ExclusionStore
from .base import ScheduleStore
from .base import Store

try:
    import boto3
except ImportError:  # pragma: no cover - exercised only when the aws extra is missing
    boto3 = None


def _require_boto3() -> None:
    if boto3 is None:
        raise RuntimeError(
            "boto3 is required for the DynamoDB backend - install with `pip install ichnos[aws]`"
        )


class DynamoDBExclusionStore(ExclusionStore):
    def __init__(self, table_name: str, *, resource: Any = None):
        _require_boto3()
        self._table = (resource or boto3.resource("dynamodb")).Table(table_name)

    def add(self, exclusion: Exclusion) -> None:
        item: Dict[str, Any] = {
            "ip_or_cidr": exclusion.ip_or_cidr,
            "source": exclusion.source.value,
            "requested_at": exclusion.requested_at.isoformat(),
        }
        if exclusion.reason:
            item["reason"] = exclusion.reason
        if exclusion.requester_ip:
            item["requester_ip"] = exclusion.requester_ip
        self._table.put_item(Item=item)

    def list_all(self) -> List[Exclusion]:
        rows: List[Exclusion] = []
        scan_kwargs: Dict[str, Any] = {}
        while True:
            response = self._table.scan(**scan_kwargs)
            for item in response.get("Items", []):
                rows.append(
                    Exclusion(
                        ip_or_cidr=item["ip_or_cidr"],
                        source=ExclusionSource(item["source"]),
                        requested_at=datetime.fromisoformat(item["requested_at"]),
                        reason=item.get("reason"),
                        requester_ip=item.get("requester_ip"),
                    )
                )
            last_key = response.get("LastEvaluatedKey")
            if not last_key:
                break
            scan_kwargs["ExclusiveStartKey"] = last_key
        return rows


class DynamoDBScheduleStore(ScheduleStore):
    def __init__(self, table_name: str, *, resource: Any = None):
        _require_boto3()
        self._table = (resource or boto3.resource("dynamodb")).Table(table_name)

    def list_enabled(self) -> List[ScheduleEntry]:
        response = self._table.scan()
        return [
            self._from_item(item) for item in response.get("Items", []) if item.get("enabled", True)
        ]

    def get(self, protocol: str) -> Optional[ScheduleEntry]:
        response = self._table.get_item(Key={"protocol": protocol})
        item = response.get("Item")
        return self._from_item(item) if item else None

    def put(self, entry: ScheduleEntry) -> None:
        self._table.put_item(
            Item={
                "protocol": entry.protocol,
                "port": entry.port,
                "zgrab2_module": entry.zgrab2_module,
                "enabled": entry.enabled,
                "cadence": entry.cadence,
                "rate_share": str(entry.rate_share),
            }
        )

    @staticmethod
    def _from_item(item: Dict[str, Any]) -> ScheduleEntry:
        return ScheduleEntry(
            protocol=item["protocol"],
            port=int(item["port"]),
            zgrab2_module=item["zgrab2_module"],
            enabled=bool(item.get("enabled", True)),
            cadence=item.get("cadence", "daily"),
            rate_share=float(item.get("rate_share", 1.0)),
        )


class DynamoDBCurrentStateStore(CurrentStateStore):
    def __init__(self, table_name: str, *, resource: Any = None):
        _require_boto3()
        self._table = (resource or boto3.resource("dynamodb")).Table(table_name)

    def get(self, protocol: str, ip: str, port: int) -> Optional[CurrentStateRecord]:
        key = f"{protocol}#{ip}#{port}"
        response = self._table.get_item(Key={"key": key})
        item = response.get("Item")
        if not item:
            return None
        return CurrentStateRecord(
            protocol=protocol,
            ip=ip,
            port=port,
            fingerprint_id=item["fingerprint_id"],
            last_seen_date=item["last_seen_date"],
        )

    def put(self, record: CurrentStateRecord) -> None:
        self._table.put_item(
            Item={
                "key": record.key,
                "fingerprint_id": record.fingerprint_id,
                "last_seen_date": record.last_seen_date,
            }
        )

    def count(self) -> int:
        # DynamoDB's DescribeTable ItemCount is only updated ~every 6 hours - fine for a
        # coarse CloudWatch metric of storage growth, not for correctness-critical reads.
        response = self._table.meta.client.describe_table(TableName=self._table.table_name)
        return int(response["Table"]["ItemCount"])


class DynamoDBStore(Store):
    def __init__(
        self,
        *,
        exclusions_table: str = "Exclusions",
        schedule_table: str = "ScanSchedule",
        current_state_table: str = "CurrentState",
        resource: Any = None,
    ):
        _require_boto3()
        resource = resource or boto3.resource("dynamodb")
        self.exclusions = DynamoDBExclusionStore(exclusions_table, resource=resource)
        self.schedule = DynamoDBScheduleStore(schedule_table, resource=resource)
        self.current_state = DynamoDBCurrentStateStore(current_state_table, resource=resource)
