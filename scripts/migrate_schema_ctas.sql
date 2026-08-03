-- One-off CTAS migration: rewrite each published dataset with its instants as real
-- TIMESTAMP columns, and drop the two columns that were null on 100% of rows.
--
-- Run this ONLY after the worker fix (publish.py's "timestamp" schema types +
-- parquet.py's retyping) is deployed. Verified against opteryx 0.9.49: an INSERT of a
-- VARCHAR source into a TIMESTAMP target is rejected outright
--     UnsupportedSyntaxError: INSERT type mismatch on column 'first_seen':
--     source VARCHAR is not compatible with target LogicalCategory.TIMESTAMP
-- so migrating first and deploying second breaks every hourly publish in between.
--
-- Why REPLACE(...,'+00:00','') rather than a bare CAST: every value was written by
-- `datetime.isoformat()` on a UTC-aware datetime, so they all carry a `+00:00` offset -
-- and CAST rejects any timezone designator (both `+00:00` and `Z`):
--     Cannot cast string to TIMESTAMP: got 2026-08-03T12:00:00.123456+00:00
-- Stripping the offset leaves a naive form the cast accepts and reads back as UTC,
-- which is what these instants have always been. REPLACE rather than a fixed-width
-- LEFT() because isoformat() omits microseconds when they are exactly zero, so the
-- strings are not all the same length. NULLs (ended_at, for a scan that never
-- finished) pass through as NULL.
--
-- headers / certificate / payload stay VARCHAR despite each holding a JSON document.
-- CAST(... AS NVARCHAR) does work here and does survive into the catalog - but rugo's
-- Parquet writer can only emit VARCHAR, so the hourly publish would then be rejected
-- the same way the timestamp case above is:
--     INSERT type mismatch on column 'payload': source VARCHAR is not compatible
--     with target LogicalCategory.NVARCHAR
-- See the note at the bottom for the view-based alternative that types them for
-- readers without breaking the writer.

CREATE OR REPLACE TABLE ichnos.landing.observations AS
SELECT scan_id,
       CAST(REPLACE(observed_at, '+00:00', '') AS TIMESTAMP) AS observed_at,
       ip,
       port,
       protocol,
       response_status,
       fingerprint_id
  FROM ichnos.landing.observations;

CREATE OR REPLACE TABLE ichnos.landing.scan_metadata AS
SELECT scan_id,
       protocol,
       CAST(REPLACE(started_at, '+00:00', '') AS TIMESTAMP) AS started_at,
       CAST(REPLACE(ended_at, '+00:00', '') AS TIMESTAMP) AS ended_at,
       targets_attempted,
       hosts_responsive,
       status,
       seed
  FROM ichnos.landing.scan_metadata;

CREATE OR REPLACE TABLE ichnos.landing.versions AS
SELECT fingerprint_id,
       protocol,
       CAST(REPLACE(first_seen, '+00:00', '') AS TIMESTAMP) AS first_seen,
       payload
  FROM ichnos.landing.versions;

-- favicon_hash dropped: the plain zgrab2 http module never fetched /favicon.ico, so it
-- was a hardcoded None on every row ever published.
CREATE OR REPLACE TABLE ichnos.landing.http AS
SELECT status_code,
       headers,
       server,
       title,
       redirect_location,
       fingerprint_id,
       CAST(REPLACE(first_seen, '+00:00', '') AS TIMESTAMP) AS first_seen
  FROM ichnos.landing.http;

-- jarm dropped: separate zgrab2 module, never wired into the scanner, same story.
CREATE OR REPLACE TABLE ichnos.landing.https AS
SELECT version,
       cipher_suite,
       certificate,
       fingerprint_id,
       CAST(REPLACE(first_seen, '+00:00', '') AS TIMESTAMP) AS first_seen
  FROM ichnos.landing.https;

CREATE OR REPLACE TABLE ichnos.landing.ssh AS
SELECT banner,
       version,
       software,
       comment,
       host_key_algorithm,
       host_key_fingerprint_sha256,
       fingerprint_id,
       CAST(REPLACE(first_seen, '+00:00', '') AS TIMESTAMP) AS first_seen
  FROM ichnos.landing.ssh;

-- CREATE OR REPLACE replaces each dataset in place, reading from the same name it
-- writes - verified working, rows preserved, column type changed. That leaves the
-- names the worker already publishes to, so there is no rename and no config repoint.
-- The tradeoff is that the pre-migration table is gone once each statement commits:
-- check the SELECT half on its own first if you want a look before committing to it.

-- Optional, for the three JSON-document columns: type them for readers via a view,
-- leaving the base tables VARCHAR so the hourly publish keeps working. Verified: the
-- view's payload column reads back as NVARCHAR while the base table stays appendable.
--
-- CREATE VIEW ichnos.landing.versions_typed AS
-- SELECT fingerprint_id, protocol, first_seen, CAST(payload AS NVARCHAR) AS payload
--   FROM ichnos.landing.versions;
