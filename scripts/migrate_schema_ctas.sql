-- One-off migration: rewrite each published dataset with its instants as real
-- TIMESTAMP columns, and drop the two columns that were null on 100% of rows.
--
-- Four statements per dataset. CREATE OR REPLACE does not update the catalog schema -
-- the data is rewritten but the column types stay as they were - so the old dataset
-- has to be dropped outright and recreated from a temp table that already carries the
-- right types:
--
--   1. CREATE the temp from the original, applying the casts
--   2. DROP the original
--   3. CREATE the original from the temp (plain SELECT * - types already correct)
--   4. DROP the temp
--
-- Run this ONLY with the publish cron paused, and only after the worker deploy. The
-- worker and the tables have to agree on type in the same window: an INSERT of a
-- VARCHAR source into a TIMESTAMP target is rejected outright
--     UnsupportedSyntaxError: INSERT type mismatch on column 'first_seen':
--     source VARCHAR is not compatible with target LogicalCategory.TIMESTAMP
-- and the reverse fails the same way. Between step 2 and step 3 the dataset does not
-- exist at all, which is the other reason nothing may be publishing.
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
-- CAST(... AS NVARCHAR) does work and does stick, but rugo's Parquet writer can only
-- emit VARCHAR, so the hourly publish would then be rejected the same way:
--     INSERT type mismatch on column 'payload': source VARCHAR is not compatible
--     with target LogicalCategory.NVARCHAR
-- See the note at the bottom for the view-based alternative.
--
-- Do ssh first and confirm it comes back with first_seen typed TIMESTAMP before
-- running the rest - it is the smallest dataset and proves the drop/recreate cycle
-- against the real catalog (in particular that the name is immediately reusable after
-- a DROP, rather than held by a tombstone).

-- ---------------------------------------------------------------- ssh
CREATE TABLE ichnos.landing.ssh_temp AS
SELECT banner, version, software, comment, host_key_algorithm,
       host_key_fingerprint_sha256, fingerprint_id,
       CAST(REPLACE(first_seen, '+00:00', '') AS TIMESTAMP) AS first_seen
  FROM ichnos.landing.ssh;

DROP TABLE ichnos.landing.ssh;

CREATE TABLE ichnos.landing.ssh AS SELECT * FROM ichnos.landing.ssh_temp;

DROP TABLE ichnos.landing.ssh_temp;

-- ---------------------------------------------------------------- observations
CREATE TABLE ichnos.landing.observations_temp AS
SELECT scan_id,
       CAST(REPLACE(observed_at, '+00:00', '') AS TIMESTAMP) AS observed_at,
       ip, port, protocol, response_status, fingerprint_id
  FROM ichnos.landing.observations;

DROP TABLE ichnos.landing.observations;

CREATE TABLE ichnos.landing.observations AS SELECT * FROM ichnos.landing.observations_temp;

DROP TABLE ichnos.landing.observations_temp;

-- ---------------------------------------------------------------- scan_metadata
CREATE TABLE ichnos.landing.scan_metadata_temp AS
SELECT scan_id, protocol,
       CAST(REPLACE(started_at, '+00:00', '') AS TIMESTAMP) AS started_at,
       CAST(REPLACE(ended_at, '+00:00', '') AS TIMESTAMP) AS ended_at,
       targets_attempted, hosts_responsive, status, seed
  FROM ichnos.landing.scan_metadata;

DROP TABLE ichnos.landing.scan_metadata;

CREATE TABLE ichnos.landing.scan_metadata AS SELECT * FROM ichnos.landing.scan_metadata_temp;

DROP TABLE ichnos.landing.scan_metadata_temp;

-- ---------------------------------------------------------------- versions
CREATE TABLE ichnos.landing.versions_temp AS
SELECT fingerprint_id, protocol,
       CAST(REPLACE(first_seen, '+00:00', '') AS TIMESTAMP) AS first_seen,
       payload
  FROM ichnos.landing.versions;

DROP TABLE ichnos.landing.versions;

CREATE TABLE ichnos.landing.versions AS SELECT * FROM ichnos.landing.versions_temp;

DROP TABLE ichnos.landing.versions_temp;

-- ---------------------------------------------------------------- http
-- favicon_hash dropped: the plain zgrab2 http module never fetched /favicon.ico, so it
-- was a hardcoded None on every row ever published.
CREATE TABLE ichnos.landing.http_temp AS
SELECT status_code, headers, server, title, redirect_location, fingerprint_id,
       CAST(REPLACE(first_seen, '+00:00', '') AS TIMESTAMP) AS first_seen
  FROM ichnos.landing.http;

DROP TABLE ichnos.landing.http;

CREATE TABLE ichnos.landing.http AS SELECT * FROM ichnos.landing.http_temp;

DROP TABLE ichnos.landing.http_temp;

-- ---------------------------------------------------------------- https
-- jarm dropped: separate zgrab2 module, never wired into the scanner, same story.
CREATE TABLE ichnos.landing.https_temp AS
SELECT version, cipher_suite, certificate, fingerprint_id,
       CAST(REPLACE(first_seen, '+00:00', '') AS TIMESTAMP) AS first_seen
  FROM ichnos.landing.https;

DROP TABLE ichnos.landing.https;

CREATE TABLE ichnos.landing.https AS SELECT * FROM ichnos.landing.https_temp;

DROP TABLE ichnos.landing.https_temp;

-- ---------------------------------------------------------------- clustering
-- Run after the recreate - CREATE TABLE AS starts with no sort order, so a CLUSTER BY
-- declared before the drop is lost with the old dataset.
--
-- Every one of these clusters on its instant. That is the column each dataset is
-- actually range-scanned by, and the only one whose min/max row-group statistics can
-- prune anything: rows arrive in time order, so consecutive row groups hold disjoint
-- time ranges and a time-bounded query skips most of the file. It is also why none of
-- these cluster on `fingerprint_id` despite it being the join key from `observations`
-- into the protocol datasets - a sha256 is uniformly random, so every row group's
-- min/max spans nearly the whole key space and prunes nothing. Equality lookups on
-- fingerprint_id are already served by the bloom filters publish.py writes
-- (write_parquet(..., bloom_filters=True)), which is the right structure for that
-- access pattern.
--
-- Only the FIRST column is used today (catalog.compaction.normalize_sort_order takes
-- it as the primary sort key and ignores the rest), so these are deliberately single
-- column rather than a composite that would read as more than it delivers.
--
-- This declares the layout for compaction to converge on; it does not rewrite the
-- existing files by itself.

ALTER TABLE ichnos.landing.ssh CLUSTER BY (first_seen);
ALTER TABLE ichnos.landing.http CLUSTER BY (first_seen);
ALTER TABLE ichnos.landing.https CLUSTER BY (first_seen);
ALTER TABLE ichnos.landing.versions CLUSTER BY (first_seen);
ALTER TABLE ichnos.landing.observations CLUSTER BY (observed_at);
ALTER TABLE ichnos.landing.scan_metadata CLUSTER BY (started_at);

-- Optional, for the three JSON-document columns: type them for readers via a view,
-- leaving the base tables VARCHAR so the hourly publish keeps working. The view's
-- payload column reads back as NVARCHAR while the base table stays appendable.
--
-- CREATE VIEW ichnos.landing.versions_typed AS
-- SELECT fingerprint_id, protocol, first_seen, CAST(payload AS NVARCHAR) AS payload
--   FROM ichnos.landing.versions;
