-- One-off migration: collapse the version datasets to one row per fingerprint_id.
--
-- Backfill half of the duplicate-rows fix (the forward half is storage/base.py's
-- VersionIndexStore - see its docstring). Dedup used to be keyed by host, so every host
-- that started serving an already-known payload appended its own copy of the identical
-- row here. Observed in production: 23 rows for a single Akamai "Invalid URL" edge page,
-- 7 for a Cloudflare 403. Any query joining observations to these on fingerprint_id then
-- multiplied each observation by that row count.
--
-- The duplicate rows are byte-identical apart from first_seen: the protocol row is built
-- as `{**version.payload, fingerprint_id, first_seen}` (publish.py) and `payload` is
-- exactly what was hashed to produce the fingerprint, so equal fingerprint => equal
-- payload columns, by construction rather than by luck. That is what makes MIN() on
-- every non-key column exactly right here and not a "pick an arbitrary row" fudge: for
-- the payload columns all candidates are equal, and for first_seen MIN is the genuinely
-- correct answer - the earliest time this project saw this payload anywhere, which is
-- what the column has always claimed to mean.
--
-- MIN(...) GROUP BY rather than ROW_NUMBER()/QUALIFY deliberately: it needs only plain
-- aggregation, so it does not depend on window-function support.
--
-- Same four-statement CTAS shape, and the same operational constraints, as
-- migrate_schema_ctas.sql - read its header first. In particular: run this ONLY with the
-- publish cron paused, since between the DROP and the CREATE the dataset does not exist
-- at all. `observations` and `scan_metadata` are untouched - they are per-event rows,
-- one per measurement, and are not deduplicated by anything.
--
-- ORDER OF OPERATIONS - the SQL here is step 5 of 6, and steps 3-4 are not optional:
--
--   1. terraform apply            (creates the VersionIndex table)
--   2. Pause the publish cron.
--   3. Export the fingerprints already published:
--          SELECT DISTINCT fingerprint_id FROM ichnos.landing.versions
--      to a newline-delimited file.
--   4. python scripts/seed_version_index.py <that file>
--   5. Run this script.
--   6. Deploy the worker, then resume the publish cron.
--
-- Skipping 3-4 leaves VersionIndex empty, which means the deployed worker considers
-- every fingerprint ever published to be brand new and appends a fresh copy of each the
-- next time it meets one - re-creating the exact duplicates this script just removed.
-- Seeding before the worker deploy (rather than after) means there is no window in which
-- the new code runs against an unseeded index.

-- ---------------------------------------------------------------- ssh
-- ssh first, same as the schema migration: smallest dataset, proves the cycle.
CREATE TABLE ichnos.landing.ssh_temp AS
SELECT fingerprint_id,
       MIN(banner) AS banner,
       MIN(version) AS version,
       MIN(software) AS software,
       MIN(comment) AS comment,
       MIN(host_key_algorithm) AS host_key_algorithm,
       MIN(host_key_fingerprint_sha256) AS host_key_fingerprint_sha256,
       MIN(first_seen) AS first_seen
  FROM ichnos.landing.ssh
 GROUP BY fingerprint_id;

DROP TABLE ichnos.landing.ssh;

CREATE TABLE ichnos.landing.ssh AS SELECT * FROM ichnos.landing.ssh_temp;

DROP TABLE ichnos.landing.ssh_temp;

-- ---------------------------------------------------------------- http
CREATE TABLE ichnos.landing.http_temp AS
SELECT fingerprint_id,
       MIN(status_code) AS status_code,
       MIN(headers) AS headers,
       MIN(server) AS server,
       MIN(title) AS title,
       MIN(redirect_location) AS redirect_location,
       MIN(first_seen) AS first_seen
  FROM ichnos.landing.http
 GROUP BY fingerprint_id;

DROP TABLE ichnos.landing.http;

CREATE TABLE ichnos.landing.http AS SELECT * FROM ichnos.landing.http_temp;

DROP TABLE ichnos.landing.http_temp;

-- ---------------------------------------------------------------- https
CREATE TABLE ichnos.landing.https_temp AS
SELECT fingerprint_id,
       MIN(version) AS version,
       MIN(cipher_suite) AS cipher_suite,
       MIN(certificate) AS certificate,
       MIN(first_seen) AS first_seen
  FROM ichnos.landing.https
 GROUP BY fingerprint_id;

DROP TABLE ichnos.landing.https;

CREATE TABLE ichnos.landing.https AS SELECT * FROM ichnos.landing.https_temp;

DROP TABLE ichnos.landing.https_temp;

-- ---------------------------------------------------------------- versions
-- MIN(protocol) is safe rather than lossy: the fingerprint hashes the normalized
-- payload, and http/tls/ssh payloads have disjoint key sets (normalize.py), so one
-- fingerprint cannot legitimately span two protocols.
CREATE TABLE ichnos.landing.versions_temp AS
SELECT fingerprint_id,
       MIN(protocol) AS protocol,
       MIN(first_seen) AS first_seen,
       MIN(payload) AS payload
  FROM ichnos.landing.versions
 GROUP BY fingerprint_id;

DROP TABLE ichnos.landing.versions;

CREATE TABLE ichnos.landing.versions AS SELECT * FROM ichnos.landing.versions_temp;

DROP TABLE ichnos.landing.versions_temp;

-- ---------------------------------------------------------------- clustering
-- Re-declared for the same reason migrate_schema_ctas.sql re-declares it: CREATE TABLE
-- AS starts with no sort order, so the CLUSTER BY set before the drop is gone with the
-- old dataset. Still first_seen, still not fingerprint_id (a sha256 prunes nothing).
ALTER TABLE ichnos.landing.ssh CLUSTER BY (first_seen);
ALTER TABLE ichnos.landing.http CLUSTER BY (first_seen);
ALTER TABLE ichnos.landing.https CLUSTER BY (first_seen);
ALTER TABLE ichnos.landing.versions CLUSTER BY (first_seen);

-- ---------------------------------------------------------------- verification
-- Each of these must come back with zero rows. Run them before resuming the cron.
--
-- SELECT fingerprint_id, COUNT(*) AS n FROM ichnos.landing.http
--  GROUP BY fingerprint_id HAVING COUNT(*) > 1;
-- SELECT fingerprint_id, COUNT(*) AS n FROM ichnos.landing.https
--  GROUP BY fingerprint_id HAVING COUNT(*) > 1;
-- SELECT fingerprint_id, COUNT(*) AS n FROM ichnos.landing.ssh
--  GROUP BY fingerprint_id HAVING COUNT(*) > 1;
-- SELECT fingerprint_id, COUNT(*) AS n FROM ichnos.landing.versions
--  GROUP BY fingerprint_id HAVING COUNT(*) > 1;
--
-- Note the column ORDER changes here: fingerprint_id moves to the front of each table,
-- because that is what GROUP BY produces. Nothing reads these positionally (publish.py
-- writes Parquet by name, and SCHEMAS declares every column), but a `SELECT *` will look
-- different afterwards.
