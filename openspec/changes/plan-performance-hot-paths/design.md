# Design notes: plan-performance-hot-paths

Concise technical context for the roadmap (not a final design for each item).

## 1. Python engine and rules

**Observation:** Each Go `Analyze()` invocation may start Python and `Engine(rules_dir)` reloads rules via dynamic import. Cost scales with **batches × rule count**, not just events.

**Directions:** (a) Long-lived Python sidecar or in-process worker that keeps modules loaded. (b) Rule indexing or log-type filtering in Python so not every `.py` runs on every event. (c) Operational mitigation: narrow `--rules` to a pack (already noted in `openspec/specs/detection-engine/spec.md`).

**Constraints:** Rule reload on SIGHUP or file watch may still be desired; any worker design must define reload semantics.

## 2. Log processor memory

**Observation:** `io.ReadAll` on decompressed bodies and `Classify(string(recordBytes))` allocate full object and per-record strings.

**Directions:** Streaming JSON decode for `Records` arrays where feasible; reuse buffers where parsers allow; measure peak RSS on multi-GB fixtures.

## 3. Scanner token size

**Observation:** Default `bufio.Scanner` max token is 64 KiB; some exports can exceed that.

**Directions:** `Scanner.Buffer` / `MaxScanTokenSize` or split path for known huge lines; document limits.

## 4. Data lake writer

**Observation:** `flushBuffer` performs S3 Put and Glue work on the path that follows detection.

**Directions:** Optional async flush with bounded queue; strict backpressure so memory does not grow without bound; metrics for queue depth and flush failures.

## 5. SQLite

**Observation:** WAL + busy timeout help; many concurrent writers can still contend.

**Directions:** Single goroutine writer for dedup/state mutations; or batch writes; verify with concurrent SQS worker count from real deployments.

## 6. `--process-workers`

**Observation:** Flag may be reserved or partially wired; parallelism must respect parser and Python subprocess assumptions.

**Directions:** Document thread-safety of classifiers; avoid sharing mutable parser state across goroutines without locks.

## 7. OpenTelemetry

**Observation:** Span overhead can matter at very high QPS.

**Directions:** Document environment variables or SDK hooks for sampling; default remains full sampling in dev.
