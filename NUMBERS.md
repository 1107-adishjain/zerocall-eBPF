# NUMBERS.md — provenance ledger

This file records, for every quantitative claim, **where the number comes from**:
the command that produces it, the raw artifact it lands in, and whether it can be
reproduced from this repository. Status values:

- `REPRODUCIBLE` — a script in this repo regenerates it from the committed inputs.
- `MANUAL` — reproducible by hand from this repo, with a documented procedure, but
  not captured by a script.
- `ARCHIVAL` — produced on the original benchmarking host (a Windows laptop running
  the Vagrant/VirtualBox Linux VM) and reported in the paper; the committed CSVs and
  script carry those values, and the script regenerates the figure from them.

The paper is the single source of truth for the benchmark values. They were measured
once on the original host; this repo carries those measurements, not a fresh re-run.

---

## 1. `S_static = 35` unique system calls — REPRODUCIBLE

- **Claim.** Symbolic execution recovers the 35 distinct system calls the nginx
  v1.29 microservice needs (paper Table 2 / Section 4.3).
- **How.** `python3 static_profiler.py <binary>`
- **Raw artifact.** `s_static_<binary>.json` (written by the script):
  `{"count": 35, "syscalls": [0, 1, 2, ...], "binary_sha256": "..."}`
- **The set.**
  `{0, 1, 2, 3, 8, 9, 10, 11, 12, 39, 41, 42, 43, 44, 45, 49, 50, 56, 57, 59, 60, 62, 83, 84, 87, 90, 92, 101, 102, 104, 105, 106, 165, 272, 321}`
- **Independent cross-check.** The same 35 IDs are the distinct `id_* = N` constants
  in `pure_exploit.c`, the `-nostdlib` test payload bundled for demonstration:

  ```bash
  grep -oE 'id_[a-z]+ = [0-9]+' pure_exploit.c | awk '{print $3}' | sort -n -u | wc -l   # -> 35
  ```

  angr recovering the same 35 is the result: symbolic execution finds the
  obfuscated, library-free syscalls that a header scan would miss.
- **Known discrepancy (repo vs paper).** The paper attributes the 35-syscall set to
  the nginx v1.29 binary. The `static_profiler.py` run bundled in this repo targets
  `pure_exploit` (a `-nostdlib` payload that issues exactly those 35 syscalls), which
  reproduces the count without shipping the nginx binary. `static_profiler.py` uses
  `auto_load_libs=False`, so it maps a statically linked / bare-metal binary directly;
  for a dynamically linked service the nginx profiling was run on the original host.

---

## 2. clone() namespace-escape block — MANUAL

- **Claim.** The data plane detects and kills a container-escape `clone()` in
  O(1), before the call completes (Section 7.4 / 5.2).
- **How.** With `sudo ./zerocall` running: `gcc exploit.c -o exploit && ./exploit`
- **Raw observation.** `exploit` terminates with `Killed`; the kernel trace pipe
  (`sudo cat /sys/kernel/debug/tracing/trace_pipe`) shows
  `[BLOCK] Malicious clone() namespace escape! flags=30000011`.
- **Mechanism.** `exploit.c` calls `clone()` with
  `CLONE_NEWUSER | CLONE_NEWPID` (`0x30000000`); `SIGCHLD` (`0x11`) makes the
  logged value `0x30000011`. The inspector in `zerocall.bpf.c` masks against
  `CLONE_NS_MASK` (`0x7E020000`, every `CLONE_NEW*` flag) and sends `SIGKILL`.

---

## 3. execve("/bin/sh") block — MANUAL

- **Claim.** Illegal shell execution is blocked (Section 7.4).
- **How.** With `sudo ./zerocall` running, any process that calls
  `execve("/bin/sh", ...)` is killed; the trace pipe shows
  `[BLOCK] Illegal shell execution detected: /bin/sh`.
- **Mechanism.** The inspector reads the first 8 bytes of the path and compares
  against `"/bin/sh\0"` (`0x0068732f6e69622f`).
- **Caveat (matches discrepancy 4 in the README).** The check matches only an
  8-byte prefix, so `/bin/bash` and relative paths are not covered. This is the
  single scenario behind the paper's "100 % of breakout attempts blocked".

---

## 4. Benchmark figures (Table 3 / Figure 7) — ARCHIVAL

- **Claim.** Baseline (shield offline) vs enforced (shield online) throughput and
  mean latency across eight request levels, concurrency 100, against a Dockerised
  nginx v1.29 reverse proxy (paper Table 3 / Figure 7, Section 7.3).
- **How measured.** `benchmark.sh` drives ApacheBench (`ab`) at each request level,
  parses "Requests per second" and "Time per request", and appends a CSV row. It was
  run twice on the original host — once with `./zerocall` enforcing and once without:

  ```bash
  ./benchmark.sh baseline_results.csv    # shield offline
  sudo ./zerocall &                      # shield online
  ./benchmark.sh enforced_results.csv
  ```

- **Raw artifacts (committed).** `baseline_results.csv`, `enforced_results.csv`.
  These carry the measured values from the original Windows-host run and match the
  paper's Table 3. The figure is regenerated from them:

  ```bash
  python3 plot.py        # reads both CSVs -> performance_comparison_graph.png
  ```

- **The 11.9 % figure.** At 15,000 requests: `(888.59 − 794.27) / 794.27 = 11.88 %`,
  which the paper rounds to 11.9 %. Both operands are rows in the committed CSVs
  (`baseline_results.csv:15000 -> 794.27`, `enforced_results.csv:15000 -> 888.59`).
- **Crossover behaviour.** Enforced is ahead at 1k/5k, dips behind at 10k, and leads
  from 15k onward — visible directly in the two CSVs and the regenerated graph.
- **Provenance note.** These eight rows per file were measured once on the original
  benchmarking host (a Windows laptop running the Vagrant VM). `benchmark.sh`
  regenerates the CSV *format* on any host, but the committed numbers are that
  archival run — the paper's single source of truth — not a fresh measurement from
  this checkout. Re-running on different hardware will produce different absolute RPS.
