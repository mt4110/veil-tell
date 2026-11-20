# Changelog

## 0.6.0

- Launch an interactive agent with `agent -- COMMAND` to observe its environment-proxied HTTPS connections. Run supported shell commands through local shims with `agent-env`. Review redacted per-command session history with `log`, including new destinations, blocked attempts, forwarded bytes and inferred attribution.
- Route supported Node.js fetch and HTTPS clients through the local proxy on both backends. Group human-readable CONNECT rows, explain denied destinations, and accept `version` as an alias for `--version`.
- Recognize possible fake-IP resolvers and support an explicit opt-in. Honor HTTP upstream proxies and count established upstream tunnels toward baseline volume limits. JSON v1 adds optional `resolver_hint`, `via_upstream_proxy`, and manager/phase attribution.
- On Linux, isolated shims open redirected regular-file stdin on a read-only mount and restore the file position at exit. This requires a named input file.
- Linux shorthand starts the system bubblewrap sandbox once on a successful run. A filtered pre-exec signal guards against replaying the command during fallback.
- On Linux, optional seccomp notification support reports `direct_attempts` and coverage values `ip_port` or `incomplete`. This is stage A only. Native DNS question names and macOS direct socket destinations remain unobserved.
- Opt into dedicated persistent manager caches. On temporary-home failures, scan up to 1 MiB of manager logs and preserve recognized error codes, explanations and npm syscall names.
- Shrink the release executables on all three targets. First launch of a freshly installed executable on macOS still exceeds the 40 ms shorthand and 50 ms replacement-shim targets.
- Add Linux aarch64 release packaging and artifact attestation, plus CodeQL and a Scorecard workflow with result publication disabled.

## 0.5.2

- Support an opt-in workspace home for install-time downloads that must survive isolation.
- Run cached Corepack pnpm shims and home-installed pnpm toolchains in isolation. Distinguish launcher failures from store configuration errors.
- Save a reviewable candidate when CI finds a new destination against the project baseline, so `veil-tell accept` can update that baseline after review.
- Keep npm lifecycle attribution enabled when `NPM_CONFIG_PREFIX` only sets a prefix.

## 0.5.1

- Require an effective project-local pnpm store before running isolated dependency operations. Reject missing or incompatible settings with exit 125 before touching `node_modules`.

## 0.5.0

- Guide macOS users of pnpm 12.4.x toward a tested version with upstream sandbox-safe TLS verification. Exercise npm, three pnpm majors, both Yarn variants, and Bun.
- Enforce recorded new lookup attempts in shorthand CI, omit empty human-facing DNS notices, and fail incomplete DNS capture at its recording limits.
- Return 21 for outbound volume anomalies in explicit baseline observation. Preserve 22 when an enforced limit cuts a tunnel.
- Show CONNECT, DNS and volume findings in one Action summary, including inferred attribution, lockfile evidence, and observed counts against limits.

## 0.4.0

- Compare dependency installs with a stable, project-level baseline. Missing destinations are informational.
- In isolation, record covered Node.js lookup attempts. npm, pnpm and Yarn lifecycle evidence is reported as inferred.
- Measure outbound bytes and connections in CONNECT tunnels. A new destination or lookup attempt can fail CI with exit 21. A tunnel cut for exceeding its volume limit fails with exit 22.
- Add pnpm, Yarn Berry and Classic, Bun and Cargo baseline keys and lockfile summaries.
- Add `--json`, opt-in baseline saving for other commands, and a preview of legacy baseline cleanup.
- Verify GitHub Artifact Attestations before running the released binary in the composite Action. Include new CONNECT destinations, DNS attempts and volume anomalies in the job summary.
