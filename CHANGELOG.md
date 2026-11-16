# Changelog

## 0.5.2 (unreleased)

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
