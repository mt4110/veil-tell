# Changelog

## 0.5.0 (unreleased)

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
