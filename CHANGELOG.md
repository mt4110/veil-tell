# Changelog

## 0.4.0

- Compare dependency installs with a stable, project-level baseline. Missing destinations are informational.
- In isolation, record covered Node.js lookup attempts. npm, pnpm and Yarn lifecycle evidence is reported as inferred.
- Measure outbound bytes and connections in CONNECT tunnels. A new destination or lookup attempt can fail CI with exit 21. A tunnel cut for exceeding its volume limit fails with exit 22.
- Add pnpm, Yarn Berry and Classic, Bun and Cargo baseline keys and lockfile summaries.
- Add `--json`, opt-in baseline saving for other commands, and a preview of legacy baseline cleanup.
- Verify GitHub Artifact Attestations before running the released binary in the composite Action. Include new CONNECT destinations, DNS attempts and volume anomalies in the job summary.
