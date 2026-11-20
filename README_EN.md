# veil-tell

[日本語](README.md)

## Use with an AI agent

Launch one CLI from the project shell. It keeps its terminal and authentication environment. After exiting the agent, read the history in the same shell. [Claude Code CLI](https://code.claude.com/docs/en/cli-reference) · [Codex CLI](https://developers.openai.com/codex/cli/) · [Cursor CLI](https://cursor.com/docs/cli/using)

```sh
veil-tell agent -- claude
# veil-tell agent -- codex
# veil-tell agent -- agent    # Cursor CLI
veil-tell log --today
```

`agent --` runs without isolation and observes CONNECT requests to port 443 from clients that use the HTTPS environment proxy. At exit, the session row lists bytes sent to each destination and connection counts. It omits launch arguments, prompts, authorization headers and TLS contents. Descendants using the same proxy contribute to this row. The launcher also puts the 12 shims on PATH. Commands such as npm and curl that run through a shim get their own rows. Use `veil-tell log --today --only-blocked` to see denials.

Direct connections, `NO_PROXY` exclusions, custom proxy settings and already-running GUI processes can fall outside session coverage. An empty row means the session proxy recorded zero CONNECT requests. If your environment requires an upstream proxy, the launcher supports an `http://` CONNECT proxy.

To install only the child-command shims, run `eval "$(veil-tell agent-env --shell zsh)"`, then start `claude`, `codex` or `agent`. Check `command -v npm` in the agent's terminal to see the selected executable. Absolute executable paths and shell aliases can bypass PATH shims.

For the Bash tool in Claude Code, a `SessionStart` command hook can run `veil-tell agent-env --shell bash >> "$CLAUDE_ENV_FILE"`. [Claude Code environment hooks](https://code.claude.com/docs/en/hooks#persist-environment-variables)

### Codex API traffic on macOS

Codex CLI 0.155.1 sent one turn to a local mock API and received a reply. The mock received one POST to `/v1/responses`. The local upstream refused CONNECT requests to the other three hosts. Zero bytes were forwarded to those destinations. This trial used no provider account or paid API.

```text
00:29:00  agent -- codex  exit 0
          ✓ allowed.test:443  ×1  39465 B  observe
          ! api.github.com:443  ×1  0 B  observe [connect_failed]
          ! chatgpt.com:443  ×2  0 B  observe [connect_failed]
          ! github.com:443  ×1  0 B  observe [connect_failed]
```

### npm install traffic on macOS and Linux

These are actual shim runs of Puppeteer 25.17.0 with `CI=true` and a reviewed registry-only baseline. The command ran in a shell on each OS. ✓ identifies an allowed CONNECT. Bytes count data sent to the destination through the TLS tunnel. A denied CONNECT has zero forwarded bytes, while the amount the child intended to send is unknown.

macOS 27.2.1 arm64

```text
23:14:19  npm ci --no-audit --no-fund  exit 21
          ✓ registry.npmjs.org:443  ×15  55682 B  observe ← npm (registry fetch) [inferred]
          ✗ storage.googleapis.com:443  ×2  0 B  new_destination [new] ← puppeteer@25.17.0 postinstall [inferred, lockfile: unchanged / 要注意]
```

Debian 13 aarch64

```text
23:14:19  npm ci --no-audit --no-fund  exit 21
          ✓ registry.npmjs.org:443  ×15  55570 B  observe ← npm (registry fetch) [inferred]
          ✗ storage.googleapis.com:443  ×2  0 B  new_destination [new] ← puppeteer@25.17.0 postinstall [inferred, lockfile: unchanged / 要注意]
```

Use `--shell bash|zsh|fish` (fish: `veil-tell agent-env --shell fish | source`), or run one command with `veil-tell --log COMMAND`. Shims observe by default and use the existing rules for dependency commands with a project baseline. Use `veil-tell log --since 2h --only-new --json` for filtered JSON Lines, or `veil-tell version` for the installed version.

veil-tell sends no telemetry. Session history stays under `$XDG_STATE_HOME/veil-tell/log` (default: `~/.local/state` on Linux, `~/Library/Application Support` on macOS as the state root). Logging masks URL paths, query strings and recognized credential arguments. Arbitrary positional arguments may still be sensitive. Set `VEIL_TELL_LOG=off` to disable history. Retention is 30 days, up to 10 MiB per day.

### Proxy and cache troubleshooting

- Node.js uses the environment proxy for both `fetch` and `https.get` on the 22.x line from 22.21 and the 24.x line from 24.5. A custom client agent can choose another route. [Node.js proxy support](https://nodejs.org/learn/http/enterprise-network-configuration)
- An all-198.18.0.0/15 DNS answer may indicate a fake-IP resolver. In a trusted TUN environment set `VEIL_TELL_ALLOW_FAKE_IP=1`. Mixed and local answers remain denied.
- An HTTP proxy in `HTTPS_PROXY` or `https_proxy` receives allowed CONNECTs. For those tunnels the upstream controls DNS and destination address checks. `NO_PROXY` supports host/domain suffixes, optional `:443` and `*`.
- If isolated curl on macOS reports `curl: (60) ... unable to get local issuer certificate`, pass a trusted CA bundle that verifies the destination’s certificate chain with `curl --cacert /path/to/ca-bundle.pem`. TLS certificate validation can fail after an allowed CONNECT.
- `VEIL_TELL_CACHE=persistent` enables a separate cache under `~/.cache/veil-tell/<manager>` in isolation. A destination absent after a cache hit is informational. Keep the pnpm project's existing store setting.
- When npm, pnpm or Yarn fails with a temporary home, veil-tell scans up to 1 MiB in total from known logs in that home. It prints the path to `.veil-tell/logs/<timestamp>-<id>/manager.log`, which contains the manager name, recognized error codes with descriptions, and recognized npm syscall names. For example, `ENOENT` and `syscall: open` identify a failed attempt to open a file. Raw log lines, including paths and arguments, are omitted. Add `/.veil-tell/logs/` and `/.veil-tell/pending.json` to the project’s `.gitignore`.

## Quick start

```sh
cargo install --locked --path .
veil-tell npm install
veil-tell ci -- npm ci
```

To check dependency updates in GitHub Actions, copy the [npm workflow template](examples/github-actions/veil-tell-npm.yml) to `.github/workflows/veil-tell-npm.yml` in your repository. Run **Check npm destinations** manually on the default branch, review the artifact's `npm.json`, and commit it as `.veil-tell/npm.json`. On the next dependency PR, the workflow checks `npm ci` against the PR base baseline. You can set this up on GitHub without installing veil-tell locally. [Setup guide (Japanese)](docs/runbook.md#10-npm-の依存更新-pr-に導入する)

### Review a new CI destination

When `veil-tell ci -- npm ci` or `CI=true veil-tell npm ci` returns `21` for a new CONNECT destination or lookup attempt, it saves a candidate in `.veil-tell/pending.json` if it used the project baseline. Review the destinations and why they appeared. To accept them, run the following from the same project root.

```sh
veil-tell accept
git diff -- .veil-tell/npm.json
veil-tell ci -- npm ci
```

Commit the reviewed baseline and exclude `.veil-tell/pending.json` from Git. For a finding from the GitHub Action or `ci --baseline FILE`, reproduce it locally with the same dependencies and comparison baseline using the project-baseline commands above.

### Keep files installed into the home directory

Isolation uses a temporary home by default. Set `VEIL_TELL_PROJECT_HOME` to a relative directory inside your project when downloaded files need to survive the install. For example, run this from a project that depends on Puppeteer.

```sh
VEIL_TELL_PROJECT_HOME=.veil-home veil-tell npm ci
PUPPETEER_CACHE_DIR="$PWD/.veil-home/.cache/puppeteer" node app.js
```

Exclude `.veil-home/` from Git. For other packages that need the same home, you can set `HOME="$PWD/.veil-home"` when running the app. If your version of Puppeteer requires `proxy-agent` to download through a proxy, add a compatible version to your dependencies. On Linux, Puppeteer can use a compatible version of `yauzl` to extract the browser when `unzip` is absent. If your package manager requires approval for dependency install scripts, review and allow Puppeteer's script. [Puppeteer configuration](https://pptr.dev/guides/configuration)

### GitHub Actions results for v0.4.0

We ran `uses: mt4110/veil-tell@v0` on macOS 26 and Ubuntu 26.04 and confirmed **`0` for no change, `21` for a blocked new destination, and `22` when the tunnel exceeded its outbound volume limit**. In the volume test, the receiver log and JSON agreed on **131,072 bytes** on both platforms. [macOS run](https://github.com/mt4110/veil-tell/actions/runs/43459261848) · [Ubuntu run](https://github.com/mt4110/veil-tell/actions/runs/43410515308) · [Reading job summaries, JSON, and receiver logs (Japanese)](docs/runbook.md#8-公開版-v040-の-github-actions-実測)

We tested the npm onboarding template on GitHub Actions with Ubuntu 26.04. We ran it manually to record `registry.npmjs.org:443`, reviewed the candidate, and committed it to the PR base. A normal `npm ci` exited **`0`**. The unlisted CONNECT received HTTP `403`. npm still exited `0`, while veil-tell exited **`21`**, failing the job and leaving a downloadable JSON report. [Verification PR #3](https://github.com/mt4110/veil-tell/pull/3) · [Baseline candidate](https://github.com/mt4110/veil-tell/actions/runs/43609198515#summary-132490298343) · [Normal run](https://github.com/mt4110/veil-tell/actions/runs/43609277174#summary-132490539684) · [Unlisted CONNECT](https://github.com/mt4110/veil-tell/actions/runs/43609366175#summary-132490812999) · [Steps and JSON guide (Japanese)](docs/runbook.md#github-actions-での実測と-json-の見方)

We also tested the onboarding template on an image-drop-input PR updating `marked` from `18.1.3` to `18.2.0`. Using the baseline recorded manually and reviewed, normal `npm ci` exited **`0`**. The unlisted CONNECT received HTTP `403`, and veil-tell exited **`21`**. The failed job still produced a downloadable JSON report. [Verification PR #76](https://github.com/mt4110/image-drop-input/pull/76) · [Baseline candidate](https://github.com/mt4110/image-drop-input/actions/runs/43687747113#summary-132731680845) · [Normal run](https://github.com/mt4110/image-drop-input/actions/runs/43687817268#summary-132731890786) · [Unlisted CONNECT](https://github.com/mt4110/image-drop-input/actions/runs/43687870837#summary-132732049536) · [Review steps and JSON guide (Japanese)](docs/runbook.md#image-drop-input-の依存更新-pr-76-での実測)

In image-drop-input dependency update PR #75, the Action used the PR base baseline even though the PR added the control destination to its own baseline. A normal `npm ci` exited **`0`**. The unlisted CONNECT received HTTP `403`, and veil-tell exited **`21`**. [PR #75](https://github.com/mt4110/image-drop-input/pull/75) · [Workflow run](https://github.com/mt4110/image-drop-input/actions/runs/43460620667) · [Reading the job summaries and JSON (Japanese)](docs/runbook.md#9-image-drop-input-の依存更新-pr-で変更前の基準を確認する)

Check network destinations **one command at a time**, **without sudo** on supported macOS and Linux systems. veil-tell records HTTP CONNECT requests that reach its local proxy. In restrict mode it can deny unlisted CONNECT requests and **fail a CI job**. veil-tell sends no telemetry of its own.

## Can I block this destination?

On macOS, we ran Prompt Recipe from the same source and lockfile, changing only the rule for `registry.npmjs.org:443`.

| Trial | `veil-tell verify` verdict |
| --- | --- |
| `npm ci`, build, and test with a populated cache | **Passes with the destination blocked.** All 19 tests passed in both runs. |
| `npm audit` with a populated cache | **Fails with the destination blocked.** Allow → block → allow returned `0 → 1 → 0`. |
| Empty cache, then a timeout or interruption during the blocked run | **Inconclusive.** JSON distinguishes `timed_out` from `interrupted`. |

[Reproduce the Prompt Recipe demo and read the JSON (Japanese)](docs/runbook.md#5-prompt-recipe-で-verify-を再現する)

On **image-drop-input**, we used the published `v0.2.0` binary on macOS with the same source, lockfile, and populated dependency cache in each trial. The build and all 216 tests **passed with `registry.npmjs.org:443` blocked**. A separate `npm audit` **failed with the destination blocked**. Its exit codes were `0 → 1 → 0` with the destination allowed, blocked, and allowed again. [Trial conditions and JSON guide (Japanese)](docs/runbook.md#6-image-drop-input-で-verify-を再現する)

On Ubuntu 26.04.1 LTS (`hp-ubuntu`), we ran the published `v0.2.0` binary without sudo. The build and all 216 tests passed with the registry both allowed and blocked. The standalone `npm audit` failed only when the registry was blocked. [Set up Node.js and npm inside Ubuntu isolation (Japanese)](docs/runbook.md#ubuntu-の隔離内で-nodejs-と-npm-を使う)

On GitHub Actions, we ran image-drop-input on the working branch and with `--ref main`. With the dependency cache populated, the build and all 216 tests passed with the registry allowed and with it blocked. The standalone `npm audit` failed only with the registry blocked. The audit step returned exit code `1`, causing the job to fail. We still downloaded both `workflow.json` and `audit.json`. [Working branch run](https://github.com/mt4110/image-drop-input/actions/runs/43370286803) · [Main branch run](https://github.com/mt4110/image-drop-input/actions/runs/43375110063) · [Run manually and read the JSON (Japanese)](docs/runbook.md#7-image-drop-input-の-github-actions-で-verify-を実行する)

## Build and run

Run `cargo install --locked --path .` from the repository. The example below allows only the public npm registry to install `is-number@7.0.0`.

Before running the demo, make sure `veil-tell`, Node.js, and npm are on PATH. On Ubuntu, install the official `bubblewrap` package first. To use Ubuntu's `/usr/bin/bwrap` from the Nix development shell, run `unset VEIL_TELL_BWRAP`. [Ubuntu setup](#try-isolation-and-exit-code-20-on-ubuntu)

```sh
demo_dir=$(mktemp -d /tmp/veil-tell-demo.XXXXXX)
mkdir "$demo_dir/project" "$demo_dir/state"
cd "$demo_dir/project"
cat > package.json <<'JSON'
{"name":"veil-tell-demo","version":"1.0.0","private":true,"dependencies":{"is-number":"7.0.0"}}
JSON
touch user.npmrc global.npmrc
cat > "$demo_dir/state/npm.toml" <<'TOML'
version = 1
profile = "npm"

[[rule]]
action = "allow"
host = "registry.npmjs.org"
port = 443
TOML

veil-tell restrict --backend isolated --policy "$demo_dir/state/npm.toml" \
  --fail-on-unknown --report "$demo_dir/state/npm-run.json" -- \
  npm install --registry=https://registry.npmjs.org/ --cache=./npm-cache \
  --userconfig=./user.npmrc --globalconfig=./global.npmrc \
  --strict-ssl --no-audit --no-fund --no-update-notifier --loglevel=http
```

Use `veil-tell COMMAND` to inspect destinations. Use `veil-tell observe --backend isolated -- COMMAND` to inspect destinations while restricting direct connections at the OS level. In restrict mode, TOML rules match exact DNS hostnames on port `443`. Use `action = "deny"` to explicitly deny a destination.

With `--fail-on-unknown`, veil-tell denies unlisted CONNECT requests and exits with code `20` even if the child handles the error and exits with code `0`. An explicit deny blocks the tunnel without triggering exit code 20. Setup and capture errors use exit code `125`.

Run `veil-tell observe --emit-policy FILE -- COMMAND` to generate a TOML draft. Each recorded CONNECT host and port appears once as a commented candidate pending review. The draft contains zero active rules. If passed directly to `restrict --fail-on-unknown`, its candidates are denied as unlisted. Uncomment only the candidates you have reviewed. The draft is written after a successful command with uninterrupted and complete capture. Existing files are protected from overwrite. With isolation, use a sibling directory such as `../state/report.json`. The output directory must be separate from the working directory and its descendants and ancestors.

## Capture scope and known limitations

- **Capture includes HTTP CONNECT requests that reach the local proxy.** The proxy backend permits direct connections, which are outside its capture scope.
- **Isolation also records supported Node.js lookup attempts.** The report identifies this as `coverage.dns_attempts: node_dns_lookup_hook`. Native system resolvers and direct IP attempts are outside this coverage. [Details](docs/dns-attempts.md)
- **The isolated backend restricts direct connections at the OS level.** Linux reports `coverage.direct_attempt_destinations = "ip_port"` when seccomp notifications are available, `not_observed` when unavailable, and `incomplete` on capture overflow.
- **Data can still leave through an allowed host.** CI and explicitly configured limits can close a tunnel when outbound volume exceeds its budget. Bytes within the limit can still reach the receiver. [Volume limits and scope](docs/volume-limits.md) For example, a child process may be able to send secrets to an allowed GitHub host or npm registry using credentials it can access or public upload features. The proxy tunnels TLS. HTTP methods, URL paths, and request bodies are outside its capture and control scope. An allow rule permits a tunnel to the host.

| Capture under isolation | Linux | macOS |
| --- | --- | --- |
| HTTP CONNECT reaching the proxy | Hostname and port | Hostname and port |
| Supported Node.js lookups | Recorded by hostname and denied | Recorded by hostname and denied |
| System resolvers used by curl, Python, Go and Rust, or literal IPs | IP, port and count with notification support. DNS question names are unavailable | Direct destinations and counts are unobserved |

`CI=true veil-tell npm install` requires isolation and an existing baseline, and returns `21` for new CONNECT destinations or newly observed lookup attempts. Local shorthand does not fail solely on recorded lookup attempts. Explicit `observe --baseline FILE` reports an outbound volume anomaly with exit `21`; an enforced tunnel cutoff still uses `22`. Small transfers below the threshold and totals spanning several runs are outside volume comparison.

For Corepack, run `corepack install` in the project root to cache the pnpm version named in `packageManager`. Then use `veil-tell pnpm install` or `veil-tell corepack pnpm install`. For a home-installed pnpm, put the installed launcher and Node.js on PATH.

If pnpm 12.4.x fails TLS verification in macOS isolation, use the tested pnpm 12.21.0 or a later version. [Cause and measurements (Japanese)](docs/destination-diff.md#pnpm-12-の-macos-tls-とバージョン別の回帰試験)

To switch between isolated and plain pnpm in the same workspace, set `storeDir: .pnpm-store` in `pnpm-workspace.yaml`. With pnpm 9, also set `store-dir=.pnpm-store` in `.npmrc`. [Setup and recovery](docs/runbook.md#11-pnpm-のストアを隔離内外でそろえる)

veil-tell overlaps with host-level controls in LuLu, Little Snitch, and OpenSnitch, process isolation in Firejail, and traffic inspection in mitmproxy. Its unit of observation is the command it launches, and a reviewed policy can be used locally and in CI. [Comparison with related tools](docs/design.md#8-先行例との関係)

## Isolation requirements

- **Linux** requires non-setuid bubblewrap and unprivileged user namespaces. The default path is `/usr/bin/bwrap`. Set `VEIL_TELL_BWRAP` to a trusted absolute path to use a different installation. The working directory is writable. Standard runtime directories and the Nix store are read-only.
- **macOS** uses the deprecated `/usr/bin/sandbox-exec`. It limits outbound IPv4/TCP to the run's localhost proxy port and denies named Mach service lookup and registration. Receiver tests on macOS 27.2 arm64 covered `CFMessagePort` and an app-bundled XPC service relaying to TCP. On the same OS, tested unicast DNS queries including A and AAAA via `getaddrinfo()` and TXT and KEY via `DNSServiceQueryRecord()` did not reach the authoritative server under isolation.
- Isolated runs use a temporary home and a reduced environment. Standard input is normally closed. Shims installed by `agent-env` or `agent --` pass input through, so commands such as `curl --config -` can read a pipeline. A regular file redirected read-only is inherited with its shared file offset. Terminal input is passed as a byte stream. Keep policy and report files outside the working directory. Choose a new report path for each run.

## Try isolation and exit code `20` on Ubuntu

Install bubblewrap from Ubuntu’s official repository. Installation requires administrator privileges. Run the subsequent `veil-tell` commands as a regular user. On Ubuntu 26.04.1 LTS x86_64, the existing AppArmor profile applied to `/usr/bin/bwrap`, and the workflow ran with the existing AppArmor and sysctl settings. [Ubuntu AppArmor documentation](https://documentation.ubuntu.com/security/security-features/privilege-restriction/apparmor/)

```sh
sudo apt install bubblewrap
```

Build and install `veil-tell` as shown above and make sure `/usr/bin/curl` is available. The example fetches metadata from the public npm registry, generates a TOML draft, and uses it as-is to try connecting to the same destination.

```sh
(
  set -eu
  unset VEIL_TELL_BWRAP
  demo_dir=$(mktemp -d /tmp/veil-tell-ubuntu.XXXXXX)
  mkdir "$demo_dir/work" "$demo_dir/state"
  cd "$demo_dir/work"
  url=https://registry.npmjs.org/is-number

  veil-tell observe --backend isolated --emit-policy "$demo_dir/state/observed.toml" \
    --report "$demo_dir/state/observe.json" -- \
    /usr/bin/curl -q --noproxy '' --fail --silent --show-error \
      --max-time 20 --output /dev/null --write-out 'HTTP %{http_code}\n' "$url"
  cat "$demo_dir/state/observed.toml"

  status=0
  veil-tell restrict --backend isolated --policy "$demo_dir/state/observed.toml" \
    --fail-on-unknown --report "$demo_dir/state/restrict.json" -- \
    /usr/bin/curl -q --noproxy '' --fail --silent --show-error \
      --max-time 20 --output /dev/null "$url" || status=$?
  printf 'veil-tell exit: %s\n' "$status"
  cat "$demo_dir/state/restrict.json"
  test "$status" -eq 20
)
```

The observation run prints `HTTP 200`, and the TOML lists `registry.npmjs.org:443` as a commented candidate. During the restriction run, the proxy returns `403` to CONNECT and the example prints `veil-tell exit: 20`. In `restrict.json`, `isolation` is `applied`, the destination’s `reason` is `unknown_destination`, and `run_status.exit_code` is `20`.

If `bwrap` fails to start with `Operation not permitted`, check that `/usr/bin/bwrap` comes from Ubuntu’s package and that the existing AppArmor profile applies to that path. Isolation depends on the host configuration.

## Development and receiver tests

`nix develop path:.` supplies development tools. `rust-toolchain.toml` pins Rust, and mise manages Node.js for tests and development tasks.

```sh
cargo test --locked
cargo build --locked --examples --bins
python3 -B tests/receivers.py target/debug/veil-tell target/debug/examples/receiver_cli
```

On Ubuntu, set `VEIL_TELL_TEST_IP` to the host's non-loopback IPv4 address for the receiver tests. [Receiver test commands](docs/runbook.md#3-ローカル受信側の回帰試験)

Pass the directory of a Node.js distribution with npm as the final argument to include a local HTTPS registry test with an empty cache. The test executable maps `allowed.test` to the controlled receiver. The ordinary build uses the system resolver and checks that the destination address is public.

On macOS, install the Xcode command-line tools and run `python3 -B tests/macos-ipc.py target/debug/veil-tell` to test Mach and XPC. The harness keeps the receiver logs and JSON reports.

[MIT license](LICENSE) · [Report a vulnerability](SECURITY.md#security-policy) · [macOS and Ubuntu runbook (Japanese)](docs/runbook.md)

[Design](docs/design.md) · [Linux experiments](experiments/linux-egress/README.md) · [macOS experiments](experiments/macos-egress/README.md)

## Other CI systems and local hooks

Review and commit `.veil-tell/npm.json` and make veil-tell, Node.js and bubblewrap available on the runner.

```yaml
# .gitlab-ci.yml
outbound:
  script:
    - veil-tell ci -- npm ci
```

To run the same check before a local push, save the following as `.git/hooks/pre-push` and run `chmod +x .git/hooks/pre-push`. The command reinstalls dependencies in the working tree.

```sh
#!/bin/sh
exec veil-tell ci -- npm ci
```

Dependency commands create baselines automatically. To save one for another command, use `veil-tell --save-baseline COMMAND`. Run `veil-tell clean` to preview legacy hash-named baselines and `veil-tell clean --apply` to remove them. `--json` writes the report to stdout and sends child output and guidance to stderr.
