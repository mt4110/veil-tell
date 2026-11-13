# veil-tell

[日本語](README.md)

Check network destinations **one command at a time**, **without sudo** on supported macOS and Linux systems. veil-tell records HTTP CONNECT requests that reach its local proxy. In restrict mode it can deny unlisted CONNECT requests and **fail a CI job**. veil-tell sends no telemetry of its own.

## Compare npm destinations in two runs

```sh
cargo install --locked --path .
```

In an npm project, run `veil-tell npm install` twice. The first successful run saves a baseline in `.veil-tell/`. The second shows new and removed destinations and large changes in request counts. Review the changes, then run `veil-tell accept` to approve them. Commit `baseline-*.json` if you want to share it, and keep the pending review file `pending.json` local.

For CI, run `veil-tell npm ci` locally, commit the baseline, and run `veil-tell ci -- npm ci`. CI enables isolation, blocks new CONNECT destinations before dialing them, and exits with code `21`. Capture covers HTTP CONNECT requests that reach the local proxy. Direct connection destinations and TLS contents are outside that scope. [Dependency update PR example and reproducible demo](docs/destination-diff.md)

For new destinations in npm runs, veil-tell can show the package, version, lifecycle script, and relative path as `inferred`. It reports `unknown` when the context is unavailable. Scripts can alter environment variables or proxy credentials to erase or forge attribution. Destination checks and CI blocking for valid CONNECT requests that reach the proxy are independent of those labels. [Measured behavior and spoofing limits](docs/destination-diff.md)

When `package-lock.json` or `Cargo.lock` is available, veil-tell can annotate new destinations with dependency changes. `veil-tell cargo build` can infer the crate behind a `build.rs` connection. Lockfile evidence describes recorded dependency changes. Installed files and the actual origin of a request remain unverified. A cached build script that does not rerun produces no connection to observe. [npm and Cargo examples and limits](docs/destination-diff.md)

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

- **Capture covers HTTP CONNECT requests that reach the local proxy.** `veil-tell COMMAND` records CONNECT requests from clients that honor the proxy settings. Direct connections can still succeed. Direct connection attempts are outside the capture scope. Zero recorded requests leaves direct network activity unknown.
- **The isolated backend restricts direct connections at the OS level.** Both modes report `coverage.proxy = "http_connect_requests"` and `coverage.direct_attempt_destinations = "not_observed"` in JSON v1. The report omits details of OS-denied direct connections and IPC.
- **Data can still leave through an allowed host.** For example, a child process may be able to send secrets to an allowed GitHub host or npm registry using credentials it can access or public upload features. The proxy tunnels TLS. HTTP methods, URL paths, and request bodies are outside its capture and control scope. An allow rule permits a tunnel to the host.

veil-tell overlaps with host-level controls in LuLu, Little Snitch, and OpenSnitch, process isolation in Firejail, and traffic inspection in mitmproxy. Its unit of observation is the command it launches, and a reviewed policy can be used locally and in CI. [Comparison with related tools](docs/design.md#8-先行例との関係)

## Isolation requirements

- **Linux** requires non-setuid bubblewrap and unprivileged user namespaces. The default path is `/usr/bin/bwrap`. Set `VEIL_TELL_BWRAP` to a trusted absolute path to use a different installation. The working directory is writable. Standard runtime directories and the Nix store are read-only.
- **macOS** uses the deprecated `/usr/bin/sandbox-exec`. It limits outbound IPv4/TCP to the run's localhost proxy port and denies named Mach service lookup and registration. Receiver tests on macOS 27.2 arm64 covered `CFMessagePort` and an app-bundled XPC service relaying to TCP. On the same OS, tested unicast DNS queries including A and AAAA via `getaddrinfo()` and TXT and KEY via `DNSServiceQueryRecord()` did not reach the authoritative server under isolation.
- Isolated runs use a temporary home, a reduced environment, and closed standard input. Keep policy and report files outside the working directory. Choose a new report path for each run.

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
