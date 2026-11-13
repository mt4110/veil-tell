# macOS・Ubuntu の再現手順

[日本語 README](../README.md) · [English README](../README_EN.md) · [脆弱性の報告](../SECURITY.md)

## 1. 環境と通常ビルド

リポジトリのルートで実行します。Rust は [rust-toolchain.toml](../rust-toolchain.toml) の指定を使い、受信側の試験には Python 3 を使います。検証時には OS、アーキテクチャ、対象のソース、バイナリの SHA-256 を記録してください。未コミット変更がある場合は、その差分と未追跡のソースも再現に必要です。

```sh
uname -smr
id -u
git rev-parse HEAD
git status --short
rustc --version
cargo build --locked --bin veil-tell --example receiver_cli
```

通常ビルドは `target/debug/veil-tell` です。`target/debug/examples/receiver_cli` は、ローカル受信口へ試験用の名前を割り当てる実行ファイルです。

### macOS

`sw_vers` で OS を確認します。隔離には `/usr/bin/sandbox-exec` を使います。Mach/XPC の受信側試験には Xcode コマンドラインツールが必要です。`/usr/bin/clang --version` で確認できます。検証済みの環境は macOS 27.2 arm64 です。

```sh
sw_vers
test -x /usr/bin/sandbox-exec
shasum -a 256 target/debug/veil-tell
```

### Ubuntu

管理者が Ubuntu 公式の `bubblewrap` を導入します。以降のコマンドは一般ユーザーで実行します。Ubuntu 26.04.1 LTS x86_64 の検証では、既存の AppArmor プロファイルが `/usr/bin/bwrap` に適用されました。 [Ubuntu の AppArmor ドキュメント](https://documentation.ubuntu.com/security/security-features/privilege-restriction/apparmor/)

```sh
sudo apt install bubblewrap
```

```sh
unset VEIL_TELL_BWRAP
dpkg-query -W bubblewrap
sha256sum target/debug/veil-tell
/usr/bin/bwrap --unshare-user --unshare-net --ro-bind / / \
  /bin/cat /proc/self/attr/current
```

最後のコマンドは、非特権のユーザー名前空間とネットワーク名前空間を作れるかの確認です。検証環境では `bwrap//&unpriv_bwrap (enforce)` が表示されました。ループバック設定時に `Operation not permitted` が出る場合は、実行ファイルのパスと AppArmor の適用先を確認します。カーネルログの閲覧権限があれば `journalctl -k --since '5 minutes ago'` で、該当時刻の `bwrap` の拒否を調べます。

## 2. 観測から制限実行まで

[README の curl 手順](../README.md#ubuntu-で隔離と終了コード-20-を試す)のうち、`demo_dir` を作るサブシェルは両 OS で使えます。ビルド後、リポジトリのルートで `export PATH="$PWD/target/debug:$PATH"` を実行してから、試験用サブシェルを一般ユーザーで実行します。試行ごとに新しい一時ディレクトリが作られ、その `state/` に TOML と JSON レポートが残ります。

| 実行 | 照合する結果 |
| --- | --- |
| 観測 | npm レジストリが HTTP `200` を返し、TOML に `registry.npmjs.org:443` がコメント付きで1候補出る |
| 未編集の TOML で制限 | プロキシが CONNECT に `403` を返し、veil-tell が `20` で終了する |
| 制限時の JSON | `isolation: "applied"`、`run_status.exit_code: 20`、宛先の `reason: "unknown_destination"` と `result: "blocked"` を確認する |

## 3. ローカル受信側の回帰試験

リポジトリのルートで、ビルドした実行ファイルを指定します。試験中に表示される `receiver case=` と `json` の行を保存すると、受信結果と終了コードを比較できます。

macOS ではループバックに受信口を作ります。

```sh
python3 -B tests/receivers.py target/debug/veil-tell target/debug/examples/receiver_cli
```

Ubuntu ではホストのループバック以外の IPv4 を使い、隔離した子からホスト宛ての直接接続が `ENETUNREACH` になることを確認します。次の例はホストに割り当てられた最初の IPv4 を選びます。複数ある場合は試験に使うインターフェースの IPv4 を `VEIL_TELL_TEST_IP` に指定してください。

```sh
(
  set -eu
  unset VEIL_TELL_BWRAP
  VEIL_TELL_TEST_IP=$(ip -4 -o addr show scope global | awk 'NR == 1 {split($4, addr, "/"); print addr[1]}')
  test -n "$VEIL_TELL_TEST_IP"
  export VEIL_TELL_TEST_IP
  python3 -B tests/receivers.py target/debug/veil-tell target/debug/examples/receiver_cli
)
```

- `policy-draft` は大文字・末尾ドットの違う同一ホストへの CONNECT を2件観測し、コメント付きの候補1件に集約します。既存ファイルへの再出力が拒否され、未編集の TOML を使った制限では受信0件、子の終了コード `0`、CLI の終了コード `20` になります。
- `isolated-allow` は CONNECT のペイロードだけが届きます。`isolated-unknown` は HTTP `403`、受信0件、終了コード `20` を確認します。`isolated-deny` は明示拒否を確認します。`inherited-fd` は継承ソケット経由でペイロードが届かないことを確認します。
- veil-tell がホスト側プロキシの異常停止を検出すると、終了コードは `125`、JSON の `run_status.reason` は `proxy_stopped`、`coverage.proxy_capture` は `until_proxy_stopped` になります。中継停止を注入する実験手順は OS 別の記録を参照してください。 [Linux の実験](../experiments/linux-egress/README.md) · [macOS の実験](../experiments/macos-egress/README.md)

macOS では Mach/XPC の受信側試験も実行できます。

```sh
python3 -B tests/macos-ipc.py target/debug/veil-tell
```

出力の `evidence=` に示されたディレクトリで、対照の送信が Mach、XPC、TCP の受信ログにあり、隔離時の送信が各受信ログにないことを確認します。 `outcomes.json` と `reports/` で終了コードを照合します。JSON の観測対象は HTTP CONNECT で、直接通信や Mach/XPC の試行先は受信ログで判定します。

## 4. リリースビルドと配布用 SHA-256

macOS 27.2 arm64 と Ubuntu 26.04.1 LTS x86_64 で、Rust 1.98.1 を使って検証しました。今回の検証では同じ作業ツリーの `Cargo.toml`、`Cargo.lock`、`rust-toolchain.toml`、`LICENSE`、`src/` を両ホストにそろえました。公開用のビルドでは、両ホストで同じリリースタグをチェックアウトし、`version` をそのタグの Cargo パッケージバージョンに合わせます。

### 各 OS でビルドと梱包

Rust を用意し、各ホストのソースルートで実行します。検証時は取得済みの依存を使い、`--offline` を付けました。キャッシュを用意するには先に `cargo fetch --locked` を実行します。

```sh
(
  set -eu
  cargo --version
  rustc -vV
  cargo build --release --locked --offline --bin veil-tell
  file target/release/veil-tell
  case "$(uname -s):$(uname -m)" in
    Darwin:arm64) platform=macos-arm64 ;;
    Linux:x86_64) platform=linux-x86_64-gnu ;;
    *) printf 'Unsupported build platform\n' >&2; exit 1 ;;
  esac
  version=0.1.0
  name="veil-tell-${version}-${platform}"
  dist_dir=$(mktemp -d "$PWD/target/dist.XXXXXX")
  mkdir "$dist_dir/$name"
  install -m 755 target/release/veil-tell "$dist_dir/$name/veil-tell"
  install -m 644 LICENSE "$dist_dir/$name/LICENSE"
  (
    cd "$dist_dir"
    COPYFILE_DISABLE=1 tar --no-xattrs -czf "$name.tar.gz" "$name"
    case "$platform" in
      macos-*) shasum -a 256 "$name.tar.gz" > "$name.sha256" ;;
      linux-*) sha256sum "$name.tar.gz" > "$name.sha256" ;;
    esac
  )
  printf 'Output: %s\n' "$dist_dir"
)
```

`Output:` に表示されたディレクトリに、実行ファイルと `LICENSE` を入れたアーカイブ、およびアーカイブ単体のチェックサムができます。Ubuntu のバイナリは glibc に動的リンクしています。動作確認済みの組み合わせは上記の2環境です。

### SHA-256 の照合と起動確認

各ホストの `Output:` のディレクトリで、自分の OS の行を実行します。

```sh
# macOS
shasum -a 256 -c veil-tell-0.1.0-macos-arm64.sha256
# Ubuntu
sha256sum -c veil-tell-0.1.0-linux-x86_64-gnu.sha256
```

次に、両 OS のアーカイブと対応する `.sha256` ファイルを一つのディレクトリに集めます。そのディレクトリで配布用の `SHA256SUMS` を生成し、移動後のファイルを照合します。

```sh
cat veil-tell-0.1.0-macos-arm64.sha256 veil-tell-0.1.0-linux-x86_64-gnu.sha256 > SHA256SUMS
# macOS
shasum -a 256 -c SHA256SUMS
# Ubuntu
sha256sum -c SHA256SUMS
```

2件とも `OK` になることを確認します。不一致があれば、梱包時のファイルと照合し直します。各 OS で隔離の前提を第1節の手順で確認し、照合済みアーカイブがあるディレクトリで次を実行します。Ubuntu では `archive` のファイル名を `veil-tell-0.1.0-linux-x86_64-gnu.tar.gz` に変更します。

```sh
(
  set -eu
  archive=veil-tell-0.1.0-macos-arm64.tar.gz
  stage=$(mktemp -d)
  mkdir "$stage/work" "$stage/state"
  tar -xzf "$archive" -C "$stage"
  package="$stage/$(basename "$archive" .tar.gz)"
  test -x "$package/veil-tell"
  test -f "$package/LICENSE"
  file "$package/veil-tell"
  (
    cd "$stage/work"
    unset VEIL_TELL_BWRAP
    "$package/veil-tell" observe --backend isolated --report "$stage/state/report.json" -- /usr/bin/true
  )
  python3 - "$stage/state/report.json" <<'PY'
import json
import sys
with open(sys.argv[1]) as report:
    result = json.load(report)
assert result["backend"] == "isolated", result
assert result["isolation"] == "applied", result
assert result["run_status"]["exit_code"] == 0, result
print("isolation=applied, exit=0")
PY
)
```

両 OS で `isolation=applied, exit=0` を確認しました。SHA-256 の照合はファイルの一致を確認します。配布元とビルド来歴の検証には、第13節で計画している来歴証明を使います。 [配布の設計](design.md#13-初回公開に向けた設計)

### GitHub Actions の配布物と来歴を確認する

[配布ビルドのワークフロー](../.github/workflows/release-build.yml) は GitHub ホストの macOS 26 arm64 と Ubuntu 26.04 x86_64 で動きます。手動実行で動作を確認でき、配布候補は Cargo のバージョンと一致するタグ（例 `v0.1.0`）から作ります。各ジョブはアーカイブと中の実行ファイルに来歴証明を作成します。集約ジョブは両アーカイブの SHA-256 を再照合し、アーカイブ2件と `SHA256SUMS` を `veil-tell-distribution` という Actions アーティファクトにまとめます。

GitHub CLI を用意して `gh auth login` で認証します。配布ページから取得したアーカイブ2件と `SHA256SUMS` を同じディレクトリに置き、上の手順で SHA-256 を照合します。配布前の確認では、成功した Actions 実行の ID を指定して同じ3ファイルを取得できます。

```sh
gh run download RUN_ID --repo mt4110/veil-tell --name veil-tell-distribution
```

アーカイブを展開する前に、来歴証明を照合します。以下はタグ `v0.1.0` の例です。ファイル名と `tag` を対象のリリースに合わせます。ブランチから手動実行した成果物の動作確認では、`--source-ref` に `refs/heads/main` など実行時のブランチを指定します。

```sh
(
  set -eu
  tag=v0.1.0
  for archive in veil-tell-0.1.0-macos-arm64.tar.gz veil-tell-0.1.0-linux-x86_64-gnu.tar.gz; do
    gh attestation verify "$archive" \
      --repo mt4110/veil-tell \
      --signer-workflow mt4110/veil-tell/.github/workflows/release-build.yml \
      --source-ref "refs/tags/$tag" \
      --deny-self-hosted-runners
  done
)
```

両ファイルで終了コード `0` を確認してから、使う OS のアーカイブを展開します。展開後の実行ファイルだけを検証する場合は、同じオプションでアーカイブの代わりに `veil-tell` のパスを指定できます。 [GitHub CLI の検証オプション](https://cli.github.com/manual/gh_attestation_verify)
