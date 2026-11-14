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

`verify` の回帰試験は macOS と Ubuntu の両方で実行できます。ローカル受信口を使い、許可・拒否・再許可で届いたデータと JSON の判定を照合します。

```sh
python3 -B tests/verify.py target/debug/veil-tell target/debug/examples/receiver_cli
```

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

[配布ビルドのワークフロー](../.github/workflows/release-build.yml) は GitHub ホストの macOS 26 arm64 と Ubuntu 26.04 x86_64 で動きます。Cargo のバージョンと一致する `vMAJOR.MINOR.PATCH` タグ（例 `v0.4.0`）を push すると起動します。各ジョブはアーカイブと中の実行ファイルに来歴証明を作成します。集約ジョブは両アーカイブの SHA-256 を再照合し、アーカイブ2件と `SHA256SUMS` を `veil-tell-distribution` という Actions アーティファクトにまとめます。

GitHub CLI を用意して `gh auth login` で認証します。配布ページから取得したアーカイブ2件と `SHA256SUMS` を同じディレクトリに置き、上の手順で SHA-256 を照合します。配布前の確認では、成功した Actions 実行の ID を指定して同じ3ファイルを取得できます。

```sh
gh run download RUN_ID --repo mt4110/veil-tell --name veil-tell-distribution
```

アーカイブを展開する前に、来歴証明を照合します。以下はタグ `v0.1.0` の例です。ファイル名と `tag` を対象のリリースに合わせます。

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

## 5. Prompt Recipe で verify を再現する

macOS 27.2 arm64、Node.js 26.9.0、npm 11.19.1 で、Prompt Recipe のコミット `78f2beb` を使った実測です。`registry.npmjs.org:443` を許可するポリシーを基準に、`verify` が試行内でその1件を拒否します。使用するバイナリは、このソースから第1節の手順でビルドしてください。

### 同じソースとキャッシュを用意する

以下は Bash で実行します。第1節のビルド後、veil-tell のルートで実行してください。試験用ディレクトリに固定コミットのソースを展開し、キャッシュの準備には別のコピーを使います。

```bash
veil="$PWD/target/debug/veil-tell"
demo=$(mktemp -d /tmp/veil-tell-prompt-recipe.XXXXXX)
commit=78f2bebf7af065d263d3d53119cc7118dcf8722b
git clone --quiet https://github.com/mt4110/prompt-recipe.git "$demo/repo"
mkdir "$demo/cold" "$demo/state"
git -C "$demo/repo" archive --output="$demo/source.tar" "$commit"
tar -xf "$demo/source.tar" -C "$demo/cold"
touch "$demo/cold/.comparison-user.npmrc" "$demo/cold/.comparison-global.npmrc"

cat > "$demo/state/allow.toml" <<'TOML'
version = 1
profile = "npm"
[[rule]]
action = "allow"
host = "registry.npmjs.org"
port = 443
TOML

cat > "$demo/cold/check.sh" <<'SH'
#!/bin/sh
set -eu
export npm_config_cache=./.comparison-cache
export npm_config_userconfig=./.comparison-user.npmrc
export npm_config_globalconfig=./.comparison-global.npmrc
export npm_config_fetch_retries=0
export npm_config_fetch_timeout=5000
export npm_config_maxsockets=1
export npm_config_update_notifier=false
export npm_config_fund=false
export npm_config_audit=true

step() {
  printf '\n>>> npm %s\n' "$*"
  npm "$@"
}

test ! -e node_modules
case "$1" in
  seed) step ci ;;
  workflow) step ci; step run build; step test ;;
  audit) step audit ;;
  *) exit 64 ;;
esac
SH

cp -R "$demo/cold" "$demo/prime"
(cd "$demo/prime" && "$veil" restrict --backend isolated \
  --policy "$demo/state/allow.toml" --report "$demo/state/prime.json" -- \
  /bin/sh ./check.sh seed)
cp -R "$demo/cold" "$demo/warm"
mkdir "$demo/warm/.comparison-cache"
cp -R "$demo/prime/.comparison-cache/_cacache" "$demo/warm/.comparison-cache/"
cmp "$demo/cold/package-lock.json" "$demo/warm/package-lock.json"
shasum -a 256 "$demo/cold/package-lock.json"
printf 'Reports and logs: %s/state\n' "$demo"
```

キャッシュ準備の `npm ci` が成功してから比較に進みます。`warm` に移すのは npm の `_cacache` だけです。どちらのソースにも `node_modules` がない状態から始めます。

### 許可と拒否を比較する

同じ Bash で実行します。関数は実行ログ、JSON、CLI の終了コードを `state/` に保存します。同じ試行をやり直すときは、関数の第1引数に新しい名前を指定します。

```bash
trial() {
  local name=$1 seed=$2 seconds=$3 check=$4 code=0
  if [ -e "$demo/state/$name.json" ] || [ -e "$demo/state/$name.exit" ]; then
    printf 'Choose a new trial name: %s\n' "$name" >&2
    return 1
  fi
  "$veil" verify --source "$demo/$seed" --policy "$demo/state/allow.toml" \
    --without registry.npmjs.org:443 --report "$demo/state/$name.json" \
    --timeout-seconds "$seconds" -- /bin/sh ./check.sh "$check" \
    > "$demo/state/$name.log" 2>&1 || code=$?
  printf '%s\n' "$code" > "$demo/state/$name.exit"
  tail -n 5 "$demo/state/$name.log"
}

trial warm-workflow warm 30 workflow
trial warm-audit warm 30 audit
trial cold-timeout cold 12 workflow
```

中断を再現する場合は、以下を端末のフォアグラウンドで実行します。`veil-tell verify: denied` に続いて `>>> npm ci` が出たら Ctrl-C を押します。

```bash
"$veil" verify --source "$demo/cold" --policy "$demo/state/allow.toml" \
  --without registry.npmjs.org:443 --report "$demo/state/cold-interrupt.json" \
  --timeout-seconds 20 -- /bin/sh ./check.sh workflow
printf 'verify exit: %s\n' "$?"
```

実測では、キャッシュありのビルド・テストは許可と拒否の両方で19件成功しました。レジストリへの CONNECT を拒否した試行でも、キャッシュからの `npm ci` は成功しました。独立した `npm audit` は拒否時に `403` で失敗し、再許可すると成功しました。公開レジストリの脆弱性情報が更新されると、許可側の監査結果も変わり得ます。

空キャッシュの12秒はこの環境で使った期限です。許可側が先に期限に達する場合は、`phase` で確認し、各試行に同じ長めの期限を設定してください。

### JSON と終了コードを照合する

`jq` があれば、判定と各試行の終了コード、観測した CONNECT をまとめて確認できます。

```bash
jq '{
  verdict, reason, phase, exit_code,
  trials: (.trials | map_values(
    if . == null or has("error") then . else
      {child_status, run_status, coverage,
       destinations: [.destinations[] |
         {host, port, reason, result, attempts, sent_bytes, received_bytes}]}
    end
  ))
}' "$demo/state/warm-workflow.json" "$demo/state/warm-audit.json" \
   "$demo/state/cold-timeout.json" "$demo/state/cold-interrupt.json"
```

| 実測 | `verdict` / `reason` | CLI の終了コード | 試行の確認箇所 |
| --- | --- | --- | --- |
| キャッシュありのビルド・テスト | `passes` / `passed_with_destination_blocked` | `0` | 許可・拒否ともに子が `0`。拒否側は `explicit_deny`、`blocked`、送受信ともに0バイト |
| キャッシュありの監査 | `fails` / `failed_with_destination_blocked` | `1` | 許可・拒否・再許可の子が `0 → 1 → 0`。拒否側は `child_failed` |
| 空キャッシュで拒否中に期限切れ | `inconclusive` / `timed_out` | `2` | 拒否試行の `run_status.exit_code` は `124` |
| 空キャッシュで拒否中に Ctrl-C | `inconclusive` / `interrupted` | `130` | 拒否試行の `run_status.exit_code` は `130` |

トップレベルの `phase` は判定を確定した試行です。`trials.allowed`、`trials.denied`、`trials.restored` で、それぞれの `child_status` と `run_status` を照合します。実行しなかった試行は `null`、試行の準備に失敗した場合は `error` に詳細が入ります。期限切れと中断の `coverage.proxy_capture` は `until_interrupted` です。SIGTERM による中断では CLI は `143` を返します。

`--timeout-seconds` は各試行のコマンド起動後に適用され、既定は300秒です。不正な引数やポリシーなどで比較を開始できない場合は `125` を返します。ポリシーとレポートは `--source` の外に置き、レポートには一時ディレクトリのルートを含まない専用のディレクトリを使います。Linux で内部中継の失敗やシグナルと区別できない子の終了コード `125`・`128` 以上は、`child_exit_ambiguous` で判定不能になります。

判定の対象は、指定したコマンド、開始時のキャッシュ、プロキシが観測した HTTP CONNECT です。信頼できるコマンドをプロジェクト相対パスで指定してください。外部サービスやスナップショット外のキャッシュは試行間で変わり得ます。

## 6. image-drop-input で verify を再現する

macOS 27.2 arm64 と Ubuntu 26.04.1 LTS x86_64（`hp-ubuntu`）で、公開版 veil-tell `v0.2.0` の各アーカイブを SHA-256 で照合し、sudo なしで実行しました。両環境で image-drop-input のコミット `1cc4f42b59992bf63cc646ac88bcb0834b6215cc`、Node.js 26.13.0、npm 12.2.2 を使いました。依存キャッシュは OS ごとに準備し、同じ OS の許可・拒否・再許可で同じ初期キャッシュを使いました。 [veil-tell v0.2.0 の配布ページ](https://github.com/mt4110/veil-tell/releases/tag/v0.2.0)

### 比較条件と実行コマンド

第5節の「同じソースとキャッシュを用意する」の手順を使い、`veil` を展開した公開バイナリの絶対パスに、`commit` を上記のコミットに設定します。`git clone` の URL は image-drop-input のリポジトリに差し替えます。照合に使った `package-lock.json` の SHA-256 は `5eddc44e5259611589640c5e77e54e1f5a4ac1d9d619dc1d2a8224a40c19137c` です。 [image-drop-input リポジトリ](https://github.com/mt4110/image-drop-input)

第5節の `check.sh` を、準備用コピーを作る前に以下に差し替えます。各試行は `node_modules` がない状態で始まり、ロックファイルの SHA-256 を実行の前後に照合します。`workflow` のコマンドは image-drop-input の CI と同じ順序です。 [比較した CI 手順](https://github.com/mt4110/image-drop-input/blob/1cc4f42b59992bf63cc646ac88bcb0834b6215cc/.github/workflows/ci.yml#L32-L36)

```bash
cat > "$demo/cold/check.sh" <<'SH'
set -eu
export npm_config_cache=./.comparison-cache
export npm_config_userconfig=./.comparison-user.npmrc
export npm_config_globalconfig=./.comparison-global.npmrc
export npm_config_fetch_retries=0
export npm_config_fetch_timeout=10000
export npm_config_update_notifier=false
export npm_config_fund=false
export npm_config_audit=true
export CI=true

lock_sha=5eddc44e5259611589640c5e77e54e1f5a4ac1d9d619dc1d2a8224a40c19137c
check_lock() {
  test "$(shasum -a 256 package-lock.json | cut -d ' ' -f1)" = "$lock_sha"
}
step() {
  printf '\n>>> npm %s\n' "$*"
  npm "$@"
}

test ! -e node_modules
check_lock
status=0
case "$1" in
  seed) step ci ;;
  workflow)
    step ci
    step run typecheck
    step test
    step run build:examples
    step run check:package
    ;;
  audit) step audit || status=$? ;;
  *) exit 64 ;;
esac
check_lock
exit "$status"
SH
```

### Ubuntu の隔離内で Node.js と npm を使う

第1節の Ubuntu の手順で `/usr/bin/bwrap` を確認します。Ubuntu x86_64 の配布アーカイブは `veil-tell-0.2.0-linux-x86_64-gnu.tar.gz` です。`SHA256SUMS` と照合して展開し、`veil` に実行ファイルの絶対パスを設定します。

Linux の隔離では、ホームディレクトリの作業ツリーの外に展開した Node.js や npm は見えません。試験用の `cold` に入れておくと、準備用の `prime` と `verify` の各試行に同じツールがコピーされます。次のコマンドは `cold` を作成してから `prime` と `warm` にコピーする前に実行します。

```bash
(
  set -euo pipefail
  cd "$demo"
  curl -fsSLO https://nodejs.org/dist/v26.13.0/node-v26.13.0-linux-x64.tar.xz
  printf '%s\n' 'd28a96af6c38596f6d9d97c0ee531c13d238d757742387d1928de822d959e997  node-v26.13.0-linux-x64.tar.xz' |
    sha256sum -c
  tar -xf node-v26.13.0-linux-x64.tar.xz
  curl -fsSLO https://registry.npmjs.org/npm/-/npm-12.2.2.tgz
  test "$(openssl dgst -sha512 -binary npm-12.2.2.tgz | openssl base64 -A)" = \
    'KglgbZyacf7jH+FHuNRqVuCzQi8VhI2a7J87Ix43FsPTuZoGWmIXXGdZtBUOA79vwL+IJREqURVzupA7PsQTcA=='
  mkdir -p cold/.trial-toolchain/bin cold/.trial-toolchain/npm
  cp node-v26.13.0-linux-x64/bin/node cold/.trial-toolchain/bin/
  tar -xzf npm-12.2.2.tgz --strip-components=1 -C cold/.trial-toolchain/npm
  ln -s ../npm/bin/npm-cli.js cold/.trial-toolchain/bin/npm
)
```

`$demo/cold/check.sh` の `set -eu` の直後に以下を入れます。`$PWD` は隔離内の各作業コピーを指し、ログの先頭でバージョンを確認できます。

```bash
export PATH="$PWD/.trial-toolchain/bin:/usr/bin:/bin"
node --version
npm --version
```

### キャッシュを用意して比較する

第5節の手順どおり、`registry.npmjs.org:443` だけを許可し、準備用の `npm ci` で得た `_cacache` だけを `warm` に移します。同じ `trial` 関数を定義し、その末尾にある Prompt Recipe 用の呼び出しを次の2行に差し替えます。

```bash
trial workflow warm 120 workflow
trial audit warm 120 audit
```

### 終了コードと JSON の見方

以下は macOS と Ubuntu の両方で、ログ・終了コード・JSON が一致した結果です。

| 工程 | トップレベルの判定と終了コード | 各試行で確認したこと |
| --- | --- | --- |
| インストール、型チェック、テスト、サンプルビルド、パッケージ検査 | `passes`、`0` | `allowed` と `denied` の `child_status.exit_code` はともに `0`。ログでは両試行で216件のテストに成功。再許可試行の `restored` は `null` |
| 単独の `npm audit` | `fails`、`1` | `allowed`、`denied`、`restored` の子の終了コードは `0 → 1 → 0`。拒否時のログに `403`、`run_status.reason` に `child_failed` |

```bash
jq '{
  verdict, exit_code,
  child_exits: ([.trials.allowed, .trials.denied, .trials.restored]
    | map(.child_status.exit_code)),
  denied_run_reason: .trials.denied.run_status.reason,
  denied: [.trials.denied.destinations[] |
    {host, port, reason, result, sent_bytes, received_bytes}]
}' "$demo/state/workflow.json" "$demo/state/audit.json"
```

トップレベルの `exit_code` を同名の `.exit` ファイルと照合します。両レポートの拒否試行では、`registry.npmjs.org:443` に対する `explicit_deny` と `blocked` を記録し、送受信はともに0バイトでした。この結果で閉じられたのは、依存キャッシュが揃ったビルド・テスト工程の許可です。監査結果はレジストリ側の脆弱性情報によって変わり得ます。

## 7. image-drop-input の GitHub Actions で verify を実行する

GitHub ホストの Ubuntu ランナーで、公開版 `v0.2.0` の SHA-256 を照合して実行しました。各実行では同じソース・ロックファイル・初期キャッシュから試行を始め、`registry.npmjs.org:443` の許可だけを切り替えました。 [作業ブランチ `feat/release-0.3.5` の実行（`17abe4c`）](https://github.com/mt4110/image-drop-input/actions/runs/43370286803) · [`main` の実行（`6f5a477`）](https://github.com/mt4110/image-drop-input/actions/runs/43375110063)

### 手動実行と Artifact の取得

ワークフローは手動実行専用です。リポジトリへの書き込み権限があるアカウントで GitHub CLI にログインし、ワークフローを含むブランチを `--ref` で指定します。手動実行には、デフォルトブランチにもワークフローファイルが必要です。Web では Actions の **Verify npm registry dependency** を選び、**Run workflow** でブランチを指定します。 [GitHub Actions の手動実行手順](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/manually-run-a-workflow)

```bash
repo=mt4110/image-drop-input
gh workflow run veil-tell-verify.yml --repo "$repo" --ref main
gh run list --repo "$repo" --workflow veil-tell-verify.yml \
  --branch main --event workflow_dispatch
```

実行一覧で対象の ID を確認し、実行が完了してから Artifact を取得します。以下の `43375110063` は `main` の実測時の ID です。新しく実行した場合は、その ID に置き換えます。

```bash
run_id=43375110063
gh run view "$run_id" --repo "$repo" --json conclusion,jobs
gh run download "$run_id" --repo "$repo" --name veil-tell-verify --dir reports
```

`Verify npm audit` ステップは `verify` の終了コードをそのまま返します。実測では終了コード `1` でジョブが失敗し、その後 `if: always()` が付いた `Upload verify reports` ステップが成功しました。実行ページの **Artifacts** からも `veil-tell-verify` を取得できます。 [`main` の Artifact](https://github.com/mt4110/image-drop-input/actions/runs/43375110063/artifacts/14013244113)

### CI ログと JSON を照合する

`main` のログ・終了コード・両 JSON を照合した結果は、作業ブランチと一致しました。

| レポート | `verdict` / `exit_code` | 実行ログとの照合 |
| --- | --- | --- |
| `workflow.json` | `passes` / `0` | 許可・拒否ともに子の終了コードは `0`。両試行のログでビルド成功とテスト216件通過を確認 |
| `audit.json` | `fails` / `1` | 子の終了コードは許可・拒否・再許可で `0 → 1 → 0`。拒否時だけログに HTTP `403` が出て、ジョブは失敗 |

第6節と同じ項目を、ダウンロードした両 JSON から確認できます。`trials.restored` が `null` の場合、再許可試行は実行されていません。監査の拒否試行は `child_failed` です。両レポートの拒否試行で、レジストリへの CONNECT は `explicit_deny` / `blocked`、送受信ともに0バイトでした。

```bash
jq '{
  verdict, exit_code,
  child_exits: ([.trials.allowed, .trials.denied, .trials.restored]
    | map(.child_status.exit_code)),
  denied_run_reason: .trials.denied.run_status.reason,
  denied: [.trials.denied.destinations[] |
    {host, port, reason, result, sent_bytes, received_bytes}]
}' reports/workflow.json reports/audit.json
```

## 8. 公開版 v0.4.0 の GitHub Actions 実測

GitHub ホストの macOS 26 と Ubuntu 26.04 で `uses: mt4110/veil-tell@v0` を実行しました。Action が公開アーカイブの来歴を検証し、隔離した `npm run postinstall` で架空のパッケージ `veil-release-smoke@1.0.0` の3ケースを試しました。受信口は各ランナー内に置きました。 [macOS の実行](https://github.com/mt4110/veil-tell/actions/runs/43459261848) · [Ubuntu の実行](https://github.com/mt4110/veil-tell/actions/runs/43410515308)

### 成果物の取得

実行ページの **Summary** で Action のジョブ要約を確認できます。**Artifacts** から `smoke-unchanged`、`smoke-new`、`smoke-volume` を取得します。各成果物には `summary.md` と `report.json` が入っています。macOS には3ケースすべて、Ubuntu には送信量超過ケースの `receiver.log` が入っています。

```bash
repo=mt4110/veil-tell
for platform in macos ubuntu; do
  case "$platform" in
    macos) run_id=43459261848 ;;
    ubuntu) run_id=43410515308 ;;
  esac
  gh run download "$run_id" --repo "$repo" --pattern 'smoke-*' --dir "reports/$platform"
done
```

### ジョブ要約・JSON・受信ログを照合する

| 成果物 | 終了コードと JSON | ジョブ要約 | 受信ログ |
| --- | --- | --- | --- |
| `smoke-unchanged` | `0`、`run_status.reason: completed`、`comparison.added` は空 | 新しい送り先・試み・送信量の異常なし | macOS は0接続・0バイト。Ubuntu はログ添付なし |
| `smoke-new` | `21`、`new_destination`、`comparison.added` に `new.test:443`、`destinations[].result: blocked` | `CONNECT` の行に宛先と `postinstall` の推定帰属 | macOS は0接続・0バイト。Ubuntu はログ添付なし |
| `smoke-volume` | `22`、`volume_limit_exceeded`、`volume_anomalies[].blocked: true` | `Volume anomaly` の行に `volume.test:443` と `postinstall` の推定帰属 | 送信を試みた524,288バイトのうち、両 OS とも131,072バイトで停止 |

`child_status.exit_code` は全ケースで `0` でした。veil-tell の終了コードは `run_status.exit_code` で確認します。検証ワークフローは `21` と `22` の Action ステップの失敗を捕捉して成果物をアップロードし、期待値との照合に成功したためジョブ全体は成功しています。

```bash
jq '{
  child_exit: .child_status.exit_code,
  run_status,
  added: (.comparison.added // []),
  results: [.destinations[] | {host, port, result}],
  volume: [.volume_anomalies[]? | {host, blocked, observed, limits, attribution}]
}' reports/*/smoke-*/report.json
```

送信量超過の `observed.sent_bytes` と `limits.max_connection_bytes` はどちらも `131072` です。両 OS の `receiver.log` で `received=131072` と一致することを確認できます。

## 9. image-drop-input の依存更新 PR で変更前の基準を確認する

検証用のドラフト PR #75 で `marked` を `18.1.3` から `18.2.0` に更新し、Ubuntu 26.04 の GitHub Actions で公開版 v0.4.0 の `uses: mt4110/veil-tell@v0` を実行しました。両ケースとも PR 側のロックファイルで隔離した `npm ci` を実行しました。 [PR #75](https://github.com/mt4110/image-drop-input/pull/75) · [実行結果](https://github.com/mt4110/image-drop-input/actions/runs/43460620667)

変更前のベースコミット `e39050e` の `.veil-tell/npm.json` には `registry.npmjs.org:443` だけが登録されています。PR 側のコミット `0fe60f4` の基準には対照用の `veil-tell-pr-control.test:443` も登録しました。それでも対照の CONNECT が拒否されたことを、Action が変更前の基準を使った証拠として確認しました。

### ジョブ要約と JSON を照合する

実行ページの **Summary** で両ケースの要約を確認できます。成果物には要約を保存した `normal-summary.md` と `control-summary.md`、各 JSON、ベース側の `base.json`、PR 側の `head.json`、両コミットの SHA を記録した `refs.txt` が入っています。 [検証成果物](https://github.com/mt4110/image-drop-input/actions/runs/43460620667/artifacts/14055089450)

```bash
gh run download 43460620667 --repo mt4110/image-drop-input \
  --name veil-tell-pr-evidence --dir pr75-evidence

cat pr75-evidence/refs.txt
jq '[.destinations[] | {host, port}]' pr75-evidence/{base,head}.json
jq '{
  child_exit: .child_status.exit_code,
  run_status,
  added: [.comparison.added[] | {host, port, attribution}],
  blocked: [.destinations[] | select(.result == "blocked") |
    {host, port, reason, result, sent_bytes}],
  lockfile_updates: [.comparison.lockfile_changes.updated[] |
    {name: .before.name, from: .before.version, to: .after.version}]
}' pr75-evidence/{normal,control}.json
```

| ケース | Action の終了コード | ジョブ要約と JSON |
| --- | --- | --- |
| 通常の `npm ci` | `0` | 新しい送り先・試み・送信量の異常なし。`normal.json` は `run_status.reason: completed`、`comparison.added` は空。 |
| `npm ci` 後に未登録 CONNECT | `21` | 要約の `CONNECT` 行に対照用の宛先が出る。実行ログは HTTP `403`、`control.json` は `run_status.reason: new_destination`、`destinations[].result: blocked`、`sent_bytes: 0`。 |

`child_status.exit_code` は両ケースで `0` です。検証ジョブは対照ステップの `21` を捕捉し、期待どおりの拒否を確認して成果物をアップロードしました。両 JSON の `comparison.lockfile_changes.updated` には `marked` の更新が記録されています。対照の要約に出る `marked@18.2.0` はロックファイル差分から挙げた変更候補です。CONNECT の帰属は `unknown` で、試行は検証用スクリプトが生成しました。

### 実行時の抜粋

PR をマージせずに閉じた後に再取得した成果物から、要約の該当行と JSON の該当フィールドを抜粋します。

```text
No new destinations, attempts or volume anomalies / 新しい送り先・試み・送信量の異常はありません
| <code>CONNECT</code> | <code>veil-tell-pr-control.test:443</code> | <code>—</code> | <code>—</code> | <code>—</code> | <code>unknown · lockfile candidates / 変更候補: marked@18.2.0</code> |
```

JSON は1行目が通常実行、2行目が対照です。

```jsonl
{"run_status":{"exit_code":0,"reason":"completed"},"comparison":{"added":[]}}
{"run_status":{"exit_code":21,"reason":"new_destination"},"destinations":[{"host":"veil-tell-pr-control.test","port":443,"result":"blocked","sent_bytes":0,"attribution":[{"confidence":"unknown"}]}]}
```
