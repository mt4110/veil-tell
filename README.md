# veil-tell

[English](README_EN.md)

## 使い方

```sh
cargo install --locked --path .
veil-tell npm install
veil-tell ci -- npm ci
```

依存更新 PR 用の例です。先に `.veil-tell/npm.json` をレビューしてコミットします。

```yaml
name: Check npm destinations
on: pull_request
permissions:
  contents: read
jobs:
  destinations:
    runs-on: ubuntu-26.04
    steps:
      - uses: actions/checkout@v7
        with:
          fetch-depth: 0
          persist-credentials: false
      - run: |
          if ! test -x /usr/bin/bwrap; then
            sudo apt-get update
            sudo apt-get install -y bubblewrap
          fi
      - uses: mt4110/veil-tell@v0
```

`@v0` は v0.4.0 の署名付き配布とタグの公開後に利用できます。 [移行・隔離・検証結果の読み方](docs/destination-diff.md)

対応する macOS と Linux で **sudo なし**で使える、**コマンド単位**の通信先チェックです。ローカルプロキシに届いた HTTP CONNECT を記録し、制限モードでは未登録の CONNECT を拒否して **CI を失敗**させられます。veil-tell 自体はテレメトリーを送りません。

## 実測デモで通信先を閉じてみる

macOS で Prompt Recipe の同じソースとロックファイルを使い、`registry.npmjs.org:443` の許可だけを切り替えました。

| 試したこと | `veil-tell verify` の判定 |
| --- | --- |
| 依存キャッシュありで `npm ci`、ビルド、テスト | **閉じても通る**。許可・拒否ともに19テスト成功 |
| 依存キャッシュありで `npm audit` | **閉じると失敗**。許可 → 拒否 → 再許可で `0 → 1 → 0` |
| 空のキャッシュで、拒否中に期限切れまたは中断 | **判定不能**。`timed_out` と `interrupted` を JSON で区別 |

[Prompt Recipe での再現手順と JSON の見方](docs/runbook.md#5-prompt-recipe-で-verify-を再現する)

**image-drop-input** でも、公開版 `v0.2.0` を macOS で使い、同じソース・ロックファイル・依存キャッシュから `registry.npmjs.org:443` の許可だけを切り替えました。ビルドとテストは**閉じても通り**、許可・拒否ともに216件成功しました。別に実行した `npm audit` は**閉じると失敗**し、許可・拒否・再許可で終了コードは `0 → 1 → 0` でした。 [比較条件と JSON の見方](docs/runbook.md#6-image-drop-input-で-verify-を再現する)

Ubuntu 26.04.1 LTS（`hp-ubuntu`）でも、公開版 `v0.2.0` を sudo なしで実行し、ビルドとテスト216件が許可・拒否の両方で通りました。単独の `npm audit` は拒否時だけ失敗しました。 [Ubuntu の隔離内で Node.js・npm を使う準備](docs/runbook.md#ubuntu-の隔離内で-nodejs-と-npm-を使う)

image-drop-input の GitHub Actions でも、作業ブランチと `--ref main` を検証しました。どちらも依存キャッシュありで、レジストリの許可時・拒否時にビルドが成功し、テストは各216件が通過しました。単独の `npm audit` は拒否時だけ失敗しました。監査ステップが終了コード `1` を返してジョブが失敗した後も、`workflow.json` と `audit.json` を回収できました。 [作業ブランチの実行結果](https://github.com/mt4110/image-drop-input/actions/runs/43370286803) · [main の実行結果](https://github.com/mt4110/image-drop-input/actions/runs/43375110063) · [手動実行と JSON の見方](docs/runbook.md#7-image-drop-input-の-github-actions-で-verify-を実行する)

## ビルドと実行

リポジトリで `cargo install --locked --path .` を実行します。以下は、公開 npm レジストリだけを許可して `is-number@7.0.0` を取得する例です。

デモの前に `veil-tell`、Node.js、npm が PATH にあることを確認します。Ubuntu では先に公式の `bubblewrap` を導入します。Nix の開発シェルで Ubuntu 公式の `/usr/bin/bwrap` を使う場合は `unset VEIL_TELL_BWRAP` を実行してください。 [Ubuntu の導入手順](#ubuntu-で隔離と終了コード-20-を試す)

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

宛先を調べるには `veil-tell COMMAND` を使います。直接通信を OS 側で制限しながら宛先を調べる場合は `veil-tell observe --backend isolated -- COMMAND` を使います。制限モードの TOML は DNS ホスト名とポート `443` の完全一致で判定します。明示的な拒否は `action = "deny"` で指定できます。

`--fail-on-unknown` は未登録の CONNECT を拒否し、子がエラーを握り潰して終了コード `0` を返しても、veil-tell は `20` を返します。明示拒否はトンネルを遮断し、このフラグによる終了コードの変更は発生しません。セットアップや記録のエラーでは `125` を返します。

`veil-tell observe --emit-policy FILE -- COMMAND` は、記録した CONNECT のホスト名とポートを重複なく並べ、全候補をコメント付きの保留として保存します。生成直後の TOML は有効なルールがゼロなので、そのまま `restrict --fail-on-unknown` に渡すと候補も未登録として拒否されます。レビュー済みの候補だけコメントを外してください。観測が中断・不完全だった場合やコマンドが失敗した場合は出力しません。既存ファイルは上書きせず、隔離時は `../state/report.json` のように、作業ディレクトリと同じ階層の別ディレクトリに出力します。作業ディレクトリ自体・その配下・その親階層は出力先ディレクトリに指定できません。

## 観測範囲と既知の弱点

- **ローカルプロキシに届いた HTTP CONNECT を記録します。** プロキシ方式では直接通信も可能で、その試行先は観測範囲外です。
- **隔離モードでは Node.js の名前解決の試みも記録します。** `coverage.dns_attempts` が `node_dns_lookup_hook` の場合に限ります。システムリゾルバや IP 直打ちの試みは範囲外です。[詳細](docs/dns-attempts.md)
- **隔離モードは OS 側で直接通信を制限します。** JSON v1 の `coverage.proxy = "http_connect_requests"` と `coverage.direct_attempt_destinations = "not_observed"` は両モードに共通です。OS が拒否した直接通信や IPC の詳細は JSON に記録されません。
- **許可したホスト経由の持ち出しは残ります。** 送信量を比較でき、CI または明示的な制限では上限超過でトンネルを閉じます。上限までのデータは届き得ます。 [送信量のしきい値と範囲](docs/volume-limits.md) たとえば、子プロセスが使える認証情報や公開アップロード機能を通じて、許可済みの GitHub や npm レジストリへ秘密情報を送れる場合があります。プロキシは TLS を終端せず、HTTP メソッド、URL パス、本文は観測・制御の範囲外です。ホストの許可は、そのホストへのトンネルを許可します。

LuLu・Little Snitch・OpenSnitch のホスト側制御、Firejail のプロセス隔離、mitmproxy の通信調査と用途が重なります。veil-tell では、起動したコマンドを単位として観測し、レビューしたポリシーをローカルと CI で使えます。 [先行例との比較](docs/design.md#8-先行例との関係)

## 隔離の動作条件

- **Linux** は非 setuid の bubblewrap と非特権 user namespace が必要です。既定のパスは `/usr/bin/bwrap` で、`VEIL_TELL_BWRAP` に信頼できる絶対パスを指定できます。作業ディレクトリは書き込み可能で、標準のランタイムディレクトリと Nix store は読み取り専用です。
- **macOS** は非推奨の `/usr/bin/sandbox-exec` を使います。外向きの IPv4/TCP は実行専用の localhost プロキシポートに限定し、名前付き Mach サービスの検索と登録を拒否します。macOS 27.2 arm64 の受信試験では `CFMessagePort` とアプリ同梱 XPC サービスの TCP 中継を確認しました。同じ環境で、`getaddrinfo()` の A・AAAA と `DNSServiceQueryRecord()` の TXT・KEY などをユニキャスト DNS で試し、隔離時は権威 DNS に届きませんでした。
- 隔離時は一時的なホーム、絞った環境変数、閉じた標準入力を使います。ポリシーとレポートは作業ディレクトリの外に置きます。レポートは実行ごとに未使用のパスを指定してください。

## Ubuntu で隔離と終了コード `20` を試す

Ubuntu 公式リポジトリから bubblewrap を導入します。導入には管理者権限が必要です。以降の `veil-tell` は一般ユーザーで実行します。Ubuntu 26.04.1 LTS x86_64 では、既存の AppArmor プロファイルが `/usr/bin/bwrap` に適用され、AppArmor と sysctl の設定を変更せずに動作しました。 [Ubuntu の AppArmor ドキュメント](https://documentation.ubuntu.com/security/security-features/privilege-restriction/apparmor/)

```sh
sudo apt install bubblewrap
```

`veil-tell` を上の手順でビルド・インストールし、`/usr/bin/curl` が使える状態で次を実行します。公開 npm レジストリからメタデータを取得して TOML を生成し、その TOML を編集せずに同じ宛先への接続を試します。

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

観測時は `HTTP 200` が表示され、TOML には `registry.npmjs.org:443` がコメント付きの候補として出ます。制限時はプロキシが CONNECT に `403` を返し、`veil-tell exit: 20` が表示されます。`restrict.json` の `isolation` は `applied`、宛先の `reason` は `unknown_destination`、`run_status.exit_code` は `20` です。

`bwrap` が起動時に `Operation not permitted` を返す場合は、`/usr/bin/bwrap` が Ubuntu 公式パッケージのもので、そのパスに既存の AppArmor プロファイルが適用されているかを確認してください。隔離の可否はホストの設定に依存します。

## 開発と受信側での検証

`nix develop path:.` で開発ツールを用意できます。Rust は `rust-toolchain.toml`、試験用の Node.js と開発タスクは mise で管理します。

```sh
cargo test --locked
cargo build --locked --examples --bins
python3 -B tests/receivers.py target/debug/veil-tell target/debug/examples/receiver_cli
```

Ubuntu で受信試験を実行するときは、ホストの IPv4 を `VEIL_TELL_TEST_IP` に指定します。 [受信試験の手順](docs/runbook.md#3-ローカル受信側の回帰試験)

最後に Node.js と npm の配布ディレクトリを渡すと、空のキャッシュを使うローカル HTTPS レジストリ試験も実行します。試験用の実行ファイルだけが `allowed.test` を試験受信口へ接続します。通常ビルドはシステムリゾルバを使い、接続先が公開アドレスかを検査します。

macOS の Mach/XPC 試験は、Xcode コマンドラインツールを用意し、`python3 -B tests/macos-ipc.py target/debug/veil-tell` で実行できます。受信ログと JSON が残ります。

[MIT ライセンス](LICENSE) · [脆弱性の報告](SECURITY.md) · [macOS・Ubuntu の再現手順](docs/runbook.md)

[設計書](docs/design.md) · [Linux の実験](experiments/linux-egress/README.md) · [macOS の実験](experiments/macos-egress/README.md)

## その他の CI とローカルフック

先に `.veil-tell/npm.json` をレビューしてコミットし、ランナーに veil-tell、Node.js と bubblewrap を用意します。

```yaml
# .gitlab-ci.yml
outbound:
  script:
    - veil-tell ci -- npm ci
```

`.git/hooks/pre-push` に次の内容を書き、`chmod +x .git/hooks/pre-push` で有効にします。`npm ci` は作業ツリーの依存を入れ直します。

```sh
#!/bin/sh
exec veil-tell ci -- npm ci
```

基準は通常の依存コマンドだけで自動作成します。ほかのコマンドで必要なときは `veil-tell --save-baseline COMMAND`。古いハッシュ名の候補は `veil-tell clean` で確認し、削除する場合は `veil-tell clean --apply` を使います。`--json` はレポートを標準出力、子の出力と案内を標準エラー出力に送ります。
