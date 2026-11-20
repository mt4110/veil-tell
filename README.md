# veil-tell

[English](README_EN.md)

## AI エージェントと使う

プロジェクトのシェルから、使う CLI を一つ選んで起動します。いつもの端末と認証環境を使えます。エージェントを終了したら、同じシェルで履歴を確認します。[Claude Code CLI](https://code.claude.com/docs/en/cli-reference) · [Codex CLI](https://developers.openai.com/codex/cli/) · [Cursor CLI](https://cursor.com/docs/cli/using)

```sh
veil-tell agent -- claude
# veil-tell agent -- codex
# veil-tell agent -- agent    # Cursor CLI
veil-tell log --today
```

`agent --` は隔離せず、HTTPS 環境プロキシを使うクライアントの CONNECT（443 番）を observe します。終了時のセッション行には、宛先へ送信したバイト数と接続回数が入ります。起動引数、プロンプト、認証ヘッダー、TLS の中身は保存しません。同じプロキシを継承した子プロセスの通信もこの行に含まれます。npm や curl など12個の shim は自動で PATH に入り、shim 経由のコマンドはそれぞれ別の行に記録されます。`veil-tell log --today --only-blocked` で拒否だけを確認できます。

直接接続、`NO_PROXY` 対象、独自のプロキシ設定、別プロセスで既に起動中の GUI はセッションの観測範囲外になり得ます。宛先が空なら、記録した CONNECT は 0 件です。上流がある場合は `http://` の CONNECT プロキシに対応します。

子コマンドに shim だけを設定するには、`eval "$(veil-tell agent-env --shell zsh)"` の後で `claude`、`codex`、`agent` のいずれかを起動します。エージェントのターミナルで `command -v npm` を実行すると参照先を確認できます。絶対パスやシェルの別名は shim を迂回する場合があります。

Claude Code の Bash ツールだけに設定する場合は、`SessionStart` の command hook に `veil-tell agent-env --shell bash >> "$CLAUDE_ENV_FILE"` を指定できます。[Claude Code の環境変数フック](https://code.claude.com/docs/en/hooks#persist-environment-variables)

### Codex 本体の通信（macOS 実測）

Codex CLI 0.155.1 がローカルの模擬 API に 1 ターン送信し、応答を受け取ったときの記録です。模擬 API は `POST /v1/responses` を 1 回受信しました。ほかの 3 ホストへの CONNECT はローカル上流で拒否され、各宛先への転送は 0 バイトでした。実アカウントや有償 API は使っていません。

```text
00:29:00  agent -- codex  exit 0
          ✓ allowed.test:443  ×1  39465 B  observe
          ! api.github.com:443  ×1  0 B  observe [connect_failed]
          ! chatgpt.com:443  ×2  0 B  observe [connect_failed]
          ! github.com:443  ×1  0 B  observe [connect_failed]
```

### npm install の通信（macOS・Linux 実測）

以下は両 OS のシェルで shim を使った実測です。Puppeteer 25.17.0 に対し、レジストリだけをレビューした基準で `CI=true` を指定しました。✓ は CONNECT の許可を示します。バイト数は TLS トンネルを通じて宛先へ送信した量です。拒否行の 0 B は転送量で、子が送ろうとした総量は分かりません。

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

対応シェルは `--shell bash|zsh|fish` です。fish では `veil-tell agent-env --shell fish | source`、単発の記録には `veil-tell --log COMMAND` を使えます。shim は既定で observe となり、プロジェクトに基準がある依存コマンドには既存の判定を適用します。`veil-tell log --since 2h --only-new --json` は新規宛先の JSON Lines、`veil-tell version` はバージョンを表示します。

veil-tell 自体はテレメトリーを送りません。履歴はローカルの `$XDG_STATE_HOME/veil-tell/log` に保存します。状態ディレクトリの既定値は Linux で `~/.local/state`、macOS で `~/Library/Application Support` です。URL のパス・クエリや既知の資格情報引数は伏せます。自由形式の引数には機密情報が残り得ます。`VEIL_TELL_LOG=off` で履歴を無効にできます。保存期間は30日、1日あたり10 MiBまでです。

### プロキシ・キャッシュでよくある失敗

- Node.js の `fetch` と `https.get` は 22 系では 22.21 から、24 系では 24.5 から両方が環境プロキシに対応します。独自のクライアントエージェントは別の経路を選べます。[Node.js のプロキシ対応](https://nodejs.org/learn/http/enterprise-network-configuration)
- DNS の解決先がすべて 198.18.0.0/15 なら fake-IP の可能性があります。信頼する TUN 環境だけで `VEIL_TELL_ALLOW_FAKE_IP=1` を指定してください。混在・ローカル宛先は引き続き拒否します。
- `HTTPS_PROXY` または `https_proxy` が HTTP プロキシなら、許可した CONNECT をそこへ中継します。この経路の名前解決・接続先アドレス検査は上流側が担います。接続先 IP が不明でも、成立したトンネルは通信量の基準と CI の判定に含まれます。`NO_PROXY` はホスト名・ドメイン接尾辞・任意の `:443`・`*` に対応します。
- macOS の隔離中に `curl: (60) ... unable to get local issuer certificate` が出たら、その宛先の証明書チェーンを検証できる、信頼済みの CA バンドルを `curl --cacert /path/to/ca-bundle.pem` で指定してください。CONNECT が許可された後でも、TLS の証明書検証は失敗することがあります。
- `VEIL_TELL_CACHE=persistent` で、隔離内に専用の `~/.cache/veil-tell/<manager>` を用意します。キャッシュ命中で消えた宛先は情報扱いです。pnpm は従来のプロジェクトストア設定も使います。
- 一時ホームで npm・pnpm・Yarn が失敗したときは、そこにある既知のログを合計 1 MiB まで調べます。マネージャー名、検出した既知のエラーコードと説明、npm の既知のシステムコール名だけを `.veil-tell/logs/<日時>-<識別子>/manager.log` に保存し、パスを表示します。たとえば `ENOENT` と `syscall: open` で、ファイルを開く際のエラーを確認できます。パスや引数を含むログ本文はコピーしません。プロジェクトの `.gitignore` に `/.veil-tell/logs/` と `/.veil-tell/pending.json` を追加してください。

## 使い方

```sh
cargo install --locked --path .
veil-tell npm install
veil-tell ci -- npm ci
```

GitHub Actions で依存更新を検査する場合は、[npm 用テンプレート](examples/github-actions/veil-tell-npm.yml) を自分のリポジトリの `.github/workflows/veil-tell-npm.yml` にコピーします。既定ブランチで **Check npm destinations** を手動実行し、成果物の `npm.json` をレビューして `.veil-tell/npm.json` としてコミットします。次の依存更新 PR から、変更前の基準で `npm ci` を検査します。GitHub 上での導入にローカルの veil-tell は不要です。 [導入手順](docs/runbook.md#10-npm-の依存更新-pr-に導入する)

### CI で新しい宛先が見つかったら

プロジェクトの基準を使う `veil-tell ci -- npm ci` または `CI=true veil-tell npm ci` が新規 CONNECT や名前解決の試みで `21` を返すと、`.veil-tell/pending.json` に承認候補を保存します。出力された宛先と用途を確認し、承認する場合は同じプロジェクトのルートで実行します。

```sh
veil-tell accept
git diff -- .veil-tell/npm.json
veil-tell ci -- npm ci
```

レビュー済みの基準をコミットし、`.veil-tell/pending.json` は Git 管理から除外します。GitHub Action や `ci --baseline FILE` の結果を承認する場合は、同じ依存関係と比較元の基準を用意したローカル環境で、上のプロジェクト基準を使う手順を実行してください。

### インストール時にホームへ置くファイルを残す

隔離中のホームは既定で一時ディレクトリです。ブラウザーなどを後から使うプロジェクトでは、`VEIL_TELL_PROJECT_HOME` にプロジェクト内の相対パスを指定すると、隔離の終了後もダウンロードを使えます。例えば、Puppeteer を依存に含むプロジェクトのルートで実行します。

```sh
VEIL_TELL_PROJECT_HOME=.veil-home veil-tell npm ci
PUPPETEER_CACHE_DIR="$PWD/.veil-home/.cache/puppeteer" node app.js
```

`.veil-home/` は Git 管理から外します。アプリから別のホームが必要な場合は、実行時に `HOME="$PWD/.veil-home"` を指定できます。Puppeteer がブラウザーの取得に `proxy-agent` を必要とするバージョンでは、対応するバージョンを依存に追加してください。Linux 環境で `unzip` がない場合は、Puppeteer が対応する `yauzl` で展開できます。使用する npm や pnpm がインストールスクリプトを承認制にしている場合は、Puppeteer のスクリプトをレビューして許可します。[Puppeteer の設定](https://pptr.dev/guides/configuration)

### 公開版 v0.4.0 の GitHub Actions 実測

`uses: mt4110/veil-tell@v0` を macOS 26 と Ubuntu 26.04 で実行し、**変更なしは `0`、新規宛先の拒否は `21`、送信量超過による切断は `22`** を確認しました。両 OS で、送信量超過時は受信ログと JSON が **131,072 バイト**で一致しました。 [macOS の実行](https://github.com/mt4110/veil-tell/actions/runs/43459261848) · [Ubuntu の実行](https://github.com/mt4110/veil-tell/actions/runs/43410515308) · [ジョブ要約・JSON・受信ログの読み方](docs/runbook.md#8-公開版-v040-の-github-actions-実測)

npm 向け導入テンプレートも GitHub Actions の Ubuntu 26.04 で検証しました。手動実行で採取した `registry.npmjs.org:443` の基準候補をレビューし、PR の比較元に保存しました。通常の `npm ci` は **`0`**。未登録 CONNECT を加えると HTTP `403` で拒否され、npm が `0` でも veil-tell は **`21`** でジョブを失敗させ、JSON を残しました。 [検証用 PR #3](https://github.com/mt4110/veil-tell/pull/3) · [基準候補](https://github.com/mt4110/veil-tell/actions/runs/43609198515#summary-132490298343) · [通常実行](https://github.com/mt4110/veil-tell/actions/runs/43609277174#summary-132490539684) · [未登録 CONNECT](https://github.com/mt4110/veil-tell/actions/runs/43609366175#summary-132490812999) · [手順と JSON の読み方](docs/runbook.md#github-actions-での実測と-json-の見方)

image-drop-input でも、`marked` を `18.1.3` から `18.2.0` に更新する PR で導入テンプレートを検証しました。手動で取得・レビューした基準を使い、通常の `npm ci` は **`0`**、未登録 CONNECT は HTTP `403` で拒否され veil-tell は **`21`**。失敗したジョブからも JSON を取得できました。 [検証用 PR #76](https://github.com/mt4110/image-drop-input/pull/76) · [基準候補](https://github.com/mt4110/image-drop-input/actions/runs/43687747113#summary-132731680845) · [通常実行](https://github.com/mt4110/image-drop-input/actions/runs/43687817268#summary-132731890786) · [未登録 CONNECT](https://github.com/mt4110/image-drop-input/actions/runs/43687870837#summary-132732049536) · [レビュー手順と JSON の見方](docs/runbook.md#image-drop-input-の依存更新-pr-76-での実測)

image-drop-input の依存更新 PR #75 では、PR 側の基準に対照用の宛先を追加しても、Action は変更前の基準を使いました。通常の `npm ci` は **`0`**、未登録 CONNECT を加えた対照は HTTP `403` で拒否され **`21`** でした。 [PR #75](https://github.com/mt4110/image-drop-input/pull/75) · [実行結果](https://github.com/mt4110/image-drop-input/actions/runs/43460620667) · [ジョブ要約と JSON の読み方](docs/runbook.md#9-image-drop-input-の依存更新-pr-で変更前の基準を確認する)

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
- **隔離モードは OS 側で直接通信を制限します。** Linux では seccomp 通知が使えると `coverage.direct_attempt_destinations = "ip_port"` になります。未対応なら `not_observed`、記録上限到達時は `incomplete` を返します。
- **許可したホスト経由の持ち出しは残ります。** 送信量を比較でき、CI または明示的な制限では上限超過でトンネルを閉じます。上限までのデータは届き得ます。 [送信量のしきい値と範囲](docs/volume-limits.md) たとえば、子プロセスが使える認証情報や公開アップロード機能を通じて、許可済みの GitHub や npm レジストリへ秘密情報を送れる場合があります。プロキシは TLS を終端せず、HTTP メソッド、URL パス、本文は観測・制御の範囲外です。ホストの許可は、そのホストへのトンネルを許可します。

| 隔離中の観測 | Linux | macOS |
| --- | --- | --- |
| プロキシに届く HTTP CONNECT | ホスト名とポート | ホスト名とポート |
| 対応する Node.js の名前解決 | ホスト名を記録して拒否 | ホスト名を記録して拒否 |
| curl・Python・Go・Rust のシステムリゾルバ、IP 直打ち | 通知時は IP・ポート・件数。DNS 質問名は未観測 | 直接通信の試行先・件数は未観測 |

`CI=true veil-tell npm install` は隔離と既存の基準を使い、新規 CONNECT や観測できた新規名前解決の試行で `21` を返します。ローカルの短い形式は観測した試行だけを理由に失敗させません。明示的な `observe --baseline FILE` は送信量の異常を記録して `21` を返し、制限による切断は `22` を返します。少量ずつの送信や実行をまたぐ累計は比較範囲外です。

Corepack を使う場合は、先にプロジェクトのルートで `corepack install` を実行して `packageManager` の pnpm を取得します。その後は `veil-tell pnpm install` と `veil-tell corepack pnpm install` がキャッシュ済みの実行ファイルを使います。pnpm をホームに入れた場合は、インストール済みの実行ファイルと Node.js が PATH から見えるようにします。

macOS の隔離で pnpm 12.4.x の TLS 検証エラーが出る場合は、実測で通った pnpm 12.21.0 以降を使ってください。[原因と実測](docs/destination-diff.md#pnpm-12-の-macos-tls-とバージョン別の回帰試験)

隔離した pnpm と素の pnpm を同じ作業ディレクトリで使うには、`pnpm-workspace.yaml` に `storeDir: .pnpm-store` を設定します。pnpm 9 は `.npmrc` にも `store-dir=.pnpm-store` を設定してください。[設定と復旧手順](docs/runbook.md#11-pnpm-のストアを隔離内外でそろえる)

LuLu・Little Snitch・OpenSnitch のホスト側制御、Firejail のプロセス隔離、mitmproxy の通信調査と用途が重なります。veil-tell では、起動したコマンドを単位として観測し、レビューしたポリシーをローカルと CI で使えます。 [先行例との比較](docs/design.md#8-先行例との関係)

## 隔離の動作条件

- **Linux** は非 setuid の bubblewrap と非特権 user namespace が必要です。既定のパスは `/usr/bin/bwrap` で、`VEIL_TELL_BWRAP` に信頼できる絶対パスを指定できます。作業ディレクトリは書き込み可能で、標準のランタイムディレクトリと Nix store は読み取り専用です。
- **macOS** は非推奨の `/usr/bin/sandbox-exec` を使います。外向きの IPv4/TCP は実行専用の localhost プロキシポートに限定し、名前付き Mach サービスの検索と登録を拒否します。macOS 27.2 arm64 の受信試験では `CFMessagePort` とアプリ同梱 XPC サービスの TCP 中継を確認しました。同じ環境で、`getaddrinfo()` の A・AAAA と `DNSServiceQueryRecord()` の TXT・KEY などをユニキャスト DNS で試し、隔離時は権威 DNS に届きませんでした。
- 隔離時は一時的なホームと絞った環境変数を使います。標準入力は通常閉じますが、`agent-env` や `agent --` の shim は呼び出し元の入力を渡すので、`curl --config -` などにパイプできます。Linux の隔離では、読み取り専用で渡す通常ファイルに有効なパスが必要です。子は読み取り専用マウントで必要な分を読み、終了時にシェルの読み取り位置を更新します。実行中は同じ入力を別のプロセスから操作しないでください。端末からの入力はバイト列として渡します。ポリシーとレポートは作業ディレクトリの外に置きます。レポートは実行ごとに未使用のパスを指定してください。

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
