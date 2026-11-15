# 宛先の差分チェック

ローカルの初回はリポジトリで `cargo install --locked --path .` を推奨します。リリース前のソースも同じ方法で試せます。隔離を使う Linux では、ランナーに非 setuid の bubblewrap と非特権ユーザー名前空間が必要です。 [Ubuntu の準備](runbook.md#ubuntu)

## 実際の npm postinstall で再現する

Rust と、`bin/node` と `bin/npm` を含む Node.js の配布ディレクトリを用意します。リポジトリのルートから実行します。

```sh
cargo build --locked --bins --examples
# NODE_ROOT に Node.js を展開した絶対パスを設定します。
# Homebrew の macOS では NODE_ROOT=$(brew --prefix node) も使えます。
if [ "$(uname -s)" = Linux ]; then
  VEIL_TELL_TEST_IP=$(ip -4 -o addr show scope global | awk 'NR == 1 {split($4, addr, "/"); print addr[1]}')
  test -n "$VEIL_TELL_TEST_IP"
  export VEIL_TELL_TEST_IP
fi
python3 -B tests/receivers.py target/debug/veil-tell target/debug/examples/receiver_cli "$NODE_ROOT"
```

試験は一時プロジェクトに [fixture](../tests/fixtures/destination-diff/) をコピーします。初回の `npm install` で基準を作成し、次に通信する `file:./postinstall` と通信しない `file:./quiet` の依存を追加します。追加したパッケージの `postinstall` は `postinstall.local:443` へ CONNECT を1回送ります。子プロセスはプロキシの `403` を受けて成功終了し、比較側は新規宛先を記録して `21` を返します。この名前は観測モードでも固定のローカル名制約で拒否され、外部の受信口を使いません。同じ fixture を `ci` でも実行し、基準にない宛先の拒否と終了コード `21` を確認します。別の受信側試験では、ローカル受信口で観測実行のペイロード1件と CI の拒否時0件を照合します。

macOS と Ubuntu で得た出力の抜粋です。通常 fixture では2つのパッケージの `postinstall` が動き、接続した一方だけが帰属に出ます。偽装 fixture は別パッケージ名を環境に設定して帰属用の付加情報を壊します。元のセッション資格情報は保持するため、CONNECT は記録され、帰属は `unknown` になります。

```text
postinstall.local:443 ← veil-tell-demo-postinstall@1.0.0 postinstall (postinstall) [inferred / 推定]
fixture os=darwin npm_exit=0 veil_tell_exit=21
fixture os=linux npm_exit=0 veil_tell_exit=21
spoof.local:443 ← unknown / 特定できません
fixture os=darwin spoof=unknown veil_tell_exit=21
fixture os=linux spoof=unknown veil_tell_exit=21
```

**記事用の一行**　テスト用の依存を追加したら、新規 CONNECT で CI が終了コード `21` を返し、`veil-tell-demo-postinstall@1.0.0` の `postinstall` が発信元の候補に出た。

## ロックファイルで裏づける

上と同じ受信側試験で npm の更新・無変更・帰属不明と、Cargo の `build.rs` とキャッシュ再実行を確認できます。両 OS の出力から抜粋します。

```text
postinstall.local:443 ← veil-tell-demo-postinstall@1.0.0 postinstall (postinstall) [inferred / 推定, lockfile: 0.9.0→1.0.0 / 裏づけあり]
postinstall.local:443 ← veil-tell-demo-postinstall@1.0.0 postinstall (postinstall) [inferred / 推定, lockfile: unchanged / 要注意]
spoof.local:443 ← unknown / 特定できません, lockfile candidates / 変更候補: veil-tell-demo-postinstall@0.9.0, veil-tell-demo-spoof@1.0.0
build-script.local:443 ← veil-build-probe@1.2.3 build.rs (build-probe) [inferred / 推定, lockfile: unchanged / 要注意]
fixture os=darwin cargo=build.rs exit=21 cached_connects=0
fixture os=linux cargo=build.rs exit=21 cached_connects=0
```

**npm の記事用の一行**　新規 CONNECT の帰属候補は `veil-tell-demo-postinstall@1.0.0`。ロック上でも `0.9.0 → 1.0.0` の更新と一致した。

**Cargo の記事用の一行**　新規 CONNECT の帰属候補は `veil-build-probe@1.2.3` の `build.rs`。同じ版のまま通信が増え、キャッシュ再実行では0件だった。

ロック上の版や integrity が同じでも、インストール後のファイルの差し替えや、環境変数・キャッシュなどをきっかけに動くコードはあり得ます。帰属情報自体も偽装できます。比較が示すのはプロキシで観測した宛先と依存記録の変化です。Cargo の proc-macro のように同一プロセス内に複数の実行主体がある場合は個別の帰属は得られません。 [方式と制約](design.md#ロックファイルと-cargo-の帰属)

## v0.4.0 の実測

macOS と Ubuntu で空の npm キャッシュから `is-number@7.0.0` を取得し、`registry.npmjs.org` を基準に記録しました。同じ `veil-tell npm install` を5回、`veil-tell npm install --offline` を1回実行して、承認待ちができないことを確認しました。その基準で `veil-tell ci -- npm ci` も終了コード `0` でした。

```text
veil-tell: No new destinations / 新しい送り先はありません
cold=registry.npmjs.org warm_repeats=5 approvals=0 offline=0 install_to_ci=0
```

依存更新の fixture は上記のロックファイル試験で再現できます。オプションによる帰属の有効化なしで、更新されたパッケージ名・版・スクリプトと終了コード `21` が出ます。

```text
veil-tell: new_destination (exit 21). Recorded HTTP CONNECT requests: 1. Direct connection attempts are outside the capture scope.
postinstall.local:443 ← veil-tell-demo-postinstall@1.0.0 postinstall (postinstall) [inferred / 推定, lockfile: 0.9.0→1.0.0 / 裏づけあり]
```

## 依存更新 PR で使う

ローカルで `veil-tell npm install` を実行し、`.veil-tell/npm.json` をレビューして Git に追加します。`npm install`、`npm i`、`npm ci` は同じ基準を使います。

```sh
veil-tell npm install
git add .veil-tell/npm.json
```

古いハッシュ名の基準がある場合は、同じ引数でローカル実行すると移行されます。別の引数で作った基準は内容をレビューし、`veil-tell migrate-baseline npm FILE` で移行します。指定ファイルを使う場合は `veil-tell ci --baseline FILE -- npm ci` です。Linux でユーザー領域に Node.js を導入している場合は、隔離内から見えるよう作業ディレクトリの下にランタイムを置いて PATH に加えます。

以下は Dependabot と Renovate を含む依存更新 PR を、通常の PR と同じ読み取り権限で検査する例です。veil-tell の Composite Action を公開した後は、利用側で `@v0` を使用できます。Action は対応ランナー用の配布アーカイブを取得し、展開前にリリースワークフローとタグの来歴を照合します。

```yaml
name: Check npm destinations
on: pull_request
permissions:
  contents: read
jobs:
  destinations:
    runs-on: ubuntu-26.04
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          fetch-depth: 0
          persist-credentials: false
      - run: |
          if ! test -x /usr/bin/bwrap; then
            sudo apt-get update
            sudo apt-get install -y bubblewrap
          fi
      - uses: mt4110/veil-tell@v0
        id: veil
      - uses: actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9 # v7.0.2
        if: ${{ always() && steps.veil.outputs.report != '' }}
        with:
          name: veil-tell-report
          path: ${{ steps.veil.outputs.report }}
```

Action は PR のベースコミットから基準とロックファイルを読み、新規宛先と推定した npm の発信元をジョブ要約の表に表示します。通常の PR に含まれる基準の変更は、同じ PR の判定に使われません。必須チェックにする場合は、ワークフロー自体をベース側で管理してください。比較結果は v1 レポートの `comparison` に入り、`run_status` の `new_destination` と終了コード `21` で CI の失敗理由を確認できます。既知の接続先が見えなかった場合はローカル出力にだけ短く示し、承認待ちを作りません。回数変化は JSON で確認できます。PR コメントは既定で無効です。必要な場合は Action に `pr-comment: true` とジョブに `pull-requests: write` を設定します。書き込み権限のない PR ではジョブ要約を使います。 [形式・判定条件](design.md#v030-宛先の差分チェック)

### Node.js のプロキシを使わない名前解決

`tests/receivers.py` の `dns_attempt_test` は、空の基準を作り、架空の npm スクリプトで `fetch` を実行する。JSON の `destinations` は空で、`comparison.attempted_added` に名前と推定帰属が入り、子の終了コード 0 に対して veil-tell は 21 を返す。

```text
veil-tell: attempted (blocked) / 名前解決を拒否: postinstall.invalid ← veil-dns-fixture@1.2.3 postinstall (.) [inferred / 推定]
```

同じ試験で 1,025 個の異なる名前を渡すと、1,024 件まで記録し、JSON の `coverage.dns_attempts` が `incomplete`、終了コードが 125 になる。

### 許可済みトンネルの送信上限

```text
veil-tell: volume anomaly / 送信量の異常: allowed.test:443 sent 131072/262144 bytes, connections 1/64, max connection 131072/131072 bytes ← veil-volume-fixture@1.2.3 postinstall (.), inferred / 推定
```

受信側試験では、同じローカル宛先に 524,288 バイトを送信した。`observe` では受信側に全量が届き、終了コード 0 と送信量の異常が記録された。`restrict` の明示上限では 8,192 バイト、基準を使う `ci` では1接続の下限にあたる 131,072 バイトで転送が止まり、子は 0、veil-tell は 22 になった。通常の npm install / ci を同じローカルレジストリで5回繰り返した試験では異常0件。npm の `postinstall` を送信元にした試験でも両OSで 131,072 バイトで止まり、推定帰属が出た。JSON の `volume_anomalies` では `blocked` と計測値・上限を確認できる。[しきい値と範囲](volume-limits.md)

### pnpm・Yarn・Bun の実測

pnpm 10.30.3、Yarn Berry 4.9.4、Yarn Classic 1.22.22、Bun 1.4.4 を使った。外部レジストリの代わりにローカル依存を追加する試験で、同じ構成の5回の実行に承認待ちはなく、CI は 0。更新側の Node.js `postinstall` では 21。pnpm と両 Yarn は推定帰属、Bun は unknown。

```text
veil-tell: attempted (blocked) / 名前解決を拒否: new-package.invalid ← probe@1.2.3 postinstall (node_modules/.pnpm/probe@file+dep/node_modules/probe) [inferred / 推定]
```

手元の再現には `tests/package_managers.py` に試す実行ファイルを渡す。Linux では Node.js と対象ツールの実行ファイルを同じランタイムディレクトリの `bin/` に用意する。試験がそのディレクトリをプロジェクトにコピーする。

```sh
cargo build --locked --bins --examples
python3 -B tests/package_managers.py target/debug/veil-tell "pnpm=$(command -v pnpm)" "yarn=$(command -v yarn)"
```

pnpm の同一ホストでの単発比較は、Ubuntu が対照 0.422 秒、隔離 0.450 秒（1.07 倍）、macOS が対照 0.320 秒、隔離 0.361 秒（1.13 倍）。同じローカル依存と空のプロジェクトキャッシュでの単発測定。レジストリを使う大規模プロジェクトの性能はこの値から判断できない。以前報告された70秒の失敗は元のプロジェクトと設定がなく、原因は特定できていない。

`pnpm install` が隔離内で失敗する場合は、pnpm・Node.js の実行ファイルが隔離内で見えること、ストアがプロジェクト内にあり再利用可能であること、プロジェクトの pnpm バージョン指定が事前に用意した実行ファイルと一致することを確認する。オフラインで未取得の依存がある場合は、明示的に使うレジストリとキャッシュ条件をそろえてから基準を作る。


### GitHub Action の公開後の検証

署名付き `v0.4.0` のタグで配布ワークフローを実行し、2つのアーカイブと `SHA256SUMS` を検証する。Release 公開後に `v0` の参照で README の例を起動する。配布バイナリの取得・来歴検証、PR ベース側からの基準読み込み、終了コード、要約と JSON を照合する。ローカルでは fixture を両OSで実行済み。GitHub 上の `@v0` と公開済みアーカイブを使う経路は未検証。

#### pnpm 12 の macOS TLS とバージョン別の回帰試験

macOS 27.2、pnpm 12.4.2、公開版 veil-tell 0.4.0 で、`is-number@7.0.0` を空のストアに入れた。失敗時の再試行を無効にすると、対照は 0.542 秒で成功し、隔離は 0.534 秒で exit 1。JSON にはレジストリへの許可済み CONNECT が1件残った。別の対照で `com.apple.trustd.agent` だけを Seatbelt で拒否すると、プロキシなしでも証明書検証が OSStatus -26276 で失敗した。12.4.2 の失敗には TLS のプラットフォーム検証が関与し、プロキシの設定を読めなかったという説明とは一致しない。

上流の [pnpm #15358](https://github.com/pnpm/pnpm/pull/15358) は、`trustd` が使えない場合に同梱の Mozilla CA へ切り替える。12.21.0 では同じ隔離のまま 0.888 秒で成功し、CONNECT 2件・終了コード 0 を確認した。12.4.x に該当する TLS エラーが出たら 12.21.0 以降を用意する。隔離の Mach 制限と TLS 検証を維持する。上流修正が入った最初のリリースの下限は、この測定では確認していない。

次はローカルのファイル依存を使った初回インストールの所要時間（対照 → 隔離、秒）。ツールの起動と計測環境による差を含む。

| pnpm | macOS 27.2 | Ubuntu 26.04.1 |
| --- | --- | --- |
| 9.15.9 | 0.283 → 0.332 | 0.427 → 0.462 |
| 10.34.9 | 0.236 → 0.289 | 0.454 → 0.504 |
| 12.21.0 | 0.096 → 0.146 | 0.040 → 0.084 |

両 OS で npm 11.20.0、上表の pnpm、Yarn Berry 4.18.1・Classic 1.22.22、Bun 1.4.4 を確認した。初回の隔離インストールでパッケージマネージャー別の基準を作成し、ロックファイル要約を読み取れた。5回の反復に承認待ち・送信量警告はなく、続く CI は 0。依存を差し替えた対照の Node.js `postinstall` は 21 で、npm・pnpm・両 Yarn では `probe@1.2.3 postinstall` と推定帰属した。Bun は名前解決の記録は残るが帰属は unknown。fixture のファイル依存を、公開パッケージの integrity が照合できる例としては扱わない。

### 0.5.0 の記事用デモ

`tests/package_managers.py` の pnpm 12.21.0 ケースはローカルの `file:` 依存を2版用意し、通常の反復、次いで `postinstall` からの新しい名前解決を試す。ソースをビルドして、実行ファイルの名前が `pnpm` になるように置いて実行する。

```sh
cargo build --locked --bins --examples
python3 -B tests/package_managers.py target/debug/veil-tell "pnpm=/path/to/pnpm"
```

macOS と Ubuntu では、ともに通常の隔離インストールから作った基準を、キャッシュあり・なしの各5回で再利用できた。承認待ちと送信量の警告は0件。対照では両 OS で次の行が出て、子は0、veil-tell は21になった。送信先は予約済みの `.invalid` 名で、Node.js のフックが名前解決を拒否した。

```text
veil-tell: attempted (blocked) / 名前解決を拒否: new-package.invalid ← probe@1.2.3 postinstall (node_modules/.pnpm/probe@file+dep/node_modules/probe) [inferred / 推定]
```

送信量の対照は `tests/receivers.py` で実行する。[受信側の手順](runbook.md#3-ローカル受信側の回帰試験)。両 OS の同じ fixture で、許可済み宛先に送ろうとした 524,288 バイトが、CI では 131,072 バイトで止まり、JSON と受信側が一致した。

```text
receiver case=volume-install-ci os=darwin bytes=131072 child=0 exit=22
receiver case=volume-install-ci os=linux bytes=131072 child=0 exit=22
```

### Action の検証範囲

[公開済み v0.4.0 の macOS 実行](https://github.com/mt4110/veil-tell/actions/runs/43459261848) と [Ubuntu 実行](https://github.com/mt4110/veil-tell/actions/runs/43410515308) は、公開タグの `uses: mt4110/veil-tell@v0` の証拠。0.5.0 の要約レンダラーは両 OS の受信テストが生成する JSON で確認した。変更したブランチは未 push で、公開タグの Action は引き続き 0.4.0 を取得する。0.5.0 の hosted runner 実測は、配布物と来歴が利用可能になってから記録する。
