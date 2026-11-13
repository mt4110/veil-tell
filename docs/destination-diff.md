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

## 依存更新 PR で使う

普段の `npm ci` と同じ条件で観測し、観測した宛先をレビューしてから `.veil-tell/npm-ci.json` を Git に追加します。

```sh
mkdir -p .veil-tell
veil-tell observe --baseline-out .veil-tell/npm-ci.json -- npm ci
git add .veil-tell/npm-ci.json
```

端末で `veil-tell ci -- npm ci` とだけ実行する場合は、先に `veil-tell npm ci` で同じ引数の既定基準を作成します。CI では引数のハッシュで特定した基準を使います。指定したファイルを使う場合は `veil-tell ci --baseline .veil-tell/npm-ci.json -- npm ci` です。Linux でユーザー領域に Node.js を導入している場合は、隔離内から見えるよう作業ディレクトリの下にランタイムを置いて PATH に加えます。

以下は Dependabot と Renovate を含む依存更新 PR を、通常の PR と同じ読み取り権限で検査する例です。veil-tell の Composite Action を公開した後は、利用側で `@v0` を使用できます。開発中は同じリポジトリの checkout に対して `uses: ./` で呼べます。

```yaml
name: Check npm destinations
on: pull_request
permissions:
  contents: read
jobs:
  destinations:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          fetch-depth: 0
          persist-credentials: false
      - uses: mt4110/veil-tell@v0
        id: veil
      - uses: actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9 # v7.0.2
        if: ${{ always() && steps.veil.outputs.report != '' }}
        with:
          name: veil-tell-report
          path: ${{ steps.veil.outputs.report }}
```

Action は PR のベースコミットから基準とロックファイルを読み、新規宛先と推定した npm の発信元をジョブ要約の表に表示します。通常の PR に含まれる基準の変更は、同じ PR の判定に使われません。必須チェックにする場合は、ワークフロー自体をベース側で管理してください。比較結果は v1 レポートの `comparison` に入り、`run_status` の `new_destination` と終了コード `21` で CI の失敗理由を確認できます。接続先の消失と大きな回数変化は表示されます。 [形式・判定条件](design.md#v030-宛先の差分チェック)
