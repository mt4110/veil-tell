# Linux の最小遮断実験

設計書の第12節に対応する試験。固定の CONNECT 要求と合成トークンを使い、二つの TCP 受信口で接続の受付とデータの到達を確認する。CONNECT の実装は試験に必要なアップロード方向の中継だけを扱う。

## 再現

Linux 上で、Rust 1.85 以降、非特権 user namespace を利用できる bubblewrap、util-linux の `unshare`、iproute2 の `ip`、coreutils の `timeout` が必要。試験用バイナリは、実行時ライブラリを sandbox に持ち込まないため静的リンクでビルドする。

```sh
cd experiments/linux-egress
out=$(mktemp -d)
rustc --edition 2024 -C target-feature=+crt-static main.rs -o "$out/veil-tell-lab"
sh run.sh "$out/veil-tell-lab" "$(command -v bwrap)"
```

`run.sh` は一般ユーザーで起動する。外部への経路がない試験専用のネットワーク名前空間を作り、その中で受信口と対照実行を動かす。隔離条件ではさらに bubblewrap のネットワーク名前空間にクライアントを入れる。中継の Unix socketpair は bubblewrap 内の中継プロセスに標準入出力として渡し、試験クライアントは別の標準入出力で起動する。

`receiver` 行の各配列は、受付済みの接続ごとに受け取ったデータを表す。空の配列は接続受付がゼロ。拒否された CONNECT では `resolve=false dial=false`、直通の失敗では `connect-attempt` と `connect-failed` が記録される。受信結果と終了状態の組み合わせが期待と異なった場合は試験全体が非ゼロで終了する。

## npm のライフサイクル試験

Node.js の Linux 向け配布物を展開し、同梱の npm を使う。下の例は Node.js v24.12.0（npm 11.6.2）の arm64 版。上記の Linux 用ツールに加え、試験用証明書とパッケージを生成する `openssl` と `tar`、対象を起動する `/usr/bin/python3` と `libseccomp.so.2` が必要。

```sh
cd experiments/linux-egress
sh run.sh /path/to/node-v24.12.0-linux-arm64/bin/node "$(command -v bwrap)" npm.mjs
```

毎回、外部への経路がない名前空間でローカル HTTPS レジストリと未登録先の TCP 受信口を作る。パッケージは二つ生成する。通常のパッケージにはスクリプトがなく、もう一方は依存パッケージの `postinstall` で CONNECT と直接 IPv4/TCP を順番に試す。試行ごとに新しいプロジェクトと空の npm キャッシュを使い、npm の証明書検証を有効にしたまま試験用証明書をその実行へ渡す。監査・寄付表示・更新確認は試験設定でオフにする。

通常パッケージの隔離付きインストールに加え、スクリプト入りの依存を制限なし・宛先ルールのみ・隔離付きの3条件でインストールする。`registry` 行はメタデータと tarball の実リクエスト、`proxy` 行は宛先判定、`receiver` 行は未登録先の接続受付数と受信トークンを示す。4回とも `npm install` の終了コードと展開ファイルを確認する。

この試験では、動的リンクの Node.js を bubblewrap 内で起動し、専用の Unix ソケットを介して試験用 CONNECT プロキシへつなぐ。中継から npm を起動する直前に、標準出力・標準エラーを匿名パイプにし、余分な FD を閉じてから対象専用の seccomp フィルターを適用する。検証範囲は npm の HTTPS 取得と、依存パッケージからの CONNECT・直接 IPv4/TCP。公開 npm レジストリとの互換性は別の検証項目。

## Linux の追加経路試験

同じ Linux VM で、試験用の名前空間に IPv6 アドレスを追加し、IPv6/TCP、IPv4/UDP、実際の DNS A クエリ（UDP/53）、ファイルパス付き Unix ストリームソケット、起動前に接続した TCP FD を試す。npm 試験と同じ `target.py` を隔離時の対象起動に使う。

```sh
cd experiments/linux-egress
sh run.sh /usr/bin/python3 "$(command -v bwrap)" acceptance.py
```

全経路で制限なしの対照を実行する。Unix ソケットと継承 FD は、追加で名前空間だけを適用した対照を実行する。Unix ソケットのファイルは隔離内からも参照できるようにして、seccomp で `socket(AF_UNIX, …)` が拒否されるかを確かめる。継承 FD は親が接続してから渡すため、受信側の接続受付は1件でも、合成データの受信が0バイトであることを確認する。

`receiver` 行に接続またはデータグラムの件数と受信バイト数を残す。受信した DNS クエリは16進表記で記録する。互換 ABI や代替 syscall を使った回避は別途確認する。

## 中継停止・CI 終了コード・JSON

「npm のライフサイクル試験」と同じコマンドで、上記4回に加えて次の3回を実行する。監督プロセスを独立して起動し、親の試験ハーネスが実際の終了コード、未登録側の受信記録、生成した JSON を照合する。

| 試行 | 注入またはポリシー | 期待する結果 |
| --- | --- | --- |
| `relay-stop` | tarball の取得後、`postinstall` と同期して隔離内の中継リスナーと既存接続を閉じる | CONNECT は `ECONNREFUSED`、明示的な直接 TCP の試行は `ENETUNREACH`。未登録側の接続受付0件。npm が0で終了しても監督側は125 |
| `ci-unknown` | 未登録 CONNECT を拒否し、`--fail-on-unknown` 相当の設定を有効にする | npm は0、監督側は20、受信0件。JSON の理由は `unknown_destination` |
| `ci-known` | 同じ宛先を明示拒否し、同じ CI 設定を適用する | npm と監督側はともに0、受信0件。JSON の宛先判定理由は `explicit_deny` |

JSON は `fixture_dir` の下の `relay-stop.json`、`ci-unknown.json`、`ci-known.json` に保存する。観測範囲は `coverage.proxy=http_connect_requests` と `coverage.direct_attempt_destinations=not_observed` で表す。中継停止時のレポートでは観測終了を示し、停止時の監督コードから npm の終了コードを推定せず、試験ログに npm の終了コードを別途記録する。この実験の CI 判定と JSON は試験ランナーのもので、製品 CLI や正式な JSON スキーマは別途実装する。
