# macOS の最小遮断実験

Linux と同じ Rust の CONNECT プロキシ、クライアント、受信側判定を使う。許可先、未登録先、プロキシはそれぞれ別ポートの IPv4 loopback で待ち受ける。合成トークンだけを送るため、外部ネットワークや DNS は使わない。

## 再現

macOS 上の一般ユーザーで、リポジトリのルートから実行する。

```sh
out=$(mktemp -d)
rustc --edition 2024 -D warnings experiments/linux-egress/main.rs -o "$out/veil-tell-lab"
"$out/veil-tell-lab" macos
```

隔離条件では `/usr/bin/sandbox-exec` で対象を起動し、その対象が起動した子プロセスに CONNECT または直接 TCP を試させる。試験プロファイルはネットワーク操作を拒否し、試験用プロキシの localhost IPv4/TCP ポートへの接続を許可する。宛先のホスト名はプロキシの固定ルールで判定する。

| 条件 | 期待する受信結果 |
| --- | --- |
| 制限なし | 未登録先に CONNECT と直接 TCP の両方で届く |
| 宛先ルールのみ | 未登録先には直接 TCP だけが届く |
| Seatbelt と宛先ルール | 許可先に CONNECT で届き、未登録先の接続受付は両経路ともゼロ |

`receiver` 行の各配列には、受付済みの接続ごとに受け取ったデータが入る。空配列は接続受付ゼロ。無効なプロファイルを渡し、子を起動する前に失敗することも確認する。

この最小実験で確認するのは、実行した macOS 上の IPv4 loopback での TCP。IPv6、UDP/DNS、IPC、継承 FD は別の試験項目。macOS の `sandbox-exec(1)` は非推奨と記載されているため、利用可否は OS バージョンごとに確認する。

## npm のライフサイクル試験

macOS 向け Node.js v24.12.0 と同梱の npm 11.6.2、`openssl`、`tar` を使う。リポジトリのルートから一般ユーザーで実行する。

```sh
/path/to/node-v24.12.0-darwin-arm64/bin/node experiments/linux-egress/npm.mjs macos
```

Linux と同じ試験用 HTTPS レジストリ、生成パッケージ、`postinstall`、受信側の判定を使う。各試行は別の空のキャッシュから開始し、証明書検証を有効にした状態で試験用証明書を npm に渡す。通常の依存パッケージの隔離付きインストールに加え、`postinstall` 付きの依存を制限なし・宛先ルールのみ・隔離付きの3条件でインストールする。

隔離条件では Seatbelt が npm とその子プロセスの外向き TCP を、試験用プロキシの localhost ポートに絞る。`registry` 行でメタデータと tarball の GET、`proxy` 行で宛先判定、`receiver` 行で未登録先の接続数と合成トークンを確認する。隔離下の直接 TCP は `EPERM` を期待する。試験はローカル HTTPS と IPv4 loopback を対象にする。

## IPv6・UDP/DNS・Unix ソケット・継承 FD の試験

macOS 上の一般ユーザーで Python 3 を使って実行する。Linux の追加経路試験と同じ送信コードと受信記録を使う。

```sh
python3 -B experiments/linux-egress/acceptance.py macos
```

- IPv6/TCP は `::1` の別ポートと、許可したプロキシと同じ番号のポートを試す。従来の `remote tcp` では同じ番号の IPv6 ポートに合成データが届く。最小試験と npm 試験のルールを `remote tcp4` に変更し、許可した IPv4/TCP と IPv6 側の受信記録を照合する。
- IPv4/UDP はプロキシと同じ番号のポート、DNS は一般ユーザーで待ち受けできる UDP ポートへの DNS A クエリを使う。macOS の実測環境では UDP/53 の bind が拒否されたため、DNS の試験は直接送信した DNS パケットに限る。
- ホスト IPC はファイルパス付き Unix ストリームソケットを試す。Mach/XPC やシステムリゾルバによる委譲は別の試験項目。
- 継承 FD は隔離外で接続した TCP ソケットを対象に渡すと、Seatbelt を掛けてもデータが届く。追加経路試験のランナーは、制限時に `close_fds=True` でその FD を引き継がせずに対象を起動する。親が開いた接続の受付は1件で、受信ペイロードは0バイトを期待する。

## 中継停止・CI 終了コード・JSON

npm のライフサイクル試験と同じコマンドで、通常の4試行に加えて3試行を実行する。Mac では監督プロセス自身が IPv4 loopback の CONNECT プロキシを待ち受け、隔離された npm を起動する。中継停止の試行では、tarball 取得後に `postinstall` から停止を要求し、待ち受けと既存接続を閉じた後に CONNECT と直接 TCP を試す。

| 試行 | 期待する結果 |
| --- | --- |
| `relay-stop` | CONNECT は `ECONNREFUSED`、直接 TCP は `EPERM`、未登録先の接続受付0件。npm は0、監督側は125 |
| `ci-unknown` | 未登録先への CONNECT は `403`、受信0件。npm は0、監督側は20。宛先判定理由は `unknown_destination` |
| `ci-known` | 同じ宛先を明示拒否する対照。CONNECT は `403`、受信0件。npm と監督側は0、宛先判定理由は `explicit_deny` |

試験ハーネスは監督プロセスの実際の終了コードと受信側の記録を、ログの `fixture_dir` 配下に生成される3件の JSON と照合する。`coverage.proxy` は CONNECT 要求を観測したこと、`coverage.direct_attempt_destinations` は直接 TCP の試行先を観測していないことを示す。中継停止時は `coverage.proxy_capture=until_relay_stopped` を記録する。
