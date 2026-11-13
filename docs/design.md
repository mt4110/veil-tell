# veil-tell 初期設計

現在の最小実装の利用手順と検証範囲は [README](../README.md) を参照。この文書は初期設計と実験の判断基準を記録する。

## 1. 製品の境界

veil-tell は、開発者が指定したコマンドを実行し、その実行で見えた送信先を一覧にして、許可する接続を自分で決めるための CLI。最初に検証する利用場面は `npm install` と、別ホストへテレメトリーを送る CLI。観測とルール適用は macOS と Linux で共通にし、直接通信の遮断を伴う実行はまず対応 Linux に限定する。

製品としての最終ゴールは、依存パッケージのインストール、ビルド、開発 CLI に必要な外向き通信を実行単位で確認し、レビューしたルールで次回の実行や CI を制限できること。macOS と Linux は OS 別のバイナリとして配布し、コマンド名・引数、TOML のルール形式と判定の意味、JSON のスキーマを共通にする。OS ごとの実行方式と観測範囲は `doctor` とレポートで確認できるようにする。隔離を指定した環境でその方式を使えない場合は、理由を示して対象コマンドの起動前にエラーを返す。

| 実行方式 | 見えるもの | 止められるもの |
| --- | --- | --- |
| `proxy`（macOS / Linux） | ローカルプロキシに届いた CONNECT の要求先、接続結果、転送量 | そのプロキシに届いた要求。コマンドが選んだ直接通信は観測範囲外 |
| `isolated`（対応 Linux） | 同じプロキシの記録。ネットワーク隔離が有効だったことを報告 | 対象プロセスツリーからの直接 IP 通信を OS で制限し、外向き接続はプロキシの判定を経由させる。直接通信の試行先一覧は取得しない |

どちらも実行時に sudo を要求しない。設定・判定・レポートはローカルで処理し、veil-tell 自体のテレメトリーや更新確認は設けない。宛先の名前解決にはホストの設定済みリゾルバを使うため、接続に必要な DNS 問い合わせは環境の DNS 経路に出る。アプリケーションの TLS はクライアントと接続先の間で維持する。

## 2. 利用手順

```sh
# プロジェクト外に、ポリシーとレポートを置く領域を用意
state_dir="$HOME/.local/state/veil-tell"
mkdir -p -m 700 "$state_dir"

# 短縮形。プロキシ経由の新しい送信先を表示し、終了時に集計
veil-tell npm install

# 学習。見えた送信先をローカルのレポートに残す
veil-tell observe --report "$state_dir/npm-first.json" -- npm install

# 直接通信も隔離して同じ条件で学習する場合（対応 Linux）
veil-tell observe --backend isolated --report "$state_dir/npm-isolated.json" -- npm install

# 確認した送信先を npm-install.toml に記入した後、未登録先を拒否
veil-tell restrict --backend isolated --policy "$state_dir/npm-install.toml" -- npm install

# macOS で、未登録先がプロキシに届いた時に対話で決定
veil-tell restrict --backend proxy --policy "$state_dir/npm-install.toml" --ask -- npm install

# 対応 Linux の CI。未登録のプロキシ要求をジョブの失敗にする
veil-tell restrict --backend isolated --policy "$state_dir/npm-install.toml" \
  --fail-on-unknown --report "$state_dir/egress.json" -- npm ci
```

- `observe` は宛先ルールを適用せず、対応する公開宛先の要求を通す。内部 IP への中継を避ける固定の制約は両モードに適用する。学習は実通信を伴う。収集した宛先は承認候補であり、自動で許可に昇格させない。短縮形は毎回 `observe --backend proxy`。制限時は適用範囲を意識して選べるように `--backend` を必須にする。
- `restrict` は登録済み許可だけを通す。明示拒否は即時に拒否し、未知の要求は既定で拒否する。`--ask` を指定した場合だけ、未知の宛先への接続前に「今回の実行だけ許可」「拒否」「許可を保存」「拒否を保存」から選ぶ。同じ宛先への並行要求は一つの確認にまとめる。入力なし・タイムアウトは拒否。`--ask` と `--fail-on-unknown` は同時指定不可。
- 保存済みの拒否は、監査上も未知の宛先と区別する。テレメトリー用ホストを拒否しつつ本体のホストを許可できる。本体が拒否後も動作するかは対象 CLI のエラー処理に依存する。

## 3. 捕捉方式の比較

| 方式 | sudo なしで使える条件と観測 | 設計上の判断 |
| --- | --- | --- |
| プロキシ環境変数 | クライアントが設定を尊重する場合に、要求先のホストとポートを接続前に判定できる。継承した子プロセスも同じ入口を使える | 両 OS の共通入口に採用。直接ソケット、プロキシの再設定、環境変数を消す子、既存デーモンへの委譲を捕捉できない。[npm 設定](https://docs.npmjs.com/cli/v11/using-npm/config/#https-proxy) · [pip CLI](https://pip.pypa.io/en/stable/cli/pip/) · [Cargo 設定](https://doc.rust-lang.org/cargo/reference/config.html#httpproxy) |
| `LD_PRELOAD` / `DYLD_INSERT_LIBRARIES` | 注入が許された動的リンク対象で `connect` などをフックできる。呼び出しの時点では宛先が IP だけの場合もある | 採用しない。静的リンク、直接システムコール、セキュア実行、macOS の SIP・Hardened Runtime などでカバレッジが変わる。[Linux 動的リンカ](https://www.man7.org/linux/man-pages/man8/ld-linux.8.html) · [Apple SIP の実行時保護](https://developer.apple.com/library/archive/documentation/Security/Conceptual/System_Integrity_Protection_Guide/RuntimeProtections/RuntimeProtections.html) · [Hardened Runtime](https://developer.apple.com/documentation/security/hardened-runtime) |
| Linux の user / network namespace ＋プロキシ | 非特権 user namespace が使えれば、対象の IPv4・IPv6 をホストと分離できる。外向き経路のない namespace では、静的バイナリも同じ制約を受ける | 隔離付き MVP に採用する設計。bubblewrap を使い、外部に接続できるのはホスト側プロキシだけにする。ディストリビューションや CI の制限で使えない環境がある。[user namespaces](https://man7.org/linux/man-pages/man7/user_namespaces.7.html) · [network namespaces](https://man7.org/linux/man-pages/man7/network_namespaces.7.html) · [bubblewrap](https://github.com/containers/bubblewrap) |
| Linux の ptrace / seccomp / Landlock | 自分が起動したプロセスの追跡や、継承されるカーネル制限に使える。Landlock のポートルールはホスト名のポリシーを表現しない。利用可能な機能はカーネル ABI や環境に依存する | ptrace は直接通信の調査候補。seccomp は隔離時のシステムコール制限に利用する。通知で読んだ `sockaddr` を判定し、対象の元のシステムコールをそのまま継続させる方式は、並行書き換えの競合があるため採らない。[ptrace](https://man7.org/linux/man-pages/man2/ptrace.2.html) · [seccomp user notification](https://man7.org/linux/man-pages/man2/seccomp_unotify.2.html#NOTES) · [Landlock](https://www.kernel.org/doc/html/latest/userspace-api/landlock.html) |
| macOS Seatbelt / `sandbox-exec` | 非特権 CLI に隔離を掛け、プロキシ経由だけを通す先行実装がある。ツールが非推奨で、対応 OS・プロファイルの継続性を検証する必要がある | macOS の隔離候補。初期 MVP の依存には入れない。既存実装を比較し、OS ごとの直接通信・DNS・IPC の試験結果で採否を決める。[Anthropic Sandbox Runtime](https://github.com/anthropics/sandbox-runtime) · [Apple リポジトリ上の非推奨に関する議論](https://github.com/apple/containerization/issues/737) |
| macOS Network Extension / Linux ホスト側フィルター | プロキシ非対応の通信も OS 側で扱える。macOS のシステム拡張方式には entitlement・署名・有効化が関わる。Linux のシステム側フックも実行環境の権限や導入手順に依存する | 初期の単発 CLI に組み込まない。ホスト全体に導入する構成を検討する段階で比較する。[Apple TN3134](https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment) · [OpenSnitch の権限要件](https://github.com/evilsocket/opensnitch/wiki/Compilation) |

## 4. 実行と判定の構成

```text
proxy     コマンドとその子 ── HTTP CONNECT ──▶ ローカルプロキシ ── TCP ──▶ 宛先

isolated  [ コマンドとその子 ── loopback ──▶ 中継 ] ── Unix IPC ──▶ ホスト側プロキシ ── TCP ──▶ 宛先
          [       外向きインターフェース・経路を持たない Linux network namespace        ]
```

### 共通のランナーとプロキシ

1. 指定した argv をシェルで再解釈せずに起動する。起動前にポリシーを検証し、セッション専用のランダムポートで loopback のみにプロキシを開く。プロキシ URL にセッション認証を付け、起動したプロセスの環境へ渡す。他セッションからの誤利用を抑えるための認証であり、起動したプロセスには URL が見える。対応クライアントが認証付き URL を扱えるかは実機試験で確認する。
2. 起動環境内の競合する `HTTP_PROXY` / `HTTPS_PROXY`（大小文字）や `ALL_PROXY`、`NO_PROXY` を整理し、npm 用の設定も明示する。ユーザーやシステムの設定ファイルは書き換えない。npm の引数や別のクライアント設定が優先される場合があるので、実行中に見えた要求だけを報告する。pip と Cargo の対応表は追加検証後に記載する。
3. MVP の中継は HTTP/1.1 CONNECT、宛先ポートは 443。CONNECT の authority を厳密に解析し、認証とルールを適用する。拒否した要求のホストを解決せず、外向きソケットも開かない。許可後にホスト側で名前解決し、候補アドレスを検査して、検査した IP に直接接続する。再試行や IPv4 / IPv6 の切り替えも検査済み候補に限る。
4. IP リテラル、ローカル用の名前、特殊用途 IP、ホスト自身のアドレスは初期版の中継対象から外す。IPv4-mapped IPv6 も正規化して検査する。名前が内部向けアドレスを返した場合も拒否する。権限のあるローカルサービスやメタデータサービスへの中継と、DNS リバインディングによる検査のすり抜けを抑えるための制約。社内レジストリ、VPN 内の宛先、上流の企業プロキシは初期対応外。[RFC 9110 §9.3.6](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.6) · [IANA IPv4 特殊用途アドレス](https://www.iana.org/assignments/iana-ipv4-special-registry/) · [IANA IPv6 特殊用途アドレス](https://www.iana.org/assignments/iana-ipv6-special-registry/)
5. 接続確立後はバイト列を解釈せずに中継する。通常の HTTPS ではこのバイト列が TLS ストリームになる。送信バイト数はプロキシから上流ソケットに書けた量であり、相手アプリケーションでの受信・保存は判定できない。ヘッダサイズ、同時接続数、入力待ち・名前解決・接続・アイドル時間には上限を設ける。終了や割り込みで待機中の要求を閉じ、制御下の子とプロキシを終了させる。`proxy` で離脱した子の直接通信は残り得る。

### Linux の隔離

- bubblewrap で user・network・PID・mount namespace を設定する。ネットワークは loopback のみ。起動に必要なランタイムを読み取り専用で渡し、書き込み可能なプロジェクトとセッション用一時領域を渡す。ホストのホーム、`/run`、デバイス、既存ソケットを一括で渡さない。隔離を作るヘルパーは対象プロジェクトから探索せず、信頼するパス・環境で起動する。namespace 内の管理権限は対象に渡さず、プロキシ・中継を含む必須構成が立ち上がってから対象を起動する。
- 信頼する中継プロセスだけが、namespace をまたぐ専用の Unix IPC を使える構成にする。中継はバイト列を決まったプロキシ入口に運ぶ。宛先選択と判定はホスト側プロキシに集約する。ソケットなどの余分な FD は対象へ継承させず、隔離時の標準入出力も監督側が用意するパイプを経由させる。
- ファイルパス付き Unix ソケットは network namespace だけでは隔離できない。対象に適用する seccomp では外部の Unix ソケットにつながる入口を閉じる。ランタイムの子プロセス用に、外部と接続できない `socketpair` は許す。互換 ABI や `io_uring` 経由で制限を回避できないこと、対象が中継をトレース・改変できないことを確認する。TTY が必要な任意の CLI への対応は別途検討する。[network namespaces](https://man7.org/linux/man-pages/man7/network_namespaces.7.html) · [Linux seccomp](https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html)
- 隔離に必要な機能がない、起動確認で中継が到達不能、または必須の制限を適用できない場合は対象を起動しない。起動後にプロキシが停止したら実行を失敗にし、隔離を外して続行しない。`doctor` で利用できる方式と失敗理由を表示する。利用者にカーネル設定の緩和を要求しない。

## 5. ルールとレポート

ルールは TOML。v1 は 1 ファイルを 1 プロファイルとして明示指定する。ファイルは実行する側が選び、作業ディレクトリから自動採用しない。ルールは対象の実行とその子に共通で、実行ファイルの認証やパッケージ単位の識別は行わない。

```toml
version = 1
profile = "npm-install"

[[rule]]
action = "allow"
host = "registry.npmjs.org"
port = 443

[[rule]]
action = "deny"
host = "telemetry.example.com"
port = 443
```

- マッチ単位は正規化した DNS ホスト名とポートの完全一致。大文字小文字と末尾ドットを正規化し、国際化名は ASCII の A-label で記述する。ワイルドカード、IP/CIDR、逆引き、URL パス、正規表現、ルールのマージは v1 に含めない。未知のキー・バージョン、無効な値、重複した宛先は起動前エラー。CONNECT が提示した名前がルールの照合対象であり、TLS 内で使われるサービスの身元を表す保証はない。
- 判定は固定の宛先制約、明示ルール、実行中に選んだ許可・拒否、未知の既定動作の順。名前解決後の IP 制約も適用する。制限モードではポリシーを起動時に読み込み、実行中は親プロセスが明示的に承認した変更だけを取り込む。対話での永続化はユーザーの管理領域にあるポリシーを対象にし、同一ディレクトリでの原子的な置換とロックで並行更新を扱う。読み込んだ後に別実行が更新した場合は変更を上書きせず、永続化した許可は書き込み成功後に適用する。
- 子の標準出力・標準エラーは子の出力として扱い、一覧・対話はランナー側で表示する。対話端末では新しい宛先を最初に見たときに表示し、終了時に集計する。`--ask` では子の出力をパイプで受けて端末制御文字を無害化し、確認中は表示を止める。対話の入力は子の stdin と共用しない。機械向け JSON は明示したファイルへ出力する。ポリシー、レポートは本人のみ読み書きできる権限で作り、既存レポートを暗黙に上書きしない。隔離時のポリシー・レポートは対象に書き込み可能な領域から外す。CI の失敗判定を要求した実行は、要求の集計や必要なレポートの生成に失敗したときも成功を返さない。

レポート v1 は `schema_version`、`backend`、`mode`、`isolation`、`coverage`、`child_status`、`run_status`、`destinations` を持つ。各宛先に `host`、`port`、判定と理由、試行数、接続結果、判明した接続先 IP、送受信バイト数を集約する。`coverage` はプロキシで観測した範囲と、直接通信の試行先を観測していないことを明示する。同じ宛先で許可と失敗が混在した場合も件数を残す。ゼロ件は「プロキシで観測した要求がゼロ」。URL、ヘッダ、本文、コマンド引数、環境変数、個々の PID は収集しない。ホスト名自体に機微情報が入り得るため、レポートのファイル保存は明示指定とする。

`--fail-on-unknown` は、**未登録の CONNECT 要求**が一つでもあれば、子が失敗を握り潰しても実行を失敗にする。明示拒否を原因にこの判定を発火させない。直接通信を OS が拒否しただけのケースはこのフラグの対象外。CI では `isolated` を指定し、レビュー済みポリシーを読み取り専用で与える。通常は子の終了結果を伝え、ラッパーのセットアップ・監査失敗とポリシー違反には個別の非ゼロ終了コードを定義する。子のコードと数値が重なる場合は JSON の状態で判別できるようにする。

## 6. 優先順位

| 優先 | ユースケース | MVP で提供する範囲 |
| --- | --- | --- |
| P0 | 1. インストール中の送信先 | npm のプロキシ経由 HTTPS。macOS / Linux で一覧と結果を表示 |
| P0 | 2. 学習 → 制限 | 観測、利用者のレビュー、明示的な制限実行 |
| P0 | 5. テレメトリーだけ遮断 | 本体とテレメトリーが別ホストの場合 |
| P0 | 10. 子プロセスへの適用 | proxy では設定の継承、isolated では OS の制限も継承 |
| P1 | 3. その場で選択・保存 | 未登録の CONNECT 要求に対するオプトインの対話 |
| P1 | 6. CI の失敗 | 対応 Linux で、未登録の CONNECT 要求が観測された場合 |
| P1 | 7. JSON | ローカルのバージョン付きファイル出力。連携先ツール側の実装は後続 |
| P2 | 8. 過去との差分 | JSON を比較できる状態まで。専用の差分コマンドは後続 |
| P2 | 9. チーム共有 | TOML を明示指定して Git 管理は可能。レイヤー管理・共有承認の操作は後続 |
| P2 | 4. 秘密情報の検知 | HTTPS の内容検査は後続。MVP は接続先と転送量の可視化まで |

P0 と P1 を初期 MVP とし、まず共通プロキシで動作を確かめ、対応 Linux で隔離の検証を通す。Linux の隔離が成立する前の成果は、送信先の調査や協調的なテレメトリー停止に使える。汚染パッケージの直接通信を止める用途には隔離の検証結果が必要。macOS の隔離、Windows、UDP/QUIC、平文 HTTP、プロキシ非対応クライアント、企業プロキシ、広範なペイロード検査は後続。

## 7. 残る抜け道

| 経路・条件 | 利用者に見える結果と制約 |
| --- | --- |
| プロキシ無視、直接 IP、独自 DNS・DoH、静的バイナリ、UDP/QUIC、SSH | `proxy` では直接通信が通り得る。対応 Linux の `isolated` では対象から外へ直接 IP 接続できないが、失敗した宛先の詳細は記録しない。許可先とのトンネル内に載った DoH 等はアプリケーション内容として見えない |
| 同一ホストで配信とテレメトリーを兼用 | ホスト・ポート単位なので URL パスによる選別はできない。同じ CONNECT に複数のリクエストが入っても識別できない |
| 許可先のクラウド、共有 CDN、アップロード API | CONNECT は許可された IP・ポートへのバイト列中継。TLS の SNI・HTTP の Host・本文を検証しないため、同一 IP 上の別サービスへのルーティング、公開アップロード先、許可サービス側の転送を利用した持ち出しが残る |
| DNS の副作用 | `observe` で許可候補を実際に通すと、要求先の名前が DNS に出る。秘密を含むサブドメインもあり得る。`restrict` は未知の名前を解決前に拒否するが、許可名の問い合わせとリゾルバの動作は残る |
| ホスト上の別プロセスや共有ファイルを介した委譲 | `proxy` ではローカル IPC も直接使える。`isolated` はホストソケットと継承 FD を閉じるが、書き込み可能なプロジェクトをホストの別サービスが読み、自分で通信する経路や、生成されたファイルを後で実行する経路は残る |
| 同一ユーザーの権限 | `proxy` では対象が同一ユーザーのルールやレポートを書き換えたり、プロキシを妨害したりできる。起動時のルールの読み込みは、その実行に設定ファイルの後続変更を自動反映しないためのもの |
| 認証情報と HTTPS の本文 | 送信先と暗号化転送量は分かるが、API キーや鍵を読んだ・送ったという判定はできない。対象が読めるプロジェクトの `.env` は隔離時も保護対象外。認証情報を渡さない実行環境と内容検査は、別の対策として設計する |

秘密検知を試すなら、合成した秘密とテスト用 HTTPS サーバーを使い、クライアント単位で明示的に TLS 検査を選ぶ構成を比較する。検査時のメモリ保持、圧縮・分割・符号化による見逃し、誤検知、証明書ピンニングへの影響が設計対象。システム全体の CA ストアの変更は初期設計に含めない。検知結果を出す場合は種類と件数で伝え、値をレポートに含めない。[mitmproxy の CA と TLS 復号](https://docs.mitmproxy.org/stable/concepts/certificates/)

## 8. 先行例との関係

| 先行例 | 重なる点と veil-tell の設計上の違い |
| --- | --- |
| Little Snitch / LuLu | macOS の送信先観測・許可拒否・継続ルールが重なる。Little Snitch は Unix コマンドやヘルパーも扱う。Linux 版 Little Snitch も eBPF とデーモンで観測する。veil-tell は単発の実行を起点に、観測・承認・CI に使うポリシーをコマンド単位で持ち回る体験に絞る。[Little Snitch のルール](https://help.obdev.at/littlesnitch7/concepts-rules) · [Little Snitch for Linux](https://help.obdev.at/littlesnitch-linux/introduction) · [LuLu](https://objective-see.org/products/lulu.html) |
| OpenSnitch | Linux のアプリ別送信制御、プロンプト、永続ルールが重なる。ホスト側デーモンで捕捉する方式なので直接通信も扱える。veil-tell はラッパーで始めた実行にスコープを置く。[OpenSnitch の利用手順](https://github.com/evilsocket/opensnitch/wiki/Getting-started) · [権限要件](https://github.com/evilsocket/opensnitch/wiki/Compilation) |
| Firejail / bubblewrap | プロセス隔離とネットワーク分離が重なる。Firejail の通常導入は SUID を前提とし、`--net=none` でネットワークを分離できる。bubblewrap は隔離の組み立てに使う部品。veil-tell はその上に宛先判定・実行レポートを置く。[Firejail](https://github.com/netblue30/firejail) · [Firejail マニュアルソース](https://github.com/netblue30/firejail/blob/master/src/man/firejail.1.in) · [bubblewrap](https://github.com/containers/bubblewrap) |
| mitmproxy | 明示プロキシに加え、PID・プロセス名で指定できる Local Capture や TLS 復号を備える。通信内容の詳細調査では既存の選択肢。veil-tell は CA の導入なしに実行単位のポリシーと集計を提供する。[Proxy Modes](https://docs.mitmproxy.org/stable/concepts/modes/) · [Certificates](https://docs.mitmproxy.org/stable/concepts/certificates/) |
| Anthropic Sandbox Runtime | 任意コマンドに対する OS 隔離とプロキシベースのネットワーク許可リストが、veil-tell の構成と直接重なる。Linux の中継構成を設計する際の参照実装。veil-tell で試す差分は、観測から個別承認へ進む手順と、実行単位で扱えるレポート。[Anthropic Sandbox Runtime](https://github.com/anthropics/sandbox-runtime) |
| SafeDep PMG | パッケージマネージャー、子プロセスの隔離、宛先制限、違反の確認まで対象が近い。npm の保護に既存手段があることを踏まえ、veil-tell では汎用 CLI の送信先をまず調べ、未知の宛先をその場でルールにできる一連の操作に価値があるかを確認する。[PMG のサンドボックス設計](https://github.com/safedep/pmg/blob/main/docs/sandbox.md) |

アーキテクチャの新規性は前提にしない。差分の仮説は、対象コマンド一つの調査を、宛先のレビュー、明示承認、次回の制限実行まで短い手順で完結できること。

## 9. リポジトリ構成

```text
veil-tell/
├── Cargo.toml / Cargo.lock
├── rust-toolchain.toml
├── flake.nix / flake.lock
├── mise.toml
├── src/
│   ├── main.rs           # 引数解析、コマンドのディスパッチ
│   ├── run.rs            # 起動順序、監督、終了状態
│   ├── proxy.rs          # CONNECT、宛先検証、TCP 中継
│   ├── policy.rs         # TOML、正規化、判定、ルールの保存
│   ├── report.rs         # 集計、端末表示、JSON
│   └── isolation/
│       ├── mod.rs        # 起動条件と実行方式
│       └── linux.rs      # namespace 構成と隔離用の起動手順
├── tests/               # CLI 統合試験とローカル通信フィクスチャ
├── examples/            # 共有可能なルールの例
└── docs/
    └── design.md
```

最初は Rust の単一クレート。プロキシ・ルール・レポートを OS 非依存に保ち、Linux 固有の起動処理を隔離する。共通仕様を持つ複数バイナリや再利用先が生まれた時点でクレート分割を考える。

Nix flake と lock で macOS / Linux の開発シェルと OS 別の開発依存を再現する。Rust のバージョン指定は `rust-toolchain.toml` を正とし、Nix と mise で同じ指定を参照する構成を取る。mise は npm の検証用 Node などのバージョンと `fmt`・`lint`・`test` の入口を管理する。利用者の実行環境では Nix と mise を必須にしない。Linux の user namespace や seccomp の可否はホスト環境で検査する。[Nix develop](https://nix.dev/manual/nix/latest/command-ref/new-cli/nix3-develop) · [mise の Rust バージョン指定](https://mise.jdx.dev/lang/rust.html#version-files) · [mise Tasks](https://mise.jdx.dev/tasks/)

## 10. 実装後に確認すること

1. **共通プロキシ。** テスト用のリゾルバと接続先を使って許可先・未知・明示拒否を用意し、ルールによる拒否時に DNS 問い合わせも外向き接続も起きないことを受信側で確認する。本番の内部 IP 拒否を緩めるオプションは加えず、テスト側で名前解決・接続を差し替える。宛先の異常形式、DNS 応答の混在、IPv6、サイズ上限、並行接続、プロキシ停止、対話のタイムアウトと保存競合を試す。
2. **npm の実機確認。** macOS と Linux で npm v11 の検証バージョンとキャッシュ条件を固定し、実際の `npm install`、プロキシ認証付き HTTPS、ライフサイクルスクリプトからのプロキシ経由通信を確認する。同じスクリプトで直接接続も試し、`proxy` の一覧に出ないことを受信側の結果と照合する。通常の操作で外部 CA を追加せず、テスト用 TLS の信頼設定は対象プロセス内に限る。
3. **Linux の隔離。** 子孫・静的バイナリによる直接 IPv4 / IPv6、UDP / DNS、ホストの Unix ソケットや継承 FD、別の syscall 経路、中継への干渉、親の異常終了を試す。許可先だけにデータが届くこと、制限を用意できない環境では対象が起動しないことを、ローカルの受信記録と照合する。
4. **CI と観測の意味。** 未知の要求を子が握り潰した場合もジョブが失敗し、既知のテレメトリー拒否だけではポリシー違反にならないことを確認する。JSON から適用した方式、拒否の理由、観測範囲、子とラッパーの終了結果を読み取れることを確認する。

以上は受け入れ条件。対象 OS での捕捉・遮断性能、対応する npm のバージョン、サポート可能な Linux 環境は実機検証後に確定する。

## 11. Linux から macOS の隔離検証へ進む条件

まず対応 Linux の一環境で、通常の `npm install` と、持ち出しを試すテスト用ライフサイクルスクリプト入りの `npm install` を、同じ隔離方式・許可ルールで実行する。実データの代わりに、試行ごとに区別できる合成データを使う。

| 確認すること | 進む条件 |
| --- | --- |
| 必要な通信でインストールが動く | 許可したレジストリ経由で通常の `npm install` が成功する。対象の npm バージョンとキャッシュ条件を記録する |
| 未登録の宛先と直接通信を止める | テスト用スクリプトが未登録ホストへのプロキシ要求と、子孫プロセスからの直接 IP 送信を実際に試す。第10節の IPv4・IPv6、UDP/DNS、IPC・継承 FD の試験も行う。制限を掛けない対照実行では合成データが試験用の受信先に届き、隔離と宛先制限を掛けた実行では未許可の受信先に届かないことを確認する |
| 隔離の失敗を明確に扱う | 起動に必要な隔離を用意できない環境では、対象が起動しない。実行中に中継やプロキシが停止した場合は失敗が返り、対象の直接通信が開通しない |
| 人と CI が結果を判断できる | 未登録のプロキシ要求は拒否理由を記録し、子が失敗を握り潰しても `--fail-on-unknown` で失敗する。直接通信の遮断は受信側の試験結果で確認し、JSON では直接通信の試行先が観測範囲外だと分かる |

この一連の結果を、OS・カーネル・npm のバージョン、使用したルール、終了状態、受信側の記録とともに再現できたら、macOS の隔離方式の検証に進む。macOS でも同じ CLI・ルール・JSON を使い、上の四つの条件を実機で確認してから、対応環境で `isolated` を提供する。Linux の結果は方式を比較する基準として使い、macOS での遮断は macOS 上の試験で判定する。

## 12. Linux の最小遮断実験

最初の問いは、**同じ子コマンドに対し、許可先への経路を残したまま、未登録先への CONNECT とプロキシを経由しない IPv4/TCP の直通をそれぞれ止められるか**。npm の設定やキャッシュの影響を避けるため、最初は接続方法を明示できる小さなテストクライアントを使う。

### 最初に作るもの

1. **受信側とテストクライアント。** 外部への経路がない Linux VM の中で、VM の loopback 以外のプライベート IPv4 アドレスに TCP 受信口を二つ用意する。片方を許可先、もう片方を未登録先とする。テストクライアントは CONNECT 経由か直接 TCP かを指定でき、試行ごとの合成トークンを送る。直接 TCP は起動した子プロセスから試す。受信側は接続受付と受信したトークンを記録する。
2. **Rust の最小 CONNECT プロキシ。** `allowed.test:443` と `blocked.test:443` を試験用の名前にし、完全一致の許可リストに前者だけを入れる。判定後に呼ぶ試験専用の名前解決・接続処理が、名前を VM 内の各受信口に対応づける。これで実際の TCP 中継を通しつつ、外部 DNS や本番の内部 IP 拒否設定の変更を避ける。プロキシは判定、名前解決・接続処理を呼んだか、接続結果を試行ごとに記録する。
3. **Linux の起動経路。** 同じクライアントを通常起動と隔離起動で切り替えられるようにする。隔離起動では bubblewrap で外向き経路のない network namespace を作り、内部の loopback に置いた中継から専用の Unix IPC を経て、VM 側のプロキシにだけつなぐ。クライアントにはその IPC の FD を渡さない。対応環境で既に利用できる非特権 user namespace を使う。最初の実験は固定ルールと試験用の記録で行い、製品 CLI・TOML・JSON の実装は後続に置く。

### 対照実行と合否

一試行につき一経路を使い、受信口とトークンを指定して実行する。受信口が起動していることを最初に確かめ、接続・受信待ちに期限を設ける。

| 条件 | クライアントの試行 | 受信側で確認する結果 |
| --- | --- | --- |
| 隔離・ルールなし | CONNECT で `blocked.test:443`、別試行で同じ受信口へ直接 TCP | 両方のトークンが届く。各試験経路が通ることの対照 |
| ルールのみ | CONNECT で `blocked.test:443`、別試行で同じ受信口へ直接 TCP | CONNECT は拒否され、対応する接続受付・トークン受信がゼロ。直接 TCP のトークンは届く |
| 隔離とルールあり | CONNECT で `allowed.test:443`、別試行で `blocked.test:443`、さらに別試行で未登録先の受信口へ直接 TCP | 許可先のトークンだけが届き、未登録先では接続受付・トークン受信がゼロ |

CONNECT の拒否では、試験用の名前解決・接続処理が未登録名に対して呼ばれていないことも照合する。直接 TCP では、クライアント側で子プロセスが実際に接続を試みて失敗したことを記録する。隔離のセットアップを意図的に失敗させる一試行も行い、クライアントの起動マーカーが出ず、ランナーがエラーを返すことを確認する。

表の全結果と起動失敗時の挙動を再現できたら、この実験は完了。合成トークン、クライアントの終了状態、プロキシ判定、受信記録を実行条件とともに残す。対照でデータが届かない場合や接続試行を確認できない場合は、そのケースの結果を判定保留にする。隔離下で未登録先への接続が受理された場合は、どの経路で到達したかを調べる。

ここで確かめるのは、試験した Linux 環境の CONNECT と IPv4/TCP の経路。結果がそろったら同じ受信側の計測を npm のライフサイクルスクリプトへ移し、IPv6、UDP/DNS、ホスト IPC、継承 FD などの試験を加えて第11節の条件を確認する。

## 13. 初回公開に向けた設計

第1〜12節は初期設計と実験の経緯を残す。この節は、macOS でも通常ビルドを検証した時点での公開準備の方針をまとめる。

### macOS の隔離を差し替えられる構成

macOS の既定の隔離は当面 Seatbelt（`sandbox-exec`）。現在の `isolation::prepare` を境界として、OS 固有の起動、プロキシへの入口、稼働確認、後片付けをそこに集める。CLI、TOML の判定、終了コード、JSON の集計は共通にする。バックエンドが起動できないときは理由を返し、対象を起動しない。

Apple の `container` は、Seatbelt が使えなくなった場合の候補として早めに試す。Apple silicon と対応 macOS が必要で、ゲスト内で実行するのは Linux 向けのコマンドと依存関係になる。まずは Linux 版 npm で、作業ディレクトリと成果物だけを受け渡す構成を試す。ホストのホーム、認証ソケット、任意のデーモンへの接続は渡さない。ゲストからプロキシ以外への直接 TCP・IPv6・UDP/DNS を止められることと、中継が落ちたときに失敗することを受信側で確認する。イメージ取得や初期設定の権限と、通常の実行に必要な権限も分けて確認する。採用後は実行前に Linux ゲストで動くことを表示し、バックエンドを切り替えた実行をレポートで識別できるようにする。[Apple container](https://github.com/apple/container) · [コマンドリファレンス](https://github.com/apple/container/blob/main/docs/command-reference.md)

### 観測範囲と実測の見せ方

- **README の冒頭。** 「対応環境で sudo なし。コマンド単位で通信先を確認し、未登録の HTTP CONNECT を CI の失敗にできる」。LuLu・Little Snitch・OpenSnitch のホスト側制御、Firejail のプロセス隔離、mitmproxy のプロキシと通信調査との重なりは第8節から短く紹介する。実行を起点に同じポリシーをローカルと CI で使える点を veil-tell の特徴とする。
- **最初の実例。** 空のキャッシュで `npm install` を実行した試験では、`is-number@7.0.0` のメタデータと tarball を取得し、veil-tell は `registry.npmjs.org:443` への許可済み CONNECT を1件記録した。npm・CLI ともに終了コードは `0`。README に載せるなら、この実測を短いコマンドと出力で示す。
- **端末出力と JSON。** `veil-tell COMMAND` の開始時に、プロキシ設定に従う通信のうち HTTP CONNECT を観測すると明示する。終了時のゼロ件は「観測した HTTP CONNECT は0件。直接通信の試行先は観測範囲外」と表示する。README と端末出力も JSON の `coverage.proxy = "http_connect_requests"`、`coverage.direct_attempt_destinations = "not_observed"` に合わせる。OS による遮断とプロキシでの記録は別の事実として伝え、`--fail-on-unknown` の対象は未登録 CONNECT と明記する。
- **既知の弱点。** 許可した GitHub や npm レジストリへ、子プロセスが使える認証や公開アップロード経路を通じて秘密を送る余地がある。中継はホスト名・ポート単位で、HTTPS の操作、URL パス、本文は観測・制御の範囲外。許可ルールは、そのホストへの接続を許可する判断として扱う。
- **macOS のシステム DNS。** Mach/XPC 対策後の通常ビルドを macOS 27.2 arm64 で実行し、A・AAAA（`getaddrinfo`）と TXT・KEY など（`DNSServiceQueryRecord`）を試した。試験したユニキャスト経路では制限なしで権威 DNS に届き、隔離時は届かなかった。README は確認した OS・API・経路を記載する。次の回帰試験では DNS レコード種別の追加より、API・通信経路・OS バージョンの違いを優先する。macOS の OS 更新時には対照と受信ログで確認し直す。

### ポリシーの初期値

`observe --emit-policy FILE` は、プロキシで観測した正規化済みの宛先を重複なく並べ、全件を保留として出す。v1 の `restrict` は `allow` / `deny` を受理するため、初案は候補をコメントにした TOML とする。有効な許可ルールはゼロ。レビューして選んだ候補だけを有効にする。保留は未登録扱いなので、`--fail-on-unknown` の判定に残る。観測が中断・不完全だったときは理由を返し、ひな形の出力に成功した扱いにしない。既存ファイルは上書きせず、宛先名を含むひな形は本人のみ読めるように作る。

v1 は完全一致を維持する。実際に頻繁な宛先変更が確認されたときは、明示的にレビューした接尾辞に対し、直下の1ラベルだけを許すワイルドカードを別案として試す。基底名、複数階層、公共サフィックスを対象から外し、明示拒否を優先する。名前解決後の IP 制約も適用する。共有 CDN やユーザー投稿を配信するドメインでは、テナントやサブドメイン自体を第三者が選べる。許可名に埋め込まれた文字列が DNS に出るため、`*.githubusercontent.com` のようなルールは利便性と持ち出し範囲を確認してから個別に判断する。ひな形の自動生成では完全一致の候補だけを出す。

### リポジトリと配布

| ファイル | 載せる内容 |
| --- | --- |
| `README.md` / `README_EN.md` | 日本語を既定にして、冒頭に相互リンクを置く。実測デモ、最短の使い方、前提環境、観測範囲、既知の弱点を両方に載せる |
| `LICENSE` | ライセンス本文。MIT を候補とし、採用は公開前に決める。決定後は Cargo のメタデータとそろえる |
| `SECURITY.md` | 脆弱性の非公開報告先、対象バージョン、報告に必要な再現情報。GitHub の非公開報告を使う場合は、設定後に入口を掲載する |
| `docs/runbook.md` | 環境の確認、受信側つきの回帰試験、隔離起動・中継停止の切り分け、リリースのビルド・検証・撤回手順 |

公開前のコミットは、設計、共通 CLI・プロキシ、OS ごとの隔離と受信側の回帰試験、利用者向け文書、配布設定の順に、レビューできる差分にまとめる。現在の初回コミットを起点に追記し、作業ツリーの既存変更を確認してから分割する。

配布はタグから OS・アーキテクチャ別にビルドし、配布する各ファイルに SHA-256 を掲載する。バイナリは GitHub Artifact Attestations の署名付き来歴証明の対象にし、利用者がリポジトリを指定して `gh attestation verify` で検証できる手順を載せる。配布ページから取得したファイルでチェックサムと来歴を確認する。Apple の署名・公証は macOS の配布形式に応じて別途判断する。[GitHub Artifact Attestations](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations)

最初の作業は、実測デモ・観測範囲・弱点の日英 README への反映と、端末出力の明示。次に完全一致のポリシーひな形を試し、公開に向けてライセンス、報告先、回帰手順、配布物の検証を整える。Apple `container` は小さな実験で隔離境界を確かめ、ワイルドカードは実測で必要になった時点で判断する。
