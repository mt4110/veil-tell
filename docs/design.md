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

## v0.3.0 宛先の差分チェック

| 優先度 | 対象 |
| --- | --- |
| P0 | 一行の初回記録・再比較、明示的な承認、安定した JSON、CI の新規宛先判定（1・2・3・5・6・7） |
| P1 | 依存更新 PR 向けの GitHub Actions サンプル（4） |

`veil-tell COMMAND [ARG...]` はカレントディレクトリの `.veil-tell/` に、引数列の SHA-256 ごとに基準を置く。引数は長さ付きでハッシュ化し、ファイルに引数そのものは残さない。初回の成功時だけ新規作成する。2回目以降は同じ基準と比較し、変更があれば最新の承認候補を `pending.json` に書く。`veil-tell accept` が候補の差分を基準に反映する。候補はプロジェクトごとに1件なので、承認前に表示された宛先を確認する。基準が候補生成後に変わった場合は再観測を求める。基準は Git 管理し、`pending.json` は除外する。

上級者向けの `observe --baseline-out FILE` と `observe --baseline FILE` は同時指定不可。出力は新規ファイルに限り、既存ファイルを保持する。隔離を指定する場合は既存の出力先規則が適用される。たとえば `project/` と同じ階層に `state/` を作り、`../state/baseline.json` を使う。既定の `.veil-tell/` は短縮形のローカル観測で書く。隔離した CI では実行前に基準を読み込み、メモリに保持する。

基準 JSON の `schema_version: 1` は実行レポートと独立して管理する。`coverage: "http_connect_requests"`、`backend` と、ホスト・ポート順に固定した `destinations: [{host, port, attempts}]` を保存する。時刻、実行パス、解決先 IP、転送量は入れない。ホスト名は CONNECT と同じ正規化を使い、接続結果や IP が違っても回数を合計する。壊れたファイル・未知バージョンは実行前に `125` で停止する。

新規宛先は `+`、消えた宛先は `-`、同じ宛先の CONNECT 回数が **2倍以上かつ3回以上増減**した場合は `~` で表示する。消失と回数変化は情報として表示する。新規宛先があれば `observe --fail-on-new` は終了コード `21` を返す。観測時は新規接続が実行中に成立し得る。`ci -- COMMAND` は隔離し、事前に読み込んだ基準にない新規 CONNECT を接続前に拒否する。基準がない場合は起動せず `125`。子が新規拒否に伴って非ゼロ終了した場合も、観測が完了していれば新規宛先を記録して `21`。この場合、消失と回数変化は判定しない。従来の `0`、`20`、`125` の意味と通常の子終了コードの引き継ぎは維持する。子が自ら `21` を返した場合はレポートの `run_status.reason` で区別できる。

実行レポートは v1 のまま、差分を要求した場合に限り `comparison` を追加する。状態は `created`、`compared`、`skipped`、`new_destinations_only` のいずれか。中断・観測不完全・通常の子プロセス失敗は基準を保存せず、比較を見送る。実行方式が変わった場合は警告を表示する。旧コマンドのレポートに新規フィールドは出力しない。

CONNECT で判別できる単位は正規化したホスト名と443番ポート。TLS の内容や同一ホスト内の用途変化、プロキシを通らない直接通信の宛先は観測範囲外。CDN のホスト名が変わると新規宛先になるため、OS・npm・キャッシュ条件を揃えて再測定し、必要性を確認してから基準を承認する。依存更新 PR ではベース側のコミットからレビュー済み基準を取り出す。必須チェックとして運用する場合は、ジョブや Action 自体も PR から書き換えられない設定で管理する。

| 先行例 | 重なる範囲と veil-tell の設計 |
| --- | --- |
| Anthropic Sandbox Runtime | OS 隔離とネットワーク許可リストが重なる。veil-tell では任意コマンドの実測を Git でレビューできる基準にし、次回の差分を出す。[公式実装](https://github.com/anthropics/sandbox-runtime) |
| Socket.dev | 依存更新で追加されるインストールスクリプトやネットワーク利用を PR に報告する点が近い。Socket の依存分析に対して、veil-tell は実行時に観測した CONNECT を比較する。[Socket for GitHub](https://docs.socket.dev/docs/socket-for-github) |
| StepSecurity Harden-Runner | CI の外向き通信を観測し、履歴ベースの異常検知と許可リストによる制限を提供するため、目的が最も近い。veil-tell の対象は個々のコマンドで、基準は利用者がローカルで生成・レビューする。[StepSecurity Baseline](https://docs.stepsecurity.io/gitlab/harden-runner/baseline) · [Harden-Runner](https://github.com/step-security/harden-runner) |

### npm ライフサイクルの帰属

| 候補 | 実現できる範囲と判断 |
| --- | --- |
| A. npm の `script-shell` と CONNECT の付加情報 | npm はスクリプトをパッケージの作業ディレクトリで起動し、マニフェストのパスとライフサイクル情報を渡す。起動時に `package.json` の名前・バージョン・スクリプト本文を環境と照合できる。Linux と macOS で同じ意味の推定を出せるので採用する。[npm scripts](https://docs.npmjs.com/cli/using-npm/scripts) · [npm の起動処理](https://github.com/npm/run-script/blob/main/lib/make-spawn-args.js) |
| B. ソケットとプロセスの照合 | Linux の `SO_PEERCRED` は Unix ソケットの相手を示す。ホスト側の相手は隔離内の中継で、実際の子は中継の手前で TCP 接続する。隔離内でソケット inode と `/proc/<pid>/fd` を照合できる場合も、FD の共有や PID の終了、cwd の変更により推定にとどまる。macOS には `libproc` のプロセス・FD 情報があるが、取得権限や競合があり、TCP の相手から npm ライフサイクルまでは分からない。[Linux unix(7)](https://man7.org/linux/man-pages/man7/unix.7.html) · [Apple の proc_info.h](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/proc_info.h) |
| C. npm ログやカーネルトレース | npm のログだけでは、並行するライフサイクルと個々の CONNECT を結びつけられない。カーネルトレースを前提にすると、両 OS での非特権運用と互換性の条件が増える。 |

短縮形や差分モードで直接起動する `npm` には、自動で起動ラッパーを指定する。シェルなどを介す場合は `--attribute-npm` を付ける。ラッパーは既存のローカルプロキシ認証に帰属の付加情報を添え、同じシェル引数を `/bin/sh` に渡す。帰属が有効な場合は npm の `script-shell` 設定にラッパーを指定し、既定の POSIX シェルで実行する。別の `script-shell` を明示してラッパーを迂回すると、帰属は得られない。Linux ではラッパーを読み取り専用でマウントし、macOS では隔離から書き換えを禁止する。

`inferred` は起動時の npm 情報とマニフェストが一致したという推定。確定できた実行主体として扱わない。情報が欠けている、照合に失敗した、付加情報が壊れている場合は `unknown`。パッケージがスクリプト起動後に環境や資格情報を変更し、付加情報を削除・再利用・作成することは可能で、もっともらしい別の推定が出る場合もある。子孫への環境継承もあるため、表示はスクリプト実行の文脈を表す。npm 由来の識別情報はローカルプロキシで消費し、宛先には転送しない。

宛先の正規化、基準との照合、拒否と終了コードは帰属情報を参照しない。帰属を有効にした実行では、構文が有効な CONNECT の宛先は認証情報が欠落・不正でも記録し、トンネルは開かない。CI ではその宛先も新規判定の対象になる。プロキシを経由しない通信の観測範囲は従来どおり。

実行レポートとベースラインは `schema_version: 1` のまま、各宛先に任意の `attribution` 配列を追加する。既存の v1 基準はそのまま読み込める。古いバイナリに基準を渡す場合は `attribution` を削除して使う。帰属は差分のキーに含めない。帰属情報が多い宛先では最大4件の推定と `unknown` を保持し、帰属だけを増やしても宛先の記録枠は消費しない。

Harden-Runner も外向き通信をプロセスやコマンドに関連付ける。veil-tell がここで提供するのは、コマンドごとの差分に npm のパッケージ・バージョン・ライフサイクル・相対パスを付けて、JSON とジョブ要約に表示する機能。[Harden-Runner](https://github.com/step-security/harden-runner)

### ロックファイルと Cargo の帰属

`package-lock.json` v2/v3 と `Cargo.lock` v3/v4 を自動で要約する。基準の任意フィールド `lockfile` はエコシステムと、名前・バージョン・integrity または checksum のソート済み集合を保存する。URL、インストールパス、ロックファイル本文は保存しない。JSON は v1 を維持し、旧基準も読める。読み取れない、形式が異なる、入力が16 MiBまたは要約が128 KiBを超える場合は照合を見送る。pnpm と Yarn はロック形式とリンク先の照合が別途必要なため対象外。

比較では追加・削除を集合の差で求め、同名で旧・新の差が各1件なら更新とする。新規 CONNECT の帰属先が追加・更新に一意に一致すれば `corroborated`、同じ名前・版が現行ロックに残り変更がなければ `unchanged`、帰属が不明で変更があれば `candidates` とする。候補には削除も含み、JSON の `comparison.lockfile_changes` で区別できる。ロックに帰属先がない場合や同じ名前・版の識別が曖昧な場合は裏づけを付けない。`comparison.lockfile_evidence` に各新規 CONNECT の注記を出す。宛先の照合と終了コードにロック情報は使わない。

比較用のロックは実行前に読む。初回記録時にファイルがまだ存在しなければ、コマンドが生成したロックも基準に使える。Action は PR のベースコミットから基準とロックを取り出し、PR 側のロックの要約と照合する。PR 側の記述は変更候補を示す調査材料として扱う。integrity は取得アーカイブの情報なので、展開済み `node_modules` や Cargo のビルド時ソースをこの照合で再検証しない。パッケージマネージャーが不一致で失敗すれば、その子終了結果が従来どおり伝わる。改変された作業ツリー、同じ版のローカル依存の差し替え、実行時条件による発火、偽装された帰属は残る。ロックの一致が示すのは依存記録の変化であり、発信元の証明やインストール済みファイルの検証には使えない。[npm lockfile](https://docs.npmjs.com/cli/configuring-npm/package-lock-json/) · [npm ci](https://docs.npmjs.com/cli/commands/npm-ci/)

Cargo は `CARGO_PKG_NAME`、`CARGO_PKG_VERSION`、`CARGO_MANIFEST_DIR` を実行時に照合する。安定版 Cargo の `RUSTC_WRAPPER` はコンパイルを包むため、そのままではビルドスクリプトの実行を観測できない。実装では Cargo が生成したビルドスクリプト用実行ファイルを検出し、元バイナリを同じ出力ディレクトリに保持して、起動時に環境を照合する。既存の環境変数 `RUSTC_WRAPPER` がある場合は追加のラッパーを挿入しない。生成形式が違う場合、マニフェストの継承などで照合できない場合、すでにコンパイル済みでラッパーがない場合は `unknown` になり得る。成果物は Cargo のターゲットディレクトリに残る。キャッシュ済みでスクリプトが再実行されなければ、その実行の CONNECT は0件。比較条件を揃えるには別々の空のターゲットディレクトリを使う。

Cargo の不安定な `host.runner` は将来、生成物に手を加えず起動を包む選択肢になる。実行ファイル名と PID だけを使う推定は、OS 差・子孫への委譲・競合が残る。proc-macro は rustc と同じプロセス内で複数が動くため、rustc の起動情報から個々のマクロに帰属できない。プロキシに届いた CONNECT は引き続き記録・判定する。[Cargo build scripts](https://doc.rust-lang.org/cargo/reference/build-scripts.html) · [Cargo host.runner](https://doc.rust-lang.org/cargo/reference/unstable.html#host-config) · [Rust procedural macros](https://doc.rust-lang.org/reference/procedural-macros.html)

pip を扱う場合は、PEP 517 フックを呼ぶ子プロセスの起動点でビルド対象名、ソース、バックエンド、フック名を記録し、隔離したビルド環境へ帰属情報を引き継ぐ必要がある。setuptools の `setup.py` もバックエンド経由で動く場合がある。バックエンドと、そのバックエンドがビルドする依存の帰属は区別が必要。[pip Build System Interface](https://pip.pypa.io/en/stable/reference/build-system/)

## v0.4.0 の基準と既定動作

npm と Cargo の短縮形と CI は、実行ディレクトリにある `.veil-tell/npm.json` または `.veil-tell/cargo.json` を使う。同じパッケージマネージャーの引数の違いを吸収する。その他のコマンドは引数のハッシュを維持する。同一引数で作った旧基準は短縮形が新しいファイルへコピーできる。引数が異なる旧基準は `veil-tell migrate-baseline npm FILE` などで、レビューしたファイルを選ぶ。CI は基準を自動更新しない。

キャッシュはツール側で削除・強制更新せず、初回観測と人が承認した新規宛先の和集合を基準にする。実行時に見えなかった既知の宛先は情報表示だけで、承認候補や失敗にならない。回数変化は JSON に残す。温まったキャッシュで初回観測すると未観測の宛先は基準に含まれないため、CI と条件を揃えたい場合は、レビュー用の実行でも同じ依存キャッシュ条件を用いる。

短縮形は隔離内で無害なコマンドの起動を確認してから対象を一度だけ起動する。プローブで隔離を使えなければ、理由と直接通信の観測範囲を表示してプロキシ観測を使う。CI は隔離を必須とする。短縮形の基準ディレクトリは子から書き込めないようにする。明示したレポートは `../state/report.json` のような兄弟ディレクトリに出力する。

npm と Cargo の帰属はコマンド名から自動で有効にする。`--no-attribute` は帰属とロック照合を無効にする。npm の script-shell または設定ファイルの明示指定を検出した場合は、既存の設定を優先し、npm の帰属を無効にした理由を出す。設定済みのシェルが壊れている場合は npm のエラーを伝える。

Action は公開版アーカイブをダウンロードし、リポジトリ・署名ワークフロー・リリースタグの来歴を検証してから展開する。PR のベースコミットから基準を読む。新規宛先があればジョブ要約に帰属とロック照合を表示し、新規宛先がなければ1行にする。PR コメントは明示的に有効にした場合に限る。

### 隔離下の名前解決

Node.js で観測する範囲、帰属の限界、Linux と macOS の DNS 受付の実験結果は [名前解決の試みの観測](dns-attempts.md) を参照。

### 許可済みトンネルの送信量

[トンネルの送信量](volume-limits.md) に基準・制限方式・観測範囲を記載。

### v0.4.0 の選択と先行例

- **StepSecurity Harden-Runner** はランナーで宛先の基準化と異常検知を行う。この用途は重なる。veil-tell は開発者のローカルと CI で同じコマンドを比較し、Git に置く基準とロックファイル差分を PR レビューに使う。[Harden-Runner](https://github.com/step-security/harden-runner)
- **Anthropic Sandbox Runtime** と OS 隔離＋プロキシの構成が重なる。veil-tell は依存更新の前後の差分、推定帰属、送信量をレビューに使う。[Sandbox Runtime](https://github.com/anthropics/sandbox-runtime)
- **Socket** は依存パッケージのリスク分析を提供する。veil-tell の記録は、利用者が実行したコマンドがその条件下で示した通信に限る。[Socket](https://socket.dev/features)
- **OpenSnitch・LuLu・Little Snitch** はホスト上でプロセスの通信を監視・制御する。veil-tell は指定コマンドの一回の実行を単位にする。[OpenSnitch](https://github.com/evilsocket/opensnitch) · [LuLu](https://objective-see.org/products/lulu.html) · [Little Snitch](https://www.obdev.at/products/littlesnitch/index.html)
- **Zeek** の `conn.log` は方向別のバイト数を記録し、`dns.log` は DNS を記録する。veil-tell の量は CONNECT トンネル内の計測で、名前解決の試みは Node.js のフックを通ったものに限る。[Zeek conn.log](https://docs.zeek.org/en/current/reference/logs/conn.html) · [Zeek dns.log](https://docs.zeek.org/en/current/reference/logs/dns.html)

採用したのは、既存の隔離境界の内側で Node.js の名前解決の試みを拾う方式と、ホスト側プロキシで TLS トンネルの送信予算を共有する方式。UDP 53 の固定受付は Ubuntu の既存 AppArmor 設定では動かなかった。macOS のホスト DNS を許可する案は隔離範囲を変えるため見送った。初期しきい値は単一のレビュー済み実行と余裕倍率を使う。分位点の採用には、同じ条件での複数回の測定とレビュー可能な採取手順が必要になる。

pnpm と Yarn の Node.js スクリプトは、起動時のライフサイクル環境を作業ディレクトリのマニフェストに照合する。Yarn Berry の組み込みシェルや pnpm の設定を置換しない。Bun が Node.js のプロセスとして起動したスクリプトでは、対応する名前解決の試みは記録でき、帰属は unknown。グローバルストアのホストマウントは行わない。再現にはプロジェクト内の pnpm ストアや Yarn キャッシュを使う。名前・バージョン・integrity または checksum が一致しても、実際に走ったコードの一致や通信の動機は証明できない。同じバージョンのままコードが差し替わる場合や、特定の実行条件だけで通信する場合がある。[pnpm settings](https://pnpm.io/settings) · [Yarn scripting](https://yarnpkg.com/features/scripting) · [Bun install](https://bun.com/docs/pm/cli/install)

pip を対象にするなら、PEP 517 のビルドバックエンド用プロセスの起動点と、そのビルド環境に入った配布名・バージョンの対応を取る必要がある。通常のインストールとソース配布物からのビルドを分けて試験する。今回の実装範囲は Cargo の既存 `build.rs` までで、proc-macro と pip の帰属は範囲外。

## 次の設計案　依存更新 PR に初めて導入する

### 誰の何を楽にするか

最初の対象は、GitHub Actions で `npm ci` を使い、Dependabot や Renovate の更新をレビューする小規模チームと OSS のメンテナー。リポジトリ直下に `package-lock.json` があり、公開 npm レジストリから認証情報なしでインストールできる構成から始める。

依存更新で `npm ci` が新しい宛先に接続しようとしたら、その接続を止め、PR のレビューで宛先と発信元の手がかりを見られるようにする。判断材料は実行時に観測できた通信と変更前の基準。帰属は推定または不明として示す。

実行時の宛先制限は StepSecurity Harden-Runner と重なる。Socket も依存更新のレビューにリスク情報を出す。GitHub はランナーのネットワーク監視を技術プレビューとして発表している。veil-tell で試す価値は、保守者が特定コマンドの通信を自分の Git リポジトリの基準で判断でき、既存 CI に一つのジョブとして追加できるかにある。[Harden-Runner](https://docs.stepsecurity.io/github-actions/harden-runner) · [Socket for GitHub](https://docs.socket.dev/docs/socket-for-github) · [GitHub の発表](https://github.blog/security/supply-chain-security/disrupting-supply-chain-attacks-on-npm-and-github-actions/)

### 初回の流れ

同じ GitHub ホスト Ubuntu ランナー、Node.js・npm の版、作業ディレクトリと空の依存キャッシュで、基準の採取と PR の検査を行う。この流れは、公開版 v0.4.0 と [npm 用テンプレート](../examples/github-actions/veil-tell-npm.yml) を使い、Ubuntu 26.04 の GitHub Actions で確認した。手動採取で基準候補を取得し、レビュー済みの基準で通常の `npm ci` は `0`、未登録 CONNECT は `21` になった。 [実測と JSON の見方](runbook.md#github-actions-での実測と-json-の見方)

1. 保守者がレビュー済みコミットを選び、GitHub Actions で初回採取を手動実行する。来歴を検証した配布バイナリを使い、`veil-tell observe --backend isolated --baseline-out FILE -- npm ci` を実行する。出力先は対象の作業ディレクトリの兄弟ディレクトリに置く。子の成功と観測の完了を確認できたときに、基準候補を成果物にする。導入手順は GitHub 上で完結し、利用者のマシンへのインストールは任意とする。
2. 保守者が候補の宛先と用途を確認し、採用する基準を `.veil-tell/npm.json` としてベースブランチに入れる。製品コード、許可範囲、採取した基準のレビューを先に済ませてから追加ジョブを有効にする。既存のテストジョブと独立させ、最初はマージの必須条件にせず、通常の更新での誤報を測る。
3. 依存更新 PR で `uses: mt4110/veil-tell@v0` を実行する。来歴検証、ベース SHA の基準の読み込み、隔離、終了コードの判定は公開版の動作を使う。ジョブ要約から宛先、推定帰属、JSON にたどり着けるようにする。検査が失敗した場合にも、存在するレポートを成果物として残す。

基準の採取は接続を観測する実行なので、レビュー済みのコードを認証情報のない環境で実行する。PR のコードは読み取り権限のジョブで実行し、シークレットと書き込み権限を渡さない。PR ベースから基準を読む機能が保護するのは基準の参照元。ジョブの定義や実行コマンドを PR が変更できる場合は、その変更もレビュー対象にする。マージの必須条件にする場合は、基準とワークフローの両方にレビューを要求できる構成を確認する。[GitHub Actions の安全な利用](https://docs.github.com/en/actions/reference/security/secure-use) · [PR ワークフローの信頼境界](https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target)

### 止まったときの次の一手

| 終了コード | 要約で分かること | 利用者が取る行動 |
| --- | --- | --- |
| `0` | 今回の観測範囲で新規宛先や拒否対象の異常がない | 通常の依存レビューを続ける |
| `21` | 基準にない宛先または観測対象の名前解決の試行を検出した | 宛先と帰属の確度を見て用途を確認する。説明できなければ依存更新を保留する |
| `22` | 許可済み宛先への送信が上限を超えようとし、トンネルが切断された | 送信量と上限を照合し、用途を確認する |
| `125` | 基準の取得、隔離の起動、観測などの失敗で検査を完了できなかった | ログと、取得できた場合は JSON の理由を確認し、該当箇所を直して再実行する |

用途を確認できた正当な新規宛先は、保守者が確認済みの条件で再採取し、新しく観測した宛先を一件ずつ確認し、用途を確認できた変更を基準の差分としてレビューする。基準だけを更新する PR を先に取り込み、依存更新 PR は新しいベースで再実行する。CI の JSON は調査に使い、承認は基準のレビューで行う。疑わしい更新を調べるときは、先に拒否した実行の要約と JSON を見る。

### 手軽さと需要を確かめる

公開版では npm の実プロジェクトで `0` と `21`、Cargo の自プロジェクトで通常の更新2件と拒否の対照を確認済み。ここから検証するのは、開発に関わっていない保守者が自分の PR でも導入でき、次の依存更新でも使い続けるか。[npm の実測](runbook.md#9-image-drop-input-の依存更新-pr-で変更前の基準を確認する) · [Cargo の実測 1](https://github.com/mt4110/veil-tell/actions/runs/43547005034) · [Cargo の実測 2](https://github.com/mt4110/veil-tell/actions/runs/43547009892)

- npm プロジェクトの保守者3人に、導入手順だけで最初の通常 PR と合成の拒否ケースを試してもらう。暫定目標は2人以上が手助けなしで最初の成功まで20分以内。CI の待ち時間と操作時間を別々に記録する。参加者の一人でも初回から手順を完遂できなければ、最初に詰まった作業から手順を見直す。
- 拒否後、要約から宛先を見つけて、保留または承認に必要な確認を自力で説明できるかを見る。承認から復帰する試験には、用途を事前に確認できる無害な宛先を用意する。
- 最初の実験の後、自分の次の依存更新でもジョブを残して使った人の数と、実際に判断に使った箇所を記録する。レジストリやキャッシュの差による誤報も確認する。試した人数、継続した人数、外した理由を残す。収集は参加者からの報告で行い、ツールに計測用の外部送信は追加しない。

導入に詰まった箇所が共通なら、その箇所に絞って直す。実行に成功しても次の更新で使われなければ、理由を聞いて対象や価値の仮説を見直す。

## 0.5.0 の設計判断

0.4.1 ではなく 0.5.0 とする。既存の隔離方式に加え、短い CI 実行と明示的な観測比較の終了判定を利用者から見える形で拡張するため。JSON は v1 を維持する。`20` は restrict の未登録 CONNECT、`21` は比較で検出した新規宛先・観測した DNS 試行と、明示的な観測比較の送信量異常、`22` は上限による遮断、`125` は検査不能・記録不完全に使う。観測だけの `21` と切断の `22` は `run_status.reason` と `volume_anomalies[].blocked` で区別する。

### 採用した範囲と見送った案

- pnpm 12.4.2 の証明書検証の失敗には上流修正を含む 12.21.0 を案内する。TLS の無効化、`trustd` の許可、veil-tell からパッケージマネージャーを勝手に置き換える案は見送った。[上流修正](https://github.com/pnpm/pnpm/pull/15358)
- Linux の非転送 DNS は非特権ポートの模擬試験まで。Ubuntu の既存設定では標準ポート53を開けなかった。macOS の拒否ログは問い合わせ名を持たず、重複が集約される。ランタイム個別の追加フックとログ件数を根拠にした CI 判定は採用しない。[DNS の実測](dns-attempts.md#次版の実測と判定)
- 送受信比だけの警告は見送った。正常な公開やアップロードにも同じ比率が出るので、基準ありの比較と明示された制限を使う。[しきい値と受信側の実測](volume-limits.md#インストールを基準にした受信側の比較)

### 先行例との重なり

- StepSecurity Harden-Runner は CI の宛先を監査・制限し、実行履歴の基準で新規宛先を検出する。Anthropic Sandbox Runtime は OS 隔離・プロキシの許可リスト・違反記録を持ち、macOS では `trustd` を許す場合の持ち出しリスクも明記する。veil-tell のこの版では、コマンド単位で Git 管理する基準と、推定帰属付きの比較結果に焦点を置く。[Harden-Runner](https://www.stepsecurity.io/blog/railway-security-incident-ci-cd-runtime-security) · [Sandbox Runtime](https://github.com/anthropics/sandbox-runtime)
- Socket は依存更新 PR にパッケージのリスク情報を出す。OpenSnitch、LuLu、Little Snitch は端末上のアプリの接続を扱う。veil-tell の記録は起動したコマンドの実測に依存し、ホスト全体の監視を行わない。[Socket for GitHub](https://docs.socket.dev/docs/socket-for-github) · [OpenSnitch](https://github.com/evilsocket/opensnitch) · [LuLu](https://objective-see.org/products/lulu.html) · [Little Snitch](https://obdev.at/products/littlesnitch/index.html)
- 転送せず NXDOMAIN を返す構成は CoreDNS の `template` と `log` でも組める。今回の論点はリゾルバの新規性より、既存の非特権隔離内に受付を置けるかどうか。Zeek の `conn.log` は方向別バイト数を記録する。veil-tell の比較対象は個々の許可済み CONNECT の暗号化トンネルで、基準または TOML の上限でそのトンネルを打ち切る。[CoreDNS template](https://coredns.io/plugins/template/) · [CoreDNS log](https://coredns.io/plugins/log/) · [Zeek conn.log](https://docs.zeek.org/en/current/logs/conn.html)

## ロードマップ

**現在地：0.6.0 実装ブランチ**

0.5.1 では、隔離内外で同じプロジェクト内の pnpm ストアを使う。実効的な `storeDir` が確認できなければ `node_modules` に触る前に終了コード `125` で止める。

### 0.5.2 で対応した互換性の問題

- Puppeteer がダウンロードした Chrome が一時ホームに入り、インストール終了時に消える。
- Corepack の shim やホーム下に入れた pnpm が隔離内で起動できず、ストア設定のエラーとして表示される。
- CI が新規宛先で `21` を返す際に承認候補が残らず、直後の `veil-tell accept` が `125` になる。README に承認手順を載せる。
- `NPM_CONFIG_PREFIX` を設定しただけで npm ライフサイクルの通信帰属が無効になり、カスタムシェルを使っているかのように表示される。

完了条件は、Puppeteer のようにホームへダウンロードするパッケージが隔離インストール後も成果物を使えること、準備済みの pnpm が起動し起動失敗時には原因が分かること、プロジェクトの基準を使った CI でレビュー後に `accept` が通ること、prefix 設定があっても通信の推定帰属が残ること。pnpm のストア事前確認と隔離による通信制限も回帰試験で確認する。

### v0.6.0 の設計判断

`agent-env` はシェルの PATH を変更する。エージェントごとの設定ファイルに変更を加えず、どの実行ファイルが選ばれるかを利用者が確認できる。shim は親の PATH から自身のディレクトリを除いて実行する。局所的な TLS トンネルの転送量を記録し、拒否前のアプリケーション上の送信予定量は推定しない。帰属の推定と lockfile に含まれる事実は別々に表示する。

隔離内の対象プロセスを起動する Linux スレッドに seccomp 通知を設定し、別スレッドで sockaddr を読み取る。元のネットワーク名前空間と seccomp 制限はそのまま適用する。Linux 6.12.95 aarch64 の非特権実験では 16 バイトの IPv4 アドレスを読み取れた。curl の直接 DNS は `127.0.0.1:53`、IP 指定の Python 接続は宛先と回数が記録された。名前解決先と質問名を混同しないため、段階 A に限る。[実験](../experiments/dns-attempts/README.md)

fake-IP は「すべての回答が 198.18.0.0/15」であるというヒントであり、VPN 製品を断定しない。混在回答とホスト自身のインターフェースは opt-in でも拒否する。HTTP 上流を明示した場合、その経路の最終的な IP 検査は上流で行う。

0.8 に想定していたエージェント用入口を 0.6 に含める。次版の順序は実測と利用者の反応を受けて決める。
