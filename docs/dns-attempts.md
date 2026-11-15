# 名前解決の試みの観測

隔離モードでは、Node.js の `dns.lookup` を使う名前解決を既存のローカル中継で記録し、ENOTFOUND を返す。中継はこの経路からホストの名前解決や TCP 接続を行わない。終了コード 21 は、CI で新しい CONNECT または新しい名前解決の試みを観測したときに使う。JSON v1 の `attempted` と `comparison.attempted_added` は追加フィールド。基準に `attempted` がない場合は従来の基準として読み込む。

npm のスクリプトが中継に渡した帰属は推定。スクリプトがフックや帰属用の環境を外す、偽の名前を中継に送る、別プロセスに委譲するといった操作ができる。カーネルの隔離は別に維持される。IP 直打ち、curl・Python・Go のシステムリゾルバ、Node.js の `dns.resolve`、ネイティブアドオンは観測範囲外。試みが空でも、この範囲外での試行はあり得る。記録した名前はローカルの JSON に含まれるため、共有前に確認する。

Linux のループバック DNS 受付は、名前を転送せず記録できることを実験で確認した。Ubuntu の既存 AppArmor 設定では 53 番ポートへの bind が拒否され、高いポートは一般のシステムリゾルバの既定経路にできない。macOS ではシステムリゾルバが mDNSResponder を使う。その IPC の禁止を維持した。DYLD での差し替えは保護対象の実行ファイルや静的リンクを含めた共通の方式にならない。Linux の seccomp 通知は IP 接続の観測候補だが、アドレス引数を読むには対象プロセスへのアクセスが要り、並行書き換えも扱う必要がある。ネットワーク隔離の代替には使わない。

- [受信側との対照実験](../experiments/dns-attempts/README.md)
- [Apple mDNSResponder](https://github.com/apple-oss-distributions/mDNSResponder)
- [Linux kernel seccomp documentation](https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html)

## 次版の実測と判定

`CI=true veil-tell npm install` のような短いインストール実行は、隔離と既存の基準を要求する。通常のローカル実行で基準を採取してから CI に置く。短い任意コマンドに比較元がない場合、CI では観測した名前解決の試行を未登録として扱う。ローカルでは試行だけを理由に失敗させず、子の終了コードを引き継ぐ。名前解決が0件なら人間向けの個別行を出さず、隔離の JSON に `attempted: []` を残す。正規化した名前は253バイト、異なる名前は1,024件、合計試行数は16,384件が上限。記録上限を超えると `incomplete_capture` と終了コード125を返す。

### Linux の namespace 内 DNS

Ubuntu 26.04.1 の標準 bubblewrap 0.11.1 で、作成直後の network namespace は `ip_unprivileged_port_start=1024`。capability なしの UDP 53 bind は EACCES になった。検証目的で namespace 内のヘルパーに `CAP_NET_BIND_SERVICE` を指定した場合も、既存の AppArmor プロファイル `unpriv_bwrap` が同 capability を拒否した。ホストの設定は変えていない。

転送なしの NXDOMAIN 応答だけなら namespace 内の非特権ポート 15353 で動いた。ホスト側の模擬 DNS では対照が1件、隔離が0件だった。通常の `resolv.conf` が指定する DNS ポートは53なので、このデモだけでは curl・Python・Go の標準リゾルバを取り込めない。固定ポートが使える隔離構成の実証が次の条件になる。既存の隔離では、Node のフックと CONNECT 記録を使う。

### macOS の Seatbelt

macOS 27.2 で、隔離した curl は exit 6、プロキシを無効にした Python urllib は名前解決エラーになった。JSON にはどちらもホスト名が出なかった。sudo なしの `log stream` には Python に対する `mDNSResponder` ソケットの拒否や、別の Mach サービスの拒否、重複を要約した行が出た。問い合わせ名は得られず、ログ件数を通信試行件数として扱える根拠も得られなかった。

Python の `sitecustomize` は当該ランタイムの起動条件に依存する。Go の `GODEBUG=netdns` はリゾルバの選択・診断を変えるための指定で、共通の観測受付にはならない。curl の `--resolve` は静的に与えた名前を使う機能。これらを共通の遮断・記録機構には採用せず、JSON は観測した範囲を示す。
