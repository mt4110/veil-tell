# 名前解決の試みの観測

隔離モードでは、Node.js の `dns.lookup` を使う名前解決を既存のローカル中継で記録し、ENOTFOUND を返す。中継はこの経路からホストの名前解決や TCP 接続を行わない。終了コード 21 は、CI で新しい CONNECT または新しい名前解決の試みを観測したときに使う。JSON v1 の `attempted` と `comparison.attempted_added` は追加フィールド。基準に `attempted` がない場合は従来の基準として読み込む。

npm のスクリプトが中継に渡した帰属は推定。スクリプトがフックや帰属用の環境を外す、偽の名前を中継に送る、別プロセスに委譲するといった操作ができる。カーネルの隔離は別に維持される。IP 直打ち、curl・Python・Go のシステムリゾルバ、Node.js の `dns.resolve`、ネイティブアドオンは観測範囲外。試みが空でも、この範囲外での試行はあり得る。記録した名前はローカルの JSON に含まれるため、共有前に確認する。

Linux のループバック DNS 受付は、名前を転送せず記録できることを実験で確認した。Ubuntu の既存 AppArmor 設定では 53 番ポートへの bind が拒否され、高いポートは一般のシステムリゾルバの既定経路にできない。macOS ではシステムリゾルバが mDNSResponder を使う。その IPC の禁止を維持した。DYLD での差し替えは保護対象の実行ファイルや静的リンクを含めた共通の方式にならない。Linux の seccomp 通知は IP 接続の観測候補だが、アドレス引数を読むには対象プロセスへのアクセスが要り、並行書き換えも扱う必要がある。ネットワーク隔離の代替には使わない。

- [受信側との対照実験](../experiments/dns-attempts/README.md)
- [Apple mDNSResponder](https://github.com/apple-oss-distributions/mDNSResponder)
- [Linux kernel seccomp documentation](https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html)
