# npm 保守者への導入検証のお願い

## 送付用

**件名　veil-tell の npm 導入手順を試してもらえますか？**

npm の依存更新で、インストール時に新しい宛先へ通信しようとすると CI で知らせる OSS を作っています。普段 npm プロジェクトを保守している方に、ご自身のプロジェクトで README を見ながら最初の導入を試してもらいたいです。手順が分かりづらかったところを知りたいので、途中まででも助かります。

対象は、ルートに `package-lock.json` があり、公開レジストリから認証情報なしで `npm ci` が通る GitHub プロジェクトです。GitHub Actions を有効にして既定ブランチにワークフローを置ける、シークレットを入れていない検証用コピーでお願いします。依存更新と対照の PR はこのコピーの中で試してください。コピーの準備が済んだら、[veil-tell の README](https://github.com/mt4110/veil-tell/blob/f016b47b2183e6502562023c751c54f4d552439e/README.md#使い方)を開いたところから計り始めてください。導入手順は README と、そこから開けるガイドを使ってください。

1. 基準候補を採取する。候補の宛先と用途を確認し、説明できるものを基準として PR のベースブランチに保存する。用途が分からない宛先で止まったら記録に残す。
2. 依存を1件更新する検証用 PR で、通常の `npm ci` を実行し、veil-tell の終了コード `0` を要約と JSON で確認する。
3. 同じ PR に下の対照入力を加え、未登録 CONNECT による veil-tell の終了コード `21` を要約と JSON で確認する。対照を含む PR は結果確認後にマージせず閉じてください。

手を動かした時間と CI を待った時間を、ざっくり分けて教えてください。詰まったら、最初に止まった画面やコマンド、そこで何が分からなかったかを一言残してもらえると助かります。最後に、要約から見つけた宛先と、その依存更新を保留するか、承認前に何を確認するかを教えてください。結果は同封の記録ひな形で返してください。要約の表示と JSON の該当項目、エラーが出た場合はその該当行だけで十分です。

## 添付する対照入力

通常実行の結果を記録してから、同じ検証用 PR に加えます。基準、ワークフロー、ロックファイルは通常実行のものを使います。

以下をプロジェクト直下の `veil-onboarding-connect.cjs` に保存してください。`package.json` の `scripts.postinstall` が未設定なら `npm pkg set 'scripts.postinstall=node veil-onboarding-connect.cjs'` で設定できます。既存の `postinstall` がある場合は、元の処理が成功した後に `node veil-onboarding-connect.cjs` を実行するよう追加します。元が単一のコマンドなら、末尾に ` && node veil-onboarding-connect.cjs` を加えます。この2ファイルを検証用 PR にコミットして push してください。

スクリプトは認証付きのローカルプロキシがあるときだけ、予約済みの `.test` ドメインへの CONNECT を送ります。送信データは CONNECT の宛先とプロキシ認証ヘッダーに限ります。HTTP `403` を受けたらスクリプトは成功で戻るため、npm の成否と veil-tell の判定をそれぞれ確認できます。

```js
const net = require("node:net");

const destination = "veil-onboarding-control.test:443";
if (!process.env.HTTPS_PROXY) process.exit(0);
const proxy = new URL(process.env.HTTPS_PROXY);
if (!["127.0.0.1", "localhost"].includes(proxy.hostname) ||
    !proxy.port || !proxy.username || !proxy.password) {
  process.exit(0);
}

const auth = Buffer.from(`${proxy.username}:${proxy.password}`).toString("base64");
const socket = net.createConnection({host: proxy.hostname, port: Number(proxy.port)});
let response = "";
socket.setTimeout(5000, () => socket.destroy(new Error("CONNECT timed out")));
socket.on("connect", () => socket.write(
  `CONNECT ${destination} HTTP/1.1\r\nHost: ${destination}\r\nProxy-Authorization: Basic ${auth}\r\n\r\n`
));
socket.setEncoding("ascii");
socket.on("data", chunk => {
  response += chunk;
  if (!response.includes("\r\n")) return;
  const status = response.split("\r\n")[0];
  console.log(`Control CONNECT ${destination}: ${status}`);
  if (!/^HTTP\/1\.[01] 403(?: |$)/.test(status)) process.exitCode = 1;
  socket.destroy();
});
socket.on("end", () => {
  if (!response.includes("\r\n")) process.exitCode = 1;
});
```
