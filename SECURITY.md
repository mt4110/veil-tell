# セキュリティポリシー

[English](#security-policy)

## 脆弱性の報告

1. GitHub のリポジトリで **Security → Advisories → Report a vulnerability** が表示されている場合は、そのボタンから非公開で報告してください。 [リポジトリの Advisories](https://github.com/mt4110/veil-tell/security/advisories) · [GitHub の報告手順](https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/report-privately)
2. ボタンが表示されない場合は、公開 Issue で非公開の連絡先だけを尋ねてください。脆弱性の内容、再現手順、ログは非公開の連絡経路が確立してから共有してください。 [Issues](https://github.com/mt4110/veil-tell/issues)

対象のタグまたはコミット SHA、OS とアーキテクチャ、`proxy` / `isolated` の別、使用したポリシー、最小の再現手順、期待した挙動と実際の影響を添えてください。可能なら終了コード、JSON レポート、受信側の記録も添えてください。認証情報や個人情報は合成データに置き換え、再現は自分が管理する環境で行ってください。 [再現手順](docs/runbook.md)

現在は開発中です。報告では使用したコミットを特定してください。保守対象のリリース系列は、配布が始まった時点でこの文書に記載します。既知の観測範囲と制約は README で確認できます。 [日本語 README](README.md#観測範囲と既知の弱点)

## Security policy

### Reporting a vulnerability

1. If **Report a vulnerability** appears under **Security → Advisories**, use it to submit a private report. [Repository advisories](https://github.com/mt4110/veil-tell/security/advisories) · [GitHub reporting instructions](https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/report-privately)
2. If the button is unavailable, open a public issue asking for a private security contact. Share the vulnerability details, reproduction steps, and logs after a private channel is established. [Issues](https://github.com/mt4110/veil-tell/issues)

Include the tag or commit SHA, OS and architecture, the `proxy` or `isolated` backend, the policy, minimal reproduction steps, expected behavior, and observed impact. Include exit codes, the JSON report, and receiver logs when available. Replace credentials and personal data with synthetic values and reproduce the issue in an environment you control. [Runbook](docs/runbook.md)

veil-tell is in development. Identify the commit used in your report. Supported release series will be listed here once distribution begins. The README describes the capture scope and known limitations. [English README](README_EN.md#capture-scope-and-known-limitations)
