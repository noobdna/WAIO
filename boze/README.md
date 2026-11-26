# boze/

BOZE は 800 上のローカル AI ワーカー。この配下にはコードだけを置く。
案件データ・ログ本体・鍵・認証情報はこのリポジトリ (public) に入れない。

| ディレクトリ | 役割 | 状態 |
|---|---|---|
| `audit/` | 追記専用・ハッシュ鎖の監査ログ (`auditlog.py`) | P2-2 |

## audit/auditlog.py

```sh
python3 -I boze/audit/auditlog.py append --log LOG --actor boze --action llm.request \
    --payload-file - --detail-json '{"job":"J01"}' < request.json
python3 -I boze/audit/auditlog.py head   --log LOG              # → off-host anchor (seq, line_sha256)
python3 -I boze/audit/auditlog.py verify --log LOG --anchor SEQ:SHA256
```

- **改ざん防止ではなく改ざん検出**です。ログ書き込み権限を持つ者は書き換えられますが、
  チェックポイントと**外部アンカー**(800 の外に控えた head 値)すべてを揃えない限り verify で検出されます。
- 本文には payload の SHA-256 だけを記録し、payload 本体は保存しません。
- 改ざんを検出した後は append を拒否します (fail closed)。
- 運用では、ログファイルに `chflags uappnd` を付けて使うことを想定しています (テスト済み)。

テスト: `tests/boze_audit_log_test.sh` (19 件。一時ディレクトリだけを使い、ネットワークには出ない)
