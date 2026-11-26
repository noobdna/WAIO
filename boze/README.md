# boze/

BOZE は 800 上のローカル AI ワーカー。この配下にはコードだけを置く。
案件データ・ログ本体・鍵・認証情報はこのリポジトリ (public) に入れない。

| ディレクトリ | 役割 | 状態 |
|---|---|---|
| `audit/` | 追記専用・ハッシュ鎖の監査ログ (`auditlog.py`) | P2-2 |
| `llm/` | 127.0.0.1 専用の llama-server クライアント (`client.py`) と JSON スキーマ検証 (`schema.py`) | U1 |
| `approval/` | 人間の SSH 署名による承認ゲート (`approval.py`、namespace `boze-approval`、一度だけ使える) | U3 |
| `jobs/` | 仕事の状態遷移と、承認済みの操作だけを実行する実行器 (`jobs.py`) | U4 |

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

## 承認の流れ (U3/U4)

```
received → analyzed → drafted → awaiting_approval → approved → executed
                                  (却下 rejected / 期限切れ expired / 書き直し → drafted / 失敗 failed)
```

1. BOZE が `request_approval()` で `jobs/<id>/approval/request-<nonce>.json` を作る
   (job_id、操作、下書きの sha256、nonce、期限)
2. 人間が 800 の外で署名する:
   `ssh-keygen -Y sign -f <鍵> -n boze-approval request-<nonce>.json`
3. `execute()` は次の順に確認し、1つでも通らなければ何もしない (拒否は監査ログに記録する)
   - 下書きを読み直して計算した sha256
   - job_id と nonce
   - 期限
   - allowed_signers に登録された鍵での署名
   - nonce が台帳で未使用であること

   すべて通ったら nonce を使用済みにし、署名された下書きのバイト列そのものを outbox に書き出す
4. MVP で実行できる操作は `export_final` だけ。送信・応募・支払いを行うコードは無い

テスト:
- `tests/boze_audit_log_test.sh`: 監査ログ (19 件)
- `tests/boze_mvp_core_test.sh`: 監査ログ、U1、U3、U4 をまとめて実行する。使うのは一時ディレクトリ、127.0.0.1 のスタブ、使い捨ての鍵だけで、ネットワークには出ない
