# Phase 100 / 101 検証記録

本ドキュメントはコード変更を一切伴わない記録・報告専用のファイルである。
WAIO Global Cyber Intelligence Patrol（Phase 100）および
Critical Infrastructure & Military Precursor Watch（Phase 101）の実装後に
行った検証結果を記録する。既存ファイル・本番設定・Guardian・Decision Engine・
既存スケジュールへの変更は本ドキュメント作成を含め一切行っていない。

- 記録日: 2026-10-09
- 対象: `security/incident_learning/global_patrol_cron.sh` /
  `global_patrol_report.py` / `critical_infra_watch.py` /
  `com.waio.global-patrol.plist.example` と、それぞれの
  `tests/*_test.sh`

## 1. PASS項目一覧

| 対象 | 結果 |
|---|---|
| `tests/critical_infra_watch_test.sh`（新規、Phase 101） | 16 passed, 0 failed |
| `tests/global_patrol_report_test.sh`（更新、Phase 100→101） | 31 passed, 0 failed |
| `tests/global_patrol_cron_test.sh`（Phase 100） | 42 passed, 0 failed |
| `tests/incident_learning_test.sh` | 35 passed, 0 failed |
| `tests/incident_learning_collector_test.sh` | 32 passed, 0 failed |
| `tests/incident_learning_evidence_test.sh` | 48 passed, 0 failed |
| `tests/incident_learning_human_gate_test.sh` | 45 passed, 0 failed |
| `tests/incident_learning_analyzer_test.sh` | 34 passed, 0 failed |
| `tests/incident_learning_promote_test.sh` | 55 passed, 0 failed |
| `tests/incident_learning_cron_test.sh` | 26 passed, 0 failed |
| `tests/incident_learning_lock_test.sh` | 29 passed, 0 failed |
| `tests/incident_learning_annotate_level_test.sh` | 43 passed, 0 failed |
| `tests/incident_learning_classification_test.sh` | 24 passed, 0 failed |
| `tests/incident_learning_correlator_test.sh` | 17 passed, 0 failed |
| `tests/decision_engine_test.sh` | 34 passed, 0 failed |
| 実データ形状での統合確認（候補ファイルをコピーした隔離環境で実施、本番状態は非破壊） | 成功。74件の既知candidateに対しセクション7が正しく生成され、単独事案から仮説が生成されないこと（S1）を実データ形状でも確認 |
| `bash -n` 全スクリプト構文チェック（CIのglob対象と同一） | OK |

セクション7（確認済み事実・仮説・未解決項目の区別）固有の確認結果:

| 区別 | テスト | 結果 |
|---|---|---|
| 単独事案から仮説を生成しない | S1 | PASS |
| 複数国・同一攻撃パターンが揃った場合のみ仮説生成（ゲートの陽性確認） | S1b | PASS |
| 裏付け不十分な場合は抑制し理由を報告（黙って破棄しない） | S1c | PASS |
| 確率・攻撃予定日を数値化しない（出力を再帰走査） | S2 | PASS |
| 確認済み事実／公的機関言及／WAIO仮説が構造的に別キー | S3 | PASS |
| 根拠不明時は「判定不能」、推測しない | S4 | PASS |
| carryoverが初検知日・最終確認日・出典・証拠状態・未解決理由を保持 | C2・C3 | PASS |
| 人間が明示的に解決するまで再掲、解決後は再掲されない | C4 | PASS（開発中に不具合を1件検出・修正済み、4章参照） |

## 2. 既存機能が変更されていないことの確認結果

`git diff --name-only` で個別に確認し、以下は全てbyte-for-byte無変更:

- `security/incident_learning/incident_learning_cron.sh`（既存1時間巡回本体）
- `security/incident_learning/com.waio.incident-learning.plist.example`
- `security/incident_learning/global_patrol_cron.sh`（72時間巡回ラッパー自体）
- `security/incident_learning/incident_normalizer.sh`（業種分類は独立モジュール内で判定し、本体は変更していない）
- `security/guardian.sh`
- `security/decision_engine/decision_engine.sh` / `decision_engine_lib.py`
- `security/egress_allowlist.conf` / `security/segments.conf`（本番設定）

## 3. 未完了事項と次回の確認手順

| # | 項目 | 状態 | 次回確認手順 |
|---|---|---|---|
| 1 | ShellCheck静的検査 | 未実施（この環境に未導入。インストールは行っていない） | shellcheckが導入された環境で `shellcheck -S error security/incident_learning/*.sh security/incident_learning/collectors/*.sh tests/*.sh` を実行する |
| 2 | launchd登録 | 未登録（`com.waio.global-patrol` / 既存の`com.waio.incident-learning`ともに登録なし。`~/Library/LaunchAgents`には`com.waio.dashboard-server.plist`のみ存在） | `launchctl list \| grep com.waio.global-patrol` で再確認する。登録作業自体は別途人間の承認を要する |
| 3 | 再起動後の継続動作テスト | 未実施（launchd登録自体が無いため前提条件が未整備） | launchd登録後、実際の再起動を行い `launchctl list` で確認する |

次回作業は、上記1〜3のいずれかの確認から開始できる。

## 4. npm prefix 書き込み権限エラー（WAIO本体の検証結果とは分離して記録）

ユーザーより報告された事象。本セッションのツール実行ログには該当するnpmコマンドの実行記録がなく、詳細未確認。WAIO本体（Phase 100/101）の検証結果・PASS/未完了判定には一切影響しない、独立した事象として記録する。

- 発生箇所: 未確認
- 実行コマンド: 未確認
- エラーメッセージ全文: 未確認
- WAIOリポジトリとの関連: 未確認（本リポジトリのテスト・スクリプトはいずれもnpmに依存しない）

詳細判明時に本セクションを更新する。

## 5. この記録の作成自体について

- 作成前に `security/incident_learning/` 配下に同名ファイルが存在しないことを読み取り専用で確認した（存在しなかったため新規作成）。
- 本ファイルの新規作成以外、リポジトリ内のいかなるファイルも変更していない。
- インストール・権限変更・再起動・サービス登録は行っていない。
