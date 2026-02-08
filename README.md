# Learning Management App（学習管理アプリ）

子供2人の学習状況を **毎日記録し、週単位で振り返るための学習管理アプリ** です。  
家庭内で実際に困っていた課題を解決する目的で開発しています。

---

## 🎯 背景・目的（Why）

現在、子供2人の勉強を日々チェックしていますが、以下の課題がありました。

- 日々の学習内容は確認しているが、**履歴として残らない**
- **1週間単位での振り返り・比較ができない**
- 勉強時間や科目の偏りが **見える化されていない**

そこで、

> **「毎日1分で記録でき、週単位で学習状況を振り返れる」**

学習管理アプリを自分用に作成し、実際に運用することを目的としています。

---

## 🧩 概要（What）

- 子供ごとの学習記録を管理
- 学習内容（科目・時間・メモ）を日単位で記録
- 週単位で学習時間を集計・可視化
- 実際に家庭で利用・継続改善を前提とした設計

---

## 🖥️ 画面イメージ（MVP）

- **学習記録入力画面**  
  今日の学習内容を簡単に入力
- **週間一覧画面**  
  1週間分の学習履歴を一覧表示
- **週間サマリー画面**  
  科目別・合計学習時間の可視化

---

## 🛠 技術スタック（Tech Stack）

### フロントエンド
- Next.js
- TypeScript

### バックエンド
- Go
- REST API

### データベース
- PostgreSQL（予定）

### その他
- Docker（予定）
- GitHub Actions（CI予定）

---

## 🏗 アーキテクチャ概要

Next.js (TypeScript)
↓
Go API
↓
Database

フロントエンドとバックエンドを分離し、  
将来的な機能追加・スケールを意識した構成にしています。

---

## 🚀 今後の予定（Roadmap）

- [ ] 学習記録CRUD API
- [ ] 週間集計API
- [ ] フロント画面実装
- [ ] 実運用・改善
- [ ] グラフ表示・分析機能（検討）

---

## 👤 開発者メモ

- 実際に家庭で使用しながら改善予定
- ポートフォリオ目的だけでなく、**継続運用を前提**

---

## ✅ API検証（MVP）

### Migration

```bash
psql "$DATABASE_URL" -f migrations/001_create_users.sql
psql "$DATABASE_URL" -f migrations/002_create_children.sql
psql "$DATABASE_URL" -f migrations/003_create_tasks.sql
psql "$DATABASE_URL" -f migrations/004_create_study_logs.sql
psql "$DATABASE_URL" -f migrations/005_add_task_sort_order.sql
psql "$DATABASE_URL" -f migrations/006_make_password_hash_nullable.sql
psql "$DATABASE_URL" -f migrations/007_add_user_profile.sql
```

### curl例（login → token → children）

```bash
# signup
curl -s -X POST http://localhost:3000/api/v1/auth/signup \\
  -H "Content-Type: application/json" \\
  -d '{"email":"parent@example.com","password":"secret123"}'

# login
TOKEN=$(curl -s -X POST http://localhost:3000/api/v1/auth/login \\
  -H "Content-Type: application/json" \\
  -d '{"email":"parent@example.com","password":"secret123"}' | jq -r .token)

# create child
curl -s -X POST http://localhost:3000/api/v1/children \\
  -H "Authorization: Bearer $TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{"name":"Taro","grade":"1"}'

# list children
curl -s -X GET http://localhost:3000/api/v1/children \\
  -H "Authorization: Bearer $TOKEN"
```

### curl例（task 作成 → 一覧 → 更新）

```bash
# create task
curl -s -X POST http://localhost:3000/api/v1/children/$CHILD_ID/tasks \\
  -H "Authorization: Bearer $TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{"name":"Math Drill","subject":"math","default_minutes":20,"days_mask":62}'

# list tasks (archived=false default)
curl -s -X GET "http://localhost:3000/api/v1/children/$CHILD_ID/tasks" \\
  -H "Authorization: Bearer $TOKEN"

# update task (archive)
curl -s -X PATCH http://localhost:3000/api/v1/tasks/$TASK_ID \\
  -H "Authorization: Bearer $TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{"is_archived":true}'

# list archived tasks
curl -s -X GET "http://localhost:3000/api/v1/children/$CHILD_ID/tasks?archived=true" \\
  -H "Authorization: Bearer $TOKEN"
```

### curl例（daily PUT → GET）

```bash
# create child
CHILD_ID=$(curl -s -X POST http://localhost:3000/api/v1/children \\
  -H "Authorization: Bearer $TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{"name":"Taro","grade":"1"}' | jq -r .id)

# create task
TASK_ID=$(curl -s -X POST http://localhost:3000/api/v1/children/$CHILD_ID/tasks \\
  -H "Authorization: Bearer $TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{"name":"Math Drill","subject":"math","default_minutes":20,"days_mask":62}' | jq -r .id)

# PUT daily
curl -s -X PUT "http://localhost:3000/api/v1/children/$CHILD_ID/daily?date=2026-01-25" \\
  -H "Authorization: Bearer $TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{"items":[{"task_id":"'"$TASK_ID"'","minutes":20}]}'

# GET daily
curl -s -X GET "http://localhost:3000/api/v1/children/$CHILD_ID/daily?date=2026-01-25" \\
  -H "Authorization: Bearer $TOKEN"
```

### curl例（daily-view）

```bash
curl -s -X GET "http://localhost:3000/api/v1/children/$CHILD_ID/daily-view?date=2026-01-25" \\
  -H "Authorization: Bearer $TOKEN"
```

### curl例（calendar-summary）

```bash
curl -s -X GET "http://localhost:3000/api/v1/children/$CHILD_ID/calendar-summary?from=2026-01-01&to=2026-01-31" \\
  -H "Authorization: Bearer $TOKEN"
```

### calendar status 定義

- white: 未来日 or 対象タスクなし
- green: 完了 = 全タスク
- yellow: 一部完了
- red: 未完了

### curl例（summary）

```bash
# 1週間
curl -s -X GET "http://localhost:3000/api/v1/children/$CHILD_ID/summary?from=2026-01-01&to=2026-01-07" \\
  -H "Authorization: Bearer $TOKEN"

# 1ヶ月
curl -s -X GET "http://localhost:3000/api/v1/children/$CHILD_ID/summary?from=2026-01-01&to=2026-01-31" \\
  -H "Authorization: Bearer $TOKEN"
```

---

## OAuth（Google/GitHub）

### 環境変数

- `FRONTEND_URL` (例: `http://localhost:3001`)
- `OAUTH_REDIRECT_BASE_URL` (例: `http://localhost:3000`)
- `GOOGLE_CLIENT_ID`
- `GOOGLE_CLIENT_SECRET`
- `GITHUB_CLIENT_ID`
- `GITHUB_CLIENT_SECRET`

### 動作確認

1) 認証開始（ブラウザでアクセス）

- `http://localhost:3000/api/v1/auth/oauth/google/start`
- `http://localhost:3000/api/v1/auth/oauth/github/start`

2) 認証後、`FRONTEND_URL/login/callback?token=...` にリダイレクトされること

3) 受け取った token で API が使えること

```bash
curl -s -X GET http://localhost:3000/api/v1/children \\
  -H "Authorization: Bearer $TOKEN"
```

4) OAuth ログイン時は users に display_name / avatar_url / provider が保存される

### /me

ログイン済みユーザーのプロフィールを取得します。

```bash
curl -s -X GET http://localhost:3000/api/v1/me \\
  -H "Authorization: Bearer $TOKEN"
```

レスポンス例:

```json
{
  "user": {
    "id": "uuid",
    "email": "demo@example.com",
    "display_name": "Taro Yamada",
    "avatar_url": "https://...",
    "provider": "google"
  }
}
```
