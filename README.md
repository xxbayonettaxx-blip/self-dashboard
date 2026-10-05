# 自己管理統計ダッシュボード (Self-Dashboard)

日常の身体・生活リズム（睡眠時間、作業時間、疲労度）を記録・可視化し、統計的に分析するためのWebダッシュボードです。

## 技術スタック
- **Runtime / Backend**: Node.js (標準 `http` モジュールによる生HTTPサーバー)
- **Database**: SQLite3 (`better-sqlite3`, WALモード並行制御)
- **Reverse Proxy**: Nginx (ポート80/443 ➔ ポート3000)
- **Frontend**: HTML5, CSS3, JavaScript (Fetch API), Chart.js v4
- **Security**: 
  - プレースホルダによるSQLインジェクション完全防止
  - 物理バイト数監視による1MB DoS防御
  - ディレクトリトラバーサル防止 (`path.normalize`)
  - 多層バリデーション（クライアントバイパス対策済み）

## 起動方法
```bash
# 依存関係のインストール
npm install

# サーバー起動 (ポート 3000)
npm start
```
