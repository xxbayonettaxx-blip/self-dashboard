/**
 * Self-Dashboard Server (Phase 3: SQLite ＆ WAL ＆ セキュリティ硬化版)
 * 
 * 【学習目的・原理原則】
 * 1. JSONファイルから本格的なRDBMS（SQLite3）への移行。
 * 2. WAL（Write-Ahead Logging）モードによるマルチプロセス並行アクセスのロック防止。
 * 3. プリペアドステートメント（? プレースホルダ）によるSQLインジェクション完全遮断。
 * 4. DB制約（PRIMARY KEY, CHECK制約）によるデータ整合性の二重防衛。
 * 5. 【改善】Bufferの物理バイト数による厳密な1MB DoS防御（文字数との乖離を解消）。
 * 6. 既存データ（metrics.json）からの初回自動マイグレーション。
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const Database = require('better-sqlite3');

const PORT = 3000;
const DB_FILE = path.join(__dirname, 'data', 'dashboard.sqlite');
const LEGACY_JSON_FILE = path.join(__dirname, 'data', 'metrics.json');
const PUBLIC_DIR = path.join(__dirname, 'public');
const MAX_BODY_BYTES = 1 * 1024 * 1024; // 1MB（物理バイト数上限）

// --- データベース初期化 ---
const db = new Database(DB_FILE);

// ① WALモード有効化（読み込みと書き込みを並行可能にし、Phase 5のcronバックアップ時もロックしない）
db.pragma('journal_mode = WAL');

// ② テーブル作成（主キーとCHECK制約）
db.exec(`
  CREATE TABLE IF NOT EXISTS daily_logs (
    date TEXT PRIMARY KEY,
    work_minutes INTEGER NOT NULL CHECK(work_minutes >= 0),
    sleep_minutes INTEGER NOT NULL CHECK(sleep_minutes >= 0 AND sleep_minutes <= 1440),
    fatigue_level INTEGER NOT NULL CHECK(fatigue_level IN (0, 1, 2)),
    created_at TEXT DEFAULT (datetime('now', 'localtime')),
    updated_at TEXT DEFAULT (datetime('now', 'localtime'))
  );
`);

// ③ 既存JSONデータからの自動マイグレーション（初回のみ）
const rowCount = db.prepare('SELECT COUNT(*) as count FROM daily_logs').get().count;
if (rowCount === 0 && fs.existsSync(LEGACY_JSON_FILE)) {
  try {
    const raw = fs.readFileSync(LEGACY_JSON_FILE, 'utf-8');
    const legacyLogs = JSON.parse(raw || '[]');
    if (Array.isArray(legacyLogs) && legacyLogs.length > 0) {
      const insertStmt = db.prepare(`
        INSERT INTO daily_logs (date, work_minutes, sleep_minutes, fatigue_level)
        VALUES (?, ?, ?, ?)
      `);
      const migrate = db.transaction((logs) => {
        for (const log of logs) {
          insertStmt.run(log.date, log.work_min || 0, log.sleep_min || 0, log.fatigue_level || 0);
        }
      });
      migrate(legacyLogs);
      console.log(`📦 [Migration] metrics.json から ${legacyLogs.length} 件のデータを SQLite へ自動移行しました。`);
    }
  } catch (err) {
    console.error('マイグレーション警告:', err.message);
  }
}

/**
 * 簡易MIMEタイプリスト
 */
const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.ico': 'image/x-icon',
  '.svg': 'image/svg+xml'
};

/**
 * JSONレスポンス送信ヘルパー関数
 */
function sendJsonResponse(res, statusCode, data) {
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store'
  });
  res.end(JSON.stringify(data));
}

/**
 * HTTPサーバー本体
 */
const server = http.createServer((req, res) => {
  const startTime = Date.now();
  const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';

  // 通信完了ログ（観測性）
  res.on('finish', () => {
    const duration = Date.now() - startTime;
    const logTime = new Date().toISOString();
    console.log(`[${logTime}] ${clientIp} | ${req.method} ${req.url} -> ${res.statusCode} (${duration}ms)`);
  });

  try {
    const parsedUrl = new URL(req.url, `http://${req.headers.host || 'localhost:3000'}`);
    const pathname = parsedUrl.pathname;

    // --- ルーティング 1: GET /api/stats (SQLiteから時系列統計を取得) ---
    if (pathname === '/api/stats' && req.method === 'GET') {
      const selectStmt = db.prepare(`
        SELECT 
          date, 
          work_minutes as work_min, 
          sleep_minutes as sleep_min, 
          fatigue_level 
        FROM daily_logs 
        ORDER BY date ASC
      `);
      const rows = selectStmt.all();
      return sendJsonResponse(res, 200, rows);
    }

    // --- ルーティング 2: POST /api/logs (日次データのUPSERT登録・更新) ---
    if (pathname === '/api/logs' && req.method === 'POST') {
      let receivedBytes = 0; // ★物理バイト数カウンター
      let body = '';
      let isTooLarge = false;

      req.on('data', chunk => {
        // ★ chunk は Buffer オブジェクト。chunk.length は純粋な物理バイト数！
        receivedBytes += chunk.length;
        if (receivedBytes > MAX_BODY_BYTES) {
          isTooLarge = true;
          req.destroy(); // TCPソケット切断
          return sendJsonResponse(res, 413, { error: 'Payload Too Large: データサイズ上限（1MB）を超過しました。' });
        }
        body += chunk;
      });

      req.on('end', () => {
        if (isTooLarge) return;

        let newLog;
        try {
          newLog = JSON.parse(body);
        } catch (err) {
          return sendJsonResponse(res, 400, { error: 'Bad Request: 不正なJSON形式です。' });
        }

        const { date, sleep_min, fatigue_level, work_min } = newLog;

        // 日付形式チェック (YYYY-MM-DD)
        if (!date || !/^\d{4}-\d{2}-\d{2}$/.test(date)) {
          return sendJsonResponse(res, 400, { error: 'Bad Request: 日付は YYYY-MM-DD 形式で入力してください。' });
        }
        
        // ① まず「空っぽ（null, undefined, 空文字）」ではないかを厳密にチェック（必須項目）
        if (sleep_min === null || sleep_min === undefined || sleep_min === '') {
          return sendJsonResponse(res, 400, { error: 'Bad Request: 睡眠時間は必須項目です。' });
        }
        if (work_min === null || work_min === undefined || work_min === '') {
          return sendJsonResponse(res, 400, { error: 'Bad Request: 作業時間は必須項目です。' });
        }
        if (fatigue_level === null || fatigue_level === undefined || fatigue_level === '') {
          return sendJsonResponse(res, 400, { error: 'Bad Request: 疲労度は必須項目です。' });
        }

        const sleep = Number(sleep_min);
        const work = Number(work_min);
        const fatigue = Number(fatigue_level);

        
        // 数値・範囲チェック（アプリ層での事前バリデーション）
        if (isNaN(sleep) || sleep < 0 || sleep > 1440) {
          return sendJsonResponse(res, 400, { error: 'Bad Request: 睡眠時間は 0〜1440分以内で入力してください。' });
        }
        if (isNaN(work) || work < 0 || work > 1440) {
          return sendJsonResponse(res, 400, { error: 'Bad Request: 作業時間は 0〜1440分以内で入力してください。' });
        }
        if (![0, 1, 2].includes(fatigue)) {
          return sendJsonResponse(res, 400, { error: 'Bad Request: 疲労度は 0, 1, 2 のいずれかです。' });
        }

        // ★ SQLインジェクション防止（プレースホルダ ?） ＆ UPSERT（同日データは上書き更新）
        const upsertStmt = db.prepare(`
          INSERT INTO daily_logs (date, work_minutes, sleep_minutes, fatigue_level, updated_at)
          VALUES (?, ?, ?, ?, datetime('now', 'localtime'))
          ON CONFLICT(date) DO UPDATE SET
            work_minutes = excluded.work_minutes,
            sleep_minutes = excluded.sleep_minutes,
            fatigue_level = excluded.fatigue_level,
            updated_at = datetime('now', 'localtime')
        `);

        try {
          upsertStmt.run(date, work, sleep, fatigue);
          const record = { date, sleep_min: sleep, fatigue_level: fatigue, work_min: work };
          return sendJsonResponse(res, 201, { message: 'SQLiteにログを正常に記録しました。', record });
        } catch (dbError) {
          console.error('DB書き込みエラー:', dbError);
          return sendJsonResponse(res, 400, { error: `Database Error: ${dbError.message}` });
        }
      });

      return;
    }

    // --- ルーティング 3: 静的ファイル配信 ---
    if (req.method === 'GET') {
      let relativePath = pathname === '/' ? 'index.html' : pathname.replace(/^\//, '');
      const filePath = path.normalize(path.join(PUBLIC_DIR, relativePath));

      // パストラバーサル防止
      if (!filePath.startsWith(PUBLIC_DIR)) {
        return sendJsonResponse(res, 403, { error: 'Forbidden: 不正なパスです。' });
      }

      if (fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
        const ext = path.extname(filePath).toLowerCase();
        const contentType = MIME_TYPES[ext] || 'application/octet-stream';
        const fileStream = fs.createReadStream(filePath);
        res.writeHead(200, { 'Content-Type': contentType });
        fileStream.pipe(res);
        return;
      }

      return sendJsonResponse(res, 404, { error: 'Not Found: 該当するファイルまたはAPIが存在しません。' });
    }

    return sendJsonResponse(res, 405, { error: 'Method Not Allowed' });

  } catch (error) {
    console.error('サーバーエラー:', error);
    return sendJsonResponse(res, 500, { error: 'Internal Server Error' });
  }
});

server.listen(PORT, () => {
  console.log(`====================================================`);
  console.log(`🚀 Self-Dashboard SQLiteサーバーが起動しました`);
  console.log(`📡 URL: http://localhost:${PORT}`);
  console.log(`💾 SQLite DB: ${DB_FILE}`);
  console.log(`⚡ WAL Mode: 有効 (journal_mode = WAL)`);
  console.log(`====================================================`);
});
