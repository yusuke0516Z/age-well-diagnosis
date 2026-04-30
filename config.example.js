/**
 * Age-Well 診断システム - セキュア設定ファイル (サンプル)
 *
 * ⚠️ 重要な注意事項:
 * 1. このファイルをコピーして config.js を作成してください
 * 2. config.js に実際の認証情報を設定してください
 * 3. config.js は絶対にGitにコミットしないでください (.gitignore に追加)
 */

const CONFIG = {
  // Google Apps Script URL
  // GASデプロイ後に取得したウェブアプリURLをここに設定
  GAS_URL: 'YOUR_GAS_URL_HERE',

  // 認証設定
  // 本番環境では、必ずサーバーサイド認証に移行してください
  // このクライアント側認証は一時的な措置です
  AUTH: {
    // 管理者メールアドレスのハッシュ値 (SHA-256)
    // 実際のメールアドレスは使用しないこと
    idHash: '',  // SHA-256ハッシュ値を設定

    // パスワードのハッシュ値 (SHA-256)
    pwHash: '',  // SHA-256ハッシュ値を設定
  },

  // セキュリティ設定
  SECURITY: {
    // HTTPS強制 (本番環境では必ず true)
    enforceHttps: true,

    // セッションタイムアウト (ミリ秒)
    sessionTimeout: 3600000, // 1時間

    // ログイン試行回数制限
    maxLoginAttempts: 5,
    lockoutDuration: 900000, // 15分
  }
};

// グローバルに公開 (後方互換性のため)
if (typeof window !== 'undefined') {
  window.CONFIG = CONFIG;
}
