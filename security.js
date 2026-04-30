/**
 * Age-Well 診断システム - セキュリティユーティリティ
 * XSS対策、入力サニタイゼーション、認証強化
 */

const Security = {
  /**
   * XSS対策: HTMLエスケープ
   * innerHTML の代わりに使用
   */
  escapeHtml(unsafe) {
    if (typeof unsafe !== 'string') return '';

    return unsafe
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  },

  /**
   * 安全なHTML生成
   * テンプレートリテラル用のタグ関数
   */
  html(strings, ...values) {
    let result = strings[0];
    for (let i = 0; i < values.length; i++) {
      result += this.escapeHtml(String(values[i])) + strings[i + 1];
    }
    return result;
  },

  /**
   * 安全な要素設定
   * innerHTML の代わりに使用
   */
  setContent(elementId, content, allowHtml = false) {
    const element = document.getElementById(elementId);
    if (!element) return;

    if (allowHtml) {
      // HTMLが必要な場合はサニタイズ済みコンテンツのみ許可
      element.innerHTML = content;
    } else {
      // デフォルトはテキストのみ
      element.textContent = content;
    }
  },

  /**
   * 入力値のサニタイゼーション
   */
  sanitizeInput(input) {
    if (typeof input !== 'string') return '';

    return input
      .trim()
      .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '') // script タグ除去
      .replace(/javascript:/gi, '') // javascript: プロトコル除去
      .replace(/on\w+\s*=/gi, ''); // イベントハンドラ除去
  },

  /**
   * メールアドレスのバリデーション
   */
  isValidEmail(email) {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(email);
  },

  /**
   * SHA-256 ハッシュ生成 (認証用)
   */
  async sha256(message) {
    const msgBuffer = new TextEncoder().encode(message);
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  },

  /**
   * HTTPS強制リダイレクト
   */
  enforceHttps() {
    if (location.protocol !== 'https:' &&
        location.hostname !== 'localhost' &&
        location.hostname !== '127.0.0.1') {
      location.replace(`https:${location.href.substring(location.protocol.length)}`);
    }
  },

  /**
   * ログイン試行回数制限
   */
  loginAttempts: {
    attempts: 0,
    lockedUntil: null,

    isLocked() {
      if (this.lockedUntil && Date.now() < this.lockedUntil) {
        return true;
      }
      if (this.lockedUntil && Date.now() >= this.lockedUntil) {
        this.reset();
      }
      return false;
    },

    increment() {
      this.attempts++;
      const maxAttempts = window.CONFIG?.SECURITY?.maxLoginAttempts || 5;

      if (this.attempts >= maxAttempts) {
        const lockoutDuration = window.CONFIG?.SECURITY?.lockoutDuration || 900000;
        this.lockedUntil = Date.now() + lockoutDuration;
        return true; // ロックされた
      }
      return false;
    },

    reset() {
      this.attempts = 0;
      this.lockedUntil = null;
    },

    getRemainingTime() {
      if (!this.lockedUntil) return 0;
      return Math.max(0, Math.ceil((this.lockedUntil - Date.now()) / 1000));
    }
  },

  /**
   * セッション管理
   */
  session: {
    key: 'agewell_session',

    set(data) {
      const session = {
        data,
        timestamp: Date.now(),
        expires: Date.now() + (window.CONFIG?.SECURITY?.sessionTimeout || 3600000)
      };
      localStorage.setItem(this.key, JSON.stringify(session));
    },

    get() {
      const sessionStr = localStorage.getItem(this.key);
      if (!sessionStr) return null;

      try {
        const session = JSON.parse(sessionStr);
        if (Date.now() > session.expires) {
          this.clear();
          return null;
        }
        return session.data;
      } catch (e) {
        this.clear();
        return null;
      }
    },

    clear() {
      localStorage.removeItem(this.key);
    },

    isValid() {
      return this.get() !== null;
    }
  },

  /**
   * CSP (Content Security Policy) ヘッダー情報
   * 実際のヘッダー設定はサーバー側で行う必要があります
   */
  getRecommendedCSP() {
    return {
      'Content-Security-Policy': [
        "default-src 'self'",
        "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com",
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
        "font-src 'self' https://fonts.gstatic.com",
        "connect-src 'self' https://script.google.com",
        "img-src 'self' data:",
        "frame-ancestors 'none'"
      ].join('; ')
    };
  }
};

// グローバルに公開
if (typeof window !== 'undefined') {
  window.Security = Security;
}
