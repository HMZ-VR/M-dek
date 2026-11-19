/* ==========================================================================
   KTUN Shell — paylaşılan UI yardımcıları
   - requireAuth(): token + role kontrolü, eksikse login'e atar
   - renderTopbar(): standart sticky topbar'ı çıkarır (auth-required sayfalar)
   - renderPublicTopbar(): public sayfalar için sade topbar
   - logout(): backend'e revoke isteği atar, sessionStorage temizler, login'e atar
   - apiFetch(path, opts): /api öneki + Bearer token ekler, 401'de logout
   - roleLabel(role): teknik role kodunu Türkçe etikete çevirir
   - htmlEscape(s): kullanıcı verisi için XSS-safe HTML çıktısı
   ========================================================================== */
(function (global) {
  'use strict';

  const API_BASE = '/api';

  // Inline KTU mührü (data URI) — harici görsel bağımlılığı yok.
  const KTUN_LOGO_SRC = 'ktun-logo.png';

  const ROLE_LABELS = {
    'admin':              'Yönetici',
    'bolum_baskani':      'Bölüm Başkanı',
    'ogretim_uyesi':      'Öğretim Üyesi',
    'mudek_kurul_uyesi':  'MÜDEK Kurul Üyesi',
    'arastirma_gorevlisi':'Araştırma Görevlisi',
    'komisyon_uyesi':     'Komisyon Üyesi',
    'student':            'Öğrenci',
  };

  function getUser() {
    try { return JSON.parse(sessionStorage.getItem('user') || '{}'); }
    catch { return {}; }
  }
  function getRole() {
    const u = getUser();
    return (u.role || sessionStorage.getItem('role') || '').toLowerCase();
  }
  function getToken() { return sessionStorage.getItem('token') || ''; }

  function roleLabel(role) {
    if (!role) return '—';
    return ROLE_LABELS[role.toLowerCase()] || role;
  }

  function htmlEscape(s) {
    if (s == null) return '';
    return String(s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  function requireAuth(opts) {
    opts = opts || {};
    const allowedRoles = (opts.roles || []).map(r => r.toLowerCase());
    const u = getUser();
    const role = getRole();
    if (!u.username || !role || !getToken()) {
      sessionStorage.setItem('postLoginRedirect', location.pathname + location.search);
      location.href = 'login.html';
      return null;
    }
    if (allowedRoles.length && !allowedRoles.includes(role)) {
      alert('Bu sayfa için yetkiniz yok.');
      location.href = 'dashboard.html';
      return null;
    }
    return { user: u, role };
  }

  async function logout() {
    const tok = getToken();
    if (tok) {
      try {
        await fetch(API_BASE + '/logout', {
          method: 'POST',
          headers: { 'Authorization': 'Bearer ' + tok },
        });
      } catch (_) { /* logout her durumda lokal temizlikle devam eder */ }
    }
    sessionStorage.clear();
    location.href = 'login.html';
  }

  async function apiFetch(path, opts) {
    opts = opts || {};
    const headers = Object.assign({}, opts.headers || {});
    const tok = getToken();
    if (tok) headers['Authorization'] = 'Bearer ' + tok;
    if (opts.body && !(opts.body instanceof FormData) && !headers['Content-Type']) {
      headers['Content-Type'] = 'application/json';
    }
    const url = path.startsWith('http') ? path
              : (path.startsWith('/api') ? path : API_BASE + (path.startsWith('/') ? path : '/' + path));
    const res = await fetch(url, Object.assign({}, opts, { headers }));
    if (res.status === 401) {
      sessionStorage.clear();
      alert('Oturum sona erdi, lütfen tekrar giriş yapın.');
      location.href = 'login.html';
      throw new Error('Unauthorized');
    }
    return res;
  }

  /**
   * Standart auth-required topbar.
   * - mountSelector: '#topbarMount' veya body başına otomatik enjekte
   * - active: 'dashboard' | 'reports' | ...  (tb-nav highlight)
   * - back: { href, label }  (geri tuşu)
   */
  function renderTopbar(opts) {
    opts = opts || {};
    const u = getUser();
    const role = getRole();
    const name = u.full_name || u.username || '—';
    const initial = (name.charAt(0) || '?').toUpperCase();

    const backHtml = opts.back
      ? `<a href="${htmlEscape(opts.back.href || 'dashboard.html')}" class="tb-back">
           <span class="mi">arrow_back</span>${htmlEscape(opts.back.label || 'Geri')}
         </a>`
      : '';

    const html = `
      <header id="topbar">
        <a href="dashboard.html" class="tb-logo">
          <div class="tb-logo-seal"><img id="tb_logo_img" alt="KTÜ"></div>
          <div>
            <div class="tb-brand-title">MÜDEK</div>
            <div class="tb-brand-sub">Konya Teknik Üniversitesi</div>
          </div>
        </a>
        <div class="tb-actions">
          ${backHtml}
          <div class="tb-user">
            <div class="tb-avatar">${htmlEscape(initial)}</div>
            <div><div class="tb-user-name">${htmlEscape(name)}</div></div>
          </div>
          <span class="tb-user-role">${htmlEscape(roleLabel(role))}</span>
          <button class="logout-btn" id="tb_logout_btn">
            <span class="mi">logout</span> Çıkış
          </button>
        </div>
      </header>
    `;
    insertTopbar(html);
    bindLogo();
    document.getElementById('tb_logout_btn').addEventListener('click', logout);
  }

  function renderPublicTopbar(opts) {
    opts = opts || {};
    const navLinks = [
      { href: 'index.html',        label: 'Anasayfa',     key: 'anasayfa' },
      { href: 'akreditasyon.html', label: 'Akreditasyon', key: 'akreditasyon' },
      { href: 'duyurular.html',    label: 'Duyurular',    key: 'duyurular' },
      { href: 'belgeler.html',     label: 'Belgeler',     key: 'belgeler' },
      { href: 'iletisim.html',     label: 'İletişim',     key: 'iletisim' },
    ];
    const navHtml = navLinks.map(l =>
      `<a href="${l.href}"${l.key === opts.active ? ' class="active"' : ''}>${l.label}</a>`
    ).join('');

    const html = `
      <header id="topbar">
        <a href="index.html" class="tb-logo">
          <div class="tb-logo-seal"><img id="tb_logo_img" alt="KTÜ"></div>
          <div>
            <div class="tb-brand-title">MÜDEK</div>
            <div class="tb-brand-sub">Konya Teknik Üniversitesi</div>
          </div>
        </a>
        <nav class="tb-nav">${navHtml}</nav>
        <div class="tb-actions">
          <a href="login.html" class="btn btn-outline btn-sm">
            <span class="mi">login</span> Giriş
          </a>
        </div>
      </header>
    `;
    insertTopbar(html);
    bindLogo();
  }

  function insertTopbar(html) {
    const mount = document.getElementById('topbarMount');
    if (mount) {
      mount.outerHTML = html;
    } else {
      document.body.insertAdjacentHTML('afterbegin', html);
    }
  }

  function bindLogo() {
    const img = document.getElementById('tb_logo_img');
    if (img) img.src = KTUN_LOGO_SRC;
  }

  function renderFooter() {
    if (document.querySelector('footer.ktun-footer')) return;
    const f = document.createElement('footer');
    f.className = 'ktun-footer';
    const yr = new Date().getFullYear();
    f.innerHTML = `© ${yr} <strong>Konya Teknik Üniversitesi</strong> — MÜDEK Akreditasyon Projesi`;
    document.body.appendChild(f);
  }

  /** Hero section helper — tek tek elle yazmak yerine. */
  function renderHero(opts) {
    opts = opts || {};
    const eyebrow = opts.eyebrow || '';
    const title = opts.title || '';
    const sub = opts.sub || '';
    const pill = opts.pill;
    const pillHtml = pill
      ? `<div class="role-pill"><span>${htmlEscape(pill.label)}</span></div>`
      : '';
    const wave = `
      <div class="hero-wave">
        <svg viewBox="0 0 1440 32" fill="none" preserveAspectRatio="none">
          <path d="M0 32 L0 16 Q360 0 720 16 Q1080 32 1440 16 L1440 32 Z" fill="#f7f5f0"/>
        </svg>
      </div>`;
    const html = `
      <div class="page-hero">
        <div class="hero-inner">
          <div class="hero-text">
            ${eyebrow ? `<div class="hero-eyebrow">${htmlEscape(eyebrow)}</div>` : ''}
            <h1 class="hero-title">${title}</h1>
            ${sub ? `<div class="hero-sub">${sub}</div>` : ''}
            ${pillHtml}
          </div>
        </div>
        ${wave}
      </div>`;
    const mount = document.getElementById('heroMount');
    if (mount) mount.outerHTML = html;
    else document.body.insertAdjacentHTML('beforeend', html);
  }

  // Toast — basit
  function toast(msg, kind) {
    let host = document.getElementById('ktun_toast_host');
    if (!host) {
      host = document.createElement('div');
      host.id = 'ktun_toast_host';
      host.style.cssText = 'position:fixed;top:80px;right:20px;z-index:2000;display:flex;flex-direction:column;gap:8px;';
      document.body.appendChild(host);
    }
    const el = document.createElement('div');
    el.className = 'alert alert-' + (kind || 'info');
    el.style.cssText = 'min-width:240px;max-width:360px;box-shadow:0 6px 20px rgba(11,31,69,.18);';
    el.innerHTML = `<span class="mi">${kind === 'danger' ? 'error' : kind === 'success' ? 'check_circle' : kind === 'warning' ? 'warning' : 'info'}</span><div>${htmlEscape(msg)}</div>`;
    host.appendChild(el);
    setTimeout(() => { el.style.transition = 'opacity .4s'; el.style.opacity = '0'; }, 3500);
    setTimeout(() => el.remove(), 4000);
  }

  /**
   * Yeni açılan öğrenci hesaplarını (geçici şifreleriyle) CSV olarak indirir.
   * Excel not/öğrenci yükleme sonrası hocaya verilir.
   *
   * accounts: [{ student_no, full_name, username, default_password }]
   * Kullanıcı adı sütunu GERÇEK kullanıcı adını yazar: backend 'username' yollar
   * (okul standardı f<no>); yoksa öğrenci no'dan f<no> türetilir — ham öğrenci
   * numarası ASLA kullanıcı adı olarak yazılmaz (öğrenci giriş yapamaz).
   */
  function downloadCredentials(accounts, filename) {
    if (!accounts || !accounts.length) return;
    const esc = v => {
      const s = String(v == null ? '' : v);
      return /[",\n;]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
    };
    const uname = a => {
      if (a.username) return a.username;
      const no = String(a.student_no == null ? '' : a.student_no).trim();
      return no ? (/^f/i.test(no) ? no : 'f' + no) : '';
    };
    const header = ['Öğrenci No', 'Ad Soyad', 'Kullanıcı Adı', 'Geçici Şifre'];
    const rows = accounts.map(a =>
      [a.student_no, a.full_name, uname(a), a.default_password].map(esc).join(','));
    const csv = '﻿' + header.join(',') + '\n' + rows.join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = filename || 'yeni-hesaplar.csv';
    document.body.appendChild(a); a.click();
    setTimeout(() => { URL.revokeObjectURL(url); a.remove(); }, 500);
    toast(accounts.length + ' yeni öğrenci hesabı CSV olarak indirildi. ' +
          'Geçici şifreler dosyada — öğrencilere iletin; ilk girişte değiştirecekler.', 'info');
  }

  global.KTUN = {
    API_BASE,
    getUser, getRole, getToken,
    roleLabel, htmlEscape,
    requireAuth, logout,
    apiFetch,
    renderTopbar, renderPublicTopbar, renderFooter, renderHero,
    toast,
    downloadCredentials,
  };
})(window);
