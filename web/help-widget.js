(function () {
  if (document.getElementById('mudek-help-fab')) return;

  const PAGE_HINTS = {
    'my-exams.html':          { section: 's5', label: 'Başarı notu & sınav yükleme nasıl işler?' },
    'exams.html':             { section: 's5', label: 'Sınav notları nasıl hesaplanır?' },
    'questions.html':         { section: 's2', label: 'Soruları DÖÇ ile eşleştirme rehberi' },
    'doc-mapping.html':       { section: 's4', label: 'DÖÇ–PÇ matrisi nasıl kurulur?' },
    'reports.html':           { section: 's7', label: 'Kazanım eşiği (0.60) ne anlama gelir?' },
    'mudek-reports.html':     { section: 's7', label: 'Eşik altı çıktılar ne demek?' },
    'course-performance.html':{ section: 's8', label: 'DÖÇ & PÇ hesabı uçtan uca örnek' },
    'student-portfolio.html': { section: 's3', label: 'Program çıktıları (PÇ) nedir?' }
  };

  const page = (location.pathname.split('/').pop() || '').toLowerCase();
  const hint = PAGE_HINTS[page] || { section: '', label: 'MÜDEK & DÖÇ-PÇ hesaplama rehberi' };
  const href = 'mudek-rehber.html' + (hint.section ? '#' + hint.section : '');

  const style = document.createElement('style');
  style.textContent = `
    #mudek-help-fab {
      position: fixed; right: 22px; bottom: 22px; z-index: 9999;
      display: flex; align-items: center; gap: 10px;
      font-family: 'Inter', system-ui, sans-serif;
    }
    #mudek-help-fab .tip {
      background: #0b1f45; color: #fff; padding: 10px 14px;
      border-radius: 8px 8px 2px 8px; font-size: 12px; font-weight: 500;
      max-width: 230px; line-height: 1.4;
      box-shadow: 0 6px 18px rgba(0,0,0,.22);
      opacity: 0; transform: translateY(4px); pointer-events: none;
      transition: opacity .18s, transform .18s;
      border-left: 3px solid #c9a84c;
    }
    #mudek-help-fab:hover .tip,
    #mudek-help-fab:focus-within .tip {
      opacity: 1; transform: translateY(0);
    }
    #mudek-help-fab a.fab {
      width: 52px; height: 52px; border-radius: 50%;
      background: #0b1f45; color: #c9a84c;
      display: inline-flex; align-items: center; justify-content: center;
      box-shadow: 0 6px 18px rgba(11,31,69,.35);
      text-decoration: none; font-size: 24px; font-weight: 700;
      border: 2px solid #c9a84c;
      transition: transform .15s, background .15s;
      font-family: 'Playfair Display', Georgia, serif;
    }
    #mudek-help-fab a.fab:hover { background: #14306b; transform: scale(1.05); }
    #mudek-help-fab a.fab:focus-visible { outline: 3px solid #c9a84c; outline-offset: 2px; }
    @media print { #mudek-help-fab { display: none !important; } }
  `;
  document.head.appendChild(style);

  const wrap = document.createElement('div');
  wrap.id = 'mudek-help-fab';
  wrap.innerHTML =
    '<span class="tip">' + hint.label + '<br><small style="opacity:.7">Rehberi aç →</small></span>' +
    '<a class="fab" href="' + href + '" target="_blank" rel="noopener" title="MÜDEK Rehberi" aria-label="MÜDEK Rehberi">?</a>';

  (document.body || document.documentElement).appendChild(wrap);
})();
