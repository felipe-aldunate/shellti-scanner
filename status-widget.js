/**
 * status-widget.js — ShellTI Scanner
 * Cronómetro + consultas restantes en ambas páginas.
 * Limpia estado anterior si el token cambia.
 */

(function() {

  // ── Token ──────────────────────────────────────────────────────────────────
  function getToken() {
    const urlToken = new URLSearchParams(window.location.search).get('token');
    if (urlToken) {
      const stored = localStorage.getItem('shellti_token');
      // Si el token de la URL es diferente al guardado → limpiar todo
      if (stored && stored !== urlToken) {
        clearAllState();
      }
      localStorage.setItem('shellti_token', urlToken);
      // Limpiar token de la URL sin recargar
      const url = new URL(window.location.href);
      url.searchParams.delete('token');
      window.history.replaceState({}, '', url.toString());
      return urlToken;
    }
    return localStorage.getItem('shellti_token') || '';
  }

  function clearAllState() {
    sessionStorage.removeItem('shellti_audit');
    sessionStorage.removeItem('shellti_perf');
    sessionStorage.removeItem('shellti_pending_url');
  }

  // ── Widget HTML ────────────────────────────────────────────────────────────
  function createWidget() {
    const el = document.createElement('div');
    el.id = 'sessionWidget';
    el.innerHTML = `
      <div style="display:flex;align-items:center;gap:6px">
        <span style="font-size:.6rem">⏱</span>
        <span id="sw-timer" style="font-family:'JetBrains Mono',monospace;font-size:.7rem;color:var(--cyan);min-width:56px">--:--:--</span>
      </div>
      <div id="sw-scans-wrap" style="display:none;align-items:center;gap:6px">
        <span style="font-size:.6rem">🔍</span>
        <span id="sw-scans-text" style="font-family:'JetBrains Mono',monospace;font-size:.7rem;color:var(--cyan)">--</span>
      </div>
      <div id="sw-warning" style="display:none;font-family:'JetBrains Mono',monospace;font-size:.58rem;padding:3px 10px;border-radius:2px;letter-spacing:.5px"></div>`;
    el.style.cssText = `display:flex;align-items:center;gap:14px;padding:5px 14px;border:1px solid var(--border);background:rgba(3,9,24,0.8)`;
    return el;
  }

  function injectWidget() {
    const navRight = document.querySelector('.nav-right');
    if (navRight) {
      navRight.prepend(createWidget());
    } else {
      const nav = document.querySelector('nav');
      if (nav) nav.appendChild(createWidget());
    }
  }

  // ── Formatear tiempo ───────────────────────────────────────────────────────
  function formatTime(ms) {
    if (ms <= 0) return '00:00:00';
    const s = Math.floor(ms / 1000);
    const h = Math.floor(s / 3600);
    const m = Math.floor((s % 3600) / 60);
    const sec = s % 60;
    return h > 0
      ? `${String(h).padStart(2,'0')}:${String(m).padStart(2,'0')}:${String(sec).padStart(2,'0')}`
      : `${String(m).padStart(2,'0')}:${String(sec).padStart(2,'0')}`;
  }

  // ── Estado global ──────────────────────────────────────────────────────────
  window._sessionStatus = null;

  function updateWidget(status) {
    window._sessionStatus = status;
    const timerEl  = document.getElementById('sw-timer');
    const scansWrap = document.getElementById('sw-scans-wrap');
    const scansText = document.getElementById('sw-scans-text');
    const warnEl   = document.getElementById('sw-warning');
    if (!timerEl) return;

    const msLeft  = new Date(status.expiresAt) - new Date();
    const expired = msLeft <= 0;

    // Cronómetro
    if (expired) {
      timerEl.textContent = 'EXPIRADO';
      timerEl.style.color = 'var(--danger)';
    } else {
      timerEl.textContent = formatTime(msLeft);
      timerEl.style.color = msLeft < 3600000 ? 'var(--warn)' : 'var(--cyan)';
    }

    // Consultas
    if (status.maxScans !== null && status.maxScans !== undefined) {
      const left = typeof status.scansLeft === 'number'
        ? status.scansLeft
        : Math.max(0, status.maxScans - (status.scansUsed || 0));
      scansWrap.style.display = 'flex';
      scansText.textContent   = `${left}/${status.maxScans}`;
      scansText.style.color   = left === 0 ? 'var(--danger)' : left <= 2 ? 'var(--warn)' : 'var(--cyan)';
    } else {
      scansWrap.style.display = 'none';
    }

    // Advertencias
    warnEl.style.display = 'none';
    if (expired) {
      warnEl.style.cssText = 'display:block;font-family:\'JetBrains Mono\',monospace;font-size:.58rem;padding:3px 10px;background:rgba(255,107,107,0.1);border:1px solid rgba(255,107,107,0.4);color:var(--danger);letter-spacing:.5px';
      warnEl.textContent = 'Acceso expirado';
    } else if (status.maxScans !== null && status.maxScans !== undefined) {
      const left = typeof status.scansLeft === 'number' ? status.scansLeft : Math.max(0, status.maxScans - (status.scansUsed || 0));
      if (left === 0) {
        warnEl.style.cssText = 'display:block;font-family:\'JetBrains Mono\',monospace;font-size:.58rem;padding:3px 10px;background:rgba(255,107,107,0.1);border:1px solid rgba(255,107,107,0.4);color:var(--danger);letter-spacing:.5px';
        warnEl.textContent = 'Consultas agotadas';
      } else if (left <= 2 && !expired) {
        warnEl.style.cssText = 'display:block;font-family:\'JetBrains Mono\',monospace;font-size:.58rem;padding:3px 10px;background:rgba(245,158,11,0.1);border:1px solid rgba(245,158,11,0.4);color:var(--warn);letter-spacing:.5px';
        warnEl.textContent = `⚠ ${left} consulta${left > 1 ? 's' : ''} restante${left > 1 ? 's' : ''}`;
      } else if (!expired && msLeft < 3600000) {
        warnEl.style.cssText = 'display:block;font-family:\'JetBrains Mono\',monospace;font-size:.58rem;padding:3px 10px;background:rgba(245,158,11,0.1);border:1px solid rgba(245,158,11,0.4);color:var(--warn);letter-spacing:.5px';
        warnEl.textContent = `⚠ Expira en ${formatTime(msLeft)}`;
      }
    } else if (!expired && msLeft < 3600000) {
      warnEl.style.cssText = 'display:block;font-family:\'JetBrains Mono\',monospace;font-size:.58rem;padding:3px 10px;background:rgba(245,158,11,0.1);border:1px solid rgba(245,158,11,0.4);color:var(--warn);letter-spacing:.5px';
      warnEl.textContent = `⚠ Expira en ${formatTime(msLeft)}`;
    }
  }

  // ── canScan / blockReason ──────────────────────────────────────────────────
  window.canMakeScan = function() {
    const s = window._sessionStatus;
    if (!s) return true;
    return s.canScan !== false;
  };

  window.getScanBlockReason = function() {
    const s = window._sessionStatus;
    if (!s) return null;
    const expired = new Date(s.expiresAt) < new Date();
    if (expired) return 'Tu acceso ha expirado. No puedes realizar nuevas consultas.';
    if (s.maxScans !== null && s.maxScans !== undefined) {
      const left = typeof s.scansLeft === 'number' ? s.scansLeft : Math.max(0, s.maxScans - (s.scansUsed || 0));
      if (left <= 0) return 'Has agotado tus consultas disponibles. Contacta al administrador.';
    }
    return null;
  };

  // ── Tick ───────────────────────────────────────────────────────────────────
  function tick() {
    if (window._sessionStatus) updateWidget(window._sessionStatus);
  }

  // ── Refresh desde servidor ─────────────────────────────────────────────────
  async function refreshStatus() {
    const token = localStorage.getItem('shellti_token');
    if (!token) { window.location.href = '/'; return; }
    try {
      const res  = await fetch('/auth/validate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token, strict: false })
      });
      const data = await res.json();
      if (!data.valid) {
        // Solo redirigir si el token es inválido de raíz (no si expiró o sin consultas)
        localStorage.removeItem('shellti_token');
        clearAllState();
        window.location.href = '/';
        return;
      }
      updateWidget(data);
    } catch(e) {}
  }

  window.refreshSessionStatus = refreshStatus;

  // ── Init ───────────────────────────────────────────────────────────────────
  // Llamar getToken() temprano para detectar nuevo token y limpiar estado
  const token = getToken();
  if (!token) { window.location.href = '/'; }

  document.addEventListener('DOMContentLoaded', () => {
    injectWidget();
    refreshStatus();
    setInterval(tick, 1000);
    setInterval(refreshStatus, 30000);
  });

})();
