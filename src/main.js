// Locke frontend — uses window.__TAURI__ injected by Tauri (withGlobalTauri: true)

//  Tauri helpers 
const invoke = (...a) => window.__TAURI__.core.invoke(...a);
const dialogOpen = (opts) => window.__TAURI__.dialog.open(opts);
const dialogSave = (opts) => window.__TAURI__.dialog.save(opts);

//  i18n 
let locale = {};
let currentLang = localStorage.getItem('lang') || 'en';
let currentTheme = localStorage.getItem('theme') || 'default';

function applyTheme(theme) {
  document.documentElement.dataset.theme = theme;
  currentTheme = theme;
  localStorage.setItem('theme', theme);
}

async function loadLocale(lang) {
  try {
    const res = await fetch(`./locales/${lang}.json`);
    locale = await res.json();
    currentLang = lang;
    localStorage.setItem('lang', lang);
    applyLocale();
  } catch (e) {
    console.warn('Failed to load locale:', lang, e);
  }
}

function t(key) {
  return locale[key] || key;
}

function typeText(el, text, speed = 40) {
  el.textContent = '';
  let i = 0;
  clearInterval(el._typeInterval);
  el.classList.add('typing-caret');
  el._typeInterval = setInterval(() => {
    el.textContent += text.charAt(i);
    i++;
    if (i >= text.length) {
      clearInterval(el._typeInterval);
      clearTimeout(el._typeTimeout);
      el._typeTimeout = setTimeout(() => el.classList.remove('typing-caret'), 2500);
    }
  }, speed);
}

function applyLocale() {
  document.querySelectorAll('[data-i18n]').forEach(el => {
    const key = el.dataset.i18n;
    if (el.classList.contains('typewriter')) {
      typeText(el, t(key));
    } else {
      el.textContent = t(key);
    }
  });
  document.querySelectorAll('[data-i18n-ph]').forEach(el => {
    el.placeholder = t(el.dataset.i18nPh);
  });
  // Update select options for autolock & clipboard
  // Update select options for autolock & clipboard and re-render recent files
  renderRecentFiles?.();
  updateCustomSelect('custom-autolock-select', [
    ['0', 'autolock_never'], ['1', 'autolock_1min'], ['5', 'autolock_5min'],
    ['15', 'autolock_15min'], ['30', 'autolock_30min'], ['60', 'autolock_1h']
  ]);
  updateCustomSelect('custom-clipboard-select', [
    ['0', 'clipboard_never'], ['10', 'clipboard_10s'],
    ['30', 'clipboard_30s'], ['60', 'clipboard_60s']
  ]);
  updateCustomSelect('custom-reveal-timeout-select', [
    ['0', 'autolock_never'], ['5', 'reveal_5s'], ['10', 'reveal_10s'], ['30', 'reveal_30s']
  ]);
  updateCustomSelect('custom-entry-timeout-select', [
    ['0', 'autolock_never'], ['30', 'entry_timeout_30s'], ['60', 'entry_timeout_60s'],
    ['120', 'entry_timeout_2min'], ['300', 'entry_timeout_5min']
  ]);
  updateCustomSelect('custom-wallet-words-select', [
    ['12', 'wallet_words_12'], ['24', 'wallet_words_24']
  ]);
}

function updateCustomSelect(id, options) {
  const container = document.getElementById(id);
  if (!container) return;
  const optionsContainer = container.querySelector('.select-items');
  const hiddenInput = container.querySelector('input[type="hidden"]');
  const display = container.querySelector('.select-selected');
  if (!optionsContainer || !hiddenInput || !display) return;
  
  const cur = hiddenInput.value;
  optionsContainer.innerHTML = '';
  let foundCur = false;
  
  options.forEach(([val, key]) => {
    const opt = document.createElement('div');
    opt.dataset.val = val;
    opt.dataset.i18n = key;
    opt.textContent = t(key);
    optionsContainer.appendChild(opt);
    if (val === cur) {
      display.textContent = t(key);
      foundCur = true;
    }
  });
  
  if (!foundCur && options.length > 0) {
    hiddenInput.value = options[0][0];
    display.textContent = t(options[0][1]);
  }
}


//  State 
let entries = [];
let activeCat = 'all';
let fromGenerator = null;
let totpTimer = null;

//  Boot 
document.addEventListener('DOMContentLoaded', async () => {
  applyTheme(currentTheme);
  await loadLocale(currentLang);
  wireTitlebar();
  await checkYubiKey();
  wireUnlock();
  wireSidebar();
  wireEntryModal();
  wireGenerator();
  wireSettings();
  wireCustomSelects();
});

function wireCustomSelects() {
  document.addEventListener('click', e => {
    const isSelect = e.target.closest('.custom-select');
    if (!isSelect) {
      document.querySelectorAll('.select-items').forEach(el => el.classList.add('hidden'));
      document.querySelectorAll('.select-arrow').forEach(el => el.classList.remove('open'));
      return;
    }
    
    const container = e.target.closest('.custom-select');
    const items = container.querySelector('.select-items');
    const arrow = container.querySelector('.select-arrow');
    const display = container.querySelector('.select-selected');
    const hiddenInput = container.querySelector('input[type="hidden"]');

    if (e.target.closest('.select-selected') || e.target.closest('.select-arrow')) {
      // Close others
      document.querySelectorAll('.select-items').forEach(el => {
        if (el !== items) el.classList.add('hidden');
      });
      document.querySelectorAll('.select-arrow').forEach(el => {
        if (el !== arrow) el.classList.remove('open');
      });
      items.classList.toggle('hidden');
      arrow.classList.toggle('open');
    } else if (e.target.closest('.select-items div')) {
      const option = e.target.closest('.select-items div');
      const i18nKey = option.dataset.i18n;
      if (i18nKey) {
        display.textContent = t(i18nKey);
        display.dataset.i18n = i18nKey;
      } else {
        display.innerHTML = option.innerHTML;
        delete display.dataset.i18n;
      }
      hiddenInput.value = option.dataset.val;
      items.classList.add('hidden');
      arrow.classList.remove('open');
      
      // Trigger change event manually for specific selects
      if (hiddenInput.id === 'setting-lang' || hiddenInput.id === 'quick-setting-lang') {
        loadLocale(hiddenInput.value);
      } else if (hiddenInput.id === 'setting-theme' || hiddenInput.id === 'quick-setting-theme') {
        applyTheme(hiddenInput.value);
      } else if (hiddenInput.id === 'swap-from-asset' || hiddenInput.id === 'swap-to-asset') {
        hiddenInput.dispatchEvent(new Event('change'));
      }
    }
  });
}

// ─── Titlebar ───────────────────────────────────────────────────────────────
function wireTitlebar() {
  function getWin() {
    const t = window.__TAURI__;
    if (t?.window?.getCurrentWindow) return t.window.getCurrentWindow();
    if (t?.webviewWindow?.getCurrentWebviewWindow) return t.webviewWindow.getCurrentWebviewWindow();
    if (t?.window?.getCurrent) return t.window.getCurrent();
    return null;
  }
  document.getElementById('titlebar-minimize')?.addEventListener('click', async () => {
    const win = await getWin();
    win?.minimize();
  });
  document.getElementById('titlebar-maximize')?.addEventListener('click', async () => {
    const win = await getWin();
    win?.toggleMaximize();
  });
  document.getElementById('titlebar-close')?.addEventListener('click', async () => {
    const win = await getWin();
    win?.close();
  });
}

//  YubiKey badge 
async function checkYubiKey() {
  try {
    const has = await invoke('has_yubikey');
    if (has) document.getElementById('yubikey-badge').classList.remove('hidden');
  } catch (_) {}
}

//  Unlock / Create vault 
function wireUnlock() {
  renderRecentFiles();
  wireDropZone();

  document.querySelectorAll('.tab').forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      const t = tab.dataset.tab;
      document.getElementById('form-open').classList.toggle('hidden', t !== 'open');
      document.getElementById('form-new').classList.toggle('hidden', t !== 'new');
      document.getElementById('unlock-error').classList.add('hidden');
    });
  });

  document.querySelectorAll('.btn-eye').forEach(btn => {
    btn.addEventListener('click', async () => {
      const inp = document.getElementById(btn.dataset.target);
      if (!inp) return;
      // If already revealed, re-hide immediately
      if (inp.type === 'text') {
        inp.type = 'password';
        clearTimeout(inp._revealTimer);
        return;
      }
      // Confirm reveal for entry-password only
      const s = loadSettings();
      if (inp.id === 'entry-password' && s.confirmReveal) {
        const ok = await showConfirmReveal();
        if (!ok) return;
      }
      inp.type = 'text';
      // Auto-hide timer
      const secs = parseInt(s?.revealTimeout ?? loadSettings().revealTimeout ?? '0');
      if (secs > 0) {
        clearTimeout(inp._revealTimer);
        inp._revealTimer = setTimeout(() => { inp.type = 'password'; }, secs * 1000);
      }
    });
  });

  document.getElementById('btn-browse-open').addEventListener('click', async () => {
    try {
      const selected = await dialogOpen({ filters: [{ name: 'Vault', extensions: ['vault'] }] });
      if (selected) document.getElementById('open-path').value = selected;
    } catch (_) {
      document.getElementById('open-path').removeAttribute('readonly');
      document.getElementById('open-path').focus();
    }
  });

  document.getElementById('btn-browse-new').addEventListener('click', async () => {
    try {
      const selected = await dialogSave({ defaultPath: 'passwords.vault', filters: [{ name: 'Vault', extensions: ['vault'] }] });
      if (selected) document.getElementById('new-path').value = selected;
    } catch (_) {
      document.getElementById('new-path').removeAttribute('readonly');
      document.getElementById('new-path').focus();
    }
  });

  document.getElementById('new-password').addEventListener('input', e => {
    const bar = document.getElementById('pw-strength-bar');
    const s = calcStrength(e.target.value);
    const colors = ['#293249', '#fb4c4c', '#f5a623', '#f5a623', '#27ae60'];
    bar.style.width = (s * 25) + '%';
    bar.style.background = colors[s];
  });

  document.getElementById('form-open').addEventListener('submit', async e => {
    e.preventDefault();
    const path = document.getElementById('open-path').value.trim();
    const pw = document.getElementById('open-password').value;
    if (!path) return showError('Select vault file path');
    
    const btn = e.target.querySelector('button[type="submit"]');
    const originalText = btn.innerHTML;
    btn.innerHTML = '<svg width="16" height="16" class="spin" style="margin-right:8px"><use href="#i-refresh"/></svg> Unlocking...';
    btn.disabled = true;
    
    try {
      await invoke('unlock_vault', { path, masterPassword: pw });
      failedAttempts = 0;
      await loadVault();
    } catch (err) {
      trackFailedAttempt();
      showError(err);
    } finally {
      btn.innerHTML = originalText;
      btn.disabled = false;
    }
  });

  document.getElementById('form-new').addEventListener('submit', async e => {
    e.preventDefault();
    const path = document.getElementById('new-path').value.trim();
    const pw = document.getElementById('new-password').value;
    const pw2 = document.getElementById('new-password2').value;
    if (!path) return showError('Select vault file path');
    if (pw !== pw2) return showError('Passwords do not match');
    const minLen = parseInt(loadSettings().pwMinLength ?? '8');
    if (pw.length < minLen) return showError(`Password must be at least ${minLen} characters`);
    try {
      await invoke('create_vault', { path, masterPassword: pw });
      await loadVault();
    } catch (err) {
      showError(err);
    }
  });
}

function showError(msg) {
  const el = document.getElementById('unlock-error');
  el.textContent = typeof msg === 'string' ? msg : JSON.stringify(msg);
  el.classList.remove('hidden');
}

//  Load vault UI 
async function loadVault() {
  const path = document.getElementById('open-path')?.value;
  if (path) { saveRecentFile(path); window._vaultPath = path; }

  // Security checks on vault open
  const s = loadSettings();
  if (s.debuggerDetect) {
    const detected = await invoke('check_debugger').catch(() => false);
    if (detected) {
      await invoke('lock_vault').catch(() => {});
      document.getElementById('screen-unlock').classList.remove('hidden');
      document.getElementById('screen-main').classList.add('hidden');
      toast(t('security_debugger_locked'), true);
      return;
    }
  }
  if (s.processMonitor) {
    const procs = await invoke('scan_processes').catch(() => []);
    if (procs.length > 0) {
      toast(t('security_suspicious_processes') + ': ' + procs.join(', '), true);
    }
  }
  if (s.windowMask) {
    invoke('set_window_title', { title: 'Untitled - Notepad' }).catch(() => {});
  }

  entries = await invoke('list_entries');
  document.getElementById('screen-unlock').classList.add('hidden');
  document.getElementById('screen-main').classList.remove('hidden');
  document.getElementById('entry-list')?.classList.toggle('compact', !!s.compact);
  renderEntries();
  // Load wallets silently
  loadWallets().catch(() => {});
}

//  Sidebar 
function wireSidebar() {
  document.getElementById('category-list').addEventListener('click', e => {
    const item = e.target.closest('.cat-item');
    if (!item) return;
    document.querySelectorAll('.cat-item').forEach(i => i.classList.remove('active'));
    item.classList.add('active');
    activeCat = item.dataset.cat;
    
    // Show vault screen, hide settings + wallet
    document.getElementById('screen-settings').classList.add('hidden');
    document.getElementById('screen-wallet').classList.add('hidden');
    document.getElementById('screen-vault').classList.remove('hidden');
    
    renderEntries();
  });

  document.getElementById('btn-settings')?.addEventListener('click', () => {
    document.querySelectorAll('.cat-item').forEach(i => i.classList.remove('active'));
    document.getElementById('screen-vault').classList.add('hidden');
    document.getElementById('screen-wallet').classList.add('hidden');
    document.getElementById('screen-settings').classList.remove('hidden');
  });

  document.getElementById('btn-wallet')?.addEventListener('click', () => {
    document.querySelectorAll('.cat-item').forEach(i => i.classList.remove('active'));
    document.getElementById('screen-vault').classList.add('hidden');
    document.getElementById('screen-settings').classList.add('hidden');
    document.getElementById('screen-wallet').classList.remove('hidden');
    loadWallets();
  });

  document.getElementById('btn-lock').addEventListener('click', async () => {
    await invoke('lock_vault');
    clearInterval(totpTimer);
    entries = [];
    failedAttempts = 0; // reset brute-force counter on explicit lock
    document.getElementById('screen-main').classList.add('hidden');
    document.getElementById('screen-unlock').classList.remove('hidden');
    document.getElementById('open-password').value = '';
    document.getElementById('unlock-error').classList.add('hidden');
    
    // Reset to vault screen for next unlock
    document.getElementById('screen-settings').classList.add('hidden');
    document.getElementById('screen-vault').classList.remove('hidden');
    document.querySelectorAll('.cat-item').forEach(i => i.classList.remove('active'));
    document.querySelector('.cat-item[data-cat="all"]').classList.add('active');
    activeCat = 'all';
    
    checkYubiKey();
  });

  document.getElementById('search-input').addEventListener('input', renderEntries);
  wireWallet();
}

//  Entry list render 
function renderEntries() {
  const query = document.getElementById('search-input').value.toLowerCase();
  const list = document.getElementById('entry-list');
  list.innerHTML = '';

  const filtered = entries.filter(e => {
    if (activeCat === 'favourite' && !e.favourite) return false;
    if (activeCat !== 'all' && activeCat !== 'favourite' && e.category !== activeCat) return false;
    if (query && !e.title.toLowerCase().includes(query) && !(e.username || '').toLowerCase().includes(query)) return false;
    return true;
  });

  if (!filtered.length) {
    list.innerHTML = '<p style="color:var(--muted);padding:20px;text-align:center">No items found</p>';
    return;
  }

  const settings_r = loadSettings();
  const pwAgeDays = parseInt(settings_r.pwAgeWarning ?? '0');
  const hidePw = settings_r.hidePasswords ?? false;

  filtered.forEach(entry => {
    const row = document.createElement('div');
    row.className = 'entry-row';
    let ageBadge = '';
    if (pwAgeDays > 0 && entry.updated_at) {
      const ageDays = (Date.now() - new Date(entry.updated_at).getTime()) / 86400000;
      if (ageDays > pwAgeDays) {
        ageBadge = `<span class="entry-age-badge"><svg width="11" height="11"><use href="#i-warning"/></svg> ${t('pw_age_warning')}</span>`;
      }
    }
    row.innerHTML = `
      ${faviconAvatarHtml(entry)}
      <div class="entry-info">
        <div class="entry-title">${esc(entry.title)}${entry.favourite ? ' <svg width="14" height="14" style="color:#f5a623"><use href="#i-star"></use></svg>' : ''}</div>
        <div class="entry-meta">${esc(entry.username || '')}${entry.url ? ' · ' + esc(formatUrl(entry.url)) : ''}</div>
      </div>
      <div class="entry-actions">
        ${entry.password && !hidePw ? '<button class="copy-btn" title="Copy Password"><svg width="14" height="14"><use href="#i-copy"></use></svg></button>' : ''}
        ${ageBadge}
      </div>`;
    row.querySelector('.copy-btn')?.addEventListener('click', ev => {
      ev.stopPropagation();
      navigator.clipboard.writeText(entry.password || '');
      toast(t('toast_copied'));        scheduleClipboardClear();    });
    row.addEventListener('click', () => openEntryModal(entry));
    list.appendChild(row);
  });
}

// ── Favicon avatar helpers ──────────────────────────────────────
function getFaviconUrl(rawUrl) {
  try {
    const u = rawUrl.startsWith('http') ? rawUrl : 'https://' + rawUrl;
    const domain = new URL(u).hostname;
    return `https://www.google.com/s2/favicons?sz=32&domain=${domain}`;
  } catch { return null; }
}

function faviconAvatarHtml(entry) {
  const letter = entry.title[0]?.toUpperCase() || '?';
  if (entry.url) {
    const src = getFaviconUrl(entry.url);
    if (src) {
      return `<div class="entry-avatar has-favicon" data-letter="${letter}">
        <img src="${src}" alt="${letter}"
          onload="this.parentElement.classList.add('loaded')"
          onerror="this.parentElement.innerHTML='${letter}';this.parentElement.classList.remove('has-favicon','loaded')" /></div>`;
    }
  }
  return `<div class="entry-avatar">${letter}</div>`;
}

function setEntryAvatar(el, entry) {
  if (!el) return;
  if (entry?.url) {
    const src = getFaviconUrl(entry.url);
    if (src) {
      el.className = 'entry-avatar has-favicon';
      el.innerHTML = `<img src="${src}" alt="${entry.title[0]?.toUpperCase() || '?'}"
        onerror="this.parentElement.innerHTML='${entry.title[0]?.toUpperCase() || '?'}';this.parentElement.classList.remove('has-favicon')" />`;
      return;
    }
  }
  el.className = 'entry-avatar';
  el.textContent = entry?.title[0]?.toUpperCase() || '?';
}

//  Entry Modal 
function wireEntryModal() {
  // Custom Select Logic
  const selectContainer = document.getElementById('custom-category-select');
  const selectDisplay = document.getElementById('entry-category-display');
  const selectOptions = document.getElementById('entry-category-options');
  const hiddenInput = document.getElementById('entry-category');

  selectDisplay.addEventListener('click', (e) => {
    e.stopPropagation();
    selectOptions.classList.toggle('hidden');
    selectContainer.classList.toggle('open');
  });

  selectOptions.querySelectorAll('div').forEach(opt => {
    opt.addEventListener('click', () => {
      const val = opt.dataset.val;
      selectDisplay.textContent = t(opt.dataset.i18n || val);
      hiddenInput.value = val;
      selectOptions.classList.add('hidden');
      selectContainer.classList.remove('open');
    });
  });

  document.addEventListener('click', () => {
    selectOptions.classList.add('hidden');
    selectContainer.classList.remove('open');
  });

  document.getElementById('btn-add-entry').addEventListener('click', () => openEntryModal(null));
  document.getElementById('btn-close-modal').addEventListener('click', closeEntryModal);
  document.getElementById('modal-entry').addEventListener('click', e => {
    if (e.target.id === 'modal-entry') closeEntryModal();
  });

  // View / Edit tab switching
  document.getElementById('tab-btn-view')?.addEventListener('click', () => switchEntryTab('view'));
  document.getElementById('tab-btn-edit')?.addEventListener('click', () => switchEntryTab('edit'));
  document.getElementById('btn-go-edit')?.addEventListener('click', () => switchEntryTab('edit'));

  // Delete from view panel
  document.getElementById('btn-delete-entry-view')?.addEventListener('click', async () => {
    const id = document.getElementById('entry-id').value;
    if (!id) return;
    if (!confirm(t('confirm_delete'))) return;
    await invoke('delete_entry', { id });
    entries = await invoke('list_entries');
    renderEntries();
    closeEntryModal();
    toast(t('toast_deleted'));
  });

  // Toggle password visibility in view panel
  document.getElementById('vf-pw-eye')?.addEventListener('click', () => {
    const span = document.getElementById('vf-password');
    if (span._revealed) {
      span.textContent = '••••••••••';
      span._revealed = false;
    } else {
      span.textContent = span._realValue || '';
      span._revealed = true;
    }
  });

  // Copy buttons in view panel
  document.getElementById('entry-view-panel')?.addEventListener('click', e => {
    const btn = e.target.closest('.view-copy-btn');
    if (!btn) return;
    const fieldId = btn.dataset.field;
    const el = document.getElementById(fieldId);
    if (!el) return;
    const text = btn.dataset.copyReal === 'true' ? (el._realValue || el.textContent) : el.textContent;
    navigator.clipboard.writeText(text);
    toast(t('toast_copied'));
    scheduleClipboardClear();
  });

  document.getElementById('btn-fill-gen').addEventListener('click', () => {
    fromGenerator = pw => { document.getElementById('entry-password').value = pw; };
    openGeneratorModal();
  });

  document.getElementById('form-entry').addEventListener('submit', async e => {
    e.preventDefault();
    await saveEntry();
  });

  document.getElementById('btn-delete-entry').addEventListener('click', async () => {
    const id = document.getElementById('entry-id').value;
    if (!id) return;
    if (!confirm(t('confirm_delete'))) return;
    await invoke('delete_entry', { id });
    entries = await invoke('list_entries');
    renderEntries();
    closeEntryModal();
    toast(t('toast_deleted'));
  });

  document.getElementById('btn-save-totp').addEventListener('click', async () => {
    const id = document.getElementById('entry-id').value;
    const secret = document.getElementById('entry-totp-secret').value.trim();
    if (!id || !secret) { toast(t('error_totp_save_first'), true); return; }
    try {
      const code = await invoke('add_totp_to_entry', { entryId: id, base32Secret: secret });
      entries = await invoke('list_entries');
      startTotpDisplay(id);
      toast(t('toast_totp_saved'));
    } catch (err) {
      toast('TOTP Error: ' + err, true);
    }
  });
}

function switchEntryTab(tab) {
  const isView = tab === 'view';
  document.getElementById('entry-view-panel').classList.toggle('hidden', !isView);
  document.getElementById('entry-edit-panel').classList.toggle('hidden', isView);
  document.getElementById('tab-btn-view')?.classList.toggle('active', isView);
  document.getElementById('tab-btn-edit')?.classList.toggle('active', !isView);
}

async function openEntryModal(entry) {
  const catKeyMap = { General: 'nav_general', Email: 'nav_email', Social: 'nav_social', Finance: 'nav_finance', Crypto: 'nav_crypto' };
  const isNew = !entry;

  // Header: title + avatar
  document.getElementById('modal-entry-title').textContent = isNew ? t('modal_new_item') : (entry.title || '');
  setEntryAvatar(document.getElementById('modal-entry-avatar'), entry);

  // Tabs: hidden for new, default to View for existing
  document.getElementById('entry-modal-tabs').classList.toggle('hidden', isNew);
  document.getElementById('entry-view-panel').classList.toggle('hidden', isNew);
  document.getElementById('entry-edit-panel').classList.toggle('hidden', !isNew);
  document.getElementById('tab-btn-view')?.classList.toggle('active', !isNew);
  document.getElementById('tab-btn-edit')?.classList.toggle('active', isNew);

  // Populate EDIT form
  document.getElementById('entry-id').value = entry?.id || '';
  document.getElementById('entry-title').value = entry?.title || '';
  document.getElementById('entry-username').value = entry?.username || '';
  document.getElementById('entry-password').value = entry?.password || '';
  document.getElementById('entry-url').value = entry?.url || '';
  document.getElementById('entry-notes').value = entry?.notes || '';
  document.getElementById('entry-favourite').checked = entry?.favourite || false;
  document.getElementById('entry-totp-secret').value = entry?.totp_secret || '';
  const cat = entry?.category || 'General';
  document.getElementById('entry-category').value = cat;
  document.getElementById('entry-category-display').textContent = t(catKeyMap[cat] || cat);
  document.getElementById('btn-delete-entry').classList.toggle('hidden', isNew);
  document.getElementById('btn-delete-entry-view')?.classList.toggle('hidden', isNew);

  // Populate VIEW panel
  if (!isNew) {
    document.getElementById('vf-username').textContent = entry.username || '—';
    const pwSpan = document.getElementById('vf-password');
    pwSpan.textContent = '••••••••••';
    pwSpan._realValue = entry.password || '';
    pwSpan._revealed = false;

    const urlField = document.getElementById('vf-url-field');
    if (entry.url) {
      document.getElementById('vf-url').textContent = entry.url;
      urlField.classList.remove('hidden');
    } else { urlField.classList.add('hidden'); }

    const notesField = document.getElementById('vf-notes-field');
    if (entry.notes) {
      document.getElementById('vf-notes').textContent = entry.notes;
      notesField.classList.remove('hidden');
    } else { notesField.classList.add('hidden'); }

    document.getElementById('vf-category').textContent = t(catKeyMap[cat] || cat);

    const totpField = document.getElementById('vf-totp-field');
    totpField.style.display = entry.totp_secret ? '' : 'none';
  }

  document.getElementById('totp-display').classList.add('hidden');
  clearInterval(totpTimer);
  if (entry?.totp_secret) startTotpDisplay(entry.id);
  document.getElementById('modal-entry').classList.remove('hidden');
  const entryTimeoutSecs = parseInt(loadSettings().entryTimeout ?? '0');
  setupEntryModalTimeout(entryTimeoutSecs);
}

function closeEntryModal() {
  const modal = document.getElementById('modal-entry');
  modal.classList.add('closing');
  if (_entryModalAC) { _entryModalAC.abort(); _entryModalAC = null; }
  clearTimeout(_entryModalTimer);
  setTimeout(() => {
    modal.classList.add('hidden');
    modal.classList.remove('closing');
  }, 180);
  clearInterval(totpTimer);
}

async function saveEntry() {
  const id = document.getElementById('entry-id').value;
  const input = {
    title: document.getElementById('entry-title').value,
    username: document.getElementById('entry-username').value,
    password: document.getElementById('entry-password').value || null,
    url: document.getElementById('entry-url').value || null,
    notes: document.getElementById('entry-notes').value || null,
    category: document.getElementById('entry-category').value,
    favourite: document.getElementById('entry-favourite').checked,
  };
  try {
    if (id) {
      await invoke('update_entry', { id, input });
    } else {
      await invoke('create_entry', { input });
    }
    entries = await invoke('list_entries');
    renderEntries();
    closeEntryModal();
    toast(t(id ? 'toast_updated' : 'toast_created'));
  } catch (err) {
    alert('Error: ' + err);
  }
}

//  Settings
function wireSettings() {
  // Load saved settings from localStorage
  const settings = loadSettings();
  const autolockInput     = document.getElementById('setting-autolock');
  const clipboardInput    = document.getElementById('setting-clipboard');
  const lockMinCb         = document.getElementById('setting-lock-minimize');
  const hidePasswordsCb   = document.getElementById('setting-hide-passwords');
  const compactCb         = document.getElementById('setting-compact');
  const langInput         = document.getElementById('setting-lang');
  const themeInput        = document.getElementById('setting-theme');
  const screenProtectCb   = document.getElementById('setting-screen-protect');
  const maxAttemptsInput  = document.getElementById('setting-max-attempts');
  const pwMinLengthInput  = document.getElementById('setting-pw-min-length');
  const confirmRevealCb   = document.getElementById('setting-confirm-reveal');
  const lockBlurCb        = document.getElementById('setting-lock-blur');
  const blockDevToolsCb   = document.getElementById('setting-block-devtools');
  const debuggerDetectCb  = document.getElementById('setting-debugger-detect');
  const processMonitorCb  = document.getElementById('setting-process-monitor');
  const windowMaskCb      = document.getElementById('setting-window-mask');
  const revealTimeoutInput = document.getElementById('setting-reveal-timeout');
  const pwAgeInput        = document.getElementById('setting-pw-age');
  const entryTimeoutInput = document.getElementById('setting-entry-timeout');

  // Helper to set custom select value
  const setCustomSelect = (inputId, val) => {
    const input = document.getElementById(inputId);
    if (!input) return;
    input.value = val;
    const container = input.closest('.custom-select');
    if (!container) return;
    const display = container.querySelector('.select-selected');
    const option = container.querySelector(`.select-items div[data-val="${val}"]`);
    if (display && option) {
      const i18nKey = option.dataset.i18n;
      display.textContent = i18nKey ? t(i18nKey) : option.textContent;
      if (i18nKey) display.dataset.i18n = i18nKey;
    }
  };

  if (autolockInput)     setCustomSelect('setting-autolock', settings.autolock ?? '0');
  if (clipboardInput)    setCustomSelect('setting-clipboard', settings.clipboard ?? '30');
  if (lockMinCb)         lockMinCb.checked     = settings.lockOnMinimize ?? false;
  if (hidePasswordsCb)   hidePasswordsCb.checked = settings.hidePasswords ?? false;
  if (compactCb) {
    compactCb.checked = settings.compact ?? false;
    document.getElementById('entry-list')?.classList.toggle('compact', settings.compact);
  }
  if (langInput) {
    setCustomSelect('setting-lang', currentLang);
    // We need to listen to changes on the hidden input.
    // Since custom selects don't fire 'change' events natively when updated via JS,
    // we'll dispatch a custom event in the custom select click handler, or just handle it there.
    // For simplicity, we'll add an observer or just handle it in the custom select logic.
  }
  if (themeInput) {
    setCustomSelect('setting-theme', currentTheme);
  }
  if (screenProtectCb) {
    screenProtectCb.checked = settings.screenProtect ?? false;
    // Apply immediately if enabled
    if (settings.screenProtect) {
      invoke('set_content_protection', { enabled: true }).catch(() => {});
    }
  }
  if (maxAttemptsInput) setCustomSelect('setting-max-attempts', settings.maxAttempts ?? '0');
  if (pwMinLengthInput) setCustomSelect('setting-pw-min-length', settings.pwMinLength ?? '12');
  if (confirmRevealCb)  confirmRevealCb.checked  = settings.confirmReveal ?? false;
  if (lockBlurCb)       lockBlurCb.checked       = settings.lockOnBlur ?? false;
  if (blockDevToolsCb)     blockDevToolsCb.checked    = settings.blockDevTools ?? false;
  if (debuggerDetectCb)    debuggerDetectCb.checked   = settings.debuggerDetect ?? false;
  if (processMonitorCb)    processMonitorCb.checked   = settings.processMonitor ?? false;
  if (windowMaskCb)        windowMaskCb.checked       = settings.windowMask ?? false;
  if (revealTimeoutInput) setCustomSelect('setting-reveal-timeout', settings.revealTimeout ?? '0');
  if (pwAgeInput)       setCustomSelect('setting-pw-age', settings.pwAgeWarning ?? '0');
  if (entryTimeoutInput) setCustomSelect('setting-entry-timeout', settings.entryTimeout ?? '0');

  // Apply security features that take effect without saving
  if (settings.blockDevTools)  setupDevToolsBlock(true);
  if (settings.lockOnBlur)     setupLockOnBlur(true);
  if (settings.debuggerDetect) setupDebuggerCheck(true);
  if (settings.windowMask)     invoke('set_window_title', { title: 'Untitled - Notepad' }).catch(() => {});
  wireConfirmReveal();

  // Quick Settings Modal
  const quickSettingsModal = document.getElementById('modal-quick-settings');
  document.getElementById('btn-quick-settings')?.addEventListener('click', () => {
    const s = loadSettings();
    setCustomSelect('quick-setting-theme', currentTheme);
    setCustomSelect('quick-setting-lang', currentLang);
    document.getElementById('quick-setting-screen-protect').checked = s.screenProtect ?? false;
    document.getElementById('quick-setting-window-mask').checked = s.windowMask ?? false;
    quickSettingsModal.classList.remove('hidden');
  });
  document.getElementById('btn-close-quick-settings')?.addEventListener('click', () => {
    quickSettingsModal.classList.add('hidden');
  });
  document.getElementById('btn-save-quick-settings')?.addEventListener('click', async () => {
    const s = loadSettings();
    const newTheme = document.getElementById('quick-setting-theme').value;
    const newLang = document.getElementById('quick-setting-lang').value;
    s.screenProtect = document.getElementById('quick-setting-screen-protect').checked;
    s.windowMask = document.getElementById('quick-setting-window-mask').checked;
    
    localStorage.setItem('settings', JSON.stringify(s));
    
    if (newTheme !== currentTheme) applyTheme(newTheme);
    if (newLang !== currentLang) await loadLocale(newLang);
    
    invoke('set_window_title', { title: s.windowMask ? 'Untitled - Notepad' : 'Locke' }).catch(() => {});
    try { await invoke('set_content_protection', { enabled: s.screenProtect }); } catch (_) {}
    
    // Sync main settings if they exist
    const mainScreenProtect = document.getElementById('setting-screen-protect');
    const mainWindowMask = document.getElementById('setting-window-mask');
    if (mainScreenProtect) mainScreenProtect.checked = s.screenProtect;
    if (mainWindowMask) mainWindowMask.checked = s.windowMask;
    setCustomSelect('setting-theme', newTheme);
    setCustomSelect('setting-lang', newLang);
    
    quickSettingsModal.classList.add('hidden');
    toast(t('toast_settings_saved'));
  });

  document.getElementById('btn-save-settings')?.addEventListener('click', async () => {
    const s = {
      autolock:       autolockInput?.value    ?? '0',
      clipboard:      clipboardInput?.value   ?? '30',
      lockOnMinimize: lockMinCb?.checked    ?? false,
      hidePasswords:  hidePasswordsCb?.checked ?? false,
      compact:        compactCb?.checked    ?? false,
      screenProtect:  screenProtectCb?.checked ?? false,
      maxAttempts:    maxAttemptsInput?.value ?? '0',
      pwMinLength:    pwMinLengthInput?.value ?? '12',
      confirmReveal:  confirmRevealCb?.checked ?? false,
      lockOnBlur:     lockBlurCb?.checked    ?? false,
      blockDevTools:  blockDevToolsCb?.checked ?? false,
      debuggerDetect: debuggerDetectCb?.checked ?? false,
      processMonitor: processMonitorCb?.checked ?? false,
      windowMask:     windowMaskCb?.checked  ?? false,
      revealTimeout:  revealTimeoutInput?.value ?? '0',
      pwAgeWarning:   pwAgeInput?.value      ?? '0',
      entryTimeout:   entryTimeoutInput?.value ?? '0',
    };
    localStorage.setItem('settings', JSON.stringify(s));
    document.getElementById('entry-list')?.classList.toggle('compact', s.compact);
    setupAutolock(parseInt(s.autolock));
    setupDevToolsBlock(s.blockDevTools);
    setupLockOnBlur(s.lockOnBlur);
    setupDebuggerCheck(s.debuggerDetect);
    setupLockOnMinimize(s.lockOnMinimize);
    renderEntries();
    invoke('set_window_title', { title: s.windowMask ? 'Untitled - Notepad' : 'Locke' }).catch(() => {});

    // Apply screen protection
    try {
      await invoke('set_content_protection', { enabled: s.screenProtect });
    } catch (_) {}

    toast(t('toast_settings_saved'));
  });

  // Access log
  async function refreshAccessLog() {
    const list = document.getElementById('access-log-list');
    if (!list) return;
    try {
      const log = await invoke('get_access_log');
      if (!log.length) {
        list.innerHTML = `<div style="color:var(--muted);font-size:0.85rem;text-align:center;padding:16px 0" data-i18n="settings_log_empty">${t('settings_log_empty')}</div>`;
        return;
      }
      list.innerHTML = [...log].reverse().map(e => `
        <div class="access-log-entry ${e.success ? 'success' : 'failed'}">
          <span class="access-log-dot"></span>
          <span class="access-log-ts">${e.timestamp}</span>
          <span class="access-log-event">${e.event}</span>
          <span class="access-log-badge">${e.success ? t('settings_log_success') : t('settings_log_failed')}</span>
        </div>`).join('');
    } catch (_) {}
  }

  document.getElementById('btn-refresh-log')?.addEventListener('click', refreshAccessLog);
  document.getElementById('btn-clear-log')?.addEventListener('click', async () => {
    await invoke('clear_access_log');
    await refreshAccessLog();
  });

  // Show log when opening settings
  document.getElementById('btn-settings')?.addEventListener('click', () => {
    refreshAccessLog();
  });

  document.getElementById('btn-backup-vault')?.addEventListener('click', async () => {
    try {
      const savePath = await dialogSave({ filters: [{ name: 'Vault Backup', extensions: ['vault'] }], defaultPath: `backup_${Date.now()}.vault` });
      if (!savePath) return;
      await invoke('backup_vault', { destPath: savePath });
      toast(t('toast_backup_ok'));
    } catch (err) {
      toast('Error: ' + err, true);
    }
  });

  document.getElementById('btn-change-password')?.addEventListener('click', () => {
    document.getElementById('modal-change-pw').classList.remove('hidden');
  });

  document.getElementById('btn-close-change-pw')?.addEventListener('click', () => {
    document.getElementById('modal-change-pw').classList.add('closing');
    setTimeout(() => {
      document.getElementById('modal-change-pw').classList.add('hidden');
      document.getElementById('modal-change-pw').classList.remove('closing');
    }, 180);
  });

  document.getElementById('form-change-pw')?.addEventListener('submit', async e => {
    e.preventDefault();
    const current = document.getElementById('change-pw-current').value;
    const newPw = document.getElementById('change-pw-new').value;
    const confirm = document.getElementById('change-pw-confirm').value;
    if (newPw !== confirm) { toast(t('error_pw_mismatch'), true); return; }
    if (newPw.length < 8) { toast(t('error_pw_too_short'), true); return; }
    try {
      await invoke('change_master_password', { currentPassword: current, newPassword: newPw });
      toast(t('toast_saved'));
      document.getElementById('modal-change-pw').classList.add('hidden');
      e.target.reset();
    } catch (err) {
      toast('Error: ' + err, true);
    }
  });

  // Apply saved settings
  setupAutolock(parseInt(settings.autolock ?? '0'));
  setupClipboardClear(parseInt(settings.clipboard ?? '30'));

  setupLockOnMinimize(settings.lockOnMinimize ?? false);
}

function setupLockOnMinimize(enabled) {
  // Remove previous listener
  if (window.__unlisten_minimize) {
    window.__unlisten_minimize();
    window.__unlisten_minimize = null;
  }
  document.removeEventListener('visibilitychange', window.__lockMinimizeHandler);
  if (!enabled) return;

  // Try Tauri window-level minimize event first (correct approach)
  const tryTauriListen = async () => {
    try {
      const t = window.__TAURI__;
      const getWin = t?.window?.getCurrentWindow
        || t?.webviewWindow?.getCurrentWebviewWindow
        || t?.window?.getCurrent;
      const win = getWin ? await getWin() : null;
      if (win) {
        const unlisten = await win.listen('tauri://window-event', async (event) => {
          if (event.payload?.type === 'minimized' || event.payload === 'minimized') {
            if (!document.getElementById('screen-main').classList.contains('hidden')) {
              await invoke('lock_vault').catch(() => {});
              entries = [];
              document.getElementById('screen-main').classList.add('hidden');
              document.getElementById('screen-unlock').classList.remove('hidden');
            }
          }
        });
        window.__unlisten_minimize = unlisten;
        return;
      }
    } catch (_) {}
    // Fallback: visibilitychange (works when tab is hidden on some platforms)
    window.__lockMinimizeHandler = async () => {
      if (document.hidden && !document.getElementById('screen-main').classList.contains('hidden')) {
        await invoke('lock_vault').catch(() => {});
        entries = [];
        document.getElementById('screen-main').classList.add('hidden');
        document.getElementById('screen-unlock').classList.remove('hidden');
      }
    };
    document.addEventListener('visibilitychange', window.__lockMinimizeHandler);
  };
  tryTauriListen();
}

function loadSettings() {
  try { return JSON.parse(localStorage.getItem('settings') || '{}'); } catch { return {}; }
}

// ─── New security feature helpers ─────────────────────────────────────────────

function setupDevToolsBlock(enabled) {
  document.removeEventListener('contextmenu', window.__blockDTCtx);
  document.removeEventListener('keydown',     window.__blockDTKey);
  if (!enabled) return;
  window.__blockDTCtx = e => e.preventDefault();
  window.__blockDTKey = e => {
    if (
      e.key === 'F12' ||
      (e.ctrlKey && e.shiftKey && ['I','J','C'].includes(e.key)) ||
      (e.ctrlKey && e.key === 'U')
    ) e.preventDefault();
  };
  document.addEventListener('contextmenu', window.__blockDTCtx);
  document.addEventListener('keydown',     window.__blockDTKey);
}

function setupLockOnBlur(enabled) {
  window.removeEventListener('blur', window.__blurLockHandler);
  if (!enabled) return;
  window.__blurLockHandler = async () => {
    if (document.getElementById('screen-main')?.classList.contains('hidden')) return;
    await invoke('lock_vault');
    entries = [];
    document.getElementById('screen-main').classList.add('hidden');
    document.getElementById('screen-unlock').classList.remove('hidden');
  };
  window.addEventListener('blur', window.__blurLockHandler);
}

function setupDebuggerCheck(enabled) {
  clearInterval(window._debuggerInterval);
  if (!enabled) return;
  window._debuggerInterval = setInterval(async () => {
    // Only check while vault is open
    if (document.getElementById('screen-main')?.classList.contains('hidden')) return;
    const detected = await invoke('check_debugger').catch(() => false);
    if (detected) {
      clearInterval(window._debuggerInterval);
      await invoke('lock_vault').catch(() => {});
      entries = [];
      document.getElementById('screen-main').classList.add('hidden');
      document.getElementById('screen-unlock').classList.remove('hidden');
      toast(t('security_debugger_locked'), true);
    }
  }, 5000);
}

let _entryModalTimer = null;
let _entryModalAC    = null;
function setupEntryModalTimeout(secs) {
  clearTimeout(_entryModalTimer);
  if (_entryModalAC) { _entryModalAC.abort(); _entryModalAC = null; }
  if (!secs) return;
  const modal = document.getElementById('modal-entry');
  if (!modal) return;
  _entryModalAC = new AbortController();
  const { signal } = _entryModalAC;
  const reset = () => {
    clearTimeout(_entryModalTimer);
    _entryModalTimer = setTimeout(() => closeEntryModal(), secs * 1000);
  };
  modal.addEventListener('mousemove', reset, { passive: true, signal });
  modal.addEventListener('keydown',   reset, { passive: true, signal });
  modal.addEventListener('click',     reset, { passive: true, signal });
  reset();
}

function wireConfirmReveal() {
  // Wired only once — subsequent calls are no-ops
  if (wireConfirmReveal._done) return;
  wireConfirmReveal._done = true;
  document.getElementById('btn-close-confirm-reveal')?.addEventListener('click', () => {
    window.__confirmRevealResolve?.(false);
  });
  document.getElementById('btn-confirm-reveal-cancel')?.addEventListener('click', () => {
    window.__confirmRevealResolve?.(false);
  });
  document.getElementById('btn-confirm-reveal-ok')?.addEventListener('click', () => {
    window.__confirmRevealDoOk?.();
  });
  document.getElementById('confirm-reveal-pw')?.addEventListener('keydown', e => {
    if (e.key === 'Enter') window.__confirmRevealDoOk?.();
    if (e.key === 'Escape') window.__confirmRevealResolve?.(false);
  });
}

function showConfirmReveal() {
  return new Promise(resolve => {
    const modal  = document.getElementById('modal-confirm-reveal');
    const input  = document.getElementById('confirm-reveal-pw');
    const errEl  = document.getElementById('confirm-reveal-error');
    input.value  = '';
    errEl.classList.add('hidden');
    modal.classList.remove('hidden');
    requestAnimationFrame(() => input.focus());

    const close = (result) => {
      modal.classList.add('hidden');
      window.__confirmRevealResolve = null;
      window.__confirmRevealDoOk   = null;
      resolve(result);
    };

    window.__confirmRevealResolve = close;
    window.__confirmRevealDoOk = async () => {
      const pw = input.value;
      if (!pw) return;
      try {
        await invoke('unlock_vault', { path: window._vaultPath || '', masterPassword: pw });
        close(true);
      } catch {
        errEl.textContent = t('error_pw_mismatch');
        errEl.classList.remove('hidden');
        input.select();
      }
    };
  });
}
//  Recent Files 
function saveRecentFile(path) {
  if (!path) return;
  let recents = getRecentFiles();
  recents = recents.filter(p => p !== path);
  recents.unshift(path);
  recents = recents.slice(0, 5);
  localStorage.setItem('recentFiles', JSON.stringify(recents));
}

function getRecentFiles() {
  try { return JSON.parse(localStorage.getItem('recentFiles') || '[]'); } catch { return []; }
}

function renderRecentFiles() {
  const container = document.getElementById('recent-files');
  if (!container) return;
  const recents = getRecentFiles();
  if (!recents.length) {
    container.classList.add('hidden');
    return;
  }
  container.classList.remove('hidden');
  container.innerHTML = `<div class="recent-files-label">${t('recent_files')}</div>` +
    recents.map(p => {
      const name = p.split(/[\\/]/).pop();
      return `<button class="recent-file-item" data-path="${p}">
        <svg width="14" height="14"><use href="#i-folder"/></svg>
        <span class="recent-file-name">${name}</span>
        <span class="recent-file-path">${p}</span>
      </button>`;
    }).join('');

  container.querySelectorAll('.recent-file-item').forEach(btn => {
    btn.addEventListener('click', () => {
      document.getElementById('open-path').value = btn.dataset.path;
      document.getElementById('open-password').focus();
    });
  });
}

//  Failed Attempts 
let failedAttempts = 0;

function trackFailedAttempt() {
  const s = loadSettings();
  const max = parseInt(s.maxAttempts ?? '0');
  if (!max) return;
  failedAttempts++;
  if (failedAttempts >= max) {
    failedAttempts = 0;
    document.getElementById('open-password').value = '';
    document.getElementById('open-path').value = '';
    document.getElementById('unlock-error').textContent = `Max attempts (${max}) reached. Entry cleared.`;
    document.getElementById('unlock-error').classList.remove('hidden');
    setTimeout(() => document.getElementById('unlock-error').classList.add('hidden'), 5000);
  }
}

//  Clipboard clear 
function scheduleClipboardClear() {
  const s = loadSettings();
  const secs = parseInt(s.clipboard ?? '0');
  if (!secs) return;
  clearTimeout(window._clipboardTimer);
  window._clipboardTimer = setTimeout(async () => {
    try {
      await navigator.clipboard.writeText('');
    } catch (_) {}
  }, secs * 1000);
}
//  Drag & Drop on unlock card 
function wireDropZone() {
  const zone = document.getElementById('unlock-drop-zone');
  const overlay = document.getElementById('drop-overlay');
  if (!zone) return;

  zone.addEventListener('dragover', e => {
    e.preventDefault();
    e.stopPropagation();
    overlay?.classList.remove('hidden');
  });
  zone.addEventListener('dragleave', e => {
    if (!zone.contains(e.relatedTarget)) overlay?.classList.add('hidden');
  });
  zone.addEventListener('drop', e => {
    e.preventDefault();
    overlay?.classList.add('hidden');
    const files = e.dataTransfer?.files;
    if (files?.length) {
      const path = files[0].path || files[0].name;
      document.getElementById('open-path').value = path;
      // Show open tab
      document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
      document.querySelector('.tab[data-tab="open"]')?.classList.add('active');
      document.getElementById('form-open').classList.remove('hidden');
      document.getElementById('form-new').classList.add('hidden');
      document.getElementById('open-password').focus();
    }
  });
}

let autolockTimeout = null;
function setupAutolock(minutes) {
  clearTimeout(autolockTimeout);
  if (!minutes) return;
  const ms = minutes * 60 * 1000;
  const reset = () => {
    clearTimeout(autolockTimeout);
    autolockTimeout = setTimeout(async () => {
      if (!document.getElementById('screen-main').classList.contains('hidden')) {
        await invoke('lock_vault');
        entries = [];
        document.getElementById('screen-main').classList.add('hidden');
        document.getElementById('screen-unlock').classList.remove('hidden');
        toast(t('btn_lock'));
      }
    }, ms);
  };
  ['mousemove','keydown','click','scroll'].forEach(e => document.addEventListener(e, reset, { passive: true }));
  reset();
}

let clipboardTimer = null;
function setupClipboardClear(seconds) {
  if (!seconds) return;
  // Override the copy button behaviour — triggered from renderEntries
  window._clipboardClearSeconds = seconds;
}

//  TOTP live display
function startTotpDisplay(entryId) {
  clearInterval(totpTimer);
  // View panel elements
  const codeView = document.getElementById('totp-code-value');
  const progView = document.getElementById('totp-progress');
  // Edit panel elements
  const displayEdit = document.getElementById('totp-display');
  const codeEdit = document.getElementById('totp-code-value-edit');
  const progEdit = document.getElementById('totp-progress-edit');
  if (displayEdit) displayEdit.classList.remove('hidden');
  async function refresh() {
    try {
      const res = await invoke('get_totp_code', { entryId });
      const formatted = res.code.replace(/(.{3})(.{3})/, '$1 $2');
      if (codeView) codeView.textContent = formatted;
      if (codeEdit) codeEdit.textContent = formatted;
    } catch (_) {}
    const val = 30 - (Math.floor(Date.now() / 1000) % 30);
    if (progView) progView.value = val;
    if (progEdit) progEdit.value = val;
  }
  refresh();
  totpTimer = setInterval(refresh, 1000);
}

//  Generator Modal 
function wireGenerator() {
  document.getElementById('btn-close-gen').addEventListener('click', closeGeneratorModal);
  document.getElementById('modal-gen').addEventListener('click', e => {
    if (e.target.id === 'modal-gen') closeGeneratorModal();
  });
  document.getElementById('gen-length').addEventListener('input', e => {
    document.getElementById('gen-len-val').textContent = e.target.value;
    generatePw();
  });
  document.getElementById('gen-symbols').addEventListener('change', generatePw);
  document.getElementById('btn-regen').addEventListener('click', generatePw);
  document.getElementById('btn-copy-gen').addEventListener('click', () => {
    navigator.clipboard.writeText(document.getElementById('gen-result').value);
    toast(t('toast_copied'));
  });
  document.getElementById('btn-gen-ok').addEventListener('click', () => {
    const pw = document.getElementById('gen-result').value;
    if (fromGenerator) { fromGenerator(pw); fromGenerator = null; }
    closeGeneratorModal();
  });
}

async function openGeneratorModal() {
  document.getElementById('modal-gen').classList.remove('hidden');
  await generatePw();
}

function closeGeneratorModal() {
  const modal = document.getElementById('modal-gen');
  modal.classList.add('closing');
  setTimeout(() => {
    modal.classList.add('hidden');
    modal.classList.remove('closing');
  }, 180);
}

async function generatePw() {
  const length = parseInt(document.getElementById('gen-length').value);
  const useSymbols = document.getElementById('gen-symbols').checked;
  const pw = await invoke('generate_password', { length, useSymbols });
  document.getElementById('gen-result').value = pw;
}

//  Utilities 
function esc(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}
function formatUrl(u) {
  try { return new URL(u).hostname; } catch { return u; }
}
function toast(msg, isError = false) {
  const el = document.getElementById('toast');
  el.textContent = msg;
  el.className = 'toast' + (isError ? ' error' : '');
  el.classList.remove('hidden');
  clearTimeout(toast._t);
  toast._t = setTimeout(() => el.classList.add('hidden'), 2800);
}
function calcStrength(pw) {
  let s = 0;
  if (pw.length >= 8) s++;
  if (pw.length >= 14) s++;
  if (/[A-Z]/.test(pw) && /[a-z]/.test(pw)) s++;
  if (/[0-9]/.test(pw)) s++;
  if (/[^A-Za-z0-9]/.test(pw)) s++;
  return Math.min(s, 4);
}

// ─── Crypto Wallet ────────────────────────────────────────────────────────────

// Alias so wallet code can use showToast() consistently with the rest of the app
const showToast = (msg, isErr = false) => toast(msg, isErr);

let wallets = [];           // cached WalletSummary[]
let activeWalletId = null;  // currently selected wallet id

// ── Crypto prices (CoinGecko free, no key) ───────────────────────────────────

let _priceCache = {};  // { bitcoin: 98000, ethereum: 2345, ... }

// Fixed 11 assets displayed in every wallet
const FIXED_ASSETS = [
  { id:'usdt', label:'Tether',      symbol:'USDT', chain:'eth', type:'evm_token',
    contract:'0xdAC17F958D2ee523a2206206994597C13D831ec7', decimals:6, chainId:1,
    rpcUrl:'https://cloudflare-eth.com/', cgId:'tether', cnTicker:'usdterc20',
    icon:'https://cryptologos.cc/logos/tether-usdt-logo.svg?v=035' },
  { id:'ton',  label:'Toncoin',     symbol:'TON',  chain:'ton', type:'native',
    cgId:'the-open-network', cnTicker:'ton',
    icon:'https://cryptologos.cc/logos/toncoin-ton-logo.svg?v=035' },
  { id:'sol',  label:'Solana',      symbol:'SOL',  chain:'sol', type:'native',
    cgId:'solana', cnTicker:'sol',
    icon:'https://cryptologos.cc/logos/solana-sol-logo.svg?v=035' },
  { id:'trx',  label:'TRON',        symbol:'TRX',  chain:'trx', type:'native',
    cgId:'tron', cnTicker:'trx',
    icon:'https://cryptologos.cc/logos/tron-trx-logo.svg?v=035' },
  { id:'btc',  label:'Bitcoin',     symbol:'BTC',  chain:'btc', type:'native',
    cgId:'bitcoin', cnTicker:'btc',
    icon:'https://cryptologos.cc/logos/bitcoin-btc-logo.svg?v=035' },
  { id:'eth',  label:'Ethereum',    symbol:'ETH',  chain:'eth', type:'native',
    cgId:'ethereum', cnTicker:'eth',
    icon:'https://cryptologos.cc/logos/ethereum-eth-logo.svg?v=035' },
  { id:'doge', label:'Dogecoin',    symbol:'DOGE', chain:'doge',type:'native',
    cgId:'dogecoin', cnTicker:'doge',
    icon:'https://cryptologos.cc/logos/dogecoin-doge-logo.svg?v=035' },
  { id:'ltc',  label:'Litecoin',    symbol:'LTC',  chain:'ltc', type:'native',
    cgId:'litecoin', cnTicker:'ltc',
    icon:'https://cryptologos.cc/logos/litecoin-ltc-logo.svg?v=035' },
  { id:'bnb',  label:'Binance Coin',symbol:'BNB',  chain:'bsc', type:'native',
    cgId:'binancecoin', cnTicker:'bnbbsc',
    rpcUrl:'https://bsc-dataseed.binance.org/',
    icon:'https://cryptologos.cc/logos/bnb-bnb-logo.svg?v=035' },
  { id:'usdc', label:'USD Coin',    symbol:'USDC', chain:'eth', type:'evm_token',
    contract:'0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48', decimals:6, chainId:1,
    rpcUrl:'https://cloudflare-eth.com/', cgId:'usd-coin', cnTicker:'usdcerc20',
    icon:'https://cryptologos.cc/logos/usd-coin-usdc-logo.svg?v=035' },
];

function getAssetAddress(w, asset) {
  switch (asset.chain) {
    case 'btc':  return w.btc_address  || '';
    case 'eth':  return w.eth_address  || '';
    case 'bsc':  return w.eth_address  || '';
    case 'sol':  return w.sol_address  || '';
    case 'ltc':  return w.ltc_address  || '';
    case 'doge': return w.doge_address || '';
    case 'trx':  return w.trx_address  || '';
    case 'ton':  return w.ton_address  || '';
    default:     return w.eth_address  || '';
  }
}

async function fetchPrices() {
  try {
    const ids = [...new Set(FIXED_ASSETS.map(a => a.cgId))].join(',');
    const resp = await fetch(`https://api.coingecko.com/api/v3/simple/price?ids=${ids}&vs_currencies=usd`);
    if (!resp.ok) return;
    const data = await resp.json();
    _priceCache = {};
    for (const [cgId, v] of Object.entries(data)) {
      _priceCache[cgId] = v.usd ?? 0;
    }
  } catch (_) {}
}

function formatUsd(amount, cgId) {
  const price = _priceCache[cgId];
  if (!price || isNaN(parseFloat(amount))) return '';
  const usd = parseFloat(amount) * price;
  if (usd < 0.01) return '';
  return '$' + usd.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
}

// ── State helpers ─────────────────────────────────────────────────────────────

async function loadWallets() {
  fetchPrices(); // fire-and-forget, updates cache in background
  try {
    wallets = await invoke('wallet_list');
  } catch { wallets = []; }
  renderWalletList();
  if (activeWalletId) {
    const w = wallets.find(w => w.id === activeWalletId);
    if (w) renderWalletDetail(w);
  }
}

// ── Sidebar wallet list ───────────────────────────────────────────────────────

function renderWalletList() {
  const el = document.getElementById('wallet-list');
  if (!el) return;
  if (wallets.length === 0) {
    el.innerHTML = '';
    document.getElementById('wallet-empty-state')?.classList.remove('hidden');
    document.getElementById('wallet-detail')?.classList.add('hidden');
    return;
  }
  el.innerHTML = wallets.map(w => `
    <div class="wallet-account-item${w.id === activeWalletId ? ' active' : ''}"
         data-wallet-id="${w.id}">
      <div class="wallet-account-icon">${w.name.charAt(0).toUpperCase()}</div>
      <div style="min-width:0">
        <div style="font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${w.name}</div>
        <div style="font-size:.75rem;color:var(--muted);margin-top:2px">${FIXED_ASSETS.length} assets</div>
      </div>
    </div>
  `).join('');

  el.querySelectorAll('.wallet-account-item').forEach(item => {
    item.addEventListener('click', () => {
      const w = wallets.find(w => w.id === item.dataset.walletId);
      if (w) { activeWalletId = w.id; renderWalletList(); renderWalletDetail(w); }
    });
  });
}

// ── Detail panel ──────────────────────────────────────────────────────────────

function renderWalletDetail(w) {
  document.getElementById('wallet-empty-state')?.classList.add('hidden');
  const det = document.getElementById('wallet-detail');
  det.classList.remove('hidden');

  document.getElementById('wd-avatar').textContent = w.name.charAt(0).toUpperCase();
  document.getElementById('wd-name').textContent = w.name;
  document.getElementById('wd-created').textContent =
    t('wallet_created_on') + ' ' + new Date(w.created_at).toLocaleDateString();

  const totalBalanceEl = document.getElementById('wd-total-balance');
  if (totalBalanceEl) totalBalanceEl.textContent = '$0.00';
  let totalUsd = 0;

  const chainsEl = document.getElementById('wd-chains');

  chainsEl.innerHTML = FIXED_ASSETS.map((asset, i) => {
    const addr = getAssetAddress(w, asset);
    return `
    <div class="chain-card" data-asset-index="${i}">
      <div class="chain-badge ${asset.chain}">
        <img src="${asset.icon}" alt="${asset.symbol}" width="24" height="24"
             style="border-radius:50%;object-fit:contain"
             onerror="this.src='https://ui-avatars.com/api/?name=${asset.symbol}&background=random&color=fff&rounded=true&bold=true'" />
      </div>
      <div class="chain-info">
        <div class="chain-name">${asset.label}</div>
        <div class="chain-address">
          <span title="${addr}">${shortAddr(addr)}</span>
          <button class="btn-icon" style="padding:4px 8px;font-size:.8rem" title="Copy"
                  onclick="copyText('${addr}')">
            <svg width="14" height="14"><use href="#i-copy"/></svg>
          </button>
        </div>
      </div>
      <div class="chain-balance-container">
        <div class="chain-balance">
          <span class="chain-balance-value" id="bal-${w.id}-${i}">—</span>
          <span class="chain-balance-symbol">${asset.symbol}</span>
          <button class="btn-icon" style="padding:4px 8px" title="Refresh"
                  data-bal-index="${i}" data-bal-walletid="${w.id}">
            <svg width="13" height="13"><use href="#i-refresh"/></svg>
          </button>
        </div>
        <div class="chain-usd-value" id="usd-${w.id}-${i}"></div>
      </div>
      <div class="chain-actions">
        ${asset.type === 'native' && asset.chain === 'eth' ? `
          <button class="btn-primary btn-sm" style="font-size:.85rem;padding:9px 18px"
                  data-send-wallet="${w.id}" data-send-chain="1"
                  data-send-from="${addr}" data-send-rpc="https://cloudflare-eth.com/">
            ${t('wallet_send')}
          </button>` : ''}
        ${asset.type === 'native' && asset.chain === 'bsc' ? `
          <button class="btn-primary btn-sm" style="font-size:.85rem;padding:9px 18px"
                  data-send-wallet="${w.id}" data-send-chain="56"
                  data-send-from="${addr}" data-send-rpc="https://bsc-dataseed.binance.org/">
            ${t('wallet_send')}
          </button>` : ''}
        ${asset.type === 'evm_token' ? `
          <button class="btn-primary btn-sm" style="font-size:.85rem;padding:9px 18px"
                  data-send-token-wallet="${w.id}"
                  data-send-token-from="${addr}"
                  data-send-token-contract="${asset.contract}"
                  data-send-token-symbol="${asset.symbol}"
                  data-send-token-decimals="${asset.decimals}"
                  data-send-token-chain="${asset.chainId}"
                  data-send-token-rpc="${asset.rpcUrl}">
            ${t('wallet_send')}
          </button>` : ''}
        <button class="btn-ghost btn-sm" style="font-size:.85rem;padding:9px 14px"
                data-receive-asset="${i}" data-receive-walletid="${w.id}">
          ${t('wallet_receive') || 'Receive'}
        </button>
      </div>
    </div>`;
  }).join('');

  // Wire balance refresh buttons
  chainsEl.querySelectorAll('[data-bal-index]').forEach(btn => {
    btn.addEventListener('click', async () => {
      const idx    = parseInt(btn.dataset.balIndex);
      const wid    = btn.dataset.balWalletid;
      const asset  = FIXED_ASSETS[idx];
      const addr   = getAssetAddress(w, asset);
      const el     = document.getElementById(`bal-${wid}-${idx}`);
      const usdEl  = document.getElementById(`usd-${wid}-${idx}`);
      if (el) { el.textContent = '…'; el.style.color = 'var(--text-dim)'; }
      if (usdEl) { usdEl.textContent = ''; }
      try {
        let bal;
        if (asset.type === 'evm_token') {
          bal = await invoke('wallet_get_token_balance', {
            address: addr,
            contractAddress: asset.contract,
            decimals: asset.decimals,
            rpcUrl: asset.rpcUrl,
          });
        } else {
          bal = await invoke('wallet_get_balance', {
            address: addr,
            chain: asset.chain,
            rpcUrl: asset.rpcUrl || null,
          });
        }
        if (el) { el.textContent = bal; el.style.color = 'var(--acc)'; }
        if (usdEl && asset.cgId) {
          if (!_priceCache[asset.cgId]) await fetchPrices();
          const usdStr = formatUsd(bal, asset.cgId);
          usdEl.textContent = usdStr;
          const price = _priceCache[asset.cgId];
          if (price && !isNaN(parseFloat(bal))) {
            const val = parseFloat(bal) * price;
            if (!isNaN(val) && val > 0) {
              totalUsd += val;
              if (totalBalanceEl)
                totalBalanceEl.textContent = '$' + totalUsd.toLocaleString('en-US', {
                  minimumFractionDigits: 2, maximumFractionDigits: 2
                });
            }
          }
        }
      } catch (e) {
        if (el) { el.textContent = t('err'); el.style.color = 'var(--red)'; }
      }
    });
    // Auto-fetch on render; skip BTC (slow API)
    if (FIXED_ASSETS[parseInt(btn.dataset.balIndex)]?.chain !== 'btc') btn.click();
  });

  // Wire ETH/BNB native send buttons
  chainsEl.querySelectorAll('[data-send-wallet]').forEach(btn => {
    btn.addEventListener('click', () => {
      openEthSendModal(btn.dataset.sendWallet, btn.dataset.sendFrom,
        parseInt(btn.dataset.sendChain), btn.dataset.sendRpc);
    });
  });

  // Wire token send buttons
  chainsEl.querySelectorAll('[data-send-token-wallet]').forEach(btn => {
    btn.addEventListener('click', () => {
      openTokenSendModal({
        walletId:    btn.dataset.sendTokenWallet,
        fromAddress: btn.dataset.sendTokenFrom,
        contract:    btn.dataset.sendTokenContract,
        symbol:      btn.dataset.sendTokenSymbol,
        decimals:    parseInt(btn.dataset.sendTokenDecimals) || 18,
        chainId:     parseInt(btn.dataset.sendTokenChain)    || 1,
        rpcUrl:      btn.dataset.sendTokenRpc,
      });
    });
  });

  // Wire per-row Receive buttons
  chainsEl.querySelectorAll('[data-receive-asset]').forEach(btn => {
    btn.addEventListener('click', () => {
      const idx   = parseInt(btn.dataset.receiveAsset);
      const asset = FIXED_ASSETS[idx];
      const addr  = getAssetAddress(w, asset);
      openReceiveModal(asset.label, asset.symbol, addr);
    });
  });

  // Clone action buttons to wipe stale listeners, then re-wire
  ['btn-wd-send','btn-wd-receive','btn-wd-swap','btn-wd-export','btn-wd-delete','btn-refresh-all'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.replaceWith(el.cloneNode(true));
  });

  document.getElementById('btn-wd-send')?.addEventListener('click', () => {
    openEthSendModal(w.id, w.eth_address, 1, 'https://cloudflare-eth.com/');
  });
  document.getElementById('btn-wd-receive')?.addEventListener('click', () => {
    openReceiveModal('Ethereum', 'ETH', w.eth_address);
  });
  document.getElementById('btn-wd-swap')?.addEventListener('click', () => {
    openSwapModal(w.id);
  });
  document.getElementById('btn-refresh-all')?.addEventListener('click', () => {
    chainsEl.querySelectorAll('[data-bal-index]').forEach(btn => btn.click());
  });
  document.getElementById('btn-wd-export')?.addEventListener('click', async () => {
    if (!confirm(t('wallet_export_confirm'))) return;
    try {
      const phrase = await invoke('wallet_export_mnemonic', { walletId: w.id });
      openSeedPhraseViewer(phrase);
    } catch (e) { showToast(String(e)); }
  });
  document.getElementById('btn-wd-delete')?.addEventListener('click', async () => {
    if (!confirm(t('wallet_delete_confirm'))) return;
    try {
      await invoke('wallet_delete', { id: w.id });
      activeWalletId = null;
      await loadWallets();
      showToast(t('wallet_deleted'));
    } catch (e) { showToast(String(e)); }
  });
}

function shortAddr(addr) {
  if (!addr || addr.length < 16) return addr;
  return addr.slice(0, 8) + '…' + addr.slice(-6);
}
function copyText(text) {
  navigator.clipboard.writeText(text).then(() => showToast(t('toast_copied')));
}

// ── Wallet create / import modal ──────────────────────────────────────────────

let pendingMnemonic = null;

function openWalletModal() {
  pendingMnemonic = null;
  document.getElementById('wallet-gen-name').value = '';
  document.getElementById('wallet-mnemonic-box').classList.add('hidden');
  document.getElementById('wallet-mnemonic-words').innerHTML = '';
  document.getElementById('wallet-backed-up').checked = false;
  document.getElementById('btn-save-gen-wallet').disabled = true;
  document.getElementById('wallet-import-name').value = '';
  document.getElementById('wallet-import-phrase').value = '';
  document.getElementById('wallet-import-status').textContent = '';
  document.getElementById('modal-wallet').classList.remove('hidden');
}
function closeWalletModal() {
  document.getElementById('modal-wallet').classList.add('hidden');
  pendingMnemonic = null;
}

// ── ETH send modal ────────────────────────────────────────────────────────────

function openEthSendModal(walletId, fromAddress, chainId = 1, rpcUrl = 'https://cloudflare-eth.com/') {
  document.getElementById('send-wallet-id').value = walletId;
  document.getElementById('send-eth-from').textContent = fromAddress;
  document.getElementById('send-eth-to').value = '';
  document.getElementById('send-eth-amount').value = '';
  document.getElementById('send-eth-chain').value = chainId;
  document.getElementById('send-eth-rpc').value = rpcUrl;
  document.getElementById('eth-tx-preview').classList.add('hidden');
  document.getElementById('btn-eth-confirm').classList.add('hidden');
  document.getElementById('eth-tx-result').classList.add('hidden');
  document.getElementById('modal-eth-send').classList.remove('hidden');
}
function closeEthSendModal() {
  document.getElementById('modal-eth-send').classList.add('hidden');
}

// ── Swap modal ────────────────────────────────────────────────────────────────

let swapWalletId = null;

function openSwapModal(walletId) {
  swapWalletId = walletId;
  document.getElementById('swap-wallet-id').value = walletId;

  const populateSwapSelect = (prefix) => {
    const container = document.getElementById(`${prefix}-container`);
    const items = container.querySelector('.select-items');
    items.innerHTML = FIXED_ASSETS.map(a => `
      <div data-val="${a.id}" style="display:flex;align-items:center;gap:12px;">
        <img src="${a.icon}" style="width:24px;height:24px;border-radius:50%" />
        <span style="color:#fff;font-size:.95rem">${a.label} <span style="color:var(--muted);font-size:.85rem">${a.symbol}</span></span>
      </div>
    `).join('');
  };

  const setSwapSelect = (prefix, val) => {
    const container = document.getElementById(`${prefix}-container`);
    const display = container.querySelector('.select-selected');
    const hiddenInput = container.querySelector('input[type="hidden"]');
    const asset = FIXED_ASSETS.find(a => a.id === val);
    if (asset) {
      display.innerHTML = `
        <div style="display:flex;align-items:center;gap:12px;">
          <img src="${asset.icon}" style="width:24px;height:24px;border-radius:50%" />
          <span style="color:#fff;font-size:.95rem">${asset.label} <span style="color:var(--muted);font-size:.85rem">${asset.symbol}</span></span>
        </div>
      `;
      hiddenInput.value = asset.id;
    }
  };

  populateSwapSelect('swap-from');
  populateSwapSelect('swap-to');

  // Default: from BTC → to ETH
  setSwapSelect('swap-from', 'btc');
  setSwapSelect('swap-to', 'eth');

  document.getElementById('swap-from-amount').value = '';
  document.getElementById('swap-to-amount').value   = '';
  document.getElementById('swap-quote-result').classList.add('hidden');
  document.getElementById('modal-swap').classList.remove('hidden');
}

function closeSwapModal() {
  document.getElementById('modal-swap').classList.add('hidden');
}

// ── Receive modal ─────────────────────────────────────────────────────────────

function openReceiveModal(assetName, symbol, address) {
  document.getElementById('receive-asset-name').textContent  = `${assetName} (${symbol})`;
  document.getElementById('receive-network-name').textContent = address ? '' : t('err') || 'Address unavailable';
  document.getElementById('receive-address').textContent     = address || '—';
  document.getElementById('modal-receive').classList.remove('hidden');
}

function closeReceiveModal() {
  document.getElementById('modal-receive').classList.add('hidden');
}

// ── Send Token modal ──────────────────────────────────────────────────────────

let activeTokenSendParams = null;
function openTokenSendModal({ walletId, fromAddress, contract, symbol, decimals, chainId, rpcUrl = 'https://cloudflare-eth.com/' }) {
  activeTokenSendParams = { walletId, contract, decimals, chainId };
  document.getElementById('token-send-wallet-id').value = walletId;
  document.getElementById('token-send-contract').value = contract;
  document.getElementById('token-send-decimals').value = decimals;
  document.getElementById('token-send-chain-id-hidden').value = chainId;
  document.getElementById('token-send-rpc').value = rpcUrl;
  document.getElementById('token-send-from').textContent = fromAddress;
  document.getElementById('token-send-title').textContent = `${t('wallet_token_send_title')}: ${symbol}`;
  document.getElementById('token-send-amount-label').querySelector('span').textContent =
    `${t('wallet_send_amount')} (${symbol})`;
  document.getElementById('token-send-to').value = '';
  document.getElementById('token-send-amount').value = '';
  document.getElementById('token-tx-preview').classList.add('hidden');
  document.getElementById('token-tx-result').classList.add('hidden');
  document.getElementById('btn-token-confirm').classList.add('hidden');
  document.getElementById('modal-token-send').classList.remove('hidden');
}
function closeTokenSendModal() {
  document.getElementById('modal-token-send').classList.add('hidden');
}

// ── Seed phrase viewer (read-only overlay) ────────────────────────────────────

function openSeedPhraseViewer(phrase) {
  const words = phrase.split(' ');
  const overlay = document.createElement('div');
  overlay.className = 'modal-overlay';
  overlay.style.zIndex = '9999';
  overlay.innerHTML = `
    <div class="modal-card" style="width:520px;max-width:95vw">
      <div class="modal-head">
        <h2>${t('wallet_your_seed')}</h2>
        <button class="btn-close" id="close-seed-viewer">
          <svg width="20" height="20"><use href="#i-x"/></svg>
        </button>
      </div>
      <div class="modal-body">
        <div class="mnemonic-warning">${t('wallet_backup_warning')}</div>
        <div class="mnemonic-grid" style="margin-top:14px">
          ${words.map((w, i) => `
            <div class="mnemonic-word">
              <span class="mnemonic-word-num">${i + 1}</span> ${w}
            </div>`).join('')}
        </div>
        <button class="btn-primary" style="margin-top:18px" id="close-seed-btn">${t('close')}</button>
      </div>
    </div>`;
  document.body.appendChild(overlay);
  const close = () => overlay.remove();
  overlay.querySelector('#close-seed-viewer').addEventListener('click', close);
  overlay.querySelector('#close-seed-btn').addEventListener('click', close);
  overlay.addEventListener('click', e => { if (e.target === overlay) close(); });
}

// ── Wire all wallet UI events ─────────────────────────────────────────────────

function wireWallet() {
  // Open modal from empty state / sidebar button
  document.getElementById('btn-new-wallet')?.addEventListener('click', openWalletModal);
  document.getElementById('btn-wallet-start')?.addEventListener('click', openWalletModal);

  // Close modal
  document.getElementById('btn-close-wallet-modal')?.addEventListener('click', closeWalletModal);
  document.getElementById('modal-wallet')?.addEventListener('click', e => {
    if (e.target.id === 'modal-wallet') closeWalletModal();
  });

  // Tabs inside create modal
  document.getElementById('tab-wallet-gen')?.addEventListener('click', () => {
    document.getElementById('tab-wallet-gen').classList.add('active');
    document.getElementById('tab-wallet-import').classList.remove('active');
    document.getElementById('wallet-panel-gen').classList.remove('hidden');
    document.getElementById('wallet-panel-import').classList.add('hidden');
  });
  document.getElementById('tab-wallet-import')?.addEventListener('click', () => {
    document.getElementById('tab-wallet-gen').classList.remove('active');
    document.getElementById('tab-wallet-import').classList.add('active');
    document.getElementById('wallet-panel-gen').classList.add('hidden');
    document.getElementById('wallet-panel-import').classList.remove('hidden');
  });

  // Generate mnemonic
  document.getElementById('btn-gen-wallet')?.addEventListener('click', async () => {
    const wordCount = parseInt(document.getElementById('wallet-gen-words').value) || 12;
    try {
      pendingMnemonic = await invoke('wallet_generate_mnemonic', { wordCount });
      const box = document.getElementById('wallet-mnemonic-box');
      box.classList.remove('hidden');
      const words = pendingMnemonic.split(' ');
      document.getElementById('wallet-mnemonic-words').innerHTML =
        words.map((w, i) => `
          <div class="mnemonic-word">
            <span class="mnemonic-word-num">${i + 1}</span> ${w}
          </div>`).join('');
    } catch (e) { showToast(String(e)); }
  });

  // Enable save only when checkbox is ticked
  document.getElementById('wallet-backed-up')?.addEventListener('change', e => {
    document.getElementById('btn-save-gen-wallet').disabled = !e.target.checked;
  });

  // Save generated wallet
  document.getElementById('btn-save-gen-wallet')?.addEventListener('click', async () => {
    const name = document.getElementById('wallet-gen-name').value.trim() || 'Wallet';
    if (!pendingMnemonic) return;
    try {
      const w = await invoke('wallet_create', { name, mnemonic: pendingMnemonic });
      wallets.push(w);
      activeWalletId = w.id;
      renderWalletList();
      renderWalletDetail(w);
      closeWalletModal();
      showToast(t('wallet_created'));
    } catch (e) { showToast(String(e)); }
  });

  // Import mnemonic — validate on input
  document.getElementById('wallet-import-phrase')?.addEventListener('input', async () => {
    const phrase = document.getElementById('wallet-import-phrase').value.trim();
    const statusEl = document.getElementById('wallet-import-status');
    if (!phrase) { statusEl.textContent = ''; return; }
    const valid = await invoke('wallet_validate_mnemonic', { phrase }).catch(() => false);
    statusEl.textContent = valid ? ('✓ ' + t('wallet_valid_seed')) : ('✗ ' + t('wallet_invalid_seed'));
    statusEl.style.color = valid ? 'var(--acc)' : 'var(--red)';
  });

  // Import wallet
  document.getElementById('btn-import-wallet')?.addEventListener('click', async () => {
    const name   = document.getElementById('wallet-import-name').value.trim() || 'Wallet';
    const phrase = document.getElementById('wallet-import-phrase').value.trim();
    if (!phrase) return;
    const valid = await invoke('wallet_validate_mnemonic', { phrase }).catch(() => false);
    if (!valid) { showToast(t('wallet_invalid_seed')); return; }
    try {
      const w = await invoke('wallet_create', { name, mnemonic: phrase });
      wallets.push(w);
      activeWalletId = w.id;
      renderWalletList();
      renderWalletDetail(w);
      closeWalletModal();
      showToast(t('wallet_imported'));
    } catch (e) { showToast(String(e)); }
  });

  // ETH send modal close
  document.getElementById('btn-close-eth-send')?.addEventListener('click', closeEthSendModal);
  document.getElementById('modal-eth-send')?.addEventListener('click', e => {
    if (e.target.id === 'modal-eth-send') closeEthSendModal();
  });

  // ETH preview
  document.getElementById('btn-eth-preview')?.addEventListener('click', async () => {
    const walletId = document.getElementById('send-wallet-id').value;
    const to       = document.getElementById('send-eth-to').value.trim();
    const amount   = parseFloat(document.getElementById('send-eth-amount').value);
    const rpc      = document.getElementById('send-eth-rpc').value.trim();
    const chainId  = parseInt(document.getElementById('send-eth-chain').value) || 1;
    if (!to || isNaN(amount) || amount <= 0) { showToast(t('wallet_fill_fields')); return; }
    try {
      const preview = await invoke('wallet_eth_preview', {
        walletId, to, amountEth: amount, chainId, rpcUrl: rpc
      });
      document.getElementById('preview-gas-gwei').textContent = `${preview.gas_price_gwei.toFixed(2)} Gwei`;
      document.getElementById('preview-fee-eth').textContent  = `${preview.fee_eth.toFixed(8)} ETH`;
      document.getElementById('preview-total-eth').textContent = `${(amount + preview.fee_eth).toFixed(8)} ETH`;
      document.getElementById('eth-tx-preview').classList.remove('hidden');
      document.getElementById('btn-eth-confirm').classList.remove('hidden');
      document.getElementById('eth-tx-result').classList.add('hidden');
    } catch (e) { showToast(String(e)); }
  });

  // ETH confirm & send
  document.getElementById('btn-eth-confirm')?.addEventListener('click', async () => {
    const walletId = document.getElementById('send-wallet-id').value;
    const to       = document.getElementById('send-eth-to').value.trim();
    const amount   = parseFloat(document.getElementById('send-eth-amount').value);
    const rpc      = document.getElementById('send-eth-rpc').value.trim();
    const chainId  = parseInt(document.getElementById('send-eth-chain').value) || 1;
    const btn      = document.getElementById('btn-eth-confirm');
    btn.disabled = true;
    btn.textContent = t('wallet_sending');
    try {
      const txHash = await invoke('wallet_eth_send', {
        walletId, to, amountEth: amount, chainId, rpcUrl: rpc
      });
      const resultEl = document.getElementById('eth-tx-result');
      let explorerUrl = `https://etherscan.io/tx/${txHash}`;
      if (chainId === 56) explorerUrl = `https://bscscan.com/tx/${txHash}`;
      else if (chainId === 137) explorerUrl = `https://polygonscan.com/tx/${txHash}`;
      else if (chainId === 43114) explorerUrl = `https://snowtrace.io/tx/${txHash}`;
      else if (chainId === 42161) explorerUrl = `https://arbiscan.io/tx/${txHash}`;
      else if (chainId === 10) explorerUrl = `https://optimistic.etherscan.io/tx/${txHash}`;
      else if (chainId === 8453) explorerUrl = `https://basescan.org/tx/${txHash}`;
      
      resultEl.innerHTML = `${t('wallet_tx_sent')} <a class="tx-hash-link" 
        href="${explorerUrl}" target="_blank">${txHash}</a>`;
      resultEl.classList.remove('hidden');
      showToast(t('wallet_tx_sent'));
    } catch (e) {
      showToast(String(e));
    } finally {
      btn.disabled = false;
      btn.textContent = t('wallet_confirm_send');
    }
  });

  // Swap modal
  document.getElementById('btn-close-swap')?.addEventListener('click', closeSwapModal);
  document.getElementById('modal-swap')?.addEventListener('click', e => {
    if (e.target.id === 'modal-swap') closeSwapModal();
  });

  document.getElementById('btn-swap-flip')?.addEventListener('click', () => {
    const fromInput = document.getElementById('swap-from-asset');
    const toInput   = document.getElementById('swap-to-asset');
    const tmp = fromInput.value;
    
    const setSwapSelect = (prefix, val) => {
      const container = document.getElementById(`${prefix}-container`);
      const display = container.querySelector('.select-selected');
      const hiddenInput = container.querySelector('input[type="hidden"]');
      const asset = FIXED_ASSETS.find(a => a.id === val);
      if (asset) {
        display.innerHTML = `
          <div style="display:flex;align-items:center;gap:12px;">
            <img src="${asset.icon}" style="width:24px;height:24px;border-radius:50%" />
            <span style="color:#fff;font-size:.95rem">${asset.label} <span style="color:var(--muted);font-size:.85rem">${asset.symbol}</span></span>
          </div>
        `;
        hiddenInput.value = asset.id;
      }
    };

    setSwapSelect('swap-from', toInput.value);
    setSwapSelect('swap-to', tmp);
    
    document.getElementById('swap-to-amount').value = '';
    document.getElementById('swap-quote-result').classList.add('hidden');
  });

  document.getElementById('btn-swap-quote')?.addEventListener('click', async () => {
    const fromId   = document.getElementById('swap-from-asset').value;
    const toId     = document.getElementById('swap-to-asset').value;
    const amountRaw = parseFloat(document.getElementById('swap-from-amount').value);
    if (!fromId || !toId || fromId === toId) { showToast('Выберите два разных актива'); return; }
    if (isNaN(amountRaw) || amountRaw <= 0) { showToast(t('wallet_fill_fields')); return; }

    const fromAsset = FIXED_ASSETS.find(a => a.id === fromId);
    const toAsset   = FIXED_ASSETS.find(a => a.id === toId);
    if (!fromAsset || !toAsset) return;

    // Get the wallet's receive address for the to-asset
    const wallet = wallets.find(w => w.id === swapWalletId);
    const toAddress = wallet ? getAssetAddress(wallet, toAsset) : '';
    const fromAddress = wallet ? getAssetAddress(wallet, fromAsset) : '';

    const btn = document.getElementById('btn-swap-quote');
    btn.disabled = true;
    btn.textContent = '…';
    try {
      const quote = await invoke('wallet_get_swap_quote', {
        fromCgId:   fromAsset.cgId,
        toCgId:     toAsset.cgId,
        fromSymbol: fromAsset.symbol,
        toSymbol:   toAsset.symbol,
        fromAmount: amountRaw,
      });
      document.getElementById('swap-to-amount').value = quote.to_amount.toFixed(8);
      document.getElementById('swap-rate-display').textContent =
        `1 ${fromAsset.symbol} = ${(quote.to_amount / amountRaw).toFixed(8)} ${toAsset.symbol}`;
      document.getElementById('swap-from-usd').textContent =
        '$' + quote.from_usd.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
      document.getElementById('swap-to-usd').textContent =
        '$' + quote.to_usd.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
      document.getElementById('swap-to-address-display').textContent = toAddress || '—';
      document.getElementById('swap-quote-result').classList.remove('hidden');

      // Store data for the exchange button
      const execBtn = document.getElementById('btn-execute-swap');
      execBtn.onclick = () => {
        if (!toAddress) { showToast('Адрес получения не найден'); return; }
        const cnFrom = fromAsset.cnTicker || fromAsset.symbol.toLowerCase();
        const cnTo   = toAsset.cnTicker   || toAsset.symbol.toLowerCase();
        let url = `https://changenow.io/exchange?from=${cnFrom}&to=${cnTo}&amount=${amountRaw}&toAddress=${encodeURIComponent(toAddress)}`;
        if (fromAddress) url += `&refundAddress=${encodeURIComponent(fromAddress)}`;
        window.open(url, '_blank');
      };
    } catch (e) {
      const msg = String(e);
      if (msg.includes('429') || msg.includes('rate') || msg.includes('Rate')) {
        showToast(t('swap_rate_limited') || 'API перегружен, подождите минуту');
      } else if (msg.includes('No price')) {
        showToast('Не удалось получить курс. Попробуйте позже.');
      } else {
        showToast('Ошибка: ' + msg);
      }
    } finally {
      btn.disabled = false;
      btn.textContent = t('swap_calculate') || 'Рассчитать курс';
    }
  });

  // Receive modal
  document.getElementById('btn-close-receive')?.addEventListener('click', closeReceiveModal);
  document.getElementById('modal-receive')?.addEventListener('click', e => {
    if (e.target.id === 'modal-receive') closeReceiveModal();
  });
  document.getElementById('btn-copy-receive-addr')?.addEventListener('click', () => {
    const addr = document.getElementById('receive-address').textContent;
    if (addr && addr !== '—') {
      copyText(addr);
    }
  });

  // Close Send Token modal
  document.getElementById('btn-close-token-send')?.addEventListener('click', closeTokenSendModal);
  document.getElementById('modal-token-send')?.addEventListener('click', e => {
    if (e.target.id === 'modal-token-send') closeTokenSendModal();
  });

  // Token preview
  document.getElementById('btn-token-preview')?.addEventListener('click', async () => {
    const walletId = document.getElementById('token-send-wallet-id').value;
    const contract = document.getElementById('token-send-contract').value;
    const decimals = parseInt(document.getElementById('token-send-decimals').value) || 18;
    const chainId  = parseInt(document.getElementById('token-send-chain-id-hidden').value) || 1;
    const to       = document.getElementById('token-send-to').value.trim();
    const amount   = parseFloat(document.getElementById('token-send-amount').value);
    const rpc      = document.getElementById('token-send-rpc').value.trim();
    if (!to || isNaN(amount) || amount <= 0) { showToast(t('wallet_fill_fields')); return; }
    try {
      const preview = await invoke('wallet_token_preview', {
        walletId, contractAddress: contract, to, amount, decimals, chainId, rpcUrl: rpc
      });
      document.getElementById('token-preview-gas-gwei').textContent = `${preview.gas_price_gwei.toFixed(2)} Gwei`;
      document.getElementById('token-preview-fee-eth').textContent  = `${preview.fee_eth.toFixed(8)} ETH`;
      document.getElementById('token-preview-amount').textContent   = `${amount}`;
      document.getElementById('token-tx-preview').classList.remove('hidden');
      document.getElementById('btn-token-confirm').classList.remove('hidden');
      document.getElementById('token-tx-result').classList.add('hidden');
    } catch (e) { showToast(String(e)); }
  });

  // Token confirm & send
  document.getElementById('btn-token-confirm')?.addEventListener('click', async () => {
    const walletId = document.getElementById('token-send-wallet-id').value;
    const contract = document.getElementById('token-send-contract').value;
    const decimals = parseInt(document.getElementById('token-send-decimals').value) || 18;
    const chainId  = parseInt(document.getElementById('token-send-chain-id-hidden').value) || 1;
    const to       = document.getElementById('token-send-to').value.trim();
    const amount   = parseFloat(document.getElementById('token-send-amount').value);
    const rpc      = document.getElementById('token-send-rpc').value.trim();
    const btn      = document.getElementById('btn-token-confirm');
    btn.disabled = true;
    btn.textContent = t('wallet_sending');
    try {
      const txHash = await invoke('wallet_token_send', {
        walletId, contractAddress: contract, to, amount, decimals, chainId, rpcUrl: rpc
      });
      const resultEl = document.getElementById('token-tx-result');
      let explorerUrl = `https://etherscan.io/tx/${txHash}`;
      if (chainId === 56) explorerUrl = `https://bscscan.com/tx/${txHash}`;
      else if (chainId === 137) explorerUrl = `https://polygonscan.com/tx/${txHash}`;
      else if (chainId === 43114) explorerUrl = `https://snowtrace.io/tx/${txHash}`;
      else if (chainId === 42161) explorerUrl = `https://arbiscan.io/tx/${txHash}`;
      else if (chainId === 10) explorerUrl = `https://optimistic.etherscan.io/tx/${txHash}`;
      else if (chainId === 8453) explorerUrl = `https://basescan.org/tx/${txHash}`;
      
      resultEl.innerHTML = `${t('wallet_tx_sent')} <a class="tx-hash-link"
        href="${explorerUrl}" target="_blank">${txHash}</a>`;
      resultEl.classList.remove('hidden');
      showToast(t('wallet_tx_sent'));
    } catch (e) {
      showToast(String(e));
    } finally {
      btn.disabled = false;
      btn.textContent = t('wallet_confirm_send');
    }
  });
}
