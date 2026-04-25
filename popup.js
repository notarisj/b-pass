/* global encryptData, decryptData, hashMasterPassword, timingSafeEqual, generatePassword, generateId */
// ─── State ───────────────────────────────────────────────────────────────────
let masterPassword = null;
let credentials = [];
let editingId = null;
let viewingCredential = null;
let massGeneratedPasswords = {};
let currentTabUrl = '';

// ─── Storage helpers ──────────────────────────────────────────────────────────
async function getStorage(keys) {
  return new Promise(resolve => chrome.storage.local.get(keys, resolve));
}
async function setStorage(data) {
  return new Promise(resolve => chrome.storage.local.set(data, resolve));
}

// ─── Credential persistence ───────────────────────────────────────────────────
async function saveCredentials() {
  const encrypted = await encryptData(JSON.stringify(credentials), masterPassword);
  await setStorage({ credentials: encrypted });
}

async function loadCredentials() {
  const { credentials: enc } = await getStorage(['credentials']);
  if (!enc) { credentials = []; return; }
  try {
    const json = await decryptData(enc, masterPassword);
    credentials = JSON.parse(json);
  } catch {
    credentials = [];
    // Decryption failed — vault may be corrupted or wrong key was used
    showToast('Vault decryption failed. Data may be corrupted.', 'error');
  }
}

// ─── Master password setup / unlock ──────────────────────────────────────────
async function setupVault(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const saltB64 = btoa(String.fromCharCode(...salt));
  const hash = await hashMasterPassword(password, salt);
  await setStorage({ vaultSetup: true, masterSalt: saltB64, masterHash: hash, credentials: null });
}

async function verifyMasterPassword(password) {
  const { masterSalt, masterHash } = await getStorage(['masterSalt', 'masterHash']);
  if (!masterSalt || !masterHash) return false;
  const salt = Uint8Array.from(atob(masterSalt), c => c.charCodeAt(0));
  const hash = await hashMasterPassword(password, salt);
  return timingSafeEqual(hash, masterHash);
}

// ─── Init ─────────────────────────────────────────────────────────────────────
async function init() {
  const { vaultSetup, settings } = await getStorage(['vaultSetup', 'settings']);

  const { key } = await chrome.runtime.sendMessage({ action: 'GET_SESSION_KEY' });
  if (key) {
    masterPassword = key;
    await loadCredentials();
    await showMain(settings);
    return;
  }

  if (!vaultSetup) showScreen('setup');
  else showScreen('unlock');
}

// ─── Screen management ────────────────────────────────────────────────────────
function showScreen(name) {
  document.querySelectorAll('.screen').forEach(s => s.classList.add('hidden'));
  document.getElementById(`screen-${name}`).classList.remove('hidden');
  if (name === 'unlock') {
    const f = document.getElementById('unlock-password');
    f.value = '';
    f.blur();
  }
}

async function showMain(settings) {
  showScreen('main');

  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  if (tabs[0]) currentTabUrl = tabs[0].url || '';

  renderCredentials();
  updateSiteBanner();
  renderMassChangeList();

  if (settings) {
    document.getElementById('auto-lock-select').value = settings.autoLockTimeout ?? 15;
    document.getElementById('autofill-enabled').checked = settings.autoFill ?? true;
    document.getElementById('autosubmit-enabled').checked = settings.autoSubmit ?? false;
  }
}

// ─── Password strength ────────────────────────────────────────────────────────
function calcStrength(pw) {
  if (!pw) return 0;
  let s = 0;
  if (pw.length >= 8) s++;
  if (pw.length >= 12) s++;
  if (/[A-Z]/.test(pw)) s++;
  if (/[a-z]/.test(pw)) s++;
  if (/[0-9]/.test(pw)) s++;
  if (/[^a-zA-Z0-9]/.test(pw)) s++;
  return Math.min(s, 4);
}

function renderStrength(pw, barId) {
  const bar = document.getElementById(barId);
  if (!bar) return;
  const str = calcStrength(pw);
  const colors = ['#f44336','#ff9800','#ffc107','#8bc34a','#4caf50'];
  const widths = [0, 25, 50, 75, 100];
  let inner = bar.querySelector('.strength-bar');
  if (!inner) { inner = document.createElement('div'); inner.className = 'strength-bar'; bar.appendChild(inner); }
  inner.style.width = widths[str] + '%';
  inner.style.background = colors[str];
}

// ─── URL matching ─────────────────────────────────────────────────────────────
function extractDomain(url) {
  try { return new URL(url).hostname.replace(/^www\./, ''); } catch { return ''; }
}

// Returns "hostname:port" for display — port omitted when it is the protocol default.
function extractSiteLabel(url) {
  try {
    const u = new URL(url);
    const host = u.hostname.replace(/^www\./, '');
    return u.port ? `${host}:${u.port}` : host;
  } catch { return ''; }
}

function matchesUrl(credUrl, pageUrl) {
  if (!credUrl || !pageUrl) return false;
  try {
    const cred = new URL(credUrl);
    const page = new URL(pageUrl);

    // Hostname must match (ignore www.)
    if (cred.hostname.replace(/^www\./, '') !== page.hostname.replace(/^www\./, '')) return false;

    // Different port = different site (normalize missing port to protocol default)
    const resolvedPort = (u) => u.port || (u.protocol === 'https:' ? '443' : '80');
    if (resolvedPort(cred) !== resolvedPort(page)) return false;

    // The page path must fall within the credential URL's directory.
    // e.g. credential stored at /Wholesale/login.jsp → credDir is /Wholesale/
    const credDir = cred.pathname.endsWith('/')
      ? cred.pathname
      : cred.pathname.slice(0, cred.pathname.lastIndexOf('/') + 1) || '/';
    return page.pathname.startsWith(credDir);
  } catch { return false; }
}

function getMatchingCredentials(url) {
  return credentials.filter(c => matchesUrl(c.url, url));
}

// ─── Site banner ──────────────────────────────────────────────────────────────
function updateSiteBanner() {
  const banner = document.getElementById('current-site-banner');
  const text = document.getElementById('current-site-text');
  const badgeList = document.getElementById('site-badge-list');
  const matching = getMatchingCredentials(currentTabUrl);

  if (matching.length === 0) { banner.classList.add('hidden'); return; }

  banner.classList.remove('hidden');
  text.textContent = extractSiteLabel(currentTabUrl);

  // Build badges without inline event handlers (CSP safe)
  badgeList.innerHTML = matching.map(c =>
    `<button class="site-badge" data-id="${escHtml(c.id)}" title="${escHtml(c.username)}">${escHtml(c.username)}</button>`
  ).join('');

  badgeList.querySelectorAll('.site-badge').forEach(btn => {
    btn.addEventListener('click', () => fillOnPage(btn.dataset.id));
  });
}

// ─── Render credentials ───────────────────────────────────────────────────────
function renderCredentials(filter = '') {
  const list = document.getElementById('credentials-list');
  let items = credentials;
  if (filter) {
    const q = filter.toLowerCase();
    items = items.filter(c =>
      (c.name || '').toLowerCase().includes(q) ||
      (c.username || '').toLowerCase().includes(q) ||
      (c.url || '').toLowerCase().includes(q)
    );
  }

  if (items.length === 0) {
    list.innerHTML = `<div class="empty-state">${filter ? 'No results.' : 'No credentials yet. Click + Add to create one.'}</div>`;
    return;
  }

  // Build HTML without inline event handlers (onerror replaced with JS below)
  list.innerHTML = items.map(c => {
    const domain = extractDomain(c.url);
    const hasFavicon = !!domain;
    const isSelected = selectedIds.has(c.id);
    return `<div class="credential-item${selectMode ? ' selectable' + (isSelected ? ' selected' : '') : ''}" data-id="${escHtml(c.id)}">
        ${selectMode ? `<input type="checkbox" class="item-checkbox" data-id="${escHtml(c.id)}"${isSelected ? ' checked' : ''} />` : ''}
        <div class="credential-favicon">
          ${hasFavicon
            ? `<img class="favicon-img" src="https://www.google.com/s2/favicons?domain=${encodeURIComponent(domain)}&sz=28" width="18" height="18" alt="" />`
            : '<span>🔑</span>'}
        </div>
        <div class="credential-info">
          <div class="credential-name">${escHtml(c.name || domain || 'Unnamed')}</div>
          <div class="credential-username">${escHtml(c.username)}</div>
        </div>
        ${!selectMode ? `<div class="credential-actions"><button class="btn btn-sm fill-btn" data-id="${escHtml(c.id)}">Fill</button></div>` : ''}
      </div>`;
  }).join('');

  // Attach error handlers after rendering (CSP-safe, no inline onerror)
  list.querySelectorAll('.favicon-img').forEach(img => {
    const fallback = () => {
      const span = document.createElement('span');
      span.textContent = '🔑';
      img.replaceWith(span);
    };
    img.addEventListener('error', fallback);
    // Handle already-failed images (browser may fire error before listener attaches)
    if (img.complete && img.naturalWidth === 0) fallback();
  });
}

// ─── Credential modal ─────────────────────────────────────────────────────────
function openAddModal() {
  editingId = null;
  document.getElementById('modal-title').textContent = 'Add Credential';
  document.getElementById('cred-name').value = '';
  document.getElementById('cred-url').value = currentTabUrl;
  document.getElementById('cred-username').value = '';
  document.getElementById('cred-password').value = '';
  document.getElementById('cred-password').type = 'password';
  document.getElementById('modal-error').classList.add('hidden');
  document.getElementById('gen-options').classList.add('hidden');
  document.getElementById('modal-credential').classList.remove('hidden');
  document.getElementById('cred-name').focus();
}

function openEditModal(id) {
  const cred = credentials.find(c => c.id === id);
  if (!cred) return;
  editingId = id;
  document.getElementById('modal-title').textContent = 'Edit Credential';
  document.getElementById('cred-name').value = cred.name;
  document.getElementById('cred-url').value = cred.url;
  document.getElementById('cred-username').value = cred.username;
  document.getElementById('cred-password').value = cred.password;
  document.getElementById('cred-password').type = 'password';
  document.getElementById('modal-error').classList.add('hidden');
  document.getElementById('gen-options').classList.add('hidden');
  document.getElementById('modal-credential').classList.remove('hidden');
}

function closeModal() {
  editingId = null;
  document.getElementById('modal-credential').classList.add('hidden');
}

async function saveCredential() {
  const name = document.getElementById('cred-name').value.trim();
  const url = document.getElementById('cred-url').value.trim();
  const username = document.getElementById('cred-username').value.trim();
  const password = document.getElementById('cred-password').value;

  if (!url || !username || !password) {
    showModalError('URL, username and password are required.');
    return;
  }

  if (editingId) {
    const idx = credentials.findIndex(c => c.id === editingId);
    if (idx >= 0) {
      credentials[idx] = { ...credentials[idx], name: name || extractDomain(url), url, username, password, lastModified: Date.now() };
    }
  } else {
    credentials.push({ id: generateId(), name: name || extractDomain(url), url, username, password, lastModified: Date.now() });
  }

  await saveCredentials();
  renderCredentials(document.getElementById('search-input').value);
  renderMassChangeList();
  updateSiteBanner();
  closeModal();
}

function showModalError(msg) {
  const el = document.getElementById('modal-error');
  el.textContent = msg;
  el.classList.remove('hidden');
}

async function deleteCredential(id) {
  credentials = credentials.filter(c => c.id !== id);
  await saveCredentials();
  renderCredentials(document.getElementById('search-input').value);
  renderMassChangeList();
  updateSiteBanner();
}

// ─── Bulk select / delete ─────────────────────────────────────────────────────
let selectMode = false;
let selectedIds = new Set();

function enterSelectMode() {
  selectMode = true;
  selectedIds.clear();
  document.getElementById('select-mode-btn').textContent = 'Cancel';
  document.getElementById('select-mode-btn').classList.add('btn-primary');
  document.getElementById('add-credential-btn').classList.add('hidden');
  document.getElementById('bulk-action-bar').classList.remove('hidden');
  renderCredentials(document.getElementById('search-input').value);
  updateBulkCount();
}

function exitSelectMode() {
  selectMode = false;
  selectedIds.clear();
  document.getElementById('select-mode-btn').textContent = 'Select';
  document.getElementById('select-mode-btn').classList.remove('btn-primary');
  document.getElementById('add-credential-btn').classList.remove('hidden');
  document.getElementById('bulk-action-bar').classList.add('hidden');
  renderCredentials(document.getElementById('search-input').value);
}

function updateBulkCount() {
  document.getElementById('bulk-count').textContent = `${selectedIds.size} selected`;
  document.getElementById('bulk-delete-btn').disabled = selectedIds.size === 0;
}

async function deleteSelected() {
  if (selectedIds.size === 0) return;
  if (!confirm(`Delete ${selectedIds.size} credential(s)? This cannot be undone.`)) return;
  credentials = credentials.filter(c => !selectedIds.has(c.id));
  await saveCredentials();
  updateSiteBanner();
  renderMassChangeList();
  exitSelectMode();
}

async function deleteAll() {
  if (credentials.length === 0) return;
  if (!confirm(`Delete ALL ${credentials.length} credential(s)? This cannot be undone.`)) return;
  credentials = [];
  await saveCredentials();
  updateSiteBanner();
  renderMassChangeList();
  exitSelectMode();
}

// ─── View credential ──────────────────────────────────────────────────────────
function openViewModal(id) {
  viewingCredential = credentials.find(c => c.id === id);
  if (!viewingCredential) return;
  document.getElementById('view-title').textContent = viewingCredential.name || extractDomain(viewingCredential.url);
  document.getElementById('view-username').textContent = viewingCredential.username;
  const pwEl = document.getElementById('view-password');
  pwEl.textContent = '••••••••';
  pwEl.dataset.real = viewingCredential.password;
  pwEl.dataset.shown = '0';
  document.getElementById('view-pw-toggle').textContent = 'Show';
  document.getElementById('view-url').textContent = viewingCredential.url;
  document.getElementById('modal-view').classList.remove('hidden');
}

function closeViewModal() {
  viewingCredential = null;
  const pwEl = document.getElementById('view-password');
  // Clear the password from the DOM when closing
  pwEl.dataset.real = '';
  pwEl.dataset.shown = '0';
  pwEl.textContent = '••••••••';
  document.getElementById('view-pw-toggle').textContent = 'Show';
  document.getElementById('modal-view').classList.add('hidden');
}

// ─── Autofill ─────────────────────────────────────────────────────────────────
async function fillOnPage(id) {
  const cred = credentials.find(c => c.id === id);
  if (!cred) return;
  const { settings } = await getStorage(['settings']);
  let res;
  try {
    res = await chrome.runtime.sendMessage({
      action: 'FILL_ACTIVE_TAB',
      username: cred.username,
      password: cred.password,
      autoSubmit: settings?.autoSubmit ?? false
    });
  } catch {
    res = null;
  }
  if (!res?.success) {
    showToast('Could not fill: ' + (res?.error || 'no login form found'), 'error');
  } else {
    window.close();
  }
}

// ─── Mass change ──────────────────────────────────────────────────────────────
function renderMassChangeList(filter = '') {
  const list = document.getElementById('mass-credentials-list');
  let items = credentials;
  if (filter) {
    const q = filter.toLowerCase();
    items = items.filter(c =>
      (c.name || '').toLowerCase().includes(q) ||
      (c.url || '').toLowerCase().includes(q) ||
      (c.username || '').toLowerCase().includes(q)
    );
  }

  if (items.length === 0) {
    list.innerHTML = '<div class="empty-state" style="padding:12px">No credentials found.</div>';
    return;
  }

  list.innerHTML = items.map(c => `
    <div class="mass-item" data-id="${escHtml(c.id)}">
      <input type="checkbox" class="mass-check" data-id="${escHtml(c.id)}" />
      <div class="mass-item-info">
        <div class="mass-item-name">${escHtml(c.name || extractDomain(c.url))}</div>
        <div class="mass-item-user">${escHtml(c.username)} · ${escHtml(extractDomain(c.url))}</div>
      </div>
    </div>`).join('');
}

async function startMassChange() {
  const checked = [...document.querySelectorAll('.mass-check:checked')];
  if (checked.length === 0) { showToast('Select at least one credential.', 'error'); return; }

  const changeUrl = document.getElementById('mass-change-url').value.trim();
  const strategy = document.querySelector('input[name="pw-strategy"]:checked').value;
  const sameNewPw = document.getElementById('mass-new-password').value;
  const pwLength = Math.max(8, Math.min(64, parseInt(document.getElementById('mass-pw-length').value) || 16));

  if (strategy === 'same' && !sameNewPw) { showToast('Enter a new password.', 'error'); return; }

  const btn = document.getElementById('mass-change-btn');
  btn.disabled = true;
  btn.textContent = 'Running…';

  const progressArea = document.getElementById('mass-change-progress');
  progressArea.classList.remove('hidden');
  progressArea.innerHTML = '';

  const selectedIds = checked.map(ch => ch.dataset.id);

  for (const id of selectedIds) {
    const cred = credentials.find(c => c.id === id);
    if (!cred) continue;

    const newPw = strategy === 'same' ? sameNewPw : generatePassword(pwLength);
    const item = document.createElement('div');
    item.className = 'progress-item pending';
    item.textContent = `⏳ ${cred.name || extractDomain(cred.url)} (${cred.username})`;
    progressArea.appendChild(item);

    if (changeUrl) {
      try {
        await new Promise((resolve, reject) => {
          // 30-second timeout per tab so the loop cannot hang indefinitely
          const timeout = setTimeout(() => {
            chrome.tabs.onUpdated.removeListener(listener);
            reject(new Error('Page load timed out after 30 seconds'));
          }, 30000);

          chrome.tabs.create({ url: changeUrl }, tab => {
            if (chrome.runtime.lastError) {
              clearTimeout(timeout);
              reject(new Error(chrome.runtime.lastError.message));
              return;
            }
            const listener = (tabId, info) => {
              if (tabId !== tab.id || info.status !== 'complete') return;
              chrome.tabs.onUpdated.removeListener(listener);
              clearTimeout(timeout);
              setTimeout(async () => {
                try {
                  const res = await chrome.runtime.sendMessage({
                    action: 'FILL_CHANGE_PASSWORD_TAB',
                    tabId: tab.id,
                    oldPassword: cred.password,
                    newPassword: newPw
                  });
                  if (res?.success) {
                    item.className = 'progress-item success';
                    item.textContent = `✓ ${cred.name || extractDomain(cred.url)} (${cred.username}) — filled, awaiting submit`;
                  } else {
                    item.className = 'progress-item error';
                    item.textContent = `✗ ${cred.name || extractDomain(cred.url)}: ${res?.error || 'Could not fill form'}`;
                  }
                } catch (e) {
                  item.className = 'progress-item error';
                  item.textContent = `✗ ${cred.name || extractDomain(cred.url)}: ${e.message}`;
                }
                resolve();
              }, 800);
            };
            chrome.tabs.onUpdated.addListener(listener);
          });
        });
      } catch (e) {
        item.className = 'progress-item error';
        item.textContent = `✗ ${cred.name || extractDomain(cred.url)}: ${e.message}`;
      }
    } else {
      item.className = 'progress-item success';
      item.textContent = `✓ ${cred.name || extractDomain(cred.url)} (${cred.username}) — vault updated`;
    }

    // Update stored password
    const idx = credentials.findIndex(c => c.id === id);
    if (idx >= 0) credentials[idx] = { ...credentials[idx], password: newPw, lastModified: Date.now() };
  }

  await saveCredentials();
  massGeneratedPasswords = {};
  renderMassChangeList(document.getElementById('mass-filter').value);

  btn.disabled = false;
  btn.textContent = 'Start Mass Change';
  showToast('Mass change complete.', 'success');
}

// ─── Settings ─────────────────────────────────────────────────────────────────
async function saveSettings() {
  const timeout = parseInt(document.getElementById('auto-lock-select').value) || 0;
  const settings = {
    autoLockTimeout: timeout,
    autoFill: document.getElementById('autofill-enabled').checked,
    autoSubmit: document.getElementById('autosubmit-enabled').checked
  };
  await setStorage({ settings });
  chrome.runtime.sendMessage({ action: 'SET_SESSION_KEY', key: masterPassword, timeoutMinutes: timeout });
}

async function changeMasterPassword() {
  const currentPw = document.getElementById('change-current-pw').value;
  const newPw = document.getElementById('change-new-pw').value;
  const confirmPw = document.getElementById('change-confirm-pw').value;
  if (!currentPw || !newPw || !confirmPw) { showPwMsg('All fields required.', 'error'); return; }
  if (newPw !== confirmPw) { showPwMsg('New passwords do not match.', 'error'); return; }
  if (newPw.length < 8) { showPwMsg('Password must be at least 8 characters.', 'error'); return; }

  const valid = await verifyMasterPassword(currentPw);
  if (!valid) { showPwMsg('Current password is incorrect.', 'error'); return; }

  await setupVault(newPw);
  masterPassword = newPw;
  await saveCredentials();

  const timeout = parseInt(document.getElementById('auto-lock-select').value) || 0;
  chrome.runtime.sendMessage({ action: 'SET_SESSION_KEY', key: newPw, timeoutMinutes: timeout });
  showPwMsg('Master password updated successfully.', 'success');
  document.getElementById('change-current-pw').value = '';
  document.getElementById('change-new-pw').value = '';
  document.getElementById('change-confirm-pw').value = '';
}

function showPwMsg(msg, type) {
  const el = document.getElementById('change-pw-msg');
  el.textContent = msg;
  el.className = `msg ${type}`;
  el.classList.remove('hidden');
  setTimeout(() => el.classList.add('hidden'), 3000);
}

// ─── Export / Import ──────────────────────────────────────────────────────────
function exportVault() {
  if (!confirm('The exported file contains your passwords in plain text. Store it securely and never share it. Continue?')) return;
  const data = JSON.stringify({ version: 1, credentials, exportedAt: new Date().toISOString() }, null, 2);
  const blob = new Blob([data], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `b-pass-export-${new Date().toISOString().slice(0,10)}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

let pendingImport = [];

async function handleImportFile(file, format) {
  try {
    const text = await file.text();
    const parsed = format === 'csv' ? parseCSV(text) : parseJSON(text);
    if (!parsed.length) { showImportMsg('No valid credentials found in file.', 'error'); return; }
    pendingImport = parsed;
    renderImportPreview();
  } catch (e) {
    showImportMsg('Parse error: ' + e.message, 'error');
  }
}

function parseJSON(text) {
  const data = JSON.parse(text);
  if (data.credentials) return data.credentials.map(normalizeCredential);
  if (Array.isArray(data)) return data.map(normalizeCredential);
  throw new Error('Unrecognized JSON format');
}

function normalizeCredential(raw) {
  const url = raw.url || raw.login?.uris?.[0]?.uri || raw.URL || raw.uri || '';
  const username = raw.username || raw.login?.username || raw.Username || raw.UserName || '';
  const password = raw.password || raw.login?.password || raw.Password || '';
  const name = raw.name || raw.Name || raw.title || raw.Title || extractDomain(url) || 'Imported';
  return { id: generateId(), name: String(name), url: String(url), username: String(username), password: String(password), lastModified: Date.now() };
}

function parseCSV(text) {
  const lines = text.trim().split(/\r?\n/);
  if (lines.length < 2) throw new Error('CSV must have a header row and at least one data row');

  const delim = lines[0].includes('\t') ? '\t' : ',';
  const headers = splitCSVLine(lines[0], delim).map(h => h.trim().toLowerCase().replace(/['"]/g, ''));

  const col = (names) => names.map(n => headers.indexOf(n)).find(i => i >= 0) ?? -1;
  const iName = col(['name','title','site','label']);
  const iUrl  = col(['url','uri','website','login_uri','web site']);
  const iUser = col(['username','user','email','login','login_username','user name']);
  const iPass = col(['password','pass','pwd','login_password']);

  if (iUser < 0 || iPass < 0) throw new Error('CSV must have username and password columns');

  return lines.slice(1).filter(l => l.trim()).map(line => {
    const cols = splitCSVLine(line, delim);
    const url      = iUrl  >= 0 ? (cols[iUrl]  || '').trim() : '';
    const username = iUser >= 0 ? (cols[iUser] || '').trim() : '';
    const password = iPass >= 0 ? (cols[iPass] || '').trim() : '';
    const name     = iName >= 0 ? (cols[iName] || '').trim() : extractDomain(url) || 'Imported';
    if (!username && !password) return null;
    return { id: generateId(), name: name || extractDomain(url) || 'Imported', url, username, password, lastModified: Date.now() };
  }).filter(Boolean);
}

function splitCSVLine(line, delim) {
  const result = [];
  let cur = '', inQuote = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '"' && !inQuote) { inQuote = true; continue; }
    if (ch === '"' && inQuote && line[i + 1] === '"') { cur += '"'; i++; continue; }
    if (ch === '"' && inQuote) { inQuote = false; continue; }
    if (ch === delim && !inQuote) { result.push(cur); cur = ''; continue; }
    cur += ch;
  }
  result.push(cur);
  return result;
}

function renderImportPreview() {
  const preview  = document.getElementById('import-preview');
  const countEl  = document.getElementById('import-preview-count');
  const listEl   = document.getElementById('import-preview-list');
  const existing = new Set(credentials.map(c => `${c.url}|${c.username}`));

  countEl.textContent = `${pendingImport.length} credential(s) found`;
  listEl.innerHTML = pendingImport.map(c => {
    const isDup = existing.has(`${c.url}|${c.username}`);
    return `<div class="import-preview-item${isDup ? ' duplicate' : ''}">
      <span class="ip-name">${escHtml(c.name)}</span>
      <span class="ip-user">${escHtml(c.username)} · ${escHtml(c.url || '—')}</span>
    </div>`;
  }).join('');

  preview.classList.remove('hidden');
  document.getElementById('import-msg').classList.add('hidden');
}

async function confirmImport() {
  let added = 0;
  pendingImport.forEach(c => {
    if (!credentials.find(e => e.url === c.url && e.username === c.username)) {
      credentials.push(c); added++;
    }
  });
  await saveCredentials();
  renderCredentials();
  renderMassChangeList();
  updateSiteBanner();
  const skipped = pendingImport.length - added;
  pendingImport = [];
  document.getElementById('import-preview').classList.add('hidden');
  showImportMsg(`Imported ${added} credential(s).${skipped > 0 ? ` ${skipped} skipped as duplicates.` : ''}`, 'success');
}

function showImportMsg(msg, type) {
  const el = document.getElementById('import-msg');
  el.textContent = msg;
  el.className = `msg ${type}`;
  el.classList.remove('hidden');
  setTimeout(() => el.classList.add('hidden'), 4000);
}

// ─── Toast ────────────────────────────────────────────────────────────────────
function showToast(msg, type = 'success') {
  const t = document.createElement('div');
  t.className = `toast toast-${type}`;
  t.textContent = msg;
  document.body.appendChild(t);
  setTimeout(() => t.remove(), 2500);
}

// ─── Utilities ────────────────────────────────────────────────────────────────
function escHtml(s) {
  return String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function setupEyeButtons() {
  document.querySelectorAll('.eye-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const target = document.getElementById(btn.dataset.target);
      if (!target) return;
      target.type = target.type === 'password' ? 'text' : 'password';
      btn.textContent = target.type === 'password' ? '👁' : '🙈';
    });
  });
}

// ─── Event wiring ─────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  setupEyeButtons();
  init();

  // Setup screen
  document.getElementById('setup-password').addEventListener('input', e => renderStrength(e.target.value, 'setup-strength'));
  document.getElementById('setup-btn').addEventListener('click', async () => {
    const pw   = document.getElementById('setup-password').value;
    const conf = document.getElementById('setup-confirm').value;
    const err  = document.getElementById('setup-error');
    if (pw.length < 8) { err.textContent = 'Password must be at least 8 characters.'; err.classList.remove('hidden'); return; }
    if (pw !== conf)   { err.textContent = 'Passwords do not match.'; err.classList.remove('hidden'); return; }
    err.classList.add('hidden');
    await setupVault(pw);
    masterPassword = pw;
    credentials = [];
    await saveCredentials();
    const { settings } = await getStorage(['settings']);
    await chrome.runtime.sendMessage({ action: 'SET_SESSION_KEY', key: pw, timeoutMinutes: 15 });
    await showMain(settings);
  });
  document.getElementById('setup-password').addEventListener('keydown', e => { if (e.key === 'Enter') document.getElementById('setup-confirm').focus(); });
  document.getElementById('setup-confirm').addEventListener('keydown', e => { if (e.key === 'Enter') document.getElementById('setup-btn').click(); });

  // Unlock screen
  document.getElementById('unlock-btn').addEventListener('click', async () => {
    const pw  = document.getElementById('unlock-password').value;
    const err = document.getElementById('unlock-error');
    err.classList.add('hidden');
    if (!pw) { err.textContent = 'Enter your master password.'; err.classList.remove('hidden'); return; }
    const valid = await verifyMasterPassword(pw);
    if (!valid) { err.textContent = 'Incorrect master password.'; err.classList.remove('hidden'); return; }
    masterPassword = pw;
    await loadCredentials();
    const { settings } = await getStorage(['settings']);
    await chrome.runtime.sendMessage({ action: 'SET_SESSION_KEY', key: pw, timeoutMinutes: settings?.autoLockTimeout ?? 15 });
    await showMain(settings);
  });
  document.getElementById('unlock-password').addEventListener('keydown', e => { if (e.key === 'Enter') document.getElementById('unlock-btn').click(); });

  // Lock
  document.getElementById('lock-btn').addEventListener('click', async () => {
    masterPassword = null;
    credentials = [];
    await chrome.runtime.sendMessage({ action: 'CLEAR_SESSION' });
    showScreen('unlock');
  });

  // Tab switching
  document.querySelectorAll('.tab').forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach(c => { c.classList.remove('active'); c.classList.remove('hidden'); });
      tab.classList.add('active');
      document.getElementById(`tab-${tab.dataset.tab}`).classList.add('active');
    });
  });

  // Vault tab
  document.getElementById('search-input').addEventListener('input', e => renderCredentials(e.target.value));
  document.getElementById('add-credential-btn').addEventListener('click', openAddModal);
  document.getElementById('select-mode-btn').addEventListener('click', () => selectMode ? exitSelectMode() : enterSelectMode());
  document.getElementById('bulk-select-all-btn').addEventListener('click', () => {
    const visible = [...document.querySelectorAll('.credential-item')].map(el => el.dataset.id);
    const allSelected = visible.every(id => selectedIds.has(id));
    visible.forEach(id => allSelected ? selectedIds.delete(id) : selectedIds.add(id));
    renderCredentials(document.getElementById('search-input').value);
    updateBulkCount();
  });
  document.getElementById('bulk-delete-btn').addEventListener('click', deleteSelected);
  document.getElementById('bulk-delete-all-btn').addEventListener('click', deleteAll);
  document.getElementById('bulk-cancel-btn').addEventListener('click', exitSelectMode);
  document.getElementById('credentials-list').addEventListener('click', e => {
    const fillBtn = e.target.closest('.fill-btn');
    const item    = e.target.closest('.credential-item');
    if (!item) return;
    const id = item.dataset.id;

    if (selectMode) {
      // Clicking anywhere on the row (except the checkbox itself) toggles it too
      if (selectedIds.has(id)) selectedIds.delete(id);
      else selectedIds.add(id);
      // Keep checkbox in sync
      const cb = item.querySelector('.item-checkbox');
      if (cb) cb.checked = selectedIds.has(id);
      item.classList.toggle('selected', selectedIds.has(id));
      updateBulkCount();
      return;
    }

    if (fillBtn) { e.stopPropagation(); fillOnPage(id); return; }
    openViewModal(id);
  });

  // Credential modal
  document.getElementById('modal-close').addEventListener('click', closeModal);
  document.getElementById('modal-cancel-btn').addEventListener('click', closeModal);
  document.getElementById('modal-save-btn').addEventListener('click', saveCredential);
  document.getElementById('modal-credential').addEventListener('click', e => {
    if (e.target === document.getElementById('modal-credential')) closeModal();
  });
  document.getElementById('gen-password-btn').addEventListener('click', () => {
    document.getElementById('gen-options').classList.toggle('hidden');
  });
  document.getElementById('gen-apply-btn').addEventListener('click', () => {
    const len  = Math.max(8, Math.min(64, parseInt(document.getElementById('gen-length').value) || 16));
    const opts = {
      upper:   document.getElementById('gen-upper').checked,
      lower:   document.getElementById('gen-lower').checked,
      numbers: document.getElementById('gen-numbers').checked,
      symbols: document.getElementById('gen-symbols').checked
    };
    document.getElementById('cred-password').value = generatePassword(len, opts);
    document.getElementById('cred-password').type = 'text';
    document.getElementById('gen-options').classList.add('hidden');
  });

  // View modal
  document.getElementById('view-close').addEventListener('click', closeViewModal);
  document.getElementById('modal-view').addEventListener('click', e => {
    if (e.target === document.getElementById('modal-view')) closeViewModal();
  });
  document.getElementById('view-pw-toggle').addEventListener('click', () => {
    const el    = document.getElementById('view-password');
    const shown = el.dataset.shown === '1';
    el.textContent   = shown ? '••••••••' : el.dataset.real;
    el.dataset.shown = shown ? '0' : '1';
    document.getElementById('view-pw-toggle').textContent = shown ? 'Show' : 'Hide';
  });
  document.querySelectorAll('.copy-btn').forEach(btn => {
    btn.addEventListener('click', async () => {
      if (!viewingCredential) return;
      const text = btn.dataset.copy === 'password' ? viewingCredential.password : viewingCredential.username;
      try {
        await navigator.clipboard.writeText(text);
        btn.textContent = '✓';
        btn.classList.add('copied');
        setTimeout(() => { btn.textContent = 'Copy'; btn.classList.remove('copied'); }, 1500);
      } catch {
        showToast('Clipboard access denied.', 'error');
      }
    });
  });
  document.getElementById('view-fill-btn').addEventListener('click', async () => {
    if (!viewingCredential) return;
    closeViewModal();
    await fillOnPage(viewingCredential?.id);
  });
  document.getElementById('view-edit-btn').addEventListener('click', () => {
    if (!viewingCredential) return;
    const id = viewingCredential.id;
    closeViewModal();
    openEditModal(id);
  });
  document.getElementById('view-delete-btn').addEventListener('click', async () => {
    if (!viewingCredential) return;
    if (!confirm(`Delete credential for "${viewingCredential.name || viewingCredential.username}"?`)) return;
    const id = viewingCredential.id;
    closeViewModal();
    await deleteCredential(id);
  });

  // Mass change tab
  document.getElementById('mass-filter').addEventListener('input', e => renderMassChangeList(e.target.value));
  document.getElementById('mass-select-all').addEventListener('click', () => {
    document.querySelectorAll('.mass-check').forEach(c => c.checked = true);
  });
  document.getElementById('mass-deselect-all').addEventListener('click', () => {
    document.querySelectorAll('.mass-check').forEach(c => c.checked = false);
  });
  document.querySelectorAll('input[name="pw-strategy"]').forEach(r => {
    r.addEventListener('change', () => {
      document.getElementById('same-pw-group').classList.toggle('hidden', r.value !== 'same');
    });
  });
  document.getElementById('mass-pw-length').addEventListener('input', e => {
    document.getElementById('mass-pw-length-val').textContent = e.target.value;
  });
  document.getElementById('mass-generate-btn').addEventListener('click', () => {
    const len = Math.max(8, Math.min(64, parseInt(document.getElementById('mass-pw-length').value) || 16));
    const pwEl = document.getElementById('mass-new-password');
    pwEl.value = generatePassword(len);
    pwEl.type  = 'text';
  });
  document.getElementById('mass-change-btn').addEventListener('click', startMassChange);

  // Settings tab
  document.getElementById('auto-lock-select').addEventListener('change', saveSettings);
  document.getElementById('autofill-enabled').addEventListener('change', saveSettings);
  document.getElementById('autosubmit-enabled').addEventListener('change', saveSettings);
  document.getElementById('change-pw-btn').addEventListener('click', changeMasterPassword);
  document.getElementById('export-btn').addEventListener('click', exportVault);
  document.getElementById('import-json-btn').addEventListener('click', () => document.getElementById('import-file-json').click());
  document.getElementById('import-csv-btn').addEventListener('click', () => document.getElementById('import-file-csv').click());
  document.getElementById('import-file-json').addEventListener('change', e => {
    if (e.target.files[0]) { handleImportFile(e.target.files[0], 'json'); e.target.value = ''; }
  });
  document.getElementById('import-file-csv').addEventListener('change', e => {
    if (e.target.files[0]) { handleImportFile(e.target.files[0], 'csv'); e.target.value = ''; }
  });
  document.getElementById('import-confirm-btn').addEventListener('click', confirmImport);
  document.getElementById('import-cancel-btn').addEventListener('click', () => {
    pendingImport = [];
    document.getElementById('import-preview').classList.add('hidden');
  });
});
