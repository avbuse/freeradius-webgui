const messageEl = document.getElementById('message');
const certActionMessageEl = document.getElementById('cert-action-message');
const trustedRootDetailsEl = document.getElementById('trusted-root-details');
const serverCertDetailsEl = document.getElementById('server-cert-details');
const serverCertMetaEl = document.getElementById('server-cert-meta');
const serverCsrOutputEl = document.getElementById('server-csr-output');
const simpleApplyStatusEl = document.getElementById('simple-apply-status');
const authSettingsStatusEl = document.getElementById('auth-settings-status');
const appConfigs = window.APP_CONFIGS || [];
const ACTIVE_TAB_STORAGE_KEY = 'freeradius-webgui.activeTab';
const INTERFACE_SETTINGS_STORAGE_KEY = 'freeradius-webgui.interfaceSettings';

let selectedCertSection = 'server';

const categorySortOrder = ['Global Config', 'Sites', 'Mods', 'Policy', 'Other'];

function getCategoryForKey(key) {
  if (key.startsWith('sites:')) {
    return 'Sites';
  }
  if (key.startsWith('mods:')) {
    return 'Mods';
  }
  if (key.startsWith('policy:')) {
    return 'Policy';
  }
  if (['radiusd', 'clients', 'proxy', 'hints', 'huntgroups'].includes(key)) {
    return 'Global Config';
  }
  return 'Other';
}

function getDisplayName(key) {
  const separator = key.indexOf(':');
  return separator > -1 ? key.slice(separator + 1) : key;
}

function buildConfigIndex(keys) {
  const grouped = new Map();
  keys.forEach((key) => {
    const category = getCategoryForKey(key);
    if (!grouped.has(category)) {
      grouped.set(category, []);
    }
    grouped.get(category).push(key);
  });

  grouped.forEach((items) => items.sort((a, b) => a.localeCompare(b)));
  return grouped;
}

const configByCategory = buildConfigIndex(appConfigs);
const sortedCategories = [...configByCategory.keys()].sort((a, b) => {
  const left = categorySortOrder.indexOf(a);
  const right = categorySortOrder.indexOf(b);
  const leftRank = left === -1 ? Number.MAX_SAFE_INTEGER : left;
  const rightRank = right === -1 ? Number.MAX_SAFE_INTEGER : right;
  if (leftRank !== rightRank) {
    return leftRank - rightRank;
  }
  return a.localeCompare(b);
});

let selectedCategory = sortedCategories[0] || '';
let selectedConfigKey = (configByCategory.get(selectedCategory) || [])[0] || appConfigs[0] || '';
let simpleConfigSnapshot = { mods: [], sites: [] };
let selectedSimpleSection = 'radiusd';
let simpleSectionsData = { radiusd: {}, clients: {}, policy: { files: [] } };

const setMessage = (text, isError = false) => {
  messageEl.textContent = text;
  messageEl.className = isError ? 'error' : 'muted';
};

const setCertMessage = (text, isError = false) => {
  if (!certActionMessageEl) {
    return;
  }
  certActionMessageEl.textContent = text;
  certActionMessageEl.className = isError ? 'error' : 'muted';
};

const setSimpleApplyStatus = (text, mode = 'muted') => {
  if (!simpleApplyStatusEl) {
    return;
  }
  simpleApplyStatusEl.textContent = text;
  simpleApplyStatusEl.className = mode;
};

const setAuthSettingsStatus = (text, mode = 'muted') => {
  if (!authSettingsStatusEl) {
    return;
  }
  authSettingsStatusEl.textContent = text;
  authSettingsStatusEl.className = mode;
};

async function api(path, options = {}) {
  const response = await fetch(path, {
    headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
    ...options,
  });

  let data = {};
  try {
    data = await response.json();
  } catch {
    data = {};
  }

  if (response.status === 401) {
    window.location.href = '/login';
    throw new Error('Unauthorized');
  }

  if (!response.ok || data.ok === false) {
    throw new Error(data.error || 'Request failed');
  }

  return data;
}

async function refreshStatus() {
  const status = await api('/api/status');
  document.getElementById('service-status').textContent = status.state || 'unknown';
}

async function serviceAction(action) {
  await api('/api/service', {
    method: 'POST',
    body: JSON.stringify({ action }),
  });
  await refreshStatus();
  setMessage(`Service ${action} completed.`);
}

async function loadConfig() {
  const key = selectedConfigKey;
  if (!key) {
    setMessage('No editable configuration files available.', true);
    return;
  }
  const data = await api(`/api/config/${encodeURIComponent(key)}`);
  document.getElementById('config-content').value = data.content;
  document.getElementById('config-title').textContent = `Configuration: ${key}`;
  document.getElementById('config-meta').textContent = `Path: ${data.path} | Backups: ${data.backups.length}`;
  setMessage(`Loaded config '${key}'.`);
}

async function saveConfig() {
  const key = selectedConfigKey;
  if (!key) {
    setMessage('No editable configuration selected.', true);
    return;
  }
  const content = document.getElementById('config-content').value;
  const data = await api(`/api/config/${encodeURIComponent(key)}`, {
    method: 'POST',
    body: JSON.stringify({ content, restart_after: true }),
  });
  setMessage(`Saved '${key}'. Backup: ${data.backup}`);
  await refreshStatus();
}

async function rollbackConfig() {
  const key = selectedConfigKey;
  if (!key) {
    setMessage('No editable configuration selected.', true);
    return;
  }
  const data = await api(`/api/config/${encodeURIComponent(key)}/rollback`, {
    method: 'POST',
    body: JSON.stringify({}),
  });
  setMessage(`Rollback complete from ${data.restored_from}`);
  await loadConfig();
  await refreshStatus();
}

async function refreshLogs() {
  const data = await api('/api/logs?lines=200');
  document.getElementById('logs').textContent = data.logs;
}

async function refreshMetrics() {
  const data = await api('/api/metrics?minutes=120');
  document.getElementById('metric-success').textContent = data.success;
  document.getElementById('metric-failure').textContent = data.failure;

  const total = data.success + data.failure;
  const successPct = total ? (data.success / total) * 100 : 0;
  const failurePct = total ? (data.failure / total) * 100 : 0;

  document.getElementById('bar-success').style.width = `${successPct}%`;
  document.getElementById('bar-failure').style.width = `${failurePct}%`;
}

function renderSimpleOptionGroup(containerId, entries, prefix) {
  const container = document.getElementById(containerId);
  if (!container) {
    return;
  }
  container.innerHTML = '';

  if (!entries.length) {
    const empty = document.createElement('p');
    empty.className = 'muted';
    empty.textContent = 'No options found.';
    container.appendChild(empty);
    return;
  }

  entries.forEach((entry) => {
    const row = document.createElement('label');
    row.className = 'simple-option-row';

    const checkbox = document.createElement('input');
    checkbox.type = 'checkbox';
    checkbox.checked = Boolean(entry.enabled);
    checkbox.dataset.optionName = entry.name;
    checkbox.id = `${prefix}-${entry.name}`;

    const textWrap = document.createElement('div');
    textWrap.className = 'simple-option-text';

    const title = document.createElement('div');
    title.className = 'simple-option-title';
    title.textContent = entry.name;

    textWrap.appendChild(title);
    if (entry.description) {
      const desc = document.createElement('div');
      desc.className = 'simple-option-desc';
      desc.textContent = entry.description;
      textWrap.appendChild(desc);
    }

    row.appendChild(checkbox);
    row.appendChild(textWrap);
    container.appendChild(row);
  });
}

function renderSimpleConfig(snapshot) {
  simpleConfigSnapshot = snapshot;
  renderSimpleOptionGroup('simple-mods', snapshot.mods || [], 'simple-mod');
  renderSimpleOptionGroup('simple-sites', snapshot.sites || [], 'simple-site');
}

async function loadSimpleConfig() {
  const data = await api('/api/simple-config');
  renderSimpleConfig({ mods: data.mods || [], sites: data.sites || [] });
  setMessage('Loaded simple module/site options.');
}

function renderSimpleSectionsData(data) {
  simpleSectionsData = data;

  document.getElementById('simple-radiusd-path').textContent = data.radiusd?.path || '';
  document.getElementById('simple-radiusd-content').value = data.radiusd?.content || '';

  document.getElementById('simple-clients-path').textContent = data.clients?.path || '';
  document.getElementById('simple-clients-content').value = data.clients?.content || '';

  document.getElementById('simple-policy-directory').textContent = data.policy?.directory || '';
  const select = document.getElementById('simple-policy-select');
  select.innerHTML = '';
  (data.policy?.files || []).forEach((file) => {
    const option = document.createElement('option');
    option.value = file.name;
    option.textContent = file.name;
    select.appendChild(option);
  });

  if (select.options.length === 0) {
    const option = document.createElement('option');
    option.value = '';
    option.textContent = 'No policy files found';
    select.appendChild(option);
  }

  document.getElementById('simple-policy-path').textContent = '';
  document.getElementById('simple-policy-content').value = '';
}

async function loadSimpleSections() {
  const data = await api('/api/simple-config/sections');
  renderSimpleSectionsData(data);
  setMessage('Loaded simple config sections.');
}

async function loadSimplePolicySelection() {
  const name = document.getElementById('simple-policy-select').value;
  if (!name) {
    setMessage('No policy file selected.', true);
    return;
  }
  const data = await api(`/api/simple-config/policy/${encodeURIComponent(name)}`);
  document.getElementById('simple-policy-path').textContent = data.path;
  document.getElementById('simple-policy-content').value = data.content;
  setMessage(`Loaded policy file '${name}'.`);
}

function collectSimpleSelections(containerId) {
  const selections = {};
  document.querySelectorAll(`#${containerId} input[type='checkbox'][data-option-name]`).forEach((checkbox) => {
    selections[checkbox.dataset.optionName] = checkbox.checked;
  });
  return selections;
}

async function applySimpleConfig() {
  const mods = collectSimpleSelections('simple-mods');
  const sites = collectSimpleSelections('simple-sites');
  const data = await api('/api/simple-config/apply', {
    method: 'POST',
    body: JSON.stringify({ mods, sites, restart_after: true }),
  });

  const changes = data.changes || [];
  if (changes.length) {
    setMessage(`Applied simple config changes: ${changes.length}`);
  } else {
    setMessage('No simple config changes were needed.');
  }
  await refreshStatus();
  await loadSimpleConfig();
}

async function addSimpleClient() {
  const payload = {
    name: document.getElementById('simple-add-client-name').value.trim(),
    ipaddr: document.getElementById('simple-add-client-ipaddr').value.trim(),
    secret: document.getElementById('simple-add-client-secret').value.trim(),
    nastype: document.getElementById('simple-add-client-nastype').value.trim(),
    require_message_authenticator: document.getElementById('simple-add-client-require-ma').checked,
  };
  const data = await api('/api/simple-config/clients/add', {
    method: 'POST',
    body: JSON.stringify(payload),
  });

  setMessage(`Added new client '${data.client}'.`);
  document.getElementById('simple-add-client-name').value = '';
  document.getElementById('simple-add-client-ipaddr').value = '';
  document.getElementById('simple-add-client-secret').value = '';
  document.getElementById('simple-add-client-nastype').value = '';
  document.getElementById('simple-add-client-require-ma').checked = false;
  await refreshStatus();
  await loadSimpleSections();
}

async function addSimplePolicy() {
  const payload = {
    filename: document.getElementById('simple-add-policy-filename').value.trim(),
    content: document.getElementById('simple-add-policy-content').value,
  };
  const data = await api('/api/simple-config/policy/add', {
    method: 'POST',
    body: JSON.stringify(payload),
  });

  setMessage(`Added new policy '${data.policy}'.`);
  document.getElementById('simple-add-policy-filename').value = '';
  document.getElementById('simple-add-policy-content').value = '';
  await refreshStatus();
  await loadSimpleSections();
}

function renderSimpleSection(sectionName) {
  selectedSimpleSection = sectionName;
  document.querySelectorAll('[data-simple-section]').forEach((button) => {
    button.classList.toggle('active', button.dataset.simpleSection === sectionName);
  });
  document.querySelectorAll('[data-simple-panel]').forEach((panel) => {
    panel.classList.toggle('hidden', panel.dataset.simplePanel !== sectionName);
  });
}

async function updateServerCert() {
  const content = document.getElementById('server-cert-content').value;
  const data = await api('/api/certs/server', {
    method: 'POST',
    body: JSON.stringify({ content, restart_after: true }),
  });
  setMessage(`Server certificate updated. Backup: ${data.backup}`);
  setCertMessage('Server certificate updated successfully.');
  await refreshStatus();
  await refreshServerCertDetails();
}

function renderServerCertDetails(data) {
  if (!serverCertDetailsEl || !serverCertMetaEl) {
    return;
  }

  if (!data.exists) {
    serverCertMetaEl.textContent = `Server cert missing at ${data.path}`;
    serverCertMetaEl.className = 'error';
    serverCertDetailsEl.textContent = [
      'No current server certificate found.',
      `Expected path: ${data.path}`,
      `Private key exists: ${data.key_exists ? 'Yes' : 'No'} (${data.key_path})`,
      `CSR exists: ${data.csr_exists ? 'Yes' : 'No'} (${data.csr_path})`,
      'Use "Generate CSR" to create a key+CSR, then upload signed cert.',
    ].join('\n');
    serverCertDetailsEl.className = 'cert-details error';
    return;
  }

  const details = data.details || {};
  const lines = [
    `Path: ${data.path}`,
    `Subject: ${details.subject || 'unknown'}`,
    `Issuer: ${details.issuer || 'unknown'}`,
    `Serial: ${details.serial || 'unknown'}`,
    `SHA256 Fingerprint: ${details.fingerprint || 'unknown'}`,
    `Not Before: ${details.not_before || 'unknown'}`,
    `Not After: ${details.not_after || 'unknown'}`,
  ];
  if (typeof details.days_remaining === 'number') {
    lines.push(`Days Remaining: ${details.days_remaining}`);
  }
  lines.push(`Private key present: ${data.key_exists ? 'Yes' : 'No'} (${data.key_path})`);
  lines.push(`CSR present: ${data.csr_exists ? 'Yes' : 'No'} (${data.csr_path})`);

  serverCertMetaEl.textContent = `Server certificate loaded from ${data.path}`;
  serverCertMetaEl.className = details.expired ? 'error' : (details.expiring_soon ? 'muted warning' : 'muted');
  serverCertDetailsEl.textContent = lines.join('\n');
  serverCertDetailsEl.className = details.expired ? 'cert-details error' : 'cert-details';
}

async function refreshServerCertDetails() {
  const data = await api('/api/certs/server/details');
  renderServerCertDetails(data);
}

function readFileAsBase64(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      const result = typeof reader.result === 'string' ? reader.result : '';
      const separator = result.indexOf(',');
      if (separator === -1) {
        reject(new Error('Failed to read file payload.'));
        return;
      }
      resolve(result.slice(separator + 1));
    };
    reader.onerror = () => reject(new Error('Failed to read file.'));
    reader.readAsDataURL(file);
  });
}

async function uploadServerCertFile() {
  const fileInput = document.getElementById('server-cert-file');
  if (!fileInput || !fileInput.files || !fileInput.files.length) {
    throw new Error('Select a certificate file to upload.');
  }

  const file = fileInput.files[0];
  const contentBase64 = await readFileAsBase64(file);
  const data = await api('/api/certs/server/upload', {
    method: 'POST',
    body: JSON.stringify({
      filename: file.name,
      content_base64: contentBase64,
      restart_after: true,
    }),
  });

  setMessage(`Server certificate uploaded and applied. Backup: ${data.backup}`);
  setCertMessage(`Upload applied using conversion: ${data.conversion}`);
  fileInput.value = '';
  await refreshStatus();
  await refreshServerCertDetails();
}

async function generateServerCsr() {
  const payload = {
    common_name: document.getElementById('csr-common-name').value,
    organization: document.getElementById('csr-organization').value,
    organizational_unit: document.getElementById('csr-org-unit').value,
    country: document.getElementById('csr-country').value,
    state: document.getElementById('csr-state').value,
    locality: document.getElementById('csr-locality').value,
    email: document.getElementById('csr-email').value,
    san: document.getElementById('csr-san').value,
  };
  const data = await api('/api/certs/server/csr', {
    method: 'POST',
    body: JSON.stringify(payload),
  });

  if (serverCsrOutputEl) {
    serverCsrOutputEl.textContent = data.csr;
    serverCsrOutputEl.className = 'cert-details';
  }
  setCertMessage(`CSR generated at ${data.csr_path}.`);
  await refreshServerCertDetails();
}

async function addRootCert() {
  const filenameInput = document.getElementById('root-cert-filename');
  const contentInput = document.getElementById('root-cert-content');
  const filename = filenameInput.value.trim();
  const content = contentInput.value;

  setCertMessage('Installing trusted root certificate...');

  if (!filename) {
    setCertMessage('Enter a filename (for example: corp-root.crt).', true);
    throw new Error('Missing filename.');
  }
  if (!content.trim()) {
    setCertMessage('Paste certificate content before adding.', true);
    throw new Error('Missing certificate content.');
  }

  const data = await api('/api/certs/root', {
    method: 'POST',
    body: JSON.stringify({ filename, content }),
  });
  setMessage(`Trusted root updated: ${data.path}`);
  setCertMessage(`Trusted root installed: ${filename}. Refreshing page...`);
  filenameInput.value = '';
  contentInput.value = '';
  await refreshTrustedRoots();
  setTimeout(() => {
    window.location.reload();
  }, 1000);
}

function formatBytes(bytes) {
  if (bytes < 1024) {
    return `${bytes} B`;
  }
  if (bytes < 1024 * 1024) {
    return `${(bytes / 1024).toFixed(1)} KB`;
  }
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

async function refreshTrustedRoots() {
  const data = await api('/api/certs/roots');
  const meta = document.getElementById('trusted-root-meta');
  const list = document.getElementById('trusted-root-list');

  const sourceText = (data.sources || []).join(', ');
  meta.textContent = `Sources: ${sourceText} | Count: ${data.certs.length}`;
  list.innerHTML = '';

  if (!data.certs.length) {
    const empty = document.createElement('li');
    empty.className = 'muted';
    empty.textContent = 'No trusted root certificates found.';
    list.appendChild(empty);
    return;
  }

  data.certs.forEach((cert) => {
    const item = document.createElement('li');
    item.className = 'cert-item';
    if (cert.expired) {
      item.classList.add('expired');
    } else if (cert.expiring_soon) {
      item.classList.add('expiring-soon');
    }

    const content = document.createElement('div');
    content.className = 'cert-item-content';

    const name = document.createElement('div');
    name.className = 'cert-item-name';
    const source = cert.source || 'Unknown';
    let expiryLabel = 'No expiry data';
    if (cert.expired) {
      expiryLabel = 'Expired';
    } else if (typeof cert.days_remaining === 'number') {
      expiryLabel = `${cert.days_remaining} days left`;
    }
    name.textContent = `[${source}] ${cert.name} (${expiryLabel})`;

    const metaLine = document.createElement('div');
    metaLine.className = 'cert-item-meta';
    const modified = cert.modified ? new Date(cert.modified).toLocaleString() : 'unknown';
    metaLine.textContent = `${formatBytes(cert.size)} • ${modified}`;

    content.appendChild(name);
    content.appendChild(metaLine);

    const actions = document.createElement('div');
    actions.className = 'cert-item-actions';

    const viewBtn = document.createElement('button');
    viewBtn.type = 'button';
    viewBtn.textContent = 'View details';
    viewBtn.addEventListener('click', async () => {
      try {
        await viewTrustedRootDetails(cert.path);
      } catch (error) {
        setCertMessage(error.message, true);
      }
    });

    actions.appendChild(viewBtn);

    if (cert.deletable) {
      const deleteBtn = document.createElement('button');
      deleteBtn.type = 'button';
      deleteBtn.className = 'danger-btn';
      deleteBtn.textContent = 'Delete';
      deleteBtn.addEventListener('click', async () => {
        try {
          await deleteTrustedRoot(cert);
        } catch (error) {
          setCertMessage(error.message, true);
        }
      });
      actions.appendChild(deleteBtn);
    }

    item.title = cert.path;
    item.appendChild(content);
    item.appendChild(actions);
    list.appendChild(item);
  });
}

function renderTrustedRootDetails(data) {
  if (!trustedRootDetailsEl) {
    return;
  }
  const details = data.details || {};
  const lines = [
    `Name: ${data.name || 'unknown'}`,
    `Path: ${data.path || 'unknown'}`,
    `Subject: ${details.subject || 'unknown'}`,
    `Issuer: ${details.issuer || 'unknown'}`,
    `Serial: ${details.serial || 'unknown'}`,
    `SHA256 Fingerprint: ${details.fingerprint || 'unknown'}`,
    `Not Before: ${details.not_before || 'unknown'}`,
    `Not After: ${details.not_after || 'unknown'}`,
  ];
  if (typeof details.days_remaining === 'number') {
    lines.push(`Days Remaining: ${details.days_remaining}`);
  }
  lines.push(`Expired: ${details.expired ? 'Yes' : 'No'}`);
  lines.push(`Expiring Soon (30 days): ${details.expiring_soon ? 'Yes' : 'No'}`);
  trustedRootDetailsEl.textContent = lines.join('\n');
  trustedRootDetailsEl.className = 'cert-details';
}

async function viewTrustedRootDetails(path) {
  const data = await api('/api/certs/root/details', {
    method: 'POST',
    body: JSON.stringify({ path }),
  });
  renderTrustedRootDetails(data);
  setCertMessage(`Loaded details for ${data.name}.`);
}

async function deleteTrustedRoot(cert) {
  const confirmed = window.confirm(`Are you sure you want to delete trusted root certificate '${cert.name}'?`);
  if (!confirmed) {
    return;
  }

  const data = await api('/api/certs/root/delete', {
    method: 'POST',
    body: JSON.stringify({ path: cert.path, confirmed: true }),
  });
  setCertMessage(`Deleted trusted root: ${data.deleted}`);
  if (trustedRootDetailsEl) {
    trustedRootDetailsEl.textContent = 'Select a certificate and click "View details".';
    trustedRootDetailsEl.className = 'cert-details muted';
  }
  await refreshTrustedRoots();
}

function renderTabState(activeTab) {
  document.querySelectorAll('[data-tab]').forEach((button) => {
    button.classList.toggle('active', button.dataset.tab === activeTab);
  });
  document.querySelectorAll('[data-tab-panel]').forEach((panel) => {
    panel.classList.toggle('hidden', panel.dataset.tabPanel !== activeTab);
  });
  try {
    localStorage.setItem(ACTIVE_TAB_STORAGE_KEY, activeTab);
  } catch {
    // Ignore browser storage failures.
  }
}

function renderCertSection(sectionName) {
  selectedCertSection = sectionName;
  document.querySelectorAll('[data-cert-section]').forEach((button) => {
    button.classList.toggle('active', button.dataset.certSection === sectionName);
  });
  document.querySelectorAll('[data-cert-panel]').forEach((panel) => {
    panel.classList.toggle('hidden', panel.dataset.certPanel !== sectionName);
  });
}

function getDefaultInterfaceSettings() {
  return {
    widthPercent: 70,
    theme: 'default',
  };
}

function getInterfaceSettings() {
  try {
    const parsed = JSON.parse(localStorage.getItem(INTERFACE_SETTINGS_STORAGE_KEY) || '{}');
    const widthPercent = Number(parsed.widthPercent);
    const theme = typeof parsed.theme === 'string' ? parsed.theme : 'default';
    return {
      widthPercent: Number.isFinite(widthPercent) ? Math.max(50, Math.min(95, widthPercent)) : 70,
      theme,
    };
  } catch {
    return getDefaultInterfaceSettings();
  }
}

function applyInterfaceSettings(settings) {
  const widthPercent = Math.max(50, Math.min(95, Number(settings.widthPercent) || 70));
  document.documentElement.style.setProperty('--container-width', `${widthPercent}vw`);
  document.body.setAttribute('data-theme', settings.theme || 'default');

  const widthControl = document.getElementById('interface-width');
  const widthValue = document.getElementById('interface-width-value');
  const themeControl = document.getElementById('interface-theme');
  if (widthControl) {
    widthControl.value = String(widthPercent);
  }
  if (widthValue) {
    widthValue.textContent = String(widthPercent);
  }
  if (themeControl) {
    themeControl.value = settings.theme || 'default';
  }
}

function saveInterfaceSettings() {
  const widthControl = document.getElementById('interface-width');
  const themeControl = document.getElementById('interface-theme');
  const settings = {
    widthPercent: Number(widthControl?.value || 70),
    theme: themeControl?.value || 'default',
  };
  localStorage.setItem(INTERFACE_SETTINGS_STORAGE_KEY, JSON.stringify(settings));
  applyInterfaceSettings(settings);
  setMessage('Interface settings saved.');
}

function resetInterfaceSettings() {
  const defaults = getDefaultInterfaceSettings();
  localStorage.setItem(INTERFACE_SETTINGS_STORAGE_KEY, JSON.stringify(defaults));
  applyInterfaceSettings(defaults);
  setMessage('Interface settings reset to defaults.');
}

function renderAuthSettings(data) {
  document.getElementById('auth-mode').value = data.auth_mode || 'local';
  document.getElementById('auth-local-fallback').checked = Boolean(data.local_auth_fallback);
  document.getElementById('auth-entra-tenant-id').value = data.entra_tenant_id || '';
  document.getElementById('auth-entra-client-id').value = data.entra_client_id || '';
  document.getElementById('auth-entra-client-secret').value = data.entra_client_secret || '';
  document.getElementById('auth-entra-redirect-uri').value = data.entra_redirect_uri || '';
  document.getElementById('auth-entra-scopes').value = data.entra_scopes || 'openid profile email';
  document.getElementById('auth-entra-group-claim').value = data.entra_group_claim || 'groups';
}

async function loadAuthSettings() {
  const data = await api('/api/auth/settings');
  renderAuthSettings(data);
  setAuthSettingsStatus('Loaded authentication settings.');
}

async function saveAuthSettings() {
  const payload = {
    auth_mode: document.getElementById('auth-mode').value,
    local_auth_fallback: document.getElementById('auth-local-fallback').checked,
    entra_tenant_id: document.getElementById('auth-entra-tenant-id').value.trim(),
    entra_client_id: document.getElementById('auth-entra-client-id').value.trim(),
    entra_client_secret: document.getElementById('auth-entra-client-secret').value.trim(),
    entra_redirect_uri: document.getElementById('auth-entra-redirect-uri').value.trim(),
    entra_scopes: document.getElementById('auth-entra-scopes').value.trim(),
    entra_group_claim: document.getElementById('auth-entra-group-claim').value.trim(),
  };
  const data = await api('/api/auth/settings', {
    method: 'POST',
    body: JSON.stringify(payload),
  });

  setAuthSettingsStatus('Saved authentication settings to .env. Restart service to apply Entra registration changes.', 'warning');
  if (data.restart_required) {
    setMessage('Auth settings saved. Restart required for full Entra changes.');
  } else {
    setMessage('Auth settings saved.');
  }
}

function selectedPermissionNames() {
  const values = [];
  document.querySelectorAll("#rbac-permissions input[type='checkbox'][data-permission-name]").forEach((checkbox) => {
    if (checkbox.checked) {
      values.push(checkbox.dataset.permissionName);
    }
  });
  return values;
}

function renderRoleOptions(roles) {
  const userSelect = document.getElementById('rbac-user-role');
  const groupSelect = document.getElementById('rbac-group-role');
  [userSelect, groupSelect].forEach((select) => {
    select.innerHTML = '';
    roles.forEach((role) => {
      const option = document.createElement('option');
      option.value = role.name;
      option.textContent = role.name;
      select.appendChild(option);
    });
  });
}

function renderRolesList(roles) {
  const list = document.getElementById('rbac-roles-list');
  list.innerHTML = '';

  roles.forEach((role) => {
    const item = document.createElement('li');
    item.className = 'cert-item';

    const content = document.createElement('div');
    content.className = 'cert-item-content';
    const name = document.createElement('div');
    name.className = 'cert-item-name';
    name.textContent = role.is_system ? `${role.name} (system)` : role.name;
    const perms = document.createElement('div');
    perms.className = 'cert-item-meta';
    perms.textContent = `${(role.permissions || []).join(', ')}`;
    content.appendChild(name);
    content.appendChild(perms);

    const actions = document.createElement('div');
    actions.className = 'cert-item-actions';
    if (!role.is_system) {
      const deleteBtn = document.createElement('button');
      deleteBtn.type = 'button';
      deleteBtn.className = 'danger-btn';
      deleteBtn.textContent = 'Delete';
      deleteBtn.addEventListener('click', async () => {
        const confirmed = window.confirm(`Delete role '${role.name}'?`);
        if (!confirmed) {
          return;
        }
        await api(`/api/rbac/roles/${encodeURIComponent(role.name)}`, { method: 'DELETE' });
        setMessage(`Deleted role '${role.name}'.`);
        await refreshRbacData();
      });
      actions.appendChild(deleteBtn);
    }

    item.appendChild(content);
    item.appendChild(actions);
    list.appendChild(item);
  });
}

function renderPermissionChecklist(permissions) {
  const container = document.getElementById('rbac-permissions');
  container.innerHTML = '';
  permissions.forEach((permission) => {
    const row = document.createElement('label');
    row.className = 'simple-option-row';
    const checkbox = document.createElement('input');
    checkbox.type = 'checkbox';
    checkbox.dataset.permissionName = permission.name;
    const text = document.createElement('div');
    text.className = 'simple-option-text';
    const title = document.createElement('div');
    title.className = 'simple-option-title';
    title.textContent = permission.name;
    const desc = document.createElement('div');
    desc.className = 'simple-option-desc';
    desc.textContent = permission.description;
    text.appendChild(title);
    text.appendChild(desc);
    row.appendChild(checkbox);
    row.appendChild(text);
    container.appendChild(row);
  });
}

function renderUserAssignments(assignments) {
  const list = document.getElementById('rbac-user-assignments');
  list.innerHTML = '';
  assignments.forEach((entry) => {
    const item = document.createElement('li');
    item.textContent = `${entry.principal} → ${entry.role}${entry.is_system ? ' (system)' : ''}`;
    list.appendChild(item);
  });
}

function renderGroupAssignments(assignments) {
  const list = document.getElementById('rbac-group-assignments');
  list.innerHTML = '';
  assignments.forEach((entry) => {
    const item = document.createElement('li');
    item.textContent = `${entry.group_id} → ${entry.role}`;
    list.appendChild(item);
  });
}

async function refreshRbacData() {
  const [permissionsData, rolesData, usersData, groupsData] = await Promise.all([
    api('/api/rbac/permissions'),
    api('/api/rbac/roles'),
    api('/api/rbac/users'),
    api('/api/rbac/groups'),
  ]);
  renderPermissionChecklist(permissionsData.permissions || []);
  renderRolesList(rolesData.roles || []);
  renderRoleOptions(rolesData.roles || []);
  renderUserAssignments(usersData.assignments || []);
  renderGroupAssignments(groupsData.assignments || []);
}

function getInitialTab() {
  const validTabs = new Set(Array.from(document.querySelectorAll('[data-tab]')).map((item) => item.dataset.tab));
  try {
    const stored = localStorage.getItem(ACTIVE_TAB_STORAGE_KEY) || 'overview';
    return validTabs.has(stored) ? stored : 'overview';
  } catch {
    return 'overview';
  }
}

function renderCategories() {
  const container = document.getElementById('config-categories');
  container.innerHTML = '';

  if (sortedCategories.length === 0) {
    const empty = document.createElement('p');
    empty.className = 'muted';
    empty.textContent = 'No categories found.';
    container.appendChild(empty);
    return;
  }

  sortedCategories.forEach((category) => {
    const button = document.createElement('button');
    button.type = 'button';
    button.textContent = category;
    button.className = `sidebar-btn${category === selectedCategory ? ' active' : ''}`;
    button.addEventListener('click', () => {
      selectedCategory = category;
      const options = configByCategory.get(selectedCategory) || [];
      selectedConfigKey = options[0] || '';
      renderCategories();
      renderFiles();
      if (selectedConfigKey) {
        loadConfig().catch((error) => setMessage(error.message, true));
      }
    });
    container.appendChild(button);
  });
}

function renderFiles() {
  const container = document.getElementById('config-files');
  container.innerHTML = '';

  const files = configByCategory.get(selectedCategory) || [];
  if (files.length === 0) {
    const empty = document.createElement('p');
    empty.className = 'muted';
    empty.textContent = 'No files in this category.';
    container.appendChild(empty);
    return;
  }

  files.forEach((key) => {
    const button = document.createElement('button');
    button.type = 'button';
    button.textContent = getDisplayName(key);
    button.title = key;
    button.className = `sidebar-btn${key === selectedConfigKey ? ' active' : ''}`;
    button.addEventListener('click', () => {
      selectedConfigKey = key;
      renderFiles();
      loadConfig().catch((error) => setMessage(error.message, true));
    });
    container.appendChild(button);
  });
}

document.querySelectorAll('[data-tab]').forEach((button) => {
  button.addEventListener('click', () => {
    renderTabState(button.dataset.tab);
  });
});

document.querySelectorAll('[data-cert-section]').forEach((button) => {
  button.addEventListener('click', () => {
    renderCertSection(button.dataset.certSection);
  });
});

document.querySelectorAll('[data-simple-section]').forEach((button) => {
  button.addEventListener('click', () => {
    renderSimpleSection(button.dataset.simpleSection);
  });
});

document.querySelectorAll('[data-service-action]').forEach((button) => {
  button.addEventListener('click', async () => {
    try {
      await serviceAction(button.dataset.serviceAction);
    } catch (error) {
      setMessage(error.message, true);
    }
  });
});

document.getElementById('load-config').addEventListener('click', async () => {
  try {
    await loadConfig();
  } catch (error) {
    setMessage(error.message, true);
  }
});

document.getElementById('save-config').addEventListener('click', async () => {
  try {
    await saveConfig();
  } catch (error) {
    setMessage(error.message, true);
  }
});

document.getElementById('rollback-config').addEventListener('click', async () => {
  try {
    await rollbackConfig();
  } catch (error) {
    setMessage(error.message, true);
  }
});

document.getElementById('refresh-logs').addEventListener('click', async () => {
  try {
    await refreshLogs();
  } catch (error) {
    setMessage(error.message, true);
  }
});

document.getElementById('refresh-metrics').addEventListener('click', async () => {
  try {
    await refreshMetrics();
  } catch (error) {
    setMessage(error.message, true);
  }
});

document.getElementById('load-simple-config').addEventListener('click', async () => {
  try {
    await loadSimpleConfig();
  } catch (error) {
    setMessage(error.message, true);
  }
});

document.getElementById('load-simple-sections').addEventListener('click', async () => {
  try {
    await loadSimpleSections();
  } catch (error) {
    setMessage(error.message, true);
  }
});

document.getElementById('apply-simple-config').addEventListener('click', async () => {
  const applyButton = document.getElementById('apply-simple-config');
  const originalLabel = applyButton.textContent;
  applyButton.disabled = true;
  applyButton.textContent = 'Running...';
  setSimpleApplyStatus('Running validate → apply → restart. Please wait...');
  try {
    await applySimpleConfig();
    setSimpleApplyStatus('Validate, apply, and restart completed successfully.', 'success');
  } catch (error) {
    setSimpleApplyStatus(`Validate/apply/restart failed: ${error.message}`, 'error');
    setMessage(error.message, true);
  } finally {
    applyButton.disabled = false;
    applyButton.textContent = originalLabel;
  }
});

document.getElementById('load-simple-policy').addEventListener('click', async () => {
  try {
    await loadSimplePolicySelection();
  } catch (error) {
    setMessage(error.message, true);
  }
});

document.getElementById('add-simple-client').addEventListener('click', async () => {
  try {
    await addSimpleClient();
  } catch (error) {
    setMessage(error.message, true);
  }
});

document.getElementById('add-simple-policy').addEventListener('click', async () => {
  try {
    await addSimplePolicy();
  } catch (error) {
    setMessage(error.message, true);
  }
});

document.getElementById('update-server-cert').addEventListener('click', async () => {
  try {
    await updateServerCert();
  } catch (error) {
    setCertMessage(error.message, true);
    setMessage(error.message, true);
  }
});

document.getElementById('refresh-server-cert-details').addEventListener('click', async () => {
  try {
    await refreshServerCertDetails();
  } catch (error) {
    setCertMessage(error.message, true);
    setMessage(error.message, true);
  }
});

document.getElementById('upload-server-cert').addEventListener('click', async () => {
  try {
    setCertMessage('Uploading server certificate file...');
    await uploadServerCertFile();
  } catch (error) {
    setCertMessage(error.message, true);
    setMessage(error.message, true);
  }
});

document.getElementById('generate-server-csr').addEventListener('click', async () => {
  try {
    setCertMessage('Generating server CSR...');
    await generateServerCsr();
  } catch (error) {
    setCertMessage(error.message, true);
    setMessage(error.message, true);
  }
});

document.getElementById('add-root-cert').addEventListener('click', async () => {
  try {
    await addRootCert();
  } catch (error) {
    setCertMessage(error.message, true);
    setMessage(error.message, true);
  }
});

document.getElementById('refresh-trusted-roots').addEventListener('click', async () => {
  try {
    await refreshTrustedRoots();
  } catch (error) {
    setMessage(error.message, true);
  }
});

document.getElementById('save-interface-settings').addEventListener('click', () => {
  try {
    saveInterfaceSettings();
  } catch (error) {
    setMessage(error.message, true);
  }
});

document.getElementById('reset-interface-settings').addEventListener('click', () => {
  try {
    resetInterfaceSettings();
  } catch (error) {
    setMessage(error.message, true);
  }
});

document.getElementById('load-auth-settings').addEventListener('click', async () => {
  try {
    await loadAuthSettings();
  } catch (error) {
    setAuthSettingsStatus(error.message, 'error');
    setMessage(error.message, true);
  }
});

document.getElementById('save-auth-settings').addEventListener('click', async () => {
  try {
    await saveAuthSettings();
  } catch (error) {
    setAuthSettingsStatus(error.message, 'error');
    setMessage(error.message, true);
  }
});

document.getElementById('refresh-rbac').addEventListener('click', async () => {
  try {
    await refreshRbacData();
    setMessage('Refreshed access control data.');
  } catch (error) {
    setMessage(error.message, true);
  }
});

document.getElementById('rbac-create-role').addEventListener('click', async () => {
  try {
    const name = document.getElementById('rbac-role-name').value.trim();
    const permissions = selectedPermissionNames();
    await api('/api/rbac/roles', {
      method: 'POST',
      body: JSON.stringify({ name, permissions }),
    });
    document.getElementById('rbac-role-name').value = '';
    setMessage(`Created role '${name}'.`);
    await refreshRbacData();
  } catch (error) {
    setMessage(error.message, true);
  }
});

document.getElementById('rbac-assign-user-role').addEventListener('click', async () => {
  try {
    const principal = document.getElementById('rbac-user-principal').value.trim();
    const role = document.getElementById('rbac-user-role').value;
    await api('/api/rbac/users/assign', {
      method: 'POST',
      body: JSON.stringify({ principal, role }),
    });
    setMessage(`Assigned ${role} to ${principal}.`);
    await refreshRbacData();
  } catch (error) {
    setMessage(error.message, true);
  }
});

document.getElementById('rbac-remove-user-role').addEventListener('click', async () => {
  try {
    const principal = document.getElementById('rbac-user-principal').value.trim();
    await api('/api/rbac/users/unassign', {
      method: 'POST',
      body: JSON.stringify({ principal }),
    });
    setMessage(`Removed role assignment for ${principal}.`);
    await refreshRbacData();
  } catch (error) {
    setMessage(error.message, true);
  }
});

document.getElementById('rbac-assign-group-role').addEventListener('click', async () => {
  try {
    const group_id = document.getElementById('rbac-group-id').value.trim();
    const role = document.getElementById('rbac-group-role').value;
    await api('/api/rbac/groups/assign', {
      method: 'POST',
      body: JSON.stringify({ group_id, role }),
    });
    setMessage(`Assigned ${role} to group ${group_id}.`);
    await refreshRbacData();
  } catch (error) {
    setMessage(error.message, true);
  }
});

document.getElementById('rbac-remove-group-role').addEventListener('click', async () => {
  try {
    const group_id = document.getElementById('rbac-group-id').value.trim();
    await api('/api/rbac/groups/unassign', {
      method: 'POST',
      body: JSON.stringify({ group_id }),
    });
    setMessage(`Removed group role assignment for ${group_id}.`);
    await refreshRbacData();
  } catch (error) {
    setMessage(error.message, true);
  }
});

document.getElementById('interface-width').addEventListener('input', (event) => {
  const value = Number(event.target.value || 70);
  const widthValue = document.getElementById('interface-width-value');
  if (widthValue) {
    widthValue.textContent = String(value);
  }
  document.documentElement.style.setProperty('--container-width', `${value}vw`);
});

document.getElementById('interface-theme').addEventListener('change', (event) => {
  document.body.setAttribute('data-theme', event.target.value || 'default');
});

document.getElementById('logout-btn').addEventListener('click', async () => {
  try {
    await api('/api/logout', { method: 'POST', body: JSON.stringify({}) });
    window.location.href = '/login';
  } catch (error) {
    setMessage(error.message, true);
  }
});

(async () => {
  try {
    applyInterfaceSettings(getInterfaceSettings());
    renderTabState(getInitialTab());
    renderCertSection(selectedCertSection);
    renderSimpleSection(selectedSimpleSection);
    renderCategories();
    renderFiles();

    await refreshStatus();
    if (appConfigs.length > 0 && selectedConfigKey) {
      await loadConfig();
    } else {
      setMessage('No editable configuration files available. Update EDITABLE_CONFIGS or enable auto-discovery.', true);
    }
    await refreshLogs();
    await refreshMetrics();
    await loadSimpleConfig();
    await loadSimpleSections();
    await refreshServerCertDetails();
    await refreshTrustedRoots();
    await refreshRbacData();
    await loadAuthSettings();
  } catch (error) {
    setMessage(error.message, true);
  }
})();
