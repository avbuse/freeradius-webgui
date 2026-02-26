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
const SIDEBAR_STATE_STORAGE_KEY = 'freeradius-webgui.sidebarState';

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
let simpleSectionsData = { radiusd: {}, clients: { items: [], sources: [] }, policy: { files: [] } };
let selectedSimpleClientId = '';
let selectedSimpleRadiusdOptionKey = '';
let currentUserPermissions = new Set();
let showCommentedRadiusdOptions = false;
let simpleRadiusdViewMode = 'directives';
let sidebarState = {};

const simpleClientFieldIds = [
  'simple-client-name',
  'simple-client-ipaddr',
  'simple-client-ipv4addr',
  'simple-client-ipv6addr',
  'simple-client-secret',
  'simple-client-nastype',
  'simple-client-shortname',
  'simple-client-proto',
  'simple-client-virtual-server',
  'simple-client-limit-max-connections',
  'simple-client-limit-lifetime',
  'simple-client-limit-idle-timeout',
];

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

const setSimpleClientStatus = (text, mode = 'muted') => {
  const statusEl = document.getElementById('simple-client-status');
  if (!statusEl) {
    return;
  }
  statusEl.textContent = text;
  statusEl.className = mode;
};

const setSimpleRadiusdStatus = (text, mode = 'muted') => {
  const statusEl = document.getElementById('simple-radiusd-status');
  if (!statusEl) {
    return;
  }
  statusEl.textContent = text;
  statusEl.className = mode;
};

function canViewSimpleClientSecrets() {
  return currentUserPermissions.has('client_secret_view');
}

function setSimpleClientSecretVisibility(isVisible) {
  const secretInput = document.getElementById('simple-client-secret');
  const toggleButton = document.getElementById('simple-client-secret-toggle');
  if (!secretInput || !toggleButton) {
    return;
  }
  secretInput.type = isVisible ? 'text' : 'password';
  toggleButton.textContent = isVisible ? '🙈' : '👁';
  toggleButton.setAttribute('aria-label', isVisible ? 'Hide secret' : 'Show secret');
  toggleButton.title = isVisible ? 'Hide secret' : 'Show secret';
}

function updateSimpleClientSecretAccess(hasExistingSecret) {
  const secretInput = document.getElementById('simple-client-secret');
  const toggleButton = document.getElementById('simple-client-secret-toggle');
  if (!secretInput || !toggleButton) {
    return;
  }

  const canView = canViewSimpleClientSecrets();
  toggleButton.disabled = !canView;
  toggleButton.title = canView ? 'Show secret' : 'Requires RBAC permission: client_secret_view';
  if (!canView && hasExistingSecret) {
    secretInput.placeholder = 'Hidden by RBAC permission';
  } else {
    secretInput.placeholder = 'Shared secret';
  }
  setSimpleClientSecretVisibility(false);
}

function markSimpleClientField(fieldId, hasError) {
  const field = document.getElementById(fieldId);
  if (!field) {
    return;
  }
  field.classList.toggle('input-error', hasError);
}

function clearSimpleClientFieldErrors() {
  simpleClientFieldIds.forEach((fieldId) => markSimpleClientField(fieldId, false));
}

function collectSimpleClientFormPayload() {
  return {
    name: document.getElementById('simple-client-name').value.trim(),
    ipaddr: document.getElementById('simple-client-ipaddr').value.trim(),
    ipv4addr: document.getElementById('simple-client-ipv4addr').value.trim(),
    ipv6addr: document.getElementById('simple-client-ipv6addr').value.trim(),
    secret: document.getElementById('simple-client-secret').value.trim(),
    nastype: document.getElementById('simple-client-nastype').value.trim(),
    shortname: document.getElementById('simple-client-shortname').value.trim(),
    proto: document.getElementById('simple-client-proto').value.trim(),
    virtual_server: document.getElementById('simple-client-virtual-server').value.trim(),
    require_message_authenticator: document.getElementById('simple-client-require-ma').checked,
    limit_max_connections: document.getElementById('simple-client-limit-max-connections').value.trim(),
    limit_lifetime: document.getElementById('simple-client-limit-lifetime').value.trim(),
    limit_idle_timeout: document.getElementById('simple-client-limit-idle-timeout').value.trim(),
    target_path: document.getElementById('simple-client-source-path').value,
  };
}

function validateSimpleClientPayload(payload, mode = 'add') {
  clearSimpleClientFieldErrors();

  const errors = [];
  const hasAddress = Boolean(payload.ipaddr || payload.ipv4addr || payload.ipv6addr);
  if (mode === 'add' && !payload.name) {
    errors.push('Client name is required for new clients.');
    markSimpleClientField('simple-client-name', true);
  }
  if (!hasAddress) {
    errors.push('Provide at least one of ipaddr, ipv4addr, or ipv6addr.');
    markSimpleClientField('simple-client-ipaddr', true);
    markSimpleClientField('simple-client-ipv4addr', true);
    markSimpleClientField('simple-client-ipv6addr', true);
  }
  if (mode === 'add' && !payload.secret) {
    errors.push('Secret is required for new clients.');
    markSimpleClientField('simple-client-secret', true);
  }

  ['limit_max_connections', 'limit_lifetime', 'limit_idle_timeout'].forEach((key) => {
    const value = payload[key];
    if (value && !/^\d+$/.test(value)) {
      errors.push(`${key.replace('limit_', '').replace('_', ' ')} must be a whole number.`);
      if (key === 'limit_max_connections') {
        markSimpleClientField('simple-client-limit-max-connections', true);
      } else if (key === 'limit_lifetime') {
        markSimpleClientField('simple-client-limit-lifetime', true);
      } else {
        markSimpleClientField('simple-client-limit-idle-timeout', true);
      }
    }
  });

  if (errors.length) {
    setSimpleClientStatus(errors.join(' '), 'error');
    return false;
  }

  setSimpleClientStatus('Client form looks valid.', 'muted');
  return true;
}

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
  renderSimpleRadiusdFromState();

  document.getElementById('simple-clients-path').textContent = data.clients?.path || '';
  const sourceSelect = document.getElementById('simple-client-source-path');
  sourceSelect.innerHTML = '';
  (data.clients?.sources || []).forEach((sourcePath) => {
    const option = document.createElement('option');
    option.value = sourcePath;
    option.textContent = sourcePath;
    sourceSelect.appendChild(option);
  });

  if (sourceSelect.options.length === 0) {
    const fallback = document.createElement('option');
    fallback.value = data.clients?.path || '';
    fallback.textContent = data.clients?.path || 'No clients source found';
    sourceSelect.appendChild(fallback);
  }

  if (!selectedSimpleClientId || !(data.clients?.items || []).some((item) => item.id === selectedSimpleClientId)) {
    selectedSimpleClientId = (data.clients?.items || [])[0]?.id || '';
  }
  renderSimpleClientsList(data.clients?.items || []);
  if (selectedSimpleClientId) {
    const selectedClient = (data.clients?.items || []).find((item) => item.id === selectedSimpleClientId);
    if (selectedClient) {
      populateSimpleClientForm(selectedClient);
    }
  } else {
    prepareNewSimpleClient();
  }

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

function getSimpleRadiusdCollections() {
  const radiusd = simpleSectionsData.radiusd || {};
  const all = radiusd.items || [];
  const directives = radiusd.directive_items || all.filter((item) => item.editable !== false);
  const structure = radiusd.structure_items || all.filter((item) => item.editable === false);
  return { directives, structure, all };
}

function getVisibleSimpleRadiusdItems(items) {
  if (simpleRadiusdViewMode === 'structure') {
    return items;
  }
  if (showCommentedRadiusdOptions) {
    return items;
  }
  return items.filter((item) => item.active !== false);
}

function renderSimpleRadiusdViewMode() {
  const directivesBtn = document.getElementById('simple-radiusd-view-directives');
  const structureBtn = document.getElementById('simple-radiusd-view-structure');
  const commentedWrap = document.getElementById('simple-radiusd-commented-wrap');

  directivesBtn.classList.toggle('active', simpleRadiusdViewMode === 'directives');
  structureBtn.classList.toggle('active', simpleRadiusdViewMode === 'structure');
  if (commentedWrap) {
    commentedWrap.classList.toggle('hidden', simpleRadiusdViewMode !== 'directives');
  }
}

function renderSimpleRadiusdFromState() {
  const collections = getSimpleRadiusdCollections();
  const sourceItems = simpleRadiusdViewMode === 'structure' ? collections.structure : collections.directives;
  const visibleItems = getVisibleSimpleRadiusdItems(sourceItems);

  if (!selectedSimpleRadiusdOptionKey || !visibleItems.some((item) => item.key === selectedSimpleRadiusdOptionKey)) {
    selectedSimpleRadiusdOptionKey = visibleItems[0]?.key || '';
  }

  renderSimpleRadiusdViewMode();
  renderSimpleRadiusdOptions(visibleItems);

  if (!selectedSimpleRadiusdOptionKey) {
    clearSimpleRadiusdOptionForm();
    return;
  }

  const selectedOption = visibleItems.find((item) => item.key === selectedSimpleRadiusdOptionKey)
    || collections.all.find((item) => item.key === selectedSimpleRadiusdOptionKey);
  if (selectedOption) {
    populateSimpleRadiusdOption(selectedOption);
  } else {
    clearSimpleRadiusdOptionForm();
  }
}

function renderSimpleRadiusdOptions(items) {
  const container = document.getElementById('simple-radiusd-options');
  container.innerHTML = '';

  if (!items.length) {
    const empty = document.createElement('p');
    empty.className = 'muted';
    empty.textContent = simpleRadiusdViewMode === 'structure'
      ? 'No structure entries found.'
      : 'No directives match the current filter.';
    container.appendChild(empty);
    return;
  }

  items.forEach((item) => {
    const row = document.createElement('div');
    row.className = 'simple-radiusd-option-row';

    if (simpleRadiusdViewMode === 'directives' && showCommentedRadiusdOptions && item.editable !== false) {
      const checkbox = document.createElement('input');
      checkbox.type = 'checkbox';
      checkbox.checked = item.active !== false;
      checkbox.title = checkbox.checked ? 'Option is active in config' : 'Option is commented/default';
      checkbox.addEventListener('change', async (event) => {
        const target = event.target;
        const intendedState = Boolean(target.checked);
        target.disabled = true;
        try {
          await toggleSimpleRadiusdOptionState(item, intendedState);
        } catch (error) {
          target.checked = !intendedState;
          setSimpleRadiusdStatus(error.message, 'error');
          setMessage(error.message, true);
        } finally {
          target.disabled = false;
        }
      });
      row.appendChild(checkbox);
    }

    const button = document.createElement('button');
    button.type = 'button';
    button.className = `sidebar-btn${item.key === selectedSimpleRadiusdOptionKey ? ' active' : ''}`;
    const isCodeEntry = item.type === 'code' || item.editable === false;
    if (isCodeEntry) {
      button.textContent = item.active === false ? `${item.label} (code/default)` : `${item.label} (code)`;
    } else {
      button.textContent = item.active === false ? `${item.label} (default)` : item.label;
    }
    button.title = `${item.category} • ${item.directive}`;
    button.addEventListener('click', () => {
      selectedSimpleRadiusdOptionKey = item.key;
      populateSimpleRadiusdOption(item);
      renderSimpleRadiusdOptions(items);
    });
    row.appendChild(button);
    container.appendChild(row);
  });
}

async function toggleSimpleRadiusdOptionState(option, shouldBeActive) {
  const value = (document.getElementById('simple-radiusd-option-value').value || option.value || '').trim();
  const data = await api('/api/simple-config/radiusd/option/state', {
    method: 'POST',
    body: JSON.stringify({
      key: option.key,
      active: shouldBeActive,
      value,
    }),
  });

  setSimpleRadiusdStatus(
    `${data.key} is now ${data.active ? 'active' : 'commented/default'}.`,
    'success',
  );
  setMessage(`Updated state for radiusd option '${data.key}'.`);
  await refreshStatus();
  await loadSimpleSections();
}

function populateSimpleRadiusdOption(option) {
  document.getElementById('simple-radiusd-form-title').textContent = option.label;
  document.getElementById('simple-radiusd-form-desc').textContent = option.description || '';
  const state = option.active === false ? 'commented/default' : 'active';
  document.getElementById('simple-radiusd-form-meta').textContent = `Section: ${option.section} • Type: ${option.type} • State: ${state}`;

  const input = document.getElementById('simple-radiusd-option-value');
  const codeArea = document.getElementById('simple-radiusd-code-entry');
  const saveButton = document.getElementById('save-simple-radiusd-option');
  const isEditable = option.editable !== false;
  const isCodeEntry = option.type === 'code' || !isEditable;

  input.value = option.value || '';
  input.dataset.optionType = option.type || 'text';
  input.dataset.optionKey = option.key || '';
  input.dataset.optionChoices = JSON.stringify(option.choices || []);
  input.dataset.optionEditable = isEditable ? 'true' : 'false';
  input.classList.remove('input-error');

  if (isCodeEntry) {
    codeArea.value = option.value || '';
    codeArea.classList.remove('hidden');
    input.classList.add('hidden');
    input.disabled = true;
    saveButton.disabled = true;
    setSimpleRadiusdStatus('Code entry is read-only in this view.', 'warning');
  } else {
    codeArea.value = '';
    codeArea.classList.add('hidden');
    input.classList.remove('hidden');
    input.disabled = false;
    saveButton.disabled = false;
    setSimpleRadiusdStatus('');
  }
}

function clearSimpleRadiusdOptionForm() {
  document.getElementById('simple-radiusd-form-title').textContent = 'Select an option';
  document.getElementById('simple-radiusd-form-desc').textContent = '';
  document.getElementById('simple-radiusd-form-meta').textContent = '';
  const input = document.getElementById('simple-radiusd-option-value');
  const codeArea = document.getElementById('simple-radiusd-code-entry');
  const saveButton = document.getElementById('save-simple-radiusd-option');
  input.value = '';
  input.dataset.optionType = 'text';
  input.dataset.optionKey = '';
  input.dataset.optionChoices = '[]';
  input.dataset.optionEditable = 'true';
  input.classList.remove('input-error');
  input.classList.remove('hidden');
  input.disabled = false;
  codeArea.value = '';
  codeArea.classList.add('hidden');
  saveButton.disabled = false;
  setSimpleRadiusdStatus('');
}

function validateSimpleRadiusdInput(optionType, rawValue, choices) {
  const value = rawValue.trim();
  if (optionType === 'number' && value && !/^\d+$/.test(value)) {
    return { ok: false, error: 'Value must be a whole number.' };
  }
  if (optionType === 'boolean') {
    const normalized = value.toLowerCase();
    if (!['yes', 'no', 'true', 'false', '1', '0'].includes(normalized)) {
      return { ok: false, error: 'Boolean value must be yes/no.' };
    }
  }
  if (optionType === 'select' && choices.length > 0 && !choices.includes(value)) {
    return { ok: false, error: `Value must be one of: ${choices.join(', ')}` };
  }
  return { ok: true };
}

async function saveSimpleRadiusdOption() {
  const input = document.getElementById('simple-radiusd-option-value');
  if (input.dataset.optionEditable === 'false') {
    throw new Error('Selected entry is code-only and read-only in this form.');
  }
  const optionKey = input.dataset.optionKey || selectedSimpleRadiusdOptionKey;
  if (!optionKey) {
    throw new Error('Select a radiusd option first.');
  }

  const optionType = input.dataset.optionType || 'text';
  let choices = [];
  try {
    choices = JSON.parse(input.dataset.optionChoices || '[]');
    if (!Array.isArray(choices)) {
      choices = [];
    }
  } catch {
    choices = [];
  }

  const value = input.value.trim();
  const validation = validateSimpleRadiusdInput(optionType, value, choices);
  if (!validation.ok) {
    input.classList.add('input-error');
    setSimpleRadiusdStatus(validation.error || 'Invalid value.', 'error');
    throw new Error(validation.error || 'Invalid value.');
  }
  input.classList.remove('input-error');

  const data = await api('/api/simple-config/radiusd/option', {
    method: 'POST',
    body: JSON.stringify({ key: optionKey, value }),
  });

  setSimpleRadiusdStatus(`Saved ${data.key}.`, 'success');
  setMessage(`Saved radiusd option '${data.key}'.`);
  await refreshStatus();
  await loadSimpleSections();
}

function populateSimpleClientForm(client) {
  document.getElementById('simple-client-form-title').textContent = `Client: ${client.name}`;
  document.getElementById('simple-client-name').value = client.name || '';
  document.getElementById('simple-client-ipaddr').value = client.ipaddr || '';
  document.getElementById('simple-client-ipv4addr').value = client.ipv4addr || '';
  document.getElementById('simple-client-ipv6addr').value = client.ipv6addr || '';
  document.getElementById('simple-client-secret').value = client.secret || '';
  document.getElementById('simple-client-nastype').value = client.nastype || '';
  document.getElementById('simple-client-shortname').value = client.shortname || '';
  document.getElementById('simple-client-proto').value = client.proto || '';
  document.getElementById('simple-client-virtual-server').value = client.virtual_server || '';
  document.getElementById('simple-client-require-ma').checked = Boolean(client.require_message_authenticator);
  document.getElementById('simple-client-limit-max-connections').value = client.limit?.max_connections || '';
  document.getElementById('simple-client-limit-lifetime').value = client.limit?.lifetime || '';
  document.getElementById('simple-client-limit-idle-timeout').value = client.limit?.idle_timeout || '';
  document.getElementById('simple-client-meta').textContent = `Source: ${client.source_path}`;
  document.getElementById('simple-client-source-path').value = client.source_path || '';
  document.getElementById('simple-client-name').readOnly = true;
  document.getElementById('add-simple-client').disabled = true;
  document.getElementById('save-simple-client').disabled = false;
  document.getElementById('delete-simple-client').disabled = false;
  updateSimpleClientSecretAccess(Boolean(client.has_secret));
  clearSimpleClientFieldErrors();
  setSimpleClientStatus('Editing existing client.', 'muted');
}

function prepareNewSimpleClient() {
  selectedSimpleClientId = '';
  document.getElementById('simple-client-form-title').textContent = 'Add new client';
  document.getElementById('simple-client-name').value = '';
  document.getElementById('simple-client-ipaddr').value = '';
  document.getElementById('simple-client-ipv4addr').value = '';
  document.getElementById('simple-client-ipv6addr').value = '';
  document.getElementById('simple-client-secret').value = '';
  document.getElementById('simple-client-nastype').value = 'other';
  document.getElementById('simple-client-shortname').value = '';
  document.getElementById('simple-client-proto').value = '';
  document.getElementById('simple-client-virtual-server').value = '';
  document.getElementById('simple-client-require-ma').checked = false;
  document.getElementById('simple-client-limit-max-connections').value = '';
  document.getElementById('simple-client-limit-lifetime').value = '';
  document.getElementById('simple-client-limit-idle-timeout').value = '';
  document.getElementById('simple-client-meta').textContent = 'New client will be added to selected source file.';
  document.getElementById('simple-client-name').readOnly = false;
  document.getElementById('add-simple-client').disabled = false;
  document.getElementById('save-simple-client').disabled = true;
  document.getElementById('delete-simple-client').disabled = true;
  updateSimpleClientSecretAccess(false);
  clearSimpleClientFieldErrors();
  setSimpleClientStatus('Enter client values and click Add client.', 'muted');
  renderSimpleClientsList(simpleSectionsData.clients?.items || []);
}

function renderSimpleClientsList(items) {
  const container = document.getElementById('simple-clients-list');
  container.innerHTML = '';

  if (!items.length) {
    const empty = document.createElement('p');
    empty.className = 'muted';
    empty.textContent = 'No client blocks found.';
    container.appendChild(empty);
    return;
  }

  items.forEach((client) => {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = `sidebar-btn${client.id === selectedSimpleClientId ? ' active' : ''}`;
    button.textContent = client.name;
    button.title = `${client.source_file}: ${client.ipaddr || client.ipv4addr || client.ipv6addr || 'no address'}`;
    button.addEventListener('click', () => {
      selectedSimpleClientId = client.id;
      populateSimpleClientForm(client);
      renderSimpleClientsList(items);
    });
    container.appendChild(button);
  });
}

async function loadSimpleSections() {
  const data = await api('/api/simple-config/sections');
  renderSimpleSectionsData(data);
  setMessage('Loaded simple config sections.');
}

async function loadCurrentUserPermissions() {
  const data = await api('/api/auth/me');
  const permissions = Array.isArray(data.permissions) ? data.permissions : [];
  currentUserPermissions = new Set(permissions);
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
  const payload = collectSimpleClientFormPayload();
  if (!validateSimpleClientPayload(payload, 'add')) {
    throw new Error('Client form validation failed.');
  }

  const data = await api('/api/simple-config/clients/add', {
    method: 'POST',
    body: JSON.stringify(payload),
  });

  setSimpleClientStatus(`Added new client '${data.client}'.`, 'success');
  setMessage(`Added new client '${data.client}'.`);
  await refreshStatus();
  await loadSimpleSections();
}

async function updateSimpleClient() {
  if (!selectedSimpleClientId) {
    throw new Error('Select a client to update.');
  }
  const payload = {
    id: selectedSimpleClientId,
    ...collectSimpleClientFormPayload(),
  };

  if (!validateSimpleClientPayload(payload, 'update')) {
    throw new Error('Client form validation failed.');
  }

  const data = await api('/api/simple-config/clients/update', {
    method: 'POST',
    body: JSON.stringify(payload),
  });

  setSimpleClientStatus(`Updated client '${data.client}'.`, 'success');
  setMessage(`Updated client '${data.client}'.`);
  await refreshStatus();
  await loadSimpleSections();
}

async function deleteSimpleClient() {
  if (!selectedSimpleClientId) {
    throw new Error('Select a client to delete.');
  }

  const selectedClient = (simpleSectionsData.clients?.items || []).find((item) => item.id === selectedSimpleClientId);
  const clientName = selectedClient?.name || 'selected client';
  const confirmed = window.confirm(`Delete client '${clientName}'?`);
  if (!confirmed) {
    return;
  }

  const data = await api('/api/simple-config/clients/delete', {
    method: 'POST',
    body: JSON.stringify({ id: selectedSimpleClientId, confirmed: true }),
  });
  setSimpleClientStatus(`Deleted client '${data.client}'.`, 'success');
  setMessage(`Deleted client '${data.client}'.`);
  selectedSimpleClientId = '';
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

function loadSidebarState() {
  try {
    const parsed = JSON.parse(localStorage.getItem(SIDEBAR_STATE_STORAGE_KEY) || '{}');
    sidebarState = parsed && typeof parsed === 'object' ? parsed : {};
  } catch {
    sidebarState = {};
  }
}

function persistSidebarState() {
  try {
    localStorage.setItem(SIDEBAR_STATE_STORAGE_KEY, JSON.stringify(sidebarState));
  } catch {
    // Ignore storage failures.
  }
}

function applySidebarCollapseState(sidebarKey) {
  const sidebar = document.querySelector(`[data-collapsible-sidebar='${sidebarKey}']`);
  if (!sidebar) {
    return;
  }

  const collapsed = Boolean(sidebarState[sidebarKey]);
  sidebar.classList.toggle('is-collapsed', collapsed);

  const layout = sidebar.closest('.config-layout, .simple-layout, .cert-layout, .simple-clients-layout');
  if (layout) {
    layout.classList.toggle('sidebar-collapsed', collapsed);
  }

  document.querySelectorAll(`[data-toggle-sidebar='${sidebarKey}']`).forEach((button) => {
    button.textContent = collapsed ? 'Expand' : 'Collapse';
    button.setAttribute('aria-expanded', collapsed ? 'false' : 'true');
    button.setAttribute('title', collapsed ? 'Expand sidebar' : 'Collapse sidebar');
  });
}

function initializeCollapsibleSidebars() {
  loadSidebarState();

  const keys = new Set();
  document.querySelectorAll('[data-collapsible-sidebar]').forEach((sidebar) => {
    const key = sidebar.getAttribute('data-collapsible-sidebar');
    if (key) {
      keys.add(key);
    }
  });

  document.querySelectorAll('[data-toggle-sidebar]').forEach((button) => {
    button.addEventListener('click', () => {
      const key = button.getAttribute('data-toggle-sidebar');
      if (!key) {
        return;
      }
      sidebarState[key] = !Boolean(sidebarState[key]);
      persistSidebarState();
      applySidebarCollapseState(key);
    });
  });

  keys.forEach((key) => applySidebarCollapseState(key));
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

document.getElementById('save-simple-radiusd-option').addEventListener('click', async () => {
  try {
    await saveSimpleRadiusdOption();
  } catch (error) {
    setMessage(error.message, true);
  }
});

document.getElementById('simple-radiusd-show-commented').addEventListener('change', (event) => {
  showCommentedRadiusdOptions = Boolean(event.target.checked);
  renderSimpleRadiusdFromState();
});

document.getElementById('simple-radiusd-view-directives').addEventListener('click', () => {
  simpleRadiusdViewMode = 'directives';
  renderSimpleRadiusdFromState();
});

document.getElementById('simple-radiusd-view-structure').addEventListener('click', () => {
  simpleRadiusdViewMode = 'structure';
  renderSimpleRadiusdFromState();
});

document.getElementById('save-simple-client').addEventListener('click', async () => {
  try {
    await updateSimpleClient();
  } catch (error) {
    setMessage(error.message, true);
  }
});

document.getElementById('delete-simple-client').addEventListener('click', async () => {
  try {
    await deleteSimpleClient();
  } catch (error) {
    setMessage(error.message, true);
  }
});

document.getElementById('simple-new-client').addEventListener('click', () => {
  prepareNewSimpleClient();
});

document.getElementById('simple-client-secret-toggle').addEventListener('click', () => {
  if (!canViewSimpleClientSecrets()) {
    setSimpleClientStatus('Viewing secrets requires RBAC permission: client_secret_view.', 'warning');
    return;
  }
  const secretInput = document.getElementById('simple-client-secret');
  setSimpleClientSecretVisibility(secretInput.type === 'password');
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
    initializeCollapsibleSidebars();
    applyInterfaceSettings(getInterfaceSettings());
    renderTabState(getInitialTab());
    renderCertSection(selectedCertSection);
    renderSimpleSection(selectedSimpleSection);
    renderCategories();
    renderFiles();

    await refreshStatus();
    await loadCurrentUserPermissions();
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
