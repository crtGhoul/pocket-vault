import {
  generateSalt,
  deriveKey,
  encryptBytes,
  decryptBytes,
  encryptJSON,
  decryptJSON,
  createVerifier,
  verifyKey
} from './crypto.js';
import {
  getMeta,
  setMeta,
  putItem,
  getItemsByType,
  getAllItems,
  deleteItem,
  wipeDatabase
} from './db.js';

const DEFAULT_SPACES = [
  { name: 'WhatsApp Web', url: 'https://web.whatsapp.com', tag: 'Messaging', pinned: false, order: 0 },
  { name: 'Instagram', url: 'https://www.instagram.com', tag: 'Social', pinned: false, order: 1 },
  { name: 'Telegram', url: 'https://web.telegram.org', tag: 'Messaging', pinned: false, order: 2 },
  { name: 'Gmail', url: 'https://mail.google.com', tag: 'Mail', pinned: false, order: 3 },
  { name: 'X', url: 'https://x.com', tag: 'Social', pinned: false, order: 4 }
];

const TRACKING_PARAMS = new Set([
  'fbclid',
  'gclid',
  'gbraid',
  'wbraid',
  'mc_cid',
  'mc_eid',
  'igshid',
  'si',
  '_hsenc',
  '_hsmi',
  'ref_src'
]);

const state = {
  key: null,
  activeTab: 'spaces',
  hasVault: false,
  spaces: [],
  files: [],
  notes: [],
  contacts: [],
  activeTag: 'All',
  activeSpaceMenuId: null,
  previewUrl: null,
  hiddenAt: null,
  toastTimer: null
};

const $ = (id) => document.getElementById(id);

function initDialogFallbacks() {
  for (const dialog of document.querySelectorAll('dialog')) {
    dialog.addEventListener('close', () => {
      if (dialog.id === 'preview-dialog' && state.previewUrl) {
        URL.revokeObjectURL(state.previewUrl);
        state.previewUrl = null;
      }
      dialog.returnValue = '';
    });
  }

  // Fallback for browsers without <dialog closedby="any"> (e.g. Safari)
  if (!('closedBy' in HTMLDialogElement.prototype)) {
    const isOutside = (e, dialog) => {
      const rect = dialog.getBoundingClientRect();
      return (
        e.clientX < rect.left ||
        e.clientX > rect.right ||
        e.clientY < rect.top ||
        e.clientY > rect.bottom
      );
    };
    for (const dialog of document.querySelectorAll('dialog[closedby="any"]')) {
      let pressedOutside = false;
      dialog.addEventListener('pointerdown', (e) => {
        pressedOutside = isOutside(e, dialog);
      });
      dialog.addEventListener('pointerup', (e) => {
        if (pressedOutside && isOutside(e, dialog)) {
          dialog.close();
        }
      });
    }
  }
}

function showStatus(msg, isError = false) {
  const el = $('lock-error');
  el.textContent = msg;
  el.hidden = !msg;
  el.classList.toggle('error', isError);
}

async function checkVaultExists() {
  const salt = await getMeta('salt');
  const verifier = await getMeta('verifier');
  state.hasVault = Boolean(salt && verifier);

  $('lock-title').textContent = state.hasVault ? 'Unlock PocketVault' : 'Create your passcode';
  $('lock-subtitle').textContent = state.hasVault
    ? 'Your spaces, notes, contacts, and files are encrypted locally on this device.'
    : 'Choose a passcode (4+ characters) to encrypt all local data with AES-256-GCM.';
  $('pin-confirm-wrap').hidden = state.hasVault;
  $('pin-confirm').required = !state.hasVault;
  $('lock-submit').textContent = state.hasVault ? 'Unlock' : 'Create Vault';
}

async function handleUnlockSubmit(e) {
  e.preventDefault();
  showStatus('');
  const pin = $('pin-input').value;
  if (pin.length < 4) {
    showStatus('Passcode must be at least 4 characters.', true);
    return;
  }

  $('lock-submit').disabled = true;
  try {
    if (!state.hasVault) {
      const confirmPin = $('pin-confirm').value;
      if (pin !== confirmPin) {
        showStatus('Passcodes do not match.', true);
        return;
      }
      const salt = generateSalt();
      const key = await deriveKey(pin, salt);
      const verifier = await createVerifier(key);
      await setMeta('salt', Array.from(salt));
      await setMeta('verifier', verifier);
      state.key = key;
      state.hasVault = true;

      // Seed default spaces on first creation
      for (const space of DEFAULT_SPACES) {
        await saveEncryptedItem('space', space);
      }
    } else {
      const saltArr = await getMeta('salt');
      const verifier = await getMeta('verifier');
      const key = await deriveKey(pin, new Uint8Array(saltArr));
      const ok = await verifyKey(key, verifier);
      if (!ok) {
        showStatus('Incorrect passcode.', true);
        $('pin-input').select();
        return;
      }
      state.key = key;
    }

    $('pin-input').value = '';
    $('pin-confirm').value = '';
    $('lock-screen').hidden = true;
    $('app-shell').hidden = false;
    await loadAllData();
    renderAll();
  } catch (err) {
    showStatus(err?.message || 'Could not unlock vault.', true);
  } finally {
    $('lock-submit').disabled = false;
  }
}

function lockVault() {
  state.key = null;
  state.spaces = [];
  state.files = [];
  state.notes = [];
  state.contacts = [];
  $('app-shell').hidden = true;
  $('lock-screen').hidden = false;
  showStatus('');
  checkVaultExists();
  $('pin-input').focus();
}

async function saveEncryptedItem(type, plainData, existingId = null) {
  const id = existingId || crypto.randomUUID();
  const payload = await encryptJSON(state.key, plainData);
  await putItem({ id, type, updatedAt: Date.now(), payload });
  return id;
}

async function loadDecryptedByType(type) {
  const rows = await getItemsByType(type);
  const out = [];
  for (const row of rows) {
    const data = await decryptJSON(state.key, row.payload);
    out.push({ id: row.id, updatedAt: row.updatedAt, ...data });
  }
  return out.sort((a, b) => b.updatedAt - a.updatedAt);
}

async function loadAllData() {
  const [spaces, notes, contacts, fileRows] = await Promise.all([
    loadDecryptedByType('space'),
    loadDecryptedByType('note'),
    loadDecryptedByType('contact'),
    getItemsByType('file')
  ]);
  state.spaces = spaces;
  state.notes = notes;
  state.contacts = contacts;

  const files = [];
  for (const row of fileRows) {
    const meta = await decryptJSON(state.key, row.payload.meta);
    files.push({
      id: row.id,
      updatedAt: row.updatedAt,
      name: meta.name,
      mime: meta.mime,
      size: meta.size,
      encryptedBytes: row.payload.file
    });
  }
  state.files = files.sort((a, b) => b.updatedAt - a.updatedAt);
}

function switchTab(tab) {
  state.activeTab = tab;
  for (const btn of document.querySelectorAll('[data-tab]')) {
    const active = btn.dataset.tab === tab;
    btn.classList.toggle('active', active);
    btn.setAttribute('aria-selected', String(active));
  }
  for (const panel of document.querySelectorAll('[data-panel]')) {
    panel.hidden = panel.dataset.panel !== tab;
  }
}

function sanitizeLaunchUrl(raw) {
  const trimmed = String(raw || '').trim();
  if (!trimmed) return { ok: false, error: 'Enter a URL.' };
  const candidate = /^[a-zA-Z][a-zA-Z\d+.-]*:/.test(trimmed) ? trimmed : `https://${trimmed}`;
  let parsed;
  try {
    parsed = new URL(candidate);
  } catch {
    return { ok: false, error: 'Enter a valid web URL.' };
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return { ok: false, error: 'Only http:// and https:// URLs are allowed.' };
  }
  for (const key of Array.from(parsed.searchParams.keys())) {
    if (key.startsWith('utm_') || TRACKING_PARAMS.has(key)) {
      parsed.searchParams.delete(key);
    }
  }
  return { ok: true, url: parsed.toString(), host: parsed.hostname };
}

function faviconUrl(url) {
  try {
    const { hostname } = new URL(url);
    return `https://www.google.com/s2/favicons?domain=${encodeURIComponent(hostname)}&sz=64`;
  } catch {
    return '';
  }
}

function sortSpaces(spaces) {
  return [...spaces].sort((a, b) => {
    const pinDiff = (b.pinned ? 1 : 0) - (a.pinned ? 1 : 0);
    if (pinDiff !== 0) return pinDiff;
    const orderA = typeof a.order === 'number' ? a.order : Number.MAX_SAFE_INTEGER;
    const orderB = typeof b.order === 'number' ? b.order : Number.MAX_SAFE_INTEGER;
    if (orderA !== orderB) return orderA - orderB;
    return b.updatedAt - a.updatedAt;
  });
}

function showToast(msg) {
  const el = $('toast');
  el.textContent = msg;
  el.hidden = false;
  clearTimeout(state.toastTimer);
  state.toastTimer = setTimeout(() => {
    el.hidden = true;
  }, 2200);
}

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function createTileIcon(space, cleanUrl) {
  const src = faviconUrl(cleanUrl);
  const initial = (space.name || '?').trim().charAt(0).toUpperCase() || '?';
  const makeFallback = () => {
    const badge = document.createElement('span');
    badge.className = 'tile-icon-fallback';
    badge.setAttribute('aria-hidden', 'true');
    badge.textContent = initial;
    return badge;
  };
  if (!src) return makeFallback();

  const img = document.createElement('img');
  img.className = 'tile-icon';
  img.src = src;
  img.alt = '';
  img.width = 44;
  img.height = 44;
  img.loading = 'lazy';
  img.decoding = 'async';
  img.addEventListener('error', () => {
    img.replaceWith(makeFallback());
  });
  return img;
}

function renderSpaceChips() {
  const chips = $('spaces-chips');
  chips.replaceChildren();
  const tags = Array.from(
    new Set(state.spaces.map((s) => (s.tag || '').trim()).filter(Boolean))
  );
  if (!tags.length) {
    state.activeTag = 'All';
    chips.hidden = true;
    return;
  }
  if (state.activeTag !== 'All' && !tags.includes(state.activeTag)) {
    state.activeTag = 'All';
  }
  chips.hidden = false;
  for (const tag of ['All', ...tags]) {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = `section-chip${state.activeTag === tag ? ' is-active' : ''}`;
    btn.setAttribute('role', 'tab');
    btn.setAttribute('aria-selected', String(state.activeTag === tag));
    btn.textContent = tag;
    btn.addEventListener('click', () => {
      state.activeTag = tag;
      renderSpaces();
    });
    chips.append(btn);
  }
}

function renderSpaces() {
  state.spaces = sortSpaces(state.spaces);
  renderSpaceChips();

  const searchInput = $('spaces-search');
  const showSearch = state.spaces.length > 6;
  searchInput.hidden = !showSearch;
  if (!showSearch && searchInput.value) searchInput.value = '';
  const query = showSearch ? searchInput.value.trim().toLowerCase() : '';

  const filtered = state.spaces.filter((s) => {
    const tagMatch = state.activeTag === 'All' || (s.tag || '').trim() === state.activeTag;
    const queryMatch =
      !query ||
      s.name.toLowerCase().includes(query) ||
      s.url.toLowerCase().includes(query) ||
      (s.tag || '').toLowerCase().includes(query);
    return tagMatch && queryMatch;
  });

  const list = $('spaces-list');
  list.replaceChildren();
  if (!filtered.length) {
    const empty = document.createElement('p');
    empty.className = 'empty-state';
    empty.style.gridColumn = '1 / -1';
    empty.textContent = state.spaces.length
      ? 'No matching spaces.'
      : 'No spaces yet. Add a web app link to launch from here.';
    list.append(empty);
    return;
  }

  for (const space of filtered) {
    const sanitized = sanitizeLaunchUrl(space.url);
    const cleanUrl = sanitized.ok ? sanitized.url : '#';
    const host = sanitized.ok ? sanitized.host : space.url;

    const tile = document.createElement('div');
    tile.className = 'space-tile';

    if (space.pinned) {
      const pin = document.createElement('span');
      pin.className = 'tile-pin';
      pin.setAttribute('aria-hidden', 'true');
      tile.append(pin);
    }

    const link = document.createElement('a');
    link.className = 'tile-launch';
    link.href = cleanUrl;
    if (sanitized.ok) {
      link.target = '_blank';
      link.rel = 'noopener noreferrer';
    } else {
      link.addEventListener('click', (e) => {
        e.preventDefault();
        openSpaceDialog(space);
      });
    }

    const icon = createTileIcon(space, cleanUrl);
    const title = document.createElement('span');
    title.className = 'tile-label';
    title.textContent = space.name;
    const sub = document.createElement('span');
    sub.className = 'tile-sub';
    sub.textContent = space.tag || host;
    link.append(icon, title, sub);

    const more = document.createElement('button');
    more.type = 'button';
    more.className = 'tile-more';
    more.setAttribute('aria-label', `Options for ${space.name}`);
    more.textContent = '⋯';
    more.addEventListener('click', () => openSpaceMenu(space.id));

    tile.append(link, more);
    list.append(tile);
  }
}

function openSpaceDialog(space = null) {
  $('space-error').hidden = true;
  $('space-error').textContent = '';
  $('space-id').value = space ? space.id : '';
  $('space-dialog-title').textContent = space ? 'Edit space' : 'Add space';
  $('space-name').value = space ? space.name : '';
  $('space-url').value = space ? space.url : '';
  $('space-tag').value = space ? space.tag || '' : '';
  $('space-dialog').showModal();
}

function getSpaceGroup(space) {
  return state.spaces.filter((s) => Boolean(s.pinned) === Boolean(space.pinned));
}

function openSpaceMenu(id) {
  const space = state.spaces.find((s) => s.id === id);
  if (!space) return;
  state.activeSpaceMenuId = id;
  $('space-menu-title').textContent = space.name;
  $('menu-pin-btn').textContent = space.pinned ? 'Unpin' : 'Pin';

  const group = getSpaceGroup(space);
  const idx = group.findIndex((s) => s.id === id);
  $('menu-left-btn').disabled = idx <= 0;
  $('menu-right-btn').disabled = idx < 0 || idx >= group.length - 1;

  $('space-menu').showModal();
}

async function moveActiveSpace(delta) {
  const space = state.spaces.find((s) => s.id === state.activeSpaceMenuId);
  if (!space) return;
  const group = getSpaceGroup(space);
  const idx = group.findIndex((s) => s.id === space.id);
  const targetIdx = idx + delta;
  if (idx < 0 || targetIdx < 0 || targetIdx >= group.length) return;

  const normalized = group.map((item, i) => ({ ...item, order: i }));
  const [moved] = normalized.splice(idx, 1);
  normalized.splice(targetIdx, 0, moved);

  await Promise.all(
    normalized.map((item, i) => {
      item.order = i;
      const { id, updatedAt, ...plain } = item;
      return saveEncryptedItem('space', plain, id).then(() => {
        item.updatedAt = Date.now();
      });
    })
  );

  const byId = new Map(normalized.map((item) => [item.id, item]));
  state.spaces = state.spaces.map((s) => byId.get(s.id) || s);
  renderSpaces();
  openSpaceMenu(space.id);
}

function renderFiles() {
  const list = $('vault-list');
  list.replaceChildren();
  if (!state.files.length) {
    const empty = document.createElement('p');
    empty.className = 'empty-state';
    empty.textContent = 'Vault is empty. Add photos or files to encrypt them on this device.';
    list.append(empty);
    return;
  }

  for (const file of state.files) {
    const row = document.createElement('div');
    row.className = 'card item-row';

    const info = document.createElement('button');
    info.type = 'button';
    info.className = 'item-main';
    const name = document.createElement('strong');
    name.textContent = file.name;
    const meta = document.createElement('span');
    meta.className = 'muted';
    meta.textContent = `${file.mime || 'File'} · ${formatBytes(file.size)}`;
    info.append(name, meta);
    info.addEventListener('click', () => openFilePreview(file));

    const del = document.createElement('button');
    del.type = 'button';
    del.className = 'icon-btn danger';
    del.setAttribute('aria-label', `Delete ${file.name}`);
    del.textContent = '×';
    del.addEventListener('click', async () => {
      await deleteItem(file.id);
      state.files = state.files.filter((f) => f.id !== file.id);
      renderFiles();
    });

    row.append(info, del);
    list.append(row);
  }
}

async function openFilePreview(file) {
  const decrypted = await decryptBytes(state.key, file.encryptedBytes);
  const blob = new Blob([decrypted], { type: file.mime || 'application/octet-stream' });
  const url = URL.createObjectURL(blob);
  state.previewUrl = url;

  $('preview-title').textContent = file.name;
  const body = $('preview-body');
  body.replaceChildren();

  if (file.mime.startsWith('image/')) {
    const img = document.createElement('img');
    img.src = url;
    img.alt = file.name;
    img.className = 'preview-img';
    body.append(img);
  } else if (file.mime.startsWith('text/')) {
    const pre = document.createElement('pre');
    pre.className = 'preview-text';
    pre.textContent = await blob.text();
    body.append(pre);
  } else {
    const p = document.createElement('p');
    p.className = 'muted';
    p.textContent = `Ready to download (${formatBytes(file.size)}).`;
    body.append(p);
  }

  const dl = $('preview-download');
  dl.href = url;
  dl.download = file.name;
  $('preview-dialog').showModal();
}

function renderNotes() {
  const query = $('notes-search').value.trim().toLowerCase();
  const list = $('notes-list');
  list.replaceChildren();

  const filtered = state.notes.filter(
    (n) =>
      n.title.toLowerCase().includes(query) ||
      n.body.toLowerCase().includes(query)
  );

  if (!filtered.length) {
    const empty = document.createElement('p');
    empty.className = 'empty-state';
    empty.textContent = query ? 'No matching notes.' : 'No private notes yet.';
    list.append(empty);
    return;
  }

  for (const note of filtered) {
    const row = document.createElement('div');
    row.className = 'card item-row';

    const main = document.createElement('button');
    main.type = 'button';
    main.className = 'item-main';
    const title = document.createElement('strong');
    title.textContent = note.title || 'Untitled note';
    const snippet = document.createElement('span');
    snippet.className = 'muted';
    snippet.textContent = note.body.slice(0, 72) || 'Empty note';
    main.append(title, snippet);
    main.addEventListener('click', () => openNoteDialog(note));

    const del = document.createElement('button');
    del.type = 'button';
    del.className = 'icon-btn danger';
    del.setAttribute('aria-label', `Delete ${note.title || 'note'}`);
    del.textContent = '×';
    del.addEventListener('click', async () => {
      await deleteItem(note.id);
      state.notes = state.notes.filter((n) => n.id !== note.id);
      renderNotes();
    });

    row.append(main, del);
    list.append(row);
  }
}

function renderContacts() {
  const list = $('contacts-list');
  list.replaceChildren();
  if (!state.contacts.length) {
    const empty = document.createElement('p');
    empty.className = 'empty-state';
    empty.textContent = 'No secondary contacts saved yet.';
    list.append(empty);
    return;
  }

  for (const contact of state.contacts) {
    const row = document.createElement('div');
    row.className = 'card contact-card';

    const info = document.createElement('div');
    info.className = 'contact-info';
    const name = document.createElement('strong');
    name.textContent = contact.name;
    const sub = document.createElement('span');
    sub.className = 'muted';
    sub.textContent = [contact.phone, contact.note].filter(Boolean).join(' · ');
    info.append(name, sub);

    const actions = document.createElement('div');
    actions.className = 'row-actions';

    if (contact.phone) {
      const chatBtn = document.createElement('button');
      chatBtn.type = 'button';
      chatBtn.className = 'btn-secondary btn-sm';
      chatBtn.textContent = 'Chat';
      chatBtn.addEventListener('click', () => {
        $('direct-phone').value = contact.phone;
        switchTab('direct');
      });
      actions.append(chatBtn);
    }

    const del = document.createElement('button');
    del.type = 'button';
    del.className = 'icon-btn danger';
    del.setAttribute('aria-label', `Delete ${contact.name}`);
    del.textContent = '×';
    del.addEventListener('click', async () => {
      await deleteItem(contact.id);
      state.contacts = state.contacts.filter((c) => c.id !== contact.id);
      renderContacts();
    });

    actions.append(del);
    row.append(info, actions);
    list.append(row);
  }
}

function renderAll() {
  renderSpaces();
  renderFiles();
  renderNotes();
  renderContacts();
}

function openNoteDialog(note = null) {
  $('note-id').value = note ? note.id : '';
  $('note-dialog-title').textContent = note ? 'Edit note' : 'New private note';
  $('note-title').value = note ? note.title : '';
  $('note-body').value = note ? note.body : '';
  $('note-dialog').showModal();
}

async function handleVaultUpload(e) {
  const files = Array.from(e.target.files || []);
  if (!files.length) return;

  for (const file of files) {
    const buffer = await file.arrayBuffer();
    const metaPayload = await encryptJSON(state.key, {
      name: file.name,
      mime: file.type || 'application/octet-stream',
      size: file.size
    });
    const filePayload = await encryptBytes(state.key, new Uint8Array(buffer));
    const id = crypto.randomUUID();
    const updatedAt = Date.now();
    await putItem({
      id,
      type: 'file',
      updatedAt,
      payload: { meta: metaPayload, file: filePayload }
    });
    state.files.unshift({
      id,
      updatedAt,
      name: file.name,
      mime: file.type || 'application/octet-stream',
      size: file.size,
      encryptedBytes: filePayload
    });
  }
  e.target.value = '';
  renderFiles();
}

function normalizePhone(raw) {
  return raw.replace(/[^\d]/g, '');
}

function openDirectChat(platform) {
  const digits = normalizePhone($('direct-phone').value);
  const message = $('direct-message').value.trim();
  const feedback = $('direct-feedback');

  if (digits.length < 7) {
    feedback.textContent = 'Enter a full phone number including country code.';
    feedback.hidden = false;
    return;
  }
  feedback.hidden = true;

  const encoded = encodeURIComponent(message);
  let url = '';
  if (platform === 'whatsapp') {
    url = message
      ? `https://wa.me/${digits}?text=${encoded}`
      : `https://wa.me/${digits}`;
  } else if (platform === 'telegram') {
    url = `https://t.me/+${digits}`;
  } else if (platform === 'sms') {
    url = message ? `sms:+${digits}?&body=${encoded}` : `sms:+${digits}`;
  }
  window.open(url, '_blank', 'noopener,noreferrer');
}

async function exportEncryptedBackup() {
  const [salt, verifier, items] = await Promise.all([
    getMeta('salt'),
    getMeta('verifier'),
    getAllItems()
  ]);
  const backup = {
    version: 1,
    exportedAt: new Date().toISOString(),
    salt,
    verifier,
    items
  };
  const blob = new Blob([JSON.stringify(backup)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `pocketvault-backup-${new Date().toISOString().slice(0, 10)}.json`;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function bindEvents() {
  $('lock-form').addEventListener('submit', handleUnlockSubmit);
  $('lock-btn').addEventListener('click', lockVault);

  for (const btn of document.querySelectorAll('[data-tab]')) {
    btn.addEventListener('click', () => switchTab(btn.dataset.tab));
  }

  $('add-space-btn').addEventListener('click', () => openSpaceDialog());
  $('spaces-search').addEventListener('input', renderSpaces);

  $('space-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const id = $('space-id').value || null;
    const name = $('space-name').value.trim();
    const tag = $('space-tag').value.trim();
    const sanitized = sanitizeLaunchUrl($('space-url').value);
    const errEl = $('space-error');

    if (!name) {
      errEl.textContent = 'Enter a space name.';
      errEl.hidden = false;
      return;
    }
    if (!sanitized.ok) {
      errEl.textContent = sanitized.error;
      errEl.hidden = false;
      return;
    }
    errEl.hidden = true;

    const existing = id ? state.spaces.find((s) => s.id === id) : null;
    const item = {
      name,
      url: sanitized.url,
      tag,
      pinned: existing ? Boolean(existing.pinned) : false,
      order: existing && typeof existing.order === 'number' ? existing.order : state.spaces.length
    };
    const savedId = await saveEncryptedItem('space', item, id);
    if (id) {
      state.spaces = state.spaces.map((s) =>
        s.id === id ? { id, updatedAt: Date.now(), ...item } : s
      );
    } else {
      state.spaces.push({ id: savedId, updatedAt: Date.now(), ...item });
    }
    renderSpaces();
    $('space-dialog').close();
    showToast(id ? 'Space updated' : 'Space added');
  });

  $('menu-open-btn').addEventListener('click', () => {
    const space = state.spaces.find((s) => s.id === state.activeSpaceMenuId);
    $('space-menu').close();
    if (!space) return;
    const sanitized = sanitizeLaunchUrl(space.url);
    if (sanitized.ok) {
      window.open(sanitized.url, '_blank', 'noopener,noreferrer');
    } else {
      openSpaceDialog(space);
    }
  });

  $('menu-pin-btn').addEventListener('click', async () => {
    const space = state.spaces.find((s) => s.id === state.activeSpaceMenuId);
    if (!space) return;
    const pinned = !space.pinned;
    const item = {
      name: space.name,
      url: space.url,
      tag: space.tag || '',
      pinned,
      order: typeof space.order === 'number' ? space.order : state.spaces.length
    };
    await saveEncryptedItem('space', item, space.id);
    state.spaces = state.spaces.map((s) =>
      s.id === space.id ? { id: space.id, updatedAt: Date.now(), ...item } : s
    );
    $('space-menu').close();
    renderSpaces();
    showToast(pinned ? 'Space pinned' : 'Space unpinned');
  });

  $('menu-edit-btn').addEventListener('click', () => {
    const space = state.spaces.find((s) => s.id === state.activeSpaceMenuId);
    $('space-menu').close();
    if (space) openSpaceDialog(space);
  });

  $('menu-duplicate-btn').addEventListener('click', async () => {
    const space = state.spaces.find((s) => s.id === state.activeSpaceMenuId);
    if (!space) return;
    const item = {
      name: `${space.name} (copy)`,
      url: space.url,
      tag: space.tag || '',
      pinned: false,
      order: state.spaces.length
    };
    const id = await saveEncryptedItem('space', item);
    state.spaces.push({ id, updatedAt: Date.now(), ...item });
    $('space-menu').close();
    renderSpaces();
    showToast('Space duplicated');
  });

  $('menu-left-btn').addEventListener('click', () => moveActiveSpace(-1));
  $('menu-right-btn').addEventListener('click', () => moveActiveSpace(1));

  $('menu-delete-btn').addEventListener('click', async () => {
    const id = state.activeSpaceMenuId;
    if (!id) return;
    await deleteItem(id);
    state.spaces = state.spaces.filter((s) => s.id !== id);
    $('space-menu').close();
    renderSpaces();
    showToast('Space removed');
  });

  $('vault-file-input').addEventListener('change', handleVaultUpload);

  $('add-note-btn').addEventListener('click', () => openNoteDialog());
  $('notes-search').addEventListener('input', renderNotes);

  $('note-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const id = $('note-id').value || null;
    const note = {
      title: $('note-title').value.trim() || 'Untitled note',
      body: $('note-body').value
    };
    const savedId = await saveEncryptedItem('note', note, id);
    if (id) {
      state.notes = state.notes.map((n) =>
        n.id === id ? { id, updatedAt: Date.now(), ...note } : n
      );
    } else {
      state.notes.unshift({ id: savedId, updatedAt: Date.now(), ...note });
    }
    renderNotes();
    $('note-dialog').close();
  });

  $('add-contact-btn').addEventListener('click', () => {
    $('contact-form').reset();
    $('contact-dialog').showModal();
  });

  $('contact-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const contact = {
      name: $('contact-name').value.trim(),
      phone: $('contact-phone').value.trim(),
      note: $('contact-note').value.trim()
    };
    if (!contact.name) return;
    const id = await saveEncryptedItem('contact', contact);
    state.contacts.unshift({ id, updatedAt: Date.now(), ...contact });
    renderContacts();
    $('contact-dialog').close();
  });

  $('direct-wa').addEventListener('click', () => openDirectChat('whatsapp'));
  $('direct-tg').addEventListener('click', () => openDirectChat('telegram'));
  $('direct-sms').addEventListener('click', () => openDirectChat('sms'));

  $('settings-btn').addEventListener('click', () => $('settings-dialog').showModal());
  $('export-backup-btn').addEventListener('click', exportEncryptedBackup);
  $('wipe-vault-btn').addEventListener('click', () => $('wipe-dialog').showModal());
  $('confirm-wipe-btn').addEventListener('click', async () => {
    await wipeDatabase();
    $('wipe-dialog').close();
    $('settings-dialog').close();
    lockVault();
  });

  // Auto-lock if backgrounded for more than 2 minutes
  document.addEventListener('visibilitychange', () => {
    if (document.hidden) {
      state.hiddenAt = Date.now();
    } else if (state.key && state.hiddenAt && Date.now() - state.hiddenAt > 120000) {
      lockVault();
    }
  });
}

async function init() {
  initDialogFallbacks();
  bindEvents();
  await checkVaultExists();
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('./sw.js').catch(() => {});
  }
}

init();