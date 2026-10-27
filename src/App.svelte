<script>
  import { onDestroy, onMount } from "svelte";
  import ConfirmModal from "./components/ConfirmModal.svelte";
  import ContextMenu from "./components/ContextMenu.svelte";
  import GroupNode from "./components/GroupNode.svelte";
  import Icon from "./components/Icon.svelte";
  import MasterPasswordModal from "./components/MasterPasswordModal.svelte";
  import PasswordDetail from "./components/PasswordDetail.svelte";
  import PromptModal from "./components/PromptModal.svelte";
  import Toast from "./components/Toast.svelte";
  import UnlockScreen from "./components/UnlockScreen.svelte";
  import { clearClipboardIfMatches } from "./lib/format.js";
  import { DEFAULT_GROUP_ID, resolveMessages } from "./lib/i18n.js";
  import { buildGroupTree, flattenGroupOptions } from "./lib/tree.js";

  const IDLE_LOCK_MS = 5 * 60 * 1000;
  const CLIPBOARD_CLEAR_MS = 30 * 1000;

  let text = $state(resolveMessages("zh"));
  let locale = $state("zh-CN");
  let groups = $state([]);
  let entries = $state([]);
  let query = $state("");
  let selectedId = $state("");
  /** Full entry from password/get (list omits secrets). */
  let selectedDetail = $state(null);
  let collapsed = $state({ [DEFAULT_GROUP_ID]: false });
  let bootError = $state("");
  let saving = $state(false);
  let busy = $state(false);
  let ready = $state(false);
  let hasPassword = $state(false);
  let unlocked = $state(false);
  let encryptionPending = $state(false);
  let unlocking = $state(false);
  let unlockError = $state("");
  /** @type {null | "set" | "change" | "clear"} */
  let masterModal = $state(null);

  let toastMessage = $state("");
  let toastVisible = $state(false);
  let toastTimer = 0;
  let idleTimer = 0;
  let clipboardTimer = 0;
  let clipboardPending = "";

  /** @type {null | { kind: "create-group" | "create-password" | "rename-group", groupId?: string, parentId?: string, value?: string }} */
  let prompt = $state(null);
  /** @type {null | { kind: "delete-group" | "delete-entry", id: string }} */
  let confirm = $state(null);
  /** @type {null | { kind: "group" | "entry" | "vault", x: number, y: number, groupId?: string, entryId?: string }} */
  let menu = $state(null);
  /** Bumped to ask PasswordDetail to enter edit mode for the selected entry */
  let editRequestToken = $state(0);

  /** Target group when creating a password from context menu / toolbar */
  let createGroupId = $state(DEFAULT_GROUP_ID);
  /** Parent when creating a nested group; empty = root */
  let createParentId = $state("");

  const selected = $derived(
    selectedDetail?.id === selectedId
      ? selectedDetail
      : entries.find((e) => e.id === selectedId) || null,
  );

  const groupOptions = $derived(flattenGroupOptions(groups, locale, text));

  const needle = $derived(query.trim().toLowerCase());

  const filteredEntries = $derived(
    needle
      ? entries.filter((entry) => {
          const hay = [entry.title, entry.username, entry.url, entry.notes]
            .join("\n")
            .toLowerCase();
          return hay.includes(needle);
        })
      : entries,
  );

  const tree = $derived(
    buildGroupTree(groups, filteredEntries, collapsed, needle, locale, text),
  );

  const hasTree = $derived(groups.length > 0);
  const hasVisible = $derived(tree.length > 0);

  function applyLocale() {
    locale = window.dbxPlugin?.locale || navigator.language || "zh-CN";
    text = resolveMessages(locale);
  }

  function showToast(message) {
    toastMessage = message;
    toastVisible = true;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => {
      toastVisible = false;
    }, 1800);
  }

  function bumpIdleTimer() {
    clearTimeout(idleTimer);
    if (!hasPassword || !unlocked) return;
    idleTimer = setTimeout(() => {
      void (async () => {
        await handleLock();
        showToast(text.vaultAutoLocked);
      })();
    }, IDLE_LOCK_MS);
  }

  function scheduleClipboardClear(value) {
    clearTimeout(clipboardTimer);
    clipboardPending = String(value ?? "");
    if (!clipboardPending) return;
    clipboardTimer = setTimeout(async () => {
      const result = await clearClipboardIfMatches(clipboardPending);
      clipboardPending = "";
      if (result === "cleared") showToast(text.clipboardCleared);
      else if (result === "denied" || result === "unsupported") {
        showToast(text.clipboardClearSkipped);
      }
    }, CLIPBOARD_CLEAR_MS);
  }

  function handleCopied(kind, value) {
    showToast(text.copied);
    if (kind === "password") {
      scheduleClipboardClear(value);
    }
  }

  function errorMessage(err) {
    const raw = err?.message || err?.error?.message || String(err || text.error);
    const mapped = {
      "Group name is required": text.requiredGroupName,
      "Group name already exists": text.groupNameExists,
      "Group not found": text.groupNotFound,
      "Parent group not found": text.parentGroupNotFound,
      "Cannot rename the default group": text.cannotRenameDefault,
      "Cannot delete the default group": text.cannotDeleteDefault,
      "Title is required": text.requiredTitle,
      "Password entry not found": text.entryNotFound,
      "Vault is locked": text.vaultLocked,
      "Wrong master password": text.wrongMasterPassword,
      "Wrong master password or vault is corrupted": text.wrongMasterPasswordOrCorrupt,
      "Master password is required": text.requiredMasterPassword,
      "Current master password is required": text.requiredCurrentMasterPassword,
      "Master password must be at least 8 characters": text.masterPasswordTooShort,
      "Invalid encrypted vault": text.invalidVault,
      "Invalid vault payload": text.invalidVault,
      "Invalid vault encoding": text.invalidVault,
      "Unsupported vault format": text.invalidVault,
      "Vault is not encrypted": text.invalidVault,
      "Vault decryption failed": text.vaultDecryptFailed,
      "Missing vault open key": text.missingOpenKey,
      "Invalid vault open key": text.missingOpenKey,
    };
    if (mapped[raw]) return mapped[raw];
    if (raw.startsWith("Unsupported vault version")) {
      return text.unsupportedVaultVersion;
    }
    if (raw.startsWith("Unsupported vault")) return text.invalidVault;
    return raw;
  }

  async function fetchEntryDetail(id) {
    if (!id) {
      selectedDetail = null;
      return;
    }
    try {
      const result = await window.dbxPlugin.invoke("password/get", { id });
      selectedDetail = result?.entry || null;
    } catch {
      selectedDetail = null;
    }
  }

  async function selectEntry(id) {
    selectedId = id || "";
    await fetchEntryDetail(selectedId);
  }

  function applyVaultStatus(result) {
    hasPassword = Boolean(result?.hasPassword);
    unlocked = Boolean(result?.unlocked);
    encryptionPending = Boolean(result?.encryptionPending);
  }

  async function refreshVaultStatus() {
    const result = await window.dbxPlugin.invoke("vault/status", {});
    applyVaultStatus(result);
    return result;
  }

  async function loadList(keepSelection = true) {
    await refreshVaultStatus().catch(() => {});
    const result = await window.dbxPlugin.invoke("password/list", {
      query: "",
    });
    groups = Array.isArray(result?.groups) ? result.groups : [];
    entries = Array.isArray(result?.entries) ? result.entries : [];

    const nextCollapsed = { ...collapsed };
    for (const group of groups) {
      if (typeof nextCollapsed[group.id] !== "boolean") {
        nextCollapsed[group.id] = false;
      }
    }
    collapsed = nextCollapsed;

    if (keepSelection && selectedId && !entries.some((e) => e.id === selectedId)) {
      selectedId = "";
      selectedDetail = null;
    } else if (keepSelection && selectedId) {
      await fetchEntryDetail(selectedId);
    }
  }

  async function handleUnlock(password) {
    unlocking = true;
    unlockError = "";
    try {
      const result = await window.dbxPlugin.invoke("vault/unlock", { password });
      applyVaultStatus(result);
      try {
        await loadList(false);
        bumpIdleTimer();
      } catch (err) {
        unlockError = errorMessage(err);
        unlocked = false;
        groups = [];
        entries = [];
      }
    } catch (err) {
      unlockError = errorMessage(err);
    } finally {
      unlocking = false;
    }
  }

  async function handleLock() {
    clearTimeout(idleTimer);
    try {
      const result = await window.dbxPlugin.invoke("vault/lock", {});
      applyVaultStatus(result);
      groups = [];
      entries = [];
      selectedId = "";
      selectedDetail = null;
      query = "";
      unlockError = "";
    } catch (err) {
      showToast(errorMessage(err));
    }
  }

  async function handleMasterPasswordConfirm(payload) {
    if (busy || !masterModal) return;
    busy = true;
    try {
      if (masterModal === "clear") {
        await window.dbxPlugin.invoke("vault/clearMasterPassword", {
          currentPassword: payload.currentPassword || "",
        });
        showToast(text.masterPasswordCleared);
      } else {
        await window.dbxPlugin.invoke("vault/setMasterPassword", {
          password: payload.password || "",
          currentPassword: payload.currentPassword || undefined,
        });
        showToast(text.masterPasswordSet);
      }
      await refreshVaultStatus();
      masterModal = null;
    } catch (err) {
      showToast(errorMessage(err));
    } finally {
      busy = false;
    }
  }

  function toggleGroup(groupId) {
    collapsed = { ...collapsed, [groupId]: !collapsed[groupId] };
  }

  function openCreatePassword(groupId = DEFAULT_GROUP_ID) {
    createGroupId = groupId || DEFAULT_GROUP_ID;
    prompt = {
      kind: "create-password",
      value: "",
    };
  }

  function openCreateGroup(parentId = "") {
    createParentId = parentId || "";
    prompt = { kind: "create-group", parentId: createParentId, value: "" };
  }

  function openRenameGroup(groupId) {
    if (groupId === DEFAULT_GROUP_ID) {
      showToast(text.cannotRenameDefault);
      return;
    }
    const group = groups.find((g) => g.id === groupId);
    prompt = {
      kind: "rename-group",
      groupId,
      value: group?.name || "",
    };
  }

  function openDeleteGroup(groupId) {
    if (groupId === DEFAULT_GROUP_ID) {
      showToast(text.cannotDeleteDefault);
      return;
    }
    confirm = { kind: "delete-group", id: groupId };
  }

  function openDeleteEntry(id) {
    confirm = { kind: "delete-entry", id };
  }

  function openGroupMenu(event, groupId) {
    event.preventDefault();
    event.stopPropagation();
    menu = {
      kind: "group",
      x: Math.min(event.clientX, window.innerWidth - 180),
      y: Math.min(event.clientY, window.innerHeight - 180),
      groupId,
    };
  }

  function openEntryMenu(event, entryId) {
    event.preventDefault();
    event.stopPropagation();
    void selectEntry(entryId);
    menu = {
      kind: "entry",
      x: Math.min(event.clientX, window.innerWidth - 180),
      y: Math.min(event.clientY, window.innerHeight - 120),
      entryId,
    };
  }

  function requestEditEntry(entryId) {
    void (async () => {
      await selectEntry(entryId);
      editRequestToken += 1;
    })();
  }

  async function handlePromptConfirm(value) {
    if (!prompt || busy) return;
    const kind = prompt.kind;
    const name = String(value || "").trim();
    busy = true;
    try {
      if (kind === "create-group") {
        if (!name) {
          showToast(text.requiredGroupName);
          return;
        }
        const parentId = prompt.parentId || createParentId || "";
        await window.dbxPlugin.invoke("group/create", {
          name,
          parentId: parentId || undefined,
        });
        await loadList();
        if (parentId) {
          collapsed = { ...collapsed, [parentId]: false };
        }
        showToast(text.groupCreated);
      } else if (kind === "rename-group") {
        if (!name) {
          showToast(text.requiredGroupName);
          return;
        }
        await window.dbxPlugin.invoke("group/rename", {
          id: prompt.groupId,
          name,
        });
        await loadList();
        showToast(text.renamed);
      } else if (kind === "create-password") {
        if (!name) {
          showToast(text.requiredTitle);
          return;
        }
        const result = await window.dbxPlugin.invoke("password/create", {
          groupId: createGroupId,
          title: name,
          username: "",
          password: "",
          url: "",
          notes: "",
        });
        await loadList();
        const newId = result?.entry?.id || "";
        if (newId) {
          selectedDetail = result.entry;
          selectedId = newId;
          editRequestToken += 1;
        }
        collapsed = { ...collapsed, [createGroupId]: false };
        showToast(text.created);
      }
      prompt = null;
    } catch (err) {
      showToast(errorMessage(err));
    } finally {
      busy = false;
    }
  }

  async function handleConfirm() {
    if (!confirm || busy) return;
    busy = true;
    try {
      if (confirm.kind === "delete-group") {
        await window.dbxPlugin.invoke("group/delete", { id: confirm.id });
        await loadList();
        showToast(text.groupDeleted);
      } else if (confirm.kind === "delete-entry") {
        const id = confirm.id;
        await window.dbxPlugin.invoke("password/delete", { id });
        if (selectedId === id) {
          selectedId = "";
          selectedDetail = null;
        }
        await loadList();
        showToast(text.deleted);
      }
      confirm = null;
    } catch (err) {
      showToast(errorMessage(err));
    } finally {
      busy = false;
    }
  }

  async function saveEntry(draft) {
    if (saving) return;
    if (!String(draft.title || "").trim()) {
      showToast(text.requiredTitle);
      throw new Error(text.requiredTitle);
    }
    saving = true;
    try {
      const result = await window.dbxPlugin.invoke("password/update", {
        id: draft.id,
        groupId: draft.groupId,
        title: draft.title,
        username: draft.username,
        password: draft.password,
        url: draft.url,
        notes: draft.notes,
      });
      await loadList();
      const nextId = result?.entry?.id || draft.id;
      selectedId = nextId;
      selectedDetail = result?.entry || null;
      showToast(text.saved);
    } catch (err) {
      showToast(errorMessage(err));
      throw err;
    } finally {
      saving = false;
    }
  }

  function openVaultSettings(event) {
    event.stopPropagation();
    if (!hasPassword) {
      masterModal = "set";
      return;
    }
    const rect = event.currentTarget.getBoundingClientRect();
    menu = {
      kind: "vault",
      x: Math.round(rect.left),
      y: Math.round(rect.bottom + 4),
    };
  }

  function onMenuSelect(actionId) {
    const current = menu;
    menu = null;
    if (!current) return;
    if (current.kind === "vault") {
      if (actionId === "lock") handleLock();
      if (actionId === "set") masterModal = "set";
      if (actionId === "change") masterModal = "change";
      if (actionId === "clear") masterModal = "clear";
      return;
    }
    if (current.kind === "entry") {
      if (actionId === "edit") requestEditEntry(current.entryId);
      if (actionId === "delete") openDeleteEntry(current.entryId);
      return;
    }
    const groupId = current.groupId;
    if (!groupId) return;
    if (actionId === "new-group") openCreateGroup(groupId);
    if (actionId === "new-password") openCreatePassword(groupId);
    if (actionId === "rename") openRenameGroup(groupId);
    if (actionId === "delete") openDeleteGroup(groupId);
  }

  const menuItems = $derived(
    !menu
      ? []
      : menu.kind === "vault"
        ? hasPassword
          ? [
              { id: "lock", label: text.lockVault },
              { id: "change", label: text.changeMasterPassword },
              { id: "clear", label: text.clearMasterPassword, danger: true },
            ]
          : [{ id: "set", label: text.setMasterPassword }]
        : menu.kind === "entry"
          ? [
              { id: "edit", label: text.edit },
              { id: "delete", label: text.delete, danger: true },
            ]
          : [
              { id: "new-group", label: text.newGroup },
              { id: "new-password", label: text.newPassword },
              {
                id: "rename",
                label: text.rename,
                disabled: menu.groupId === DEFAULT_GROUP_ID,
              },
              {
                id: "delete",
                label: text.deleteGroup,
                danger: true,
                disabled: menu.groupId === DEFAULT_GROUP_ID,
              },
            ],
  );

  const promptTitle = $derived(
    prompt?.kind === "create-group"
      ? text.createGroupTitle
      : prompt?.kind === "rename-group"
        ? text.renameGroupTitle
        : text.createPasswordTitle,
  );

  const promptLabel = $derived(
    prompt?.kind === "create-password" ? text.title : text.groupName,
  );

  const promptPlaceholder = $derived(
    prompt?.kind === "create-password"
      ? text.titlePlaceholder
      : text.groupNamePlaceholder,
  );

  async function lockVaultQuiet() {
    try {
      const result = await window.dbxPlugin.invoke("vault/lock", {});
      applyVaultStatus(result);
    } catch {
      hasPassword = true;
      unlocked = false;
    }
    groups = [];
    entries = [];
    selectedId = "";
    selectedDetail = null;
    query = "";
    unlockError = "";
  }

  onMount(async () => {
    applyLocale();
    window.addEventListener("dbx-plugin-env", applyLocale);
    window.addEventListener("pointerdown", bumpIdleTimer, true);
    window.addEventListener("keydown", bumpIdleTimer, true);
    try {
      await window.dbxPlugin.ready;
      applyLocale();
      await refreshVaultStatus();
      // Master-password vaults must unlock every time the workbench opens
      // (sidecar may still hold an unlocked session from a previous open).
      if (hasPassword) {
        await lockVaultQuiet();
      } else if (unlocked) {
        await loadList(false);
        bumpIdleTimer();
      } else {
        // Open-mode vault present but vault.key missing/corrupt — do not show MP unlock.
        bootError = text.vaultUnavailable;
      }
      ready = true;
    } catch (err) {
      bootError = errorMessage(err);
      ready = true;
    }
  });

  onDestroy(() => {
    clearTimeout(toastTimer);
    clearTimeout(idleTimer);
    clearTimeout(clipboardTimer);
    window.removeEventListener("dbx-plugin-env", applyLocale);
    window.removeEventListener("pointerdown", bumpIdleTimer, true);
    window.removeEventListener("keydown", bumpIdleTimer, true);
    if (hasPassword) {
      void window.dbxPlugin?.invoke?.("vault/lock", {}).catch(() => {});
    }
  });
</script>

<svelte:head>
  <title>{text.appTitle}</title>
</svelte:head>

{#if !ready}
  <div class="boot"></div>
{:else if bootError}
  <div class="boot error">{bootError}</div>
{:else if hasPassword && !unlocked}
  <UnlockScreen
    {text}
    {unlocking}
    error={unlockError}
    onunlock={handleUnlock}
  />
{:else if !unlocked}
  <div class="boot error">{text.vaultUnavailable}</div>
{:else}
<div class="shell">
  {#if encryptionPending}
    <div class="encrypt-warn" role="status">
      {text.encryptionPending}
    </div>
  {/if}
<div class="app">
  <aside class="sidebar">
    <div class="actions">
      <button
        type="button"
        class="btn primary"
        onclick={() =>
          openCreatePassword(selected?.groupId || DEFAULT_GROUP_ID)
        }
      >
        <Icon name="key" size={15} />
        <span>{text.newPassword}</span>
      </button>
      <button type="button" class="btn" onclick={() => openCreateGroup("")}>
        <Icon name="folder-plus" size={15} />
        <span>{text.newGroup}</span>
      </button>
      <button
        type="button"
        class="btn icon"
        title={text.vaultSettings}
        aria-label={text.vaultSettings}
        onclick={openVaultSettings}
      >
        <Icon name="settings" size={15} />
      </button>
    </div>

    <div class="search-wrap">
      <span class="search-icon" aria-hidden="true">
        <Icon name="search" size={15} />
      </span>
      <input
        class="search"
        type="search"
        autocomplete="off"
        spellcheck="false"
        placeholder={text.search}
        bind:value={query}
      />
    </div>

    <div class="tree">
      {#if bootError}
        <div class="empty error">{bootError}</div>
      {:else if !hasTree}
        <div class="empty">{text.empty}</div>
      {:else if needle && !hasVisible}
        <div class="empty">{text.emptyFilter}</div>
      {:else}
        {#each tree as node (node.group.id)}
          <GroupNode
            {node}
            {selectedId}
            {text}
            onToggle={toggleGroup}
            onGroupMenu={openGroupMenu}
            onSelectEntry={selectEntry}
            onEntryMenu={openEntryMenu}
          />
        {/each}
      {/if}
    </div>
  </aside>

  <main class="main">
    <PasswordDetail
      entry={selected}
      groups={groupOptions}
      {text}
      {locale}
      {saving}
      {editRequestToken}
      onsave={saveEntry}
      ondelete={() => selected && openDeleteEntry(selected.id)}
      oncopied={handleCopied}
      ongenerated={() => showToast(text.passwordGenerated)}
    />
  </main>
</div>
</div>

<Toast message={toastMessage} visible={toastVisible} />

<ContextMenu
  open={Boolean(menu)}
  x={menu?.x || 0}
  y={menu?.y || 0}
  items={menuItems}
  onselect={onMenuSelect}
  onclose={() => (menu = null)}
/>

<PromptModal
  open={Boolean(prompt)}
  title={promptTitle}
  label={promptLabel}
  value={prompt?.value || ""}
  placeholder={promptPlaceholder}
  confirmLabel={text.save}
  cancelLabel={text.cancel}
  confirming={busy}
  oncancel={() => (prompt = null)}
  onconfirm={handlePromptConfirm}
/>

<ConfirmModal
  open={Boolean(confirm)}
  title={confirm?.kind === "delete-group" ? text.deleteGroupTitle : text.deletePasswordTitle}
  body={confirm?.kind === "delete-group" ? text.deleteGroupBody : text.deletePasswordBody}
  confirmLabel={text.confirmDelete}
  cancelLabel={text.cancel}
  confirming={busy}
  oncancel={() => (confirm = null)}
  onconfirm={handleConfirm}
/>

<MasterPasswordModal
  open={Boolean(masterModal)}
  mode={masterModal || "set"}
  {text}
  confirming={busy}
  oncancel={() => (masterModal = null)}
  onconfirm={handleMasterPasswordConfirm}
/>
{/if}

<style>
  .boot {
    height: 100%;
    display: grid;
    place-items: center;
    background: var(--bg, Canvas);
    color: var(--fg, CanvasText);
    padding: 24px;
  }

  .boot.error {
    color: var(--danger, #dc2626);
    text-align: center;
    white-space: pre-wrap;
  }
  :global(:root) {
    color-scheme: light dark;
    --bg: var(--color-background, Canvas);
    --fg: var(--color-foreground, CanvasText);
    --muted: color-mix(in srgb, var(--fg) 55%, transparent);
    --border: color-mix(in srgb, var(--fg) 14%, transparent);
    --hover: color-mix(in srgb, var(--fg) 6%, transparent);
    --active: color-mix(in srgb, var(--fg) 10%, transparent);
    --accent: var(--color-primary, #0f766e);
    --accent-fg: var(--color-primary-foreground, #fff);
    --danger: var(--color-destructive, #dc2626);
    --danger-fg: var(--color-destructive-foreground, #fff);
    --radius: var(--radius-md, 10px);
    --font: var(--font-sans, ui-sans-serif, system-ui, -apple-system, sans-serif);
    --sidebar-width: 280px;
  }

  :global(*) {
    box-sizing: border-box;
  }

  :global(html),
  :global(body) {
    margin: 0;
    height: 100%;
    background: var(--bg);
    color: var(--fg);
    font: 13px/1.45 var(--font);
  }

  :global(#app) {
    height: 100%;
  }

  .shell {
    display: flex;
    flex-direction: column;
    height: 100%;
    min-height: 0;
  }

  .encrypt-warn {
    flex: 0 0 auto;
    padding: 8px 12px;
    border-bottom: 1px solid color-mix(in srgb, #ca8a04 35%, var(--border));
    background: color-mix(in srgb, #ca8a04 14%, var(--bg));
    color: color-mix(in srgb, #a16207 70%, var(--fg));
    font-size: 12px;
    line-height: 1.4;
  }

  .app {
    display: grid;
    grid-template-columns: var(--sidebar-width) 1fr;
    flex: 1;
    min-height: 0;
  }

  .sidebar {
    display: flex;
    flex-direction: column;
    min-width: 0;
    min-height: 0;
    border-right: 1px solid var(--border);
    background: color-mix(in srgb, var(--fg) 2.5%, var(--bg));
  }

  .actions {
    display: flex;
    gap: 8px;
    padding: 12px;
    border-bottom: 1px solid var(--border);
    flex-shrink: 0;
  }

  .actions .btn:not(.icon) {
    flex: 1;
    min-width: 0;
  }

  .btn {
    height: 32px;
    padding: 0 10px;
    border: 1px solid var(--border);
    border-radius: 8px;
    background: transparent;
    color: inherit;
    font: inherit;
    cursor: pointer;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 6px;
    min-width: 0;
  }

  .btn.icon {
    width: 32px;
    padding: 0;
    flex: 0 0 32px;
    color: var(--muted);
  }

  .btn.icon:hover {
    color: var(--fg);
  }

  .btn span {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .btn:hover:not(.primary) {
    background: var(--hover);
  }

  .btn.primary {
    background: var(--accent);
    border-color: var(--accent);
    color: var(--accent-fg);
  }

  .btn.primary:hover {
    background: color-mix(in srgb, var(--accent) 88%, var(--fg));
    border-color: color-mix(in srgb, var(--accent) 88%, var(--fg));
  }

  .search-wrap {
    position: relative;
    padding: 10px 12px;
    border-bottom: 1px solid var(--border);
    flex-shrink: 0;
  }

  .search-icon {
    position: absolute;
    left: 22px;
    top: 50%;
    transform: translateY(-50%);
    color: var(--muted);
    display: grid;
    place-items: center;
    pointer-events: none;
  }

  .search {
    width: 100%;
    height: 34px;
    padding: 0 12px 0 34px;
    border: 1px solid var(--border);
    border-radius: var(--radius);
    background: transparent;
    color: inherit;
    font: inherit;
    outline: none;
  }

  .search:focus {
    border-color: color-mix(in srgb, var(--accent) 70%, var(--border));
    box-shadow: 0 0 0 3px color-mix(in srgb, var(--accent) 18%, transparent);
  }

  .tree {
    flex: 1;
    min-height: 0;
    overflow: auto;
    /* Left 22px matches .search-icon left; right matches search-wrap. */
    padding: 8px 12px 16px 22px;
  }

  .empty {
    display: grid;
    place-items: center;
    height: 100%;
    padding: 24px 18px;
    text-align: center;
    color: var(--muted);
    white-space: pre-line;
  }

  .empty.error {
    color: var(--danger);
  }

  .main {
    min-width: 0;
    min-height: 0;
    overflow: hidden;
  }

  @media (max-width: 720px) {
    .app {
      grid-template-columns: 1fr;
      grid-template-rows: minmax(240px, 42%) 1fr;
    }

    .sidebar {
      border-right: 0;
      border-bottom: 1px solid var(--border);
    }
  }
</style>
