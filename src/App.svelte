<script>
  import { onDestroy, onMount } from "svelte";
  import ConfirmModal from "./components/ConfirmModal.svelte";
  import ContextMenu from "./components/ContextMenu.svelte";
  import Icon from "./components/Icon.svelte";
  import PasswordDetail from "./components/PasswordDetail.svelte";
  import PromptModal from "./components/PromptModal.svelte";
  import Toast from "./components/Toast.svelte";
  import {
    DEFAULT_GROUP_ID,
    displayGroupName,
    resolveMessages,
  } from "./lib/i18n.js";

  let text = $state(resolveMessages("zh"));
  let locale = $state("zh-CN");
  let groups = $state([]);
  let entries = $state([]);
  let query = $state("");
  let selectedId = $state("");
  let collapsed = $state({ [DEFAULT_GROUP_ID]: false });
  let bootError = $state("");
  let saving = $state(false);
  let busy = $state(false);

  let toastMessage = $state("");
  let toastVisible = $state(false);
  let toastTimer = 0;

  /** @type {null | { kind: "create-group" | "rename-group", groupId?: string, value?: string }} */
  let prompt = $state(null);
  /** @type {null | { kind: "delete-group" | "delete-entry", id: string }} */
  let confirm = $state(null);
  /** @type {null | { x: number, y: number, groupId: string }} */
  let menu = $state(null);

  /** Target group when creating a password from context menu / toolbar */
  let createGroupId = $state(DEFAULT_GROUP_ID);

  const selected = $derived(entries.find((e) => e.id === selectedId) || null);

  const groupOptions = $derived(
    groups.map((g) => ({
      id: g.id,
      label: displayGroupName(g, text),
    })),
  );

  const needle = $derived(query.trim().toLowerCase());

  const filteredEntries = $derived(
    needle
      ? entries.filter((entry) => {
          const hay = [
            entry.title,
            entry.username,
            entry.url,
            entry.notes,
          ]
            .join("\n")
            .toLowerCase();
          return hay.includes(needle);
        })
      : entries,
  );

  const sections = $derived(
    groups.map((group) => {
      const items = filteredEntries
        .filter((entry) => entry.groupId === group.id)
        .slice()
        .sort((a, b) => String(a.title).localeCompare(String(b.title), locale));
      return {
        group,
        label: displayGroupName(group, text),
        items,
        collapsed: Boolean(collapsed[group.id]),
      };
    }),
  );

  const visibleSections = $derived(
    needle ? sections.filter((section) => section.items.length > 0) : sections,
  );

  const hasAny = $derived(entries.length > 0);
  const hasVisible = $derived(visibleSections.some((s) => s.items.length > 0));

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

  function errorMessage(err) {
    return err?.message || err?.error?.message || String(err || text.error);
  }

  async function loadList(keepSelection = true) {
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

  function openCreateGroup() {
    prompt = { kind: "create-group", value: "" };
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
      x: Math.min(event.clientX, window.innerWidth - 180),
      y: Math.min(event.clientY, window.innerHeight - 140),
      groupId,
    };
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
        await window.dbxPlugin.invoke("group/create", { name });
        await loadList();
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
        selectedId = result?.entry?.id || "";
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
        if (selectedId === id) selectedId = "";
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
      selectedId = result?.entry?.id || draft.id;
      showToast(text.saved);
    } catch (err) {
      showToast(errorMessage(err));
      throw err;
    } finally {
      saving = false;
    }
  }

  function onMenuSelect(actionId) {
    const groupId = menu?.groupId;
    menu = null;
    if (!groupId) return;
    if (actionId === "new-password") openCreatePassword(groupId);
    if (actionId === "rename") openRenameGroup(groupId);
    if (actionId === "delete") openDeleteGroup(groupId);
  }

  const menuItems = $derived(
    menu
      ? [
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
        ]
      : [],
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

  onMount(async () => {
    applyLocale();
    window.addEventListener("dbx-plugin-env", applyLocale);
    try {
      await window.dbxPlugin.ready;
      applyLocale();
      await loadList(false);
    } catch (err) {
      bootError = errorMessage(err);
    }
  });

  onDestroy(() => {
    clearTimeout(toastTimer);
    window.removeEventListener("dbx-plugin-env", applyLocale);
  });
</script>

<svelte:head>
  <title>密码管理</title>
</svelte:head>

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
      <button type="button" class="btn" onclick={openCreateGroup}>
        <Icon name="folder-plus" size={15} />
        <span>{text.newGroup}</span>
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
      {:else if !hasAny}
        <div class="empty">{text.empty}</div>
      {:else if !hasVisible}
        <div class="empty">{text.emptyFilter}</div>
      {:else}
        {#each visibleSections as section (section.group.id)}
          <div class="group" aria-expanded={!section.collapsed}>
            <div class="group-row">
              <button
                type="button"
                class="chevron"
                class:collapsed={section.collapsed}
                aria-label="toggle"
                onclick={() => toggleGroup(section.group.id)}
              >
                ▾
              </button>
              <button
                type="button"
                class="group-name"
                onclick={() => toggleGroup(section.group.id)}
                oncontextmenu={(event) => openGroupMenu(event, section.group.id)}
              >
                <span class="group-label">{section.label}</span>
                <span class="count">{section.items.length}</span>
              </button>
            </div>

            {#if !section.collapsed}
              <div class="entries" role="group">
                {#each section.items as entry (entry.id)}
                  <button
                    type="button"
                    class="entry"
                    class:active={selectedId === entry.id}
                    onclick={() => (selectedId = entry.id)}
                  >
                    <span class="entry-title">{entry.title || "—"}</span>
                  </button>
                {/each}
              </div>
            {/if}
          </div>
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
      onsave={saveEntry}
      ondelete={() => selected && openDeleteEntry(selected.id)}
      oncopied={() => showToast(text.copied)}
      ongenerated={() => showToast(text.passwordGenerated)}
    />
  </main>
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

<style>
  :global(:root) {
    color-scheme: light dark;
    --bg: var(--color-background, Canvas);
    --fg: var(--color-foreground, CanvasText);
    --muted: color-mix(in srgb, var(--fg) 55%, transparent);
    --border: color-mix(in srgb, var(--fg) 14%, transparent);
    --hover: color-mix(in srgb, var(--fg) 6%, transparent);
    --active: color-mix(in srgb, var(--fg) 10%, transparent);
    --accent: var(--color-primary, #0f766e);
    --danger: #dc2626;
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

  .app {
    display: grid;
    grid-template-columns: var(--sidebar-width) 1fr;
    height: 100%;
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
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 8px;
    padding: 12px;
    border-bottom: 1px solid var(--border);
    flex-shrink: 0;
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

  .btn span {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .btn:hover {
    background: var(--hover);
  }

  .btn.primary {
    background: var(--accent);
    border-color: var(--accent);
    color: #fff;
  }

  .btn.primary:hover {
    filter: brightness(1.05);
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
    padding: 8px 0 16px;
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

  .group {
    margin-bottom: 2px;
  }

  .group-row {
    display: flex;
    align-items: center;
    gap: 2px;
    padding: 0 8px;
  }

  .chevron,
  .group-name,
  .entry {
    border: 0;
    background: transparent;
    color: inherit;
    font: inherit;
    cursor: pointer;
  }

  .chevron {
    width: 24px;
    height: 28px;
    display: grid;
    place-items: center;
    border-radius: 6px;
    color: var(--muted);
    transition: transform 0.12s ease;
    flex-shrink: 0;
  }

  .chevron.collapsed {
    transform: rotate(-90deg);
  }

  .chevron:hover,
  .group-name:hover,
  .entry:hover {
    background: var(--hover);
  }

  .group-name {
    flex: 1;
    min-width: 0;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    height: 28px;
    padding: 0 8px;
    border-radius: 6px;
    font-weight: 600;
  }

  .group-label {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .count {
    color: var(--muted);
    font-weight: 500;
    font-size: 11px;
  }

  .entries {
    display: flex;
    flex-direction: column;
    padding: 2px 8px 6px 28px;
    gap: 2px;
  }

  .entry {
    display: block;
    width: 100%;
    padding: 7px 10px;
    border-radius: 8px;
    text-align: left;
  }

  .entry.active {
    background: color-mix(in srgb, var(--accent) 16%, transparent);
  }

  .entry-title {
    display: block;
    width: 100%;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
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
