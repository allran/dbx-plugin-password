<script>
  import {
    copyText,
    formatDateTime,
    generateRandomPassword,
    passwordStrength,
  } from "../lib/format.js";
  import Icon from "./Icon.svelte";

  /** @type {{
   *  entry: any,
   *  groups: any[],
   *  text: Record<string, any>,
   *  locale: string,
   *  saving?: boolean,
   *  editRequestToken?: number,
   *  onsave: (draft: any) => void,
   *  ondelete: () => void,
   *  oncopied: (kind?: string, value?: string) => void,
   *  ongenerated?: () => void,
   * }} */
  let {
    entry,
    groups = [],
    text,
    locale = "en",
    saving = false,
    editRequestToken = 0,
    onsave,
    ondelete,
    oncopied,
    ongenerated,
  } = $props();

  let draft = $state({
    id: "",
    groupId: "",
    title: "",
    username: "",
    password: "",
    url: "",
    notes: "",
    createdAt: 0,
    updatedAt: 0,
  });
  let showPassword = $state(false);
  let editing = $state(false);
  let entryId = $state("");
  let lastEditRequestToken = $state(0);

  function syncFromEntry(source) {
    draft = {
      id: source.id,
      groupId: source.groupId,
      title: source.title || "",
      username: source.username || "",
      password: source.password || "",
      url: source.url || "",
      notes: source.notes || "",
      createdAt: source.createdAt || 0,
      updatedAt: source.updatedAt || 0,
    };
    showPassword = false;
  }

  $effect(() => {
    if (!entry) {
      entryId = "";
      editing = false;
      return;
    }
    if (entry.id !== entryId) {
      entryId = entry.id;
      editing = false;
      syncFromEntry(entry);
      return;
    }
    if (!editing) {
      syncFromEntry(entry);
    }
  });

  $effect(() => {
    if (!editRequestToken || editRequestToken === lastEditRequestToken || !entry) {
      return;
    }
    lastEditRequestToken = editRequestToken;
    startEdit();
  });

  async function copyField(value, kind = "generic") {
    if (await copyText(value)) oncopied?.(kind, value);
  }

  const strength = $derived(passwordStrength(draft.password));
  const strengthLabel = $derived(
    strength === "weak"
      ? text.passwordStrengthWeak
      : strength === "fair"
        ? text.passwordStrengthFair
        : strength === "strong"
          ? text.passwordStrengthStrong
          : "",
  );

  function generatePassword() {
    draft = { ...draft, password: generateRandomPassword(20) };
    showPassword = true;
    ongenerated?.();
  }

  function startEdit() {
    if (!entry) return;
    syncFromEntry(entry);
    editing = true;
  }

  function cancelEdit() {
    if (!entry) return;
    syncFromEntry(entry);
    editing = false;
  }

  async function save() {
    if (!draft.title.trim() || saving) return;
    try {
      await onsave?.({ ...draft });
      editing = false;
    } catch {
      // Parent shows toast; stay in edit mode.
    }
  }

  function groupLabel(groupId) {
    return groups.find((g) => g.id === groupId)?.label || groupId || "—";
  }

  function displayValue(value) {
    const textValue = String(value ?? "").trim();
    return textValue || "—";
  }
</script>

{#if !entry}
  <div class="empty">{text.selectHint}</div>
{:else}
  <div class="detail">
    <div class="header">
      <h1>{draft.title || text.title}</h1>
      <div class="header-actions">
        {#if editing}
          <button
            type="button"
            class="icon-btn"
            title={text.save}
            aria-label={text.save}
            disabled={saving || !draft.title.trim()}
            onclick={save}
          >
            <Icon name="save" />
          </button>
          <button
            type="button"
            class="icon-btn danger"
            title={text.delete}
            aria-label={text.delete}
            disabled={saving}
            onclick={ondelete}
          >
            <Icon name="trash" />
          </button>
          <button
            type="button"
            class="icon-btn"
            title={text.cancel}
            aria-label={text.cancel}
            disabled={saving}
            onclick={cancelEdit}
          >
            <Icon name="x" />
          </button>
        {:else}
          <button
            type="button"
            class="icon-btn"
            title={text.edit}
            aria-label={text.edit}
            onclick={startEdit}
          >
            <Icon name="edit" />
          </button>
        {/if}
      </div>
    </div>

    <div class="fields">
      <div class="field">
        <span class="label">{text.title}</span>
        <div class="control">
          {#if editing}
            <input
              type="text"
              bind:value={draft.title}
              placeholder={text.titlePlaceholder}
              disabled={saving}
            />
          {:else}
            <div class="value">{displayValue(draft.title)}</div>
          {/if}
        </div>
      </div>

      <div class="field">
        <span class="label">{text.group}</span>
        <div class="control">
          {#if editing}
            <select bind:value={draft.groupId} disabled={saving}>
              {#each groups as group (group.id)}
                <option value={group.id}>{group.label}</option>
              {/each}
            </select>
          {:else}
            <div class="value">{groupLabel(draft.groupId)}</div>
          {/if}
        </div>
      </div>

      <div class="field">
        <span class="label">{text.username}</span>
        <div class="control with-action">
          {#if editing}
            <input
              type="text"
              bind:value={draft.username}
              placeholder={text.usernamePlaceholder}
              disabled={saving}
              autocomplete="off"
            />
          {:else}
            <div class="value">{displayValue(draft.username)}</div>
          {/if}
          <button
            type="button"
            class="icon-btn"
            title={text.copy}
            aria-label={text.copy}
            onclick={() => copyField(draft.username, "username")}
          >
            <Icon name="copy" />
          </button>
        </div>
      </div>

      <div class="field">
        <span class="label">{text.password}</span>
        <div class="stack">
          <div class="control with-action">
            {#if editing}
              <input
                type={showPassword ? "text" : "password"}
                bind:value={draft.password}
                placeholder={text.passwordPlaceholder}
                disabled={saving}
                autocomplete="new-password"
              />
            {:else}
              <div class="value mono">
                {showPassword ? displayValue(draft.password) : "••••••••"}
              </div>
            {/if}
            {#if editing}
              <button
                type="button"
                class="icon-btn"
                title={text.generatePassword}
                aria-label={text.generatePassword}
                disabled={saving}
                onclick={generatePassword}
              >
                <Icon name="dice" />
              </button>
            {/if}
            <button
              type="button"
              class="icon-btn"
              title={showPassword ? text.hide : text.show}
              aria-label={showPassword ? text.hide : text.show}
              onclick={() => (showPassword = !showPassword)}
            >
              <Icon name={showPassword ? "eye-off" : "eye"} />
            </button>
            <button
              type="button"
              class="icon-btn"
              title={text.copy}
              aria-label={text.copy}
              onclick={() => copyField(draft.password, "password")}
            >
              <Icon name="copy" />
            </button>
          </div>
          {#if editing && strengthLabel}
            <div
              class="strength"
              class:weak={strength === "weak"}
              class:fair={strength === "fair"}
              class:strong={strength === "strong"}
            >
              {strengthLabel}
            </div>
          {/if}
        </div>
      </div>

      <div class="field">
        <span class="label">{text.url}</span>
        <div class="control with-action">
          {#if editing}
            <input
              type="url"
              bind:value={draft.url}
              placeholder={text.urlPlaceholder}
              disabled={saving}
            />
          {:else}
            <div class="value">{displayValue(draft.url)}</div>
          {/if}
          <button
            type="button"
            class="icon-btn"
            title={text.copy}
            aria-label={text.copy}
            onclick={() => copyField(draft.url, "url")}
          >
            <Icon name="copy" />
          </button>
        </div>
      </div>

      <div class="field notes">
        <span class="label">{text.notes}</span>
        <div class="control">
          {#if editing}
            <textarea
              rows="5"
              bind:value={draft.notes}
              placeholder={text.notesPlaceholder}
              disabled={saving}
            ></textarea>
          {:else}
            <div class="value multiline">{displayValue(draft.notes)}</div>
          {/if}
        </div>
      </div>

      <div class="field">
        <span class="label">{text.createdAt}</span>
        <div class="control">
          <div class="value muted">{formatDateTime(draft.createdAt, locale)}</div>
        </div>
      </div>

      <div class="field">
        <span class="label">{text.updatedAt}</span>
        <div class="control">
          <div class="value muted">{formatDateTime(draft.updatedAt, locale)}</div>
        </div>
      </div>
    </div>
  </div>
{/if}

<style>
  .empty {
    display: grid;
    place-items: center;
    height: 100%;
    padding: 32px;
    color: var(--muted);
    text-align: center;
    white-space: pre-line;
  }

  .detail {
    display: flex;
    flex-direction: column;
    height: 100%;
    min-height: 0;
    padding: 18px 20px;
    overflow: auto;
  }

  .header {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 12px;
    margin-bottom: 18px;
  }

  h1 {
    margin: 0;
    font-size: 18px;
    font-weight: 650;
    line-height: 1.3;
    word-break: break-word;
  }

  .header-actions {
    display: flex;
    gap: 6px;
    flex-shrink: 0;
  }

  .fields {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }

  .field {
    display: grid;
    grid-template-columns: 88px minmax(0, 1fr);
    gap: 12px;
    align-items: start;
  }

  .strength {
    margin-top: 4px;
    font-size: 11px;
  }

  .strength.weak {
    color: var(--danger);
  }

  .strength.fair {
    color: var(--muted);
  }

  .strength.strong {
    color: color-mix(in srgb, #16a34a 80%, var(--fg));
  }

  .label {
    padding-top: 8px;
    font-size: 12px;
    color: var(--muted);
    line-height: 1.4;
  }

  .control {
    min-width: 0;
  }

  .stack {
    min-width: 0;
    display: flex;
    flex-direction: column;
    gap: 4px;
  }

  .with-action {
    display: flex;
    gap: 6px;
    align-items: center;
  }

  .with-action > :first-child {
    flex: 1;
    min-width: 0;
  }

  input,
  select,
  textarea {
    width: 100%;
    border: 1px solid var(--border);
    border-radius: 8px;
    background: transparent;
    color: var(--fg);
    font: inherit;
    outline: none;
  }

  input,
  select {
    height: 34px;
    padding: 0 10px;
  }

  textarea {
    padding: 8px 10px;
    resize: vertical;
    min-height: 96px;
    line-height: 1.45;
  }

  input:focus,
  select:focus,
  textarea:focus {
    border-color: color-mix(in srgb, var(--accent) 70%, var(--border));
    box-shadow: 0 0 0 3px color-mix(in srgb, var(--accent) 18%, transparent);
  }

  .value {
    min-height: 34px;
    display: flex;
    align-items: center;
    padding: 0 2px;
    color: var(--fg);
    word-break: break-word;
  }

  .value.multiline {
    display: block;
    white-space: pre-wrap;
    padding-top: 8px;
    line-height: 1.5;
    min-height: auto;
  }

  .value.mono {
    font-family: var(--mono, ui-monospace, SFMono-Regular, Menlo, monospace);
  }

  .value.muted {
    color: var(--muted);
  }

  .icon-btn {
    width: 34px;
    height: 34px;
    padding: 0;
    display: grid;
    place-items: center;
    border: 1px solid var(--border);
    border-radius: 8px;
    background: transparent;
    color: inherit;
    cursor: pointer;
    flex-shrink: 0;
  }

  .icon-btn:hover:not(:disabled) {
    background: var(--hover);
  }

  .icon-btn:disabled {
    opacity: 0.45;
    cursor: not-allowed;
  }

  .icon-btn.danger {
    color: var(--danger);
  }

  .icon-btn.danger:hover:not(:disabled) {
    background: color-mix(in srgb, var(--danger) 10%, transparent);
  }

  @media (max-width: 520px) {
    .field {
      grid-template-columns: 72px minmax(0, 1fr);
      gap: 8px;
    }
  }
</style>
