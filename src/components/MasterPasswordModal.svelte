<script>
  /** @type {{
   *  open: boolean,
   *  mode: "set" | "change" | "clear",
   *  text: Record<string, any>,
   *  confirming?: boolean,
   *  oncancel: () => void,
   *  onconfirm: (payload: { password?: string, currentPassword?: string }) => void,
   * }} */
  let {
    open = false,
    mode = "set",
    text,
    confirming = false,
    oncancel,
    onconfirm,
  } = $props();

  let currentPassword = $state("");
  let password = $state("");
  let confirmPassword = $state("");
  let localError = $state("");

  $effect(() => {
    if (open) {
      currentPassword = "";
      password = "";
      confirmPassword = "";
      localError = "";
    }
  });

  const title = $derived(
    mode === "clear"
      ? text.clearMasterPasswordTitle
      : mode === "change"
        ? text.changeMasterPasswordTitle
        : text.setMasterPasswordTitle,
  );

  const body = $derived(
    mode === "clear"
      ? text.clearMasterPasswordBody
      : mode === "change"
        ? text.changeMasterPasswordBody
        : text.setMasterPasswordBody,
  );

  /** @type {HTMLInputElement | null} */
  let currentInput = $state(null);
  /** @type {HTMLInputElement | null} */
  let newInput = $state(null);

  $effect(() => {
    if (!open) return;
    queueMicrotask(() => {
      (mode === "set" ? newInput : currentInput)?.focus();
    });
  });

  function submit() {
    if (confirming) return;
    localError = "";
    if (mode === "clear") {
      if (!currentPassword.trim()) {
        localError = text.requiredCurrentMasterPassword;
        return;
      }
      onconfirm?.({ currentPassword });
      return;
    }
    if (mode === "change" && !currentPassword.trim()) {
      localError = text.requiredCurrentMasterPassword;
      return;
    }
    if (!password.trim()) {
      localError = text.requiredMasterPassword;
      return;
    }
    if ([...password.trim()].length < 4) {
      localError = text.masterPasswordTooShort;
      return;
    }
    if (password !== confirmPassword) {
      localError = text.masterPasswordMismatch;
      return;
    }
    onconfirm?.({
      password,
      currentPassword: mode === "change" ? currentPassword : undefined,
    });
  }

  function onKeydown(event) {
    if (event.key === "Escape") oncancel?.();
    if (event.key === "Enter") {
      event.preventDefault();
      submit();
    }
  }
</script>

{#if open}
  <div class="backdrop" role="presentation" onclick={oncancel}>
    <div
      class="dialog"
      role="dialog"
      aria-modal="true"
      aria-label={title}
      tabindex="-1"
      onclick={(e) => e.stopPropagation()}
      onkeydown={onKeydown}
    >
      <h2>{title}</h2>
      <p class="hint">{body}</p>

      {#if mode !== "set"}
        <label class="field">
          <span>{text.currentMasterPassword}</span>
          <input
            type="password"
            autocomplete="current-password"
            bind:value={currentPassword}
            bind:this={currentInput}
            disabled={confirming}
          />
        </label>
      {/if}

      {#if mode !== "clear"}
        <label class="field">
          <span>{text.newMasterPassword}</span>
          <input
            type="password"
            autocomplete="new-password"
            bind:value={password}
            bind:this={newInput}
            disabled={confirming}
          />
        </label>
        <label class="field">
          <span>{text.confirmMasterPassword}</span>
          <input
            type="password"
            autocomplete="new-password"
            bind:value={confirmPassword}
            disabled={confirming}
          />
        </label>
      {/if}

      {#if localError}
        <div class="error">{localError}</div>
      {/if}

      <div class="actions">
        <button type="button" class="btn" onclick={oncancel} disabled={confirming}>
          {text.cancel}
        </button>
        <button
          type="button"
          class="btn"
          class:primary={mode !== "clear"}
          class:danger={mode === "clear"}
          onclick={submit}
          disabled={confirming}
        >
          {mode === "clear" ? text.clearMasterPassword : text.save}
        </button>
      </div>
    </div>
  </div>
{/if}

<style>
  .backdrop {
    position: fixed;
    inset: 0;
    z-index: 900;
    display: grid;
    place-items: center;
    background: color-mix(in srgb, #000 35%, transparent);
    padding: 16px;
  }

  .dialog {
    width: min(420px, 100%);
    padding: 18px;
    border-radius: var(--radius);
    border: 1px solid var(--border);
    background: var(--bg);
    box-shadow: 0 16px 48px color-mix(in srgb, #000 22%, transparent);
  }

  h2 {
    margin: 0 0 8px;
    font-size: 15px;
    font-weight: 600;
  }

  .hint {
    margin: 0 0 14px;
    color: var(--muted);
    line-height: 1.45;
    font-size: 12px;
  }

  .field {
    display: grid;
    gap: 6px;
    margin-bottom: 12px;
    font-size: 12px;
    color: var(--muted);
  }

  input {
    height: 34px;
    padding: 0 10px;
    border: 1px solid var(--border);
    border-radius: 8px;
    background: transparent;
    color: var(--fg);
    font: inherit;
    outline: none;
  }

  input:focus {
    border-color: color-mix(in srgb, var(--accent) 70%, var(--border));
    box-shadow: 0 0 0 3px color-mix(in srgb, var(--accent) 18%, transparent);
  }

  .error {
    color: var(--danger);
    font-size: 12px;
    margin-bottom: 10px;
  }

  .actions {
    display: flex;
    justify-content: flex-end;
    gap: 8px;
  }

  .btn {
    height: 32px;
    padding: 0 12px;
    border: 1px solid var(--border);
    border-radius: 8px;
    background: transparent;
    color: inherit;
    font: inherit;
    cursor: pointer;
  }

  .btn:hover:not(:disabled):not(.primary):not(.danger) {
    background: var(--hover);
  }

  .btn:disabled {
    opacity: 0.5;
    cursor: wait;
  }

  .btn.primary {
    background: var(--accent);
    border-color: var(--accent);
    color: var(--accent-fg, #fff);
  }

  .btn.primary:hover:not(:disabled) {
    background: color-mix(in srgb, var(--accent) 88%, var(--fg));
    border-color: color-mix(in srgb, var(--accent) 88%, var(--fg));
  }

  .btn.danger {
    background: var(--danger);
    border-color: var(--danger);
    color: var(--danger-fg, #fff);
  }

  .btn.danger:hover:not(:disabled) {
    background: color-mix(in srgb, var(--danger) 88%, var(--fg));
    border-color: color-mix(in srgb, var(--danger) 88%, var(--fg));
  }
</style>
