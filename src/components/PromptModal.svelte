<script>
  /** @type {{
   *  open: boolean,
   *  title: string,
   *  label: string,
   *  value?: string,
   *  placeholder?: string,
   *  confirmLabel: string,
   *  cancelLabel: string,
   *  confirming?: boolean,
   *  oncancel: () => void,
   *  onconfirm: (value: string) => void,
   * }} */
  let {
    open = false,
    title = "",
    label = "",
    value = "",
    placeholder = "",
    confirmLabel = "OK",
    cancelLabel = "Cancel",
    confirming = false,
    oncancel,
    onconfirm,
  } = $props();

  let draft = $state("");

  $effect(() => {
    if (open) draft = value || "";
  });

  function submit() {
    if (confirming) return;
    onconfirm?.(draft);
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
      <label class="field">
        <span>{label}</span>
        <input
          type="text"
          bind:value={draft}
          {placeholder}
          disabled={confirming}
        />
      </label>
      <div class="actions">
        <button type="button" class="btn" onclick={oncancel} disabled={confirming}>
          {cancelLabel}
        </button>
        <button
          type="button"
          class="btn primary"
          onclick={submit}
          disabled={confirming || !draft.trim()}
        >
          {confirmLabel}
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
    margin: 0 0 14px;
    font-size: 15px;
    font-weight: 600;
  }

  .field {
    display: grid;
    gap: 6px;
    margin-bottom: 16px;
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

  .btn:hover:not(:disabled) {
    background: var(--hover);
  }

  .btn:disabled {
    opacity: 0.5;
    cursor: wait;
  }

  .btn.primary {
    background: var(--accent);
    border-color: var(--accent);
    color: #fff;
  }

  .btn.primary:hover:not(:disabled) {
    filter: brightness(1.05);
  }
</style>
