<script>
  /** @type {{
   *  open: boolean,
   *  title: string,
   *  body: string,
   *  confirmLabel: string,
   *  cancelLabel: string,
   *  confirming?: boolean,
   *  oncancel: () => void,
   *  onconfirm: () => void,
   * }} */
  let {
    open = false,
    title = "",
    body = "",
    confirmLabel = "Delete",
    cancelLabel = "Cancel",
    confirming = false,
    oncancel,
    onconfirm,
  } = $props();
</script>

{#if open}
  <div class="backdrop" role="presentation" onclick={oncancel}>
    <div
      class="dialog"
      role="dialog"
      aria-modal="true"
      aria-label={title}
      tabindex="-1"
      onkeydown={(e) => {
        if (e.key === "Escape") oncancel?.();
      }}
      onclick={(e) => e.stopPropagation()}
    >
      <h2>{title}</h2>
      <p>{body}</p>
      <div class="actions">
        <button type="button" class="btn" onclick={oncancel} disabled={confirming}>
          {cancelLabel}
        </button>
        <button
          type="button"
          class="btn danger"
          onclick={onconfirm}
          disabled={confirming}
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
    margin: 0 0 8px;
    font-size: 15px;
    font-weight: 600;
  }

  p {
    margin: 0 0 16px;
    color: var(--muted);
    line-height: 1.5;
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

  .btn:hover:not(:disabled):not(.danger) {
    background: var(--hover);
  }

  .btn:disabled {
    opacity: 0.5;
    cursor: wait;
  }

  .btn.danger {
    background: var(--danger);
    border-color: var(--danger);
    color: var(--danger-fg, var(--color-destructive-foreground, #fff));
  }

  .btn.danger:hover:not(:disabled) {
    background: color-mix(in srgb, var(--danger) 88%, var(--fg));
    border-color: color-mix(in srgb, var(--danger) 88%, var(--fg));
  }
</style>
