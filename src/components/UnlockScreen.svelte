<script>
  import Icon from "./Icon.svelte";

  /** @type {{
   *  text: Record<string, any>,
   *  unlocking?: boolean,
   *  error?: string,
   *  onunlock: (password: string) => void,
   * }} */
  let {
    text,
    unlocking = false,
    error = "",
    onunlock,
  } = $props();

  let password = $state("");
  /** @type {HTMLInputElement | null} */
  let inputEl = $state(null);

  $effect(() => {
    queueMicrotask(() => inputEl?.focus());
  });

  function submit() {
    if (unlocking) return;
    onunlock?.(password);
  }

  function onKeydown(event) {
    if (event.key === "Enter") {
      event.preventDefault();
      submit();
    }
  }
</script>

<div class="unlock">
  <div class="card">
    <div class="icon" aria-hidden="true">
      <Icon name="lock" size={28} />
    </div>
    <h1>{text.unlockTitle}</h1>
    <p>{text.unlockBody}</p>
    <label class="field">
      <span>{text.masterPassword}</span>
      <input
        type="password"
        autocomplete="current-password"
        bind:value={password}
        bind:this={inputEl}
        disabled={unlocking}
        onkeydown={onKeydown}
        placeholder={text.masterPasswordPlaceholder}
      />
    </label>
    {#if error}
      <div class="error">{error}</div>
    {/if}
    <button
      type="button"
      class="btn primary"
      disabled={unlocking || !password.trim()}
      onclick={submit}
    >
      {unlocking ? text.unlocking : text.unlock}
    </button>
  </div>
</div>

<style>
  .unlock {
    display: grid;
    place-items: center;
    height: 100%;
    min-height: 0;
    padding: 24px;
    background: var(--bg);
    color: var(--fg);
  }

  .card {
    width: min(360px, 100%);
    padding: 28px 24px;
    border: 1px solid var(--border);
    border-radius: var(--radius);
    background: color-mix(in srgb, var(--fg) 2.5%, var(--bg));
    display: flex;
    flex-direction: column;
    gap: 12px;
  }

  .icon {
    width: 48px;
    height: 48px;
    border-radius: 12px;
    display: grid;
    place-items: center;
    color: var(--accent);
    background: color-mix(in srgb, var(--accent) 14%, transparent);
  }

  h1 {
    margin: 0;
    font-size: 18px;
    font-weight: 650;
  }

  p {
    margin: 0;
    color: var(--muted);
    line-height: 1.5;
  }

  .field {
    display: grid;
    gap: 6px;
    margin-top: 4px;
    font-size: 12px;
    color: var(--muted);
  }

  input {
    height: 36px;
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
  }

  .btn {
    height: 36px;
    margin-top: 4px;
    border: 1px solid var(--border);
    border-radius: 8px;
    background: transparent;
    color: inherit;
    font: inherit;
    cursor: pointer;
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
</style>
