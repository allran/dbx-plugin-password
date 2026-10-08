<script>
  /** @type {{ message: string, visible: boolean }} */
  let { message = "", visible = false } = $props();
</script>

{#if visible && message}
  <div class="toast" role="status">{message}</div>
{/if}

<style>
  .toast {
    position: fixed;
    left: 50%;
    bottom: 24px;
    transform: translateX(-50%);
    z-index: 1000;
    padding: 8px 14px;
    border-radius: 999px;
    background: color-mix(in srgb, var(--fg) 88%, transparent);
    color: var(--bg);
    font-size: 12px;
    pointer-events: none;
    box-shadow: 0 8px 24px color-mix(in srgb, #000 18%, transparent);
  }
</style>
