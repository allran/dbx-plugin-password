<script>
  /** @type {{
   *  open: boolean,
   *  x: number,
   *  y: number,
   *  items: Array<{ id: string, label: string, danger?: boolean, disabled?: boolean }>,
   *  onselect: (id: string) => void,
   *  onclose: () => void,
   * }} */
  let { open = false, x = 0, y = 0, items = [], onselect, onclose } = $props();

  function onWindow(event) {
    if (!open) return;
    if (event.type === "keydown" && event.key !== "Escape") return;
    onclose?.();
  }
</script>

<svelte:window onclick={onWindow} onkeydown={onWindow} oncontextmenu={onWindow} />

{#if open}
  <div
    class="menu"
    style:left="{x}px"
    style:top="{y}px"
    role="menu"
    tabindex="-1"
    onkeydown={(e) => e.stopPropagation()}
    onclick={(e) => e.stopPropagation()}
  >
    {#each items as item (item.id)}
      <button
        type="button"
        class="item"
        class:danger={item.danger}
        class:disabled={item.disabled}
        role="menuitem"
        disabled={item.disabled}
        onclick={() => {
          if (item.disabled) return;
          onselect?.(item.id);
          onclose?.();
        }}
      >
        {item.label}
      </button>
    {/each}
  </div>
{/if}

<style>
  .menu {
    position: fixed;
    z-index: 950;
    min-width: 160px;
    padding: 4px;
    border: 1px solid var(--border);
    border-radius: 8px;
    background: var(--bg);
    box-shadow: 0 10px 28px color-mix(in srgb, #000 18%, transparent);
  }

  .item {
    display: block;
    width: 100%;
    text-align: left;
    height: 30px;
    padding: 0 10px;
    border: 0;
    border-radius: 6px;
    background: transparent;
    color: inherit;
    font: inherit;
    cursor: pointer;
  }

  .item:hover:not(:disabled) {
    background: var(--hover);
  }

  .item.danger {
    color: var(--danger);
  }

  .item.disabled,
  .item:disabled {
    opacity: 0.45;
    cursor: not-allowed;
  }
</style>
