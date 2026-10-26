<script>
  import GroupNode from "./GroupNode.svelte";
  import Icon from "./Icon.svelte";

  /** @type {{
   *  node: any,
   *  selectedId: string,
   *  text: Record<string, any>,
   *  onToggle: (groupId: string) => void,
   *  onGroupMenu: (event: MouseEvent, groupId: string) => void,
   *  onSelectEntry: (entryId: string) => void,
   *  onEntryMenu: (event: MouseEvent, entryId: string) => void,
   * }} */
  let {
    node,
    selectedId = "",
    text,
    onToggle,
    onGroupMenu,
    onSelectEntry,
    onEntryMenu,
  } = $props();

  // Depth 0 aligns with search icon (tree padding-left: 22px).
  const indent = $derived(node.depth * 12);
  const hasChildren = $derived(
    node.children.length > 0 || node.items.length > 0,
  );

  function toggle() {
    if (!hasChildren) return;
    onToggle(node.group.id);
  }
</script>

<div class="group" aria-expanded={hasChildren ? !node.collapsed : undefined}>
  <div class="group-row" style:padding-left="{indent}px">
    <button
      type="button"
      class="group-name"
      onclick={toggle}
      oncontextmenu={(event) => onGroupMenu(event, node.group.id)}
    >
      <span class="group-label">{node.label}</span>
    </button>
    {#if hasChildren}
      <button
        type="button"
        class="chevron"
        class:collapsed={node.collapsed}
        aria-label={text.toggleGroup}
        title={text.toggleGroup}
        onclick={toggle}
      >
        ▾
      </button>
    {/if}
    {#if node.entryCount > 0}
      <span class="count">{node.entryCount}</span>
    {/if}
  </div>

  {#if hasChildren && !node.collapsed}
    {#if node.items.length > 0}
      <div class="entries" role="group" style:padding-left="{indent}px">
        {#each node.items as entry (entry.id)}
          <button
            type="button"
            class="entry"
            class:active={selectedId === entry.id}
            onclick={() => onSelectEntry(entry.id)}
            oncontextmenu={(event) => onEntryMenu(event, entry.id)}
          >
            <span class="entry-icon" aria-hidden="true">
              <Icon name="lock" size={13} />
            </span>
            <span class="entry-title">{entry.title || "—"}</span>
          </button>
        {/each}
      </div>
    {/if}

    {#each node.children as child (child.group.id)}
      <GroupNode
        node={child}
        {selectedId}
        {text}
        {onToggle}
        {onGroupMenu}
        {onSelectEntry}
        {onEntryMenu}
      />
    {/each}
  {/if}
</div>

<style>
  .group {
    margin-bottom: 2px;
  }

  .group-row {
    display: flex;
    align-items: center;
    gap: 2px;
    padding-right: 8px;
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

  .group-name {
    min-width: 0;
    display: flex;
    align-items: center;
    height: 28px;
    padding: 0 2px 0 0;
    border-radius: 6px;
    font-weight: 600;
  }

  .group-label {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .count {
    margin-left: auto;
    color: var(--muted);
    font-weight: 500;
    font-size: 11px;
    flex-shrink: 0;
    padding-left: 8px;
  }

  .chevron {
    width: 22px;
    height: 28px;
    display: grid;
    place-items: center;
    border-radius: 4px;
    color: var(--muted);
    font-size: 14px;
    line-height: 1;
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

  .entries {
    display: flex;
    flex-direction: column;
    padding-bottom: 4px;
    gap: 2px;
  }

  .entry {
    display: flex;
    align-items: center;
    gap: 6px;
    width: 100%;
    padding: 7px 8px 7px 0;
    border-radius: 8px;
    text-align: left;
  }

  .entry.active {
    background: color-mix(in srgb, var(--accent) 16%, transparent);
  }

  .entry-title {
    flex: 1;
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .entry-icon {
    flex-shrink: 0;
    color: var(--muted);
    display: grid;
    place-items: center;
  }
</style>
