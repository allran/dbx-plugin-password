<script>
  import GroupNode from "./GroupNode.svelte";
  import Icon from "./Icon.svelte";

  /** @type {{
   *  node: any,
   *  selectedId: string,
   *  onToggle: (groupId: string) => void,
   *  onGroupMenu: (event: MouseEvent, groupId: string) => void,
   *  onSelectEntry: (entryId: string) => void,
   *  onEntryMenu: (event: MouseEvent, entryId: string) => void,
   * }} */
  let {
    node,
    selectedId = "",
    onToggle,
    onGroupMenu,
    onSelectEntry,
    onEntryMenu,
  } = $props();

  const indent = $derived(12 + node.depth * 10);
  const hasChildren = $derived(
    node.children.length > 0 || node.items.length > 0,
  );
</script>

<div class="group" aria-expanded={!node.collapsed}>
  <div class="group-row" style:padding-left="{indent}px">
    <button
      type="button"
      class="chevron"
      class:collapsed={node.collapsed}
      class:hidden={!hasChildren}
      aria-label="toggle"
      onclick={() => onToggle(node.group.id)}
    >
      ▾
    </button>
    <button
      type="button"
      class="group-name"
      onclick={() => onToggle(node.group.id)}
      oncontextmenu={(event) => onGroupMenu(event, node.group.id)}
    >
      <span class="group-label">{node.label}</span>
      {#if node.entryCount > 0}
        <span class="count">{node.entryCount}</span>
      {/if}
    </button>
  </div>

  {#if !node.collapsed}
    <div class="entries" role="group" style:padding-left="{indent + 28}px">
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

    {#each node.children as child (child.group.id)}
      <GroupNode
        node={child}
        {selectedId}
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

  .chevron.hidden {
    visibility: hidden;
    pointer-events: none;
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
    padding-right: 8px;
    padding-bottom: 4px;
    gap: 2px;
  }

  .entry {
    display: flex;
    align-items: center;
    gap: 6px;
    width: 100%;
    padding: 7px 10px;
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
