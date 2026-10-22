<script>
  /** @type {{ name: string, size?: number }} */
  let { name, size = 16 } = $props();
</script>

<svg
  class="icon-svg"
  viewBox="0 0 24 24"
  width={size}
  height={size}
  aria-hidden="true"
  fill="none"
  stroke="currentColor"
  stroke-width="2"
  stroke-linecap="round"
  stroke-linejoin="round"
>
  {#if name === "key"}
    <circle cx="8" cy="15" r="4" />
    <path d="M12 15h9" />
    <path d="M18 12v6" />
    <path d="M21 12v6" />
  {:else if name === "lock"}
    <rect x="5" y="11" width="14" height="10" rx="2" />
    <path d="M8 11V8a4 4 0 0 1 8 0v3" />
  {:else if name === "folder-plus"}
    <path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V7z" />
    <path d="M12 11v6" />
    <path d="M9 14h6" />
  {:else if name === "search"}
    <circle cx="11" cy="11" r="7" />
    <path d="M20 20l-3.5-3.5" />
  {:else if name === "copy"}
    <rect x="9" y="9" width="11" height="11" rx="2" />
    <path d="M5 15V5a2 2 0 0 1 2-2h10" />
  {:else if name === "eye"}
    <path d="M2 12s4-7 10-7 10 7 10 7-4 7-10 7S2 12 2 12z" />
    <circle cx="12" cy="12" r="3" />
  {:else if name === "eye-off"}
    <path d="M3 3l18 18" />
    <path d="M10.6 10.6a3 3 0 0 0 4.2 4.2" />
    <path d="M9.9 5.1A10.9 10.9 0 0 1 12 5c6 0 10 7 10 7a18.5 18.5 0 0 1-2.2 3.1" />
    <path d="M6.1 6.1C3.9 7.7 2 12 2 12s4 7 10 7a10.5 10.5 0 0 0 4.3-.9" />
  {:else if name === "edit"}
    <path d="M12 20h9" />
    <path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L8 18l-4 1 1-4 11.5-11.5z" />
  {:else if name === "dice"}
    <rect x="3" y="3" width="18" height="18" rx="2" />
    <circle cx="8" cy="8" r="1.25" fill="currentColor" stroke="none" />
    <circle cx="16" cy="8" r="1.25" fill="currentColor" stroke="none" />
    <circle cx="12" cy="12" r="1.25" fill="currentColor" stroke="none" />
    <circle cx="8" cy="16" r="1.25" fill="currentColor" stroke="none" />
    <circle cx="16" cy="16" r="1.25" fill="currentColor" stroke="none" />
  {:else if name === "save"}
    <path d="M5 3h11l3 3v15a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2z" />
    <path d="M8 3v6h8V3" />
    <path d="M8 17h8" />
  {:else if name === "x"}
    <path d="M6 6l12 12" />
    <path d="M18 6L6 18" />
  {:else if name === "trash"}
    <path d="M4 7h16" />
    <path d="M9 7V5a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2" />
    <path d="M7 7l1 13a2 2 0 0 0 2 2h4a2 2 0 0 0 2-2l1-13" />
    <path d="M10 11v7" />
    <path d="M14 11v7" />
  {/if}
</svg>

<style>
  .icon-svg {
    display: block;
    flex-shrink: 0;
  }
</style>
