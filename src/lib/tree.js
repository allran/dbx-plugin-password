import { DEFAULT_GROUP_ID, displayGroupName } from "./i18n.js";

/**
 * @param {any[]} groups
 * @param {any[]} entries
 * @param {Record<string, boolean>} collapsed
 * @param {string} needle lowercase search
 * @param {string} locale
 * @param {Record<string, any>} text
 */
export function buildGroupTree(groups, entries, collapsed, needle, locale, text) {
  const byParent = new Map();
  for (const group of groups) {
    const parentId = normalizeParentId(group.parentId, group.id, groups);
    if (!byParent.has(parentId)) byParent.set(parentId, []);
    byParent.get(parentId).push(group);
  }

  for (const list of byParent.values()) {
    list.sort((a, b) => {
      if (a.id === DEFAULT_GROUP_ID) return -1;
      if (b.id === DEFAULT_GROUP_ID) return 1;
      return String(a.name || "").localeCompare(String(b.name || ""), locale);
    });
  }

  const entriesByGroup = new Map();
  for (const entry of entries) {
    const gid = entry.groupId || DEFAULT_GROUP_ID;
    if (!entriesByGroup.has(gid)) entriesByGroup.set(gid, []);
    entriesByGroup.get(gid).push(entry);
  }
  for (const list of entriesByGroup.values()) {
    list.sort((a, b) =>
      String(a.title || "").localeCompare(String(b.title || ""), locale),
    );
  }

  function buildNodes(parentId, depth) {
    const children = byParent.get(parentId) || [];
    /** @type {any[]} */
    const nodes = [];
    for (const group of children) {
      const items = entriesByGroup.get(group.id) || [];
      const childNodes = buildNodes(group.id, depth + 1);
      const selfMatch = !needle || items.length > 0;
      const childVisible = childNodes.filter((n) => n.visible);
      const visible = !needle || selfMatch || childVisible.length > 0;
      if (!visible) continue;
      nodes.push({
        group,
        label: displayGroupName(group, text),
        items,
        children: needle ? childVisible : childNodes,
        // While searching, force-expand so matches under collapsed parents stay visible.
        collapsed: needle ? false : Boolean(collapsed[group.id]),
        depth,
        visible: true,
        entryCount: items.length,
      });
    }
    return nodes;
  }

  return buildNodes("", 0);
}

/**
 * Flat options for <select>, with indentation prefixes.
 * @param {any[]} groups
 * @param {string} locale
 * @param {Record<string, any>} text
 */
export function flattenGroupOptions(groups, locale, text) {
  const byParent = new Map();
  for (const group of groups) {
    const parentId = normalizeParentId(group.parentId, group.id, groups);
    if (!byParent.has(parentId)) byParent.set(parentId, []);
    byParent.get(parentId).push(group);
  }
  for (const list of byParent.values()) {
    list.sort((a, b) => {
      if (a.id === DEFAULT_GROUP_ID) return -1;
      if (b.id === DEFAULT_GROUP_ID) return 1;
      return String(a.name || "").localeCompare(String(b.name || ""), locale);
    });
  }

  /** @type {{ id: string, label: string }[]} */
  const options = [];
  function walk(parentId, depth) {
    for (const group of byParent.get(parentId) || []) {
      const name = displayGroupName(group, text);
      const pad = depth > 0 ? `${"— ".repeat(depth)}` : "";
      options.push({ id: group.id, label: `${pad}${name}` });
      walk(group.id, depth + 1);
    }
  }
  walk("", 0);
  return options;
}

/**
 * @param {unknown} parentId
 * @param {string} groupId
 * @param {any[]} groups
 */
function normalizeParentId(parentId, groupId, groups) {
  if (groupId === DEFAULT_GROUP_ID) return "";
  const raw = String(parentId || "").trim();
  if (!raw || raw === groupId) return "";
  if (!groups.some((g) => g.id === raw)) return "";
  return raw;
}
