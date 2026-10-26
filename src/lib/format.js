export function formatDateTime(ms, locale = "en") {
  const value = Number(ms);
  if (!Number.isFinite(value) || value <= 0) return "—";
  try {
    return new Intl.DateTimeFormat(locale.startsWith("zh") ? "zh-CN" : "en", {
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
    }).format(new Date(value));
  } catch {
    return new Date(value).toLocaleString();
  }
}

const LOWER = "abcdefghijklmnopqrstuvwxyz";
const UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS = "0123456789";
const SYMBOLS = "!@#$%^&*()-_=+[]{}?,.";

/** Uniform int in [0, max) without modulo bias. */
function randomInt(max) {
  if (max <= 0) return 0;
  const limit = Math.floor(0x100000000 / max) * max;
  const buffer = new Uint32Array(1);
  for (;;) {
    crypto.getRandomValues(buffer);
    if (buffer[0] < limit) return buffer[0] % max;
  }
}

function pick(charset) {
  return charset[randomInt(charset.length)];
}

/** Generate a strong random password (default 20 chars, mixed classes). */
export function generateRandomPassword(length = 20) {
  const size = Math.max(12, Math.min(64, Number(length) || 20));
  const pools = [LOWER, UPPER, DIGITS, SYMBOLS];
  const all = pools.join("");
  const chars = pools.map((pool) => pick(pool));
  while (chars.length < size) {
    chars.push(pick(all));
  }
  for (let i = chars.length - 1; i > 0; i -= 1) {
    const j = randomInt(i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }
  return chars.join("");
}

export async function copyText(value) {
  const text = String(value ?? "");
  if (!text) return false;
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    const area = document.createElement("textarea");
    area.value = text;
    area.setAttribute("readonly", "");
    area.style.position = "fixed";
    area.style.left = "-9999px";
    document.body.appendChild(area);
    area.select();
    const ok = document.execCommand("copy");
    document.body.removeChild(area);
    return ok;
  }
}

/** Best-effort clear; only clears if clipboard still matches `expected`. */
export async function clearClipboardIfMatches(expected) {
  const target = String(expected ?? "");
  if (!target || !navigator.clipboard?.readText) return false;
  try {
    const current = await navigator.clipboard.readText();
    if (current !== target) return false;
    await navigator.clipboard.writeText("");
    return true;
  } catch {
    return false;
  }
}

/** Rough entry-password strength: weak | fair | strong */
export function passwordStrength(value) {
  const s = String(value ?? "");
  if (!s) return "";
  let score = 0;
  if (s.length >= 8) score += 1;
  if (s.length >= 12) score += 1;
  if (/[a-z]/.test(s) && /[A-Z]/.test(s)) score += 1;
  if (/\d/.test(s)) score += 1;
  if (/[^A-Za-z0-9]/.test(s)) score += 1;
  if (score <= 2) return "weak";
  if (score <= 3) return "fair";
  return "strong";
}
