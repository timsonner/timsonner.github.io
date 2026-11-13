// Host and URL checks for the allowlisted feed fetcher.
// This Worker is not an open proxy: callers never choose the URL.

const BLOCKED_KEY = /crowdstrike/i;

export function safeItemLink(value) {
  if (value == null) return null;
  const trimmed = String(value).replace(/\s+/g, "").trim();
  if (!trimmed || trimmed.length > 2000) return null;
  let url;
  try {
    url = new URL(trimmed);
  } catch {
    return null;
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") return null;
  if (url.username || url.password) return null;
  if (isBlockedHost(url.hostname)) return null;
  return url.href;
}

export function isAllowedFeedUrl(value) {
  return safeItemLink(value) != null;
}

export function feedAllowed(key, url) {
  const name = String(key || "").trim().toLowerCase();
  if (!name || BLOCKED_KEY.test(name)) return false;
  return isAllowedFeedUrl(url);
}

export function isBlockedHost(hostname) {
  if (!hostname) return true;
  let host = String(hostname).trim().toLowerCase().replace(/\.$/, "");
  if (host.startsWith("[") && host.endsWith("]")) host = host.slice(1, -1);
  if (!host) return true;
  if (host === "localhost" || host.endsWith(".localhost")) return true;
  if (host.endsWith(".local") || host.endsWith(".internal")) return true;
  const blockedBrand = "crowdstrike";
  if (host === blockedBrand + ".com" || host.endsWith("." + blockedBrand + ".com") || host.includes(blockedBrand)) return true;
  if (host.includes(":")) return ipv6Blocked(host);
  if (ipv4Blocked(host)) return true;
  if (/^\d+$/.test(host)) return true;
  return false;
}

function ipv4Blocked(host) {
  const match = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
  if (!match) return false;
  const parts = match.slice(1).map(Number);
  if (parts.some((n) => n > 255)) return true;
  const a = parts[0];
  const b = parts[1];
  if (a === 0 || a === 10 || a === 127) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;
  if (a >= 224) return true;
  return false;
}

function ipv6Blocked(host) {
  const h = host.toLowerCase();
  if (h.startsWith("::ffff:")) {
    const mapped = h.slice("::ffff:".length);
    if (mapped.includes(".")) return ipv4Blocked(mapped) || mapped === ["0", "0", "0", "0"].join(".");
  }
  if (h === "::1" || h === "::") return true;
  if (h.startsWith("fc") || h.startsWith("fd")) return true;
  if (/^fe[89ab]/.test(h)) return true;
  return false;
}
