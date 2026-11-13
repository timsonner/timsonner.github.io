// RSS and Atom to plain title, link, and published. No descriptions.

import { safeItemLink } from "./guard.js";

const TITLE_MAX = 300;

export function parseFeed(xml, limit) {
  const text = String(xml || "").replace(/^\uFEFF/, "");
  const max = Number.isFinite(limit) ? limit : Infinity;
  const blocks = splitBlocks(text, "item", max).concat(splitBlocks(text, "entry", max));
  const items = [];
  for (const block of blocks) {
    if (items.length >= max) break;
    const title = cleanText(tagText(block, "title"));
    const link = pickLink(block);
    const published = toIso(
      tagText(block, "pubDate") ||
      tagText(block, "published") ||
      tagText(block, "updated") ||
      tagText(block, "date")
    );
    if (!title && !link) continue;
    items.push({
      title: title || "Untitled",
      link,
      published
    });
  }
  return items;
}

export function splitBlocks(xml, local, limit) {
  const max = Number.isFinite(limit) ? limit : Infinity;
  const open = new RegExp(`<(([\\w.-]+):)?${local}(\\s[^>]*)?>`, "gi");
  const blocks = [];
  let match;
  while (blocks.length < max && (match = open.exec(xml))) {
    const prefix = match[2] ? `${match[2]}:` : "";
    const closeToken = `</${prefix}${local}>`;
    const start = match.index + match[0].length;
    const end = xml.toLowerCase().indexOf(closeToken.toLowerCase(), start);
    if (end === -1) break;
    blocks.push(xml.slice(start, end));
    open.lastIndex = end + closeToken.length;
  }
  return blocks;
}

function tagText(block, local) {
  const open = new RegExp(`<(([\\w.-]+):)?${local}(\\s[^>]*)?>`, "i");
  const match = open.exec(block);
  if (!match) return "";
  const prefix = match[2] ? `${match[2]}:` : "";
  const start = match.index + match[0].length;
  const closeToken = `</${prefix}${local}>`;
  const end = block.toLowerCase().indexOf(closeToken.toLowerCase(), start);
  if (end === -1) return "";
  return block.slice(start, end);
}

function pickLink(block) {
  const candidates = [];
  const linkOpen = /<(([\w.-]+):)?link(\s[^>]*)?>([\s\S]*?)<\/(?:[\w.-]+:)?link>/gi;
  let match;
  while ((match = linkOpen.exec(block))) {
    const attrs = match[3] || "";
    const inner = match[4] || "";
    const href = attr(attrs, "href") || cleanText(inner);
    const rel = (attr(attrs, "rel") || "").toLowerCase();
    const type = (attr(attrs, "type") || "").toLowerCase();
    const url = safeItemLink(href);
    if (!url) continue;
    candidates.push({ url, rel, type });
  }
  const selfClosing = /<(([\w.-]+):)?link(\s[^>]*?)\/>/gi;
  while ((match = selfClosing.exec(block))) {
    const attrs = match[3] || "";
    const href = attr(attrs, "href");
    const rel = (attr(attrs, "rel") || "").toLowerCase();
    const type = (attr(attrs, "type") || "").toLowerCase();
    const url = safeItemLink(href);
    if (!url) continue;
    candidates.push({ url, rel, type });
  }
  if (!candidates.length) {
    const guid = /<guid([^>]*)>([\s\S]*?)<\/guid>/i.exec(block);
    if (guid && /ispermalink\s*=\s*["']true["']/i.test(guid[1] || "")) {
      const url = safeItemLink(cleanText(guid[2]));
      if (url) return url;
    }
    return null;
  }
  const rank = (c) => {
    if (c.rel === "replies" || c.rel === "self" || c.rel === "enclosure") return 3;
    if (c.rel === "alternate" || c.rel === "") {
      if (!c.type || c.type.includes("html")) return 0;
      return 1;
    }
    return 2;
  };
  candidates.sort((a, b) => rank(a) - rank(b));
  return candidates[0].url;
}

function attr(source, name) {
  const re = new RegExp(`${name}\\s*=\\s*("([^"]*)"|'([^']*)')`, "i");
  const match = re.exec(source);
  if (!match) return "";
  return decodeXml(match[2] != null ? match[2] : match[3]);
}

export function cleanText(value) {
  if (!value) return "";
  let text = String(value).replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, "$1");
  text = decodeXml(text);
  text = text.replace(/<[^>]+>/g, " ");
  text = text.replace(/\s+/g, " ").trim();
  if (text.length > TITLE_MAX) text = text.slice(0, TITLE_MAX).trim();
  return text;
}

export function decodeXml(value) {
  return String(value)
    .replace(/&#x([0-9a-f]+);/gi, (_, hex) => fromCode(parseInt(hex, 16)))
    .replace(/&#(\d+);/g, (_, num) => fromCode(parseInt(num, 10)))
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, "\"")
    .replace(/&apos;/g, "'")
    .replace(/&amp;/g, "&");
}

function fromCode(code) {
  if (!Number.isFinite(code) || code < 0 || code > 0x10ffff) return "";
  try {
    return String.fromCodePoint(code);
  } catch {
    return "";
  }
}

const META_CAP = 8192;
const TAG_TAIL = 64;
const OPEN_TAG = /<((?:[\w.-]+:)?)(item|entry)(?=[\s>])/i;

// Pull up to `limit` items without keeping the rest of a feed body.
// Title, link, and date are taken from the start of each item.
export function createItemScanner(limit) {
  const max = Number.isFinite(limit) && limit > 0 ? limit : 0;
  let pending = "";
  let inItem = false;
  let meta = "";
  let closeNeedle = "";
  const items = [];
  let done = max === 0;

  function pump() {
    while (!done) {
      if (!inItem) {
        const open = findOpen(pending);
        if (!open) {
          if (pending.length > TAG_TAIL) pending = pending.slice(-TAG_TAIL);
          return;
        }
        if (open.partial) {
          if (open.index > 0) pending = pending.slice(open.index);
          return;
        }
        pending = pending.slice(open.after);
        inItem = true;
        meta = "";
        closeNeedle = open.close;
        continue;
      }
      const closeAt = pending.toLowerCase().indexOf(closeNeedle);
      if (closeAt === -1) {
        const room = META_CAP - meta.length;
        if (room > 0) {
          meta += pending.slice(0, room);
          pending = pending.slice(room);
        }
        if (pending.length > TAG_TAIL) pending = pending.slice(-TAG_TAIL);
        return;
      }
      const room = META_CAP - meta.length;
      const head = meta + (room > 0 ? pending.slice(0, Math.min(closeAt, room)) : "");
      const parsed = parseFeed("<item>" + head + "</item>", 1);
      if (parsed[0]) items.push(parsed[0]);
      pending = pending.slice(closeAt + closeNeedle.length);
      inItem = false;
      meta = "";
      closeNeedle = "";
      if (items.length >= max) {
        done = true;
        pending = "";
      }
    }
  }

  return {
    push(chunk) {
      if (done || !chunk) return;
      pending += chunk;
      pump();
    },
    finish() {
      return items;
    },
    abort() {
      if (!done && inItem && meta) {
        const parsed = parseFeed("<item>" + meta + "</item>", 1);
        if (parsed[0]) items.push(parsed[0]);
      }
      done = true;
      pending = "";
      inItem = false;
      meta = "";
      return items;
    },
    get done() {
      return done;
    }
  };
}

function findOpen(text) {
  const match = OPEN_TAG.exec(text);
  if (!match) return null;
  const end = text.indexOf(">", match.index);
  if (end === -1) return { partial: true, index: match.index };
  return {
    partial: false,
    after: end + 1,
    close: "</" + match[1].toLowerCase() + match[2].toLowerCase() + ">"
  };
}

export function toIso(value) {
  const text = cleanText(value);
  if (!text) return null;
  const ms = Date.parse(text);
  if (!Number.isFinite(ms)) return null;
  return new Date(ms).toISOString();
}
