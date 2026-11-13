// RSS and Atom to plain title, link, and published. No descriptions.

import { safeItemLink } from "./guard.js";

const TITLE_MAX = 300;

export function parseFeed(xml) {
  const text = String(xml || "").replace(/^\uFEFF/, "");
  const blocks = splitBlocks(text, "item").concat(splitBlocks(text, "entry"));
  const items = [];
  for (const block of blocks) {
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

export function splitBlocks(xml, local) {
  const open = new RegExp(`<(([\\w.-]+):)?${local}(\\s[^>]*)?>`, "gi");
  const blocks = [];
  let match;
  while ((match = open.exec(xml))) {
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

export function toIso(value) {
  const text = cleanText(value);
  if (!text) return null;
  const ms = Date.parse(text);
  if (!Number.isFinite(ms)) return null;
  return new Date(ms).toISOString();
}
