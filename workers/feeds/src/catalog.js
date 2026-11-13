import raw from "../../../assets/data/news-feeds.json" with { type: "json" };
import { feedAllowed, safeItemLink } from "./guard.js";

export const CATEGORIES = ["Security", "Advisories", "Linux/Tech", "Community"];

export function normalizeCatalog(data) {
  const list = Array.isArray(data) ? data : (data && data.feeds) || [];
  const seenKey = new Set();
  const seenUrl = new Set();
  const feeds = [];
  for (const row of list) {
    const key = String(row.key || "").trim().toLowerCase();
    const name = String(row.name || "").trim();
    const category = String(row.category || "").trim();
    const url = safeItemLink(row.url);
    if (!key || !name || !url) continue;
    if (!CATEGORIES.includes(category)) continue;
    if (!feedAllowed(key, url)) continue;
    if (seenKey.has(key) || seenUrl.has(url)) continue;
    seenKey.add(key);
    seenUrl.add(url);
    feeds.push({ key, name, url, category });
  }
  return feeds;
}

export const FEEDS = normalizeCatalog(raw);
