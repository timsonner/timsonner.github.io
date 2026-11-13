(function () {
  var REFRESH_MS = 15 * 60 * 1000;
  var STORAGE_KEY = "timsonner-news-view";
  var CATEGORIES = ["Security", "Advisories", "Linux/Tech", "Community"];

  var root = document.getElementById("news-root");
  if (!root) return;

  var sourcesEl = document.getElementById("news-sources");
  var listEl = document.getElementById("news-list");
  var bannerEl = document.getElementById("news-banner");
  var problemsEl = document.getElementById("news-problems");
  var updatedEl = document.getElementById("news-updated");
  var perEl = document.getElementById("news-per");
  var rangeEl = document.getElementById("news-range");
  var fromEl = document.getElementById("news-from");
  var toEl = document.getElementById("news-to");
  var searchEl = document.getElementById("news-search");
  var refreshEl = document.getElementById("news-refresh");
  var chips = Array.prototype.slice.call(document.querySelectorAll("[data-chip]"));

  var FETCH_CONCURRENCY = 4;
  var catalog = [];
  var state = null;
  var payload = null;
  var held = {};
  var apiError = null;
  var loading = false;
  var lastFetchAt = 0;
  var timer = 0;
  var loadGeneration = 0;

  document.getElementById("news-toolbar").addEventListener("submit", function (event) {
    event.preventDefault();
  });

  fetch(root.getAttribute("data-catalog"), { headers: { Accept: "application/json" } })
    .then(function (response) {
      if (!response.ok) throw new Error("catalog");
      return response.json();
    })
    .then(function (data) {
      var rows = data && Array.isArray(data.feeds) ? data.feeds : [];
      catalog = rows.filter(function (row) {
        return row && row.key && !/crowdstrike/i.test(row.key) && !/crowdstrike/i.test(row.url || "");
      });
      state = loadState();
      applyControls();
      renderSources();
      wire();
      loadItems();
    })
    .catch(function () {
      setBanner("The feed catalog did not load.", true);
    });

  function knownKeys() {
    var keys = {};
    catalog.forEach(function (row) { keys[String(row.key).toLowerCase()] = true; });
    return keys;
  }

  function defaultSources() {
    return catalog.filter(function (row) {
      return row.category === "Security" || row.category === "Advisories";
    }).map(function (row) { return row.key; });
  }

  function sanitize(input) {
    var known = knownKeys();
    var sources = [];
    var raw = Array.isArray(input.sources) ? input.sources : String(input.sources || "").split(",");
    raw.forEach(function (key) {
      var name = String(key || "").trim().toLowerCase();
      if (!name || !known[name] || /crowdstrike/i.test(name)) return;
      if (sources.indexOf(name) === -1) sources.push(name);
    });
    var per = parseInt(input.per, 10);
    if (!isFinite(per) || per < 1) per = 5;
    if (per > 50) per = 50;
    var range = input.range;
    if (["24h", "48h", "7d", "all", "custom"].indexOf(range) === -1) range = "48h";
    var from = /^\d{4}-\d{2}-\d{2}$/.test(input.from || "") ? input.from : "";
    var to = /^\d{4}-\d{2}-\d{2}$/.test(input.to || "") ? input.to : "";
    if (from || to) range = "custom";
    return { sources: sources, per: per, range: range, from: from, to: to };
  }

  function loadState() {
    var params = new URLSearchParams(window.location.search);
    var queryKeys = ["sources", "per", "range", "from", "to"];
    var hasQuery = queryKeys.some(function (key) { return params.has(key); });
    if (hasQuery) {
      var base = { sources: defaultSources(), per: 5, range: "48h", from: "", to: "" };
      return sanitize({
        sources: params.has("sources") ? params.get("sources") : base.sources,
        per: params.has("per") ? params.get("per") : base.per,
        range: params.has("range") ? params.get("range") : base.range,
        from: params.get("from") || "",
        to: params.get("to") || ""
      });
    }
    try {
      var saved = JSON.parse(localStorage.getItem(STORAGE_KEY) || "null");
      if (saved && typeof saved === "object") return sanitize(saved);
    } catch (err) { /* ignore broken storage */ }
    return sanitize({ sources: defaultSources(), per: 5, range: "48h", from: "", to: "" });
  }

  function persist() {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
    } catch (err) { /* storage may be blocked */ }
    var params = new URLSearchParams();
    params.set("sources", state.sources.join(","));
    params.set("per", String(state.per));
    params.set("range", state.range);
    if (state.from) params.set("from", state.from);
    if (state.to) params.set("to", state.to);
    var next = window.location.pathname + "?" + params.toString();
    window.history.replaceState(null, "", next);
  }

  function applyControls() {
    perEl.value = String(state.per);
    rangeEl.value = state.range;
    fromEl.value = state.from;
    toEl.value = state.to;
    syncChips();
  }

  function keysIn(category) {
    return catalog.filter(function (row) { return row.category === category; }).map(function (row) { return row.key; });
  }

  function hasAll(keys) {
    if (!keys.length) return false;
    return keys.every(function (key) { return state.sources.indexOf(key) !== -1; });
  }

  function syncChips() {
    var allKeys = catalog.map(function (row) { return row.key; });
    var fullCategories = CATEGORIES.filter(function (category) { return hasAll(keysIn(category)); });
    var onlyFull = state.sources.length > 0 && state.sources.every(function (key) {
      var row = catalog.find(function (item) { return item.key === key; });
      return row && fullCategories.indexOf(row.category) !== -1;
    });
    chips.forEach(function (button) {
      var chip = button.getAttribute("data-chip");
      var pressed = false;
      if (chip === "all") pressed = hasAll(allKeys);
      else if (chip === "custom") pressed = !onlyFull;
      else pressed = hasAll(keysIn(chip));
      button.setAttribute("aria-pressed", pressed ? "true" : "false");
    });
  }

  function renderSources() {
    var query = searchEl.value.trim().toLowerCase();
    sourcesEl.replaceChildren();
    CATEGORIES.forEach(function (category) {
      var rows = catalog.filter(function (row) { return row.category === category; });
      rows.sort(function (a, b) { return a.name.localeCompare(b.name); });
      var visible = 0;
      var group = document.createElement("fieldset");
      group.className = "news-group";
      var legend = document.createElement("legend");
      legend.textContent = category;
      group.appendChild(legend);
      rows.forEach(function (row) {
        if (query && !sourceMatches(row, query)) return;
        visible += 1;
        var label = document.createElement("label");
        label.className = "news-source-label";
        var box = document.createElement("input");
        box.type = "checkbox";
        box.value = row.key;
        box.checked = state.sources.indexOf(row.key) !== -1;
        box.addEventListener("change", function () {
          if (box.checked) {
            if (state.sources.indexOf(row.key) === -1) state.sources.push(row.key);
          } else {
            state.sources = state.sources.filter(function (key) { return key !== row.key; });
          }
          syncChips();
          persist();
          loadItems(false);
        });
        label.appendChild(box);
        label.appendChild(document.createTextNode(row.name));
        group.appendChild(label);
      });
      if (visible) sourcesEl.appendChild(group);
    });
    if (query && !sourcesEl.childElementCount) {
      var none = document.createElement("p");
      none.className = "news-empty";
      none.textContent = "No sources match.";
      sourcesEl.appendChild(none);
    }
  }

  function sourceMatches(row, query) {
    var name = String(row.name || "").toLowerCase();
    var key = String(row.key || "").toLowerCase();
    return name.indexOf(query) !== -1 || key.indexOf(query) !== -1;
  }

  function wire() {
    chips.forEach(function (button) {
      button.addEventListener("click", function () {
        var chip = button.getAttribute("data-chip");
        if (chip === "custom") {
          searchEl.focus();
          return;
        }
        if (chip === "all") {
          state.sources = catalog.map(function (row) { return row.key; });
        } else {
          var keys = keysIn(chip);
          if (hasAll(keys)) {
            var drop = {};
            keys.forEach(function (key) { drop[key] = true; });
            state.sources = state.sources.filter(function (key) { return !drop[key]; });
          } else {
            keys.forEach(function (key) {
              if (state.sources.indexOf(key) === -1) state.sources.push(key);
            });
          }
        }
        syncChips();
        renderSources();
        persist();
        loadItems(false);
      });
    });

    perEl.addEventListener("change", function () {
      state.per = sanitize({ sources: state.sources, per: perEl.value, range: state.range, from: state.from, to: state.to }).per;
      perEl.value = String(state.per);
      persist();
      loadItems(false);
    });

    rangeEl.addEventListener("change", function () {
      state.range = rangeEl.value;
      if (state.range !== "custom") {
        state.from = "";
        state.to = "";
        fromEl.value = "";
        toEl.value = "";
      }
      persist();
      renderList();
    });

    function onDate() {
      state.from = fromEl.value || "";
      state.to = toEl.value || "";
      state.range = "custom";
      rangeEl.value = "custom";
      persist();
      renderList();
    }
    fromEl.addEventListener("change", onDate);
    toEl.addEventListener("change", onDate);

    searchEl.addEventListener("input", renderSources);
    refreshEl.addEventListener("click", function () { loadItems(true); });
    document.addEventListener("visibilitychange", onVisibility);
  }

  function onVisibility() {
    if (document.hidden) {
      window.clearTimeout(timer);
      return;
    }
    if (lastFetchAt && Date.now() - lastFetchAt >= REFRESH_MS) loadItems(true);
    else arm();
  }

  function arm() {
    window.clearTimeout(timer);
    if (document.hidden) return;
    var elapsed = lastFetchAt ? Date.now() - lastFetchAt : REFRESH_MS;
    var wait = Math.max(1000, REFRESH_MS - elapsed);
    timer = window.setTimeout(function () { loadItems(true); }, wait);
  }

  function loadItems(force) {
    var generation = ++loadGeneration;
    var keys = state.sources.filter(function (key) { return !/crowdstrike/i.test(key); });
    var per = state.per;
    var needed = keys.filter(function (key) {
      var row = held[key];
      return force || !row || row.per < per;
    });
    if (!needed.length) {
      loading = false;
      refreshEl.disabled = false;
      apiError = null;
      publish(generation);
      if (!lastFetchAt) lastFetchAt = Date.now();
      arm();
      return;
    }
    loading = true;
    refreshEl.disabled = true;
    publish(generation);
    var api = String(root.getAttribute("data-api") || "").replace(/\/$/, "");
    var cursor = 0;
    var active = 0;
    var finished = 0;
    var networkErrors = 0;

    function pump() {
      if (generation !== loadGeneration) return;
      while (active < FETCH_CONCURRENCY && cursor < needed.length) {
        active += 1;
        (function (key) {
          fetchSource(api, key, per).then(function (result) {
          if (generation !== loadGeneration) return;
          active -= 1;
          finished += 1;
          if (result.network) {
            networkErrors += 1;
            if (!held[key]) held[key] = { status: "unavailable", items: [], fetched_at: null, per: per };
          } else {
            held[key] = result.row;
          }
          var complete = finished === needed.length;
          if (complete) {
            loading = false;
            refreshEl.disabled = false;
            var anyItems = keys.some(function (name) { return held[name] && held[name].items && held[name].items.length; });
            apiError = networkErrors === needed.length ? (anyItems ? "refresh" : "down") : null;
            lastFetchAt = Date.now();
          }
          publish(generation);
          if (complete) arm();
          else pump();
          });
        })(needed[cursor]);
        cursor += 1;
      }
    }
    pump();
  }

  function fetchSource(api, key, per) {
    var url = api + "/items?sources=" + encodeURIComponent(key) + "&per=" + encodeURIComponent(String(per));
    return fetch(url, { headers: { Accept: "application/json" }, cache: "no-store" })
      .then(function (response) {
        if (!response.ok) throw new Error("status");
        return response.json();
      })
      .then(function (data) {
        var status = "unavailable";
        var items = [];
        var fetched = data && data.fetched_at ? data.fetched_at : null;
        if (data && Array.isArray(data.sources)) {
          data.sources.forEach(function (source) {
            if (source && source.key === key && source.status) status = source.status;
          });
        }
        if (data && Array.isArray(data.items)) {
          items = data.items.filter(function (item) { return item && item.source === key; });
        }
        return { network: false, row: { status: status, items: items, fetched_at: fetched, per: per } };
      })
      .catch(function () {
        return { network: true };
      });
  }

  function publish(generation) {
    if (generation !== loadGeneration) return;
    var items = [];
    var sources = [];
    var fetchedAt = null;
    state.sources.forEach(function (key) {
      var row = held[key];
      if (!row) {
        sources.push({ key: key, status: "unknown" });
        return;
      }
      sources.push({ key: key, status: row.status || "unknown" });
      if (row.fetched_at && (!fetchedAt || row.fetched_at > fetchedAt)) fetchedAt = row.fetched_at;
      (row.items || []).forEach(function (item) { items.push(item); });
    });
    items.sort(function (a, b) {
      var am = a && a.published ? Date.parse(a.published) : NaN;
      var bm = b && b.published ? Date.parse(b.published) : NaN;
      if (!isFinite(am) && !isFinite(bm)) return 0;
      if (!isFinite(am)) return 1;
      if (!isFinite(bm)) return -1;
      return bm - am;
    });
    payload = { fetched_at: fetchedAt, sources: sources, items: items };
    renderList();
  }

  function safeHref(value) {
    try {
      var url = new URL(String(value || ""), window.location.href);
      if (url.protocol !== "http:" && url.protocol !== "https:") return "";
      if (url.username || url.password) return "";
      return url.href;
    } catch (err) {
      return "";
    }
  }

  function formatDenver(iso) {
    var date = new Date(iso);
    if (!isFinite(date.getTime())) return "";
    var formatted = new Intl.DateTimeFormat("en-US", {
      timeZone: "America/Denver",
      month: "short",
      day: "numeric",
      year: "numeric",
      hour: "numeric",
      minute: "2-digit"
    }).format(date);
    var zone = "";
    new Intl.DateTimeFormat("en-US", {
      timeZone: "America/Denver",
      timeZoneName: "short"
    }).formatToParts(date).forEach(function (part) {
      if (part.type === "timeZoneName") zone = part.value;
    });
    return zone ? formatted + " " + zone : formatted;
  }

  function denverMidnight(ymd) {
    var guess = Date.parse(ymd + "T00:00:00Z");
    var parts = {};
    new Intl.DateTimeFormat("en-US", {
      timeZone: "America/Denver",
      hourCycle: "h23",
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit"
    }).formatToParts(new Date(guess)).forEach(function (part) {
      parts[part.type] = part.value;
    });
    var asUtc = Date.UTC(
      Number(parts.year),
      Number(parts.month) - 1,
      Number(parts.day),
      Number(parts.hour),
      Number(parts.minute),
      Number(parts.second)
    );
    return guess - (asUtc - guess);
  }

  function nextYmd(ymd) {
    var bits = ymd.split("-").map(Number);
    var date = new Date(Date.UTC(bits[0], bits[1] - 1, bits[2]));
    date.setUTCDate(date.getUTCDate() + 1);
    return date.toISOString().slice(0, 10);
  }

  function inWindow(item) {
    var published = item.published ? Date.parse(item.published) : NaN;
    var from = state.from;
    var to = state.to;
    if (from && to && from > to) {
      var swap = from;
      from = to;
      to = swap;
    }
    if (state.range === "custom" || from || to) {
      if (!isFinite(published)) return false;
      if (from && published < denverMidnight(from)) return false;
      if (to && published >= denverMidnight(nextYmd(to))) return false;
      return true;
    }
    if (state.range === "all") return true;
    if (!isFinite(published)) return false;
    var spans = { "24h": 86400000, "48h": 172800000, "7d": 604800000 };
    var span = spans[state.range] || spans["48h"];
    return Date.now() - published <= span;
  }

  function nameFor(key) {
    var row = catalog.find(function (item) { return item.key === key; });
    return row ? row.name : key;
  }

  function setBanner(text, isError) {
    bannerEl.textContent = text;
    bannerEl.className = isError ? "news-banner is-error" : "news-banner";
  }

  function renderList() {
    problemsEl.replaceChildren();
    listEl.replaceChildren();
    if (!payload) {
      if (loading) setBanner("Loading headlines.", false);
      else if (apiError === "down") {
        setBanner("The feeds API is not reachable yet. Headlines show up here after the feeds Worker is deployed.", true);
      }
      updatedEl.textContent = "Links open in a new tab.";
      return;
    }

    var selected = {};
    state.sources.forEach(function (key) { selected[key] = true; });
    var counts = {};
    var rows = [];
    payload.items.forEach(function (item) {
      if (!item || !selected[item.source]) return;
      if (/crowdstrike/i.test(item.source || "")) return;
      if (!inWindow(item)) return;
      counts[item.source] = counts[item.source] || 0;
      if (counts[item.source] >= state.per) return;
      counts[item.source] += 1;
      rows.push(item);
    });

    var statuses = {};
    (payload.sources || []).forEach(function (source) {
      if (source && source.key) statuses[source.key] = source.status || "unknown";
    });
    state.sources.forEach(function (key) {
      var status = statuses[key] || "unknown";
      if (status !== "stale" && status !== "unavailable" && status !== "pending") return;
      var li = document.createElement("li");
      var label = status === "stale" ? "stale, showing last good items" : (status === "pending" ? "not loaded yet" : "unavailable");
      li.textContent = nameFor(key) + ": " + label;
      problemsEl.appendChild(li);
    });

    if (loading) {
      setBanner("Loading headlines.", false);
    } else if (apiError === "refresh") {
      setBanner("Refresh failed. Showing the last headlines loaded in this tab.", true);
    } else if (payload.fetched_at) {
      setBanner("Updated " + formatDenver(payload.fetched_at) + ". Links open in a new tab.", false);
    } else {
      setBanner("Links open in a new tab.", false);
    }
    updatedEl.textContent = payload.fetched_at ? "Updated " + formatDenver(payload.fetched_at) : "Links open in a new tab.";

    if (!state.sources.length) {
      var pick = document.createElement("p");
      pick.className = "news-empty";
      pick.textContent = "Pick at least one source.";
      listEl.appendChild(pick);
      return;
    }
    if (!rows.length) {
      var empty = document.createElement("p");
      empty.className = "news-empty";
      empty.textContent = "No headlines in this window.";
      listEl.appendChild(empty);
      return;
    }

    rows.forEach(function (item) {
      var row = document.createElement("article");
      row.className = "news-row";
      var source = document.createElement("span");
      source.className = "news-source";
      source.textContent = nameFor(item.source);
      var href = safeHref(item.link);
      var titleNode;
      if (href) {
        titleNode = document.createElement("a");
        titleNode.className = "news-link";
        titleNode.href = href;
        titleNode.target = "_blank";
        titleNode.rel = "noopener noreferrer";
      } else {
        titleNode = document.createElement("span");
        titleNode.className = "news-title-text";
      }
      titleNode.textContent = item.title || "Untitled";
      var time = document.createElement("time");
      time.className = "news-time";
      if (item.published) {
        time.dateTime = item.published;
        time.textContent = formatDenver(item.published);
      }
      row.appendChild(source);
      row.appendChild(titleNode);
      row.appendChild(time);
      listEl.appendChild(row);
    });
  }
})();
