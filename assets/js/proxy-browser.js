/**
 * Proxy Browser — client-side CORS-proxy fetch + sandboxed iframe viewer.
 * Used for phishing / X-Frame inspection on the homepage.
 */
(function () {
  'use strict';

  document.addEventListener('DOMContentLoaded', function () {
    const xfWindow = document.getElementById('xframe-window');
    const xfHeader = document.getElementById('xframe-header');
    if (!xfWindow || !xfHeader) return;

    const btnRed = document.getElementById('xframe-btn-red');
    const btnYellow = document.getElementById('xframe-btn-yellow');
    const btnGreen = document.getElementById('xframe-btn-green');

    const backBtn = document.getElementById('xf-back');
    const fwdBtn = document.getElementById('xf-forward');
    const reloadBtn = document.getElementById('xf-reload');
    const urlbar = document.getElementById('xf-urlbar');
    const methodSel = document.getElementById('xf-method');
    const proxySelEl = document.getElementById('xf-proxy');
    const goBtn = document.getElementById('xf-go');
    const cancelBtn = document.getElementById('xf-cancel');
    const retryBtn = document.getElementById('xf-retry');
    const viewToggle = document.getElementById('xf-view-toggle');
    const status = document.getElementById('xf-status');
    const spinner = document.getElementById('xf-spinner');
    const spinnerText = document.getElementById('xf-spinner-text');
    const placeholder = document.getElementById('xf-placeholder');
    const iframe = document.getElementById('xf-iframe');
    const rawView = document.getElementById('xf-raw');
    const chromeEl = document.getElementById('xf-chrome');

    // ── State ───────────────────────────────────────────────────────────────
    const navHistory = [];
    let histIdx = -1;
    let currentUrl = null;
    let lastHtml = null;
    let lastFinalUrl = null;
    let lastProxyUsed = null;
    let lastError = null;
    let viewMode = 'render'; // 'render' | 'raw'
    let loadGen = 0;
    let activeController = null;
    let directWatchTimer = null;

    const PROXY_TIMEOUT_MS = 9000;
    const DIRECT_BLANK_MS = 2500;
    const MIN_HTML_LEN = 40;
    const MAX_HTML_CHARS = 2_500_000;

    // Public CORS proxies — free tiers flap; Auto races them.
    // allorigins /get exposes post-redirect URL via status.url.
    // Raw proxies need HTML heuristics for final URL.
    const PROXIES = [
      {
        name: 'cors.eu.org',
        raw: true,
        fn: (u) => 'https://cors.eu.org/' + u,
      },
      {
        name: 'proxy.cors.sh',
        raw: true,
        fn: (u) => 'https://proxy.cors.sh/' + u,
      },
      {
        name: 'allorigins.win',
        raw: false,
        fn: (u) => 'https://api.allorigins.win/get?url=' + encodeURIComponent(u),
      },
      {
        name: 'corsproxy.io',
        raw: true,
        fn: (u) => 'https://corsproxy.io/?' + encodeURIComponent(u),
      },
      {
        name: 'codetabs.com',
        raw: true,
        fn: (u) => 'https://api.codetabs.com/v1/proxy?quest=' + encodeURIComponent(u),
      },
    ];

    // Injected into every proxied page. Intercepts nav and posts to parent.
    // Escaped <\/script> so this file stays valid if ever inlined.
    const NAV_INTERCEPTOR = [
      '<scr' + 'ipt>',
      '(function(){',
      '  function abs(h){try{return new URL(h,document.baseURI).href}catch(e){return h}}',
      '  function send(u){',
      '    try{window.parent.postMessage({type:"xframe-nav",url:String(u||"")},"*")}catch(e){}',
      '  }',
      '  function isHttp(u){return /^https?:\\/\\//i.test(u)}',
      '  document.addEventListener("click",function(e){',
      '    var el=e.target;',
      '    while(el&&el.tagName!=="A"&&el.tagName!=="AREA")el=el.parentElement;',
      '    if(!el)return;',
      '    var href=el.getAttribute("href");',
      '    if(!href||href.charAt(0)==="#")return;',
      '    var t=(el.getAttribute("target")||"_self").toLowerCase();',
      '    if(t&&t!=="_self"&&t!=="")return;',
      '    var u=abs(el.href||href);',
      '    if(!isHttp(u))return;',
      '    e.preventDefault();e.stopPropagation();',
      '    send(u);',
      '  },true);',
      '  document.addEventListener("submit",function(e){',
      '    e.preventDefault();',
      '    var f=e.target,action=f.action||document.baseURI;',
      '    var method=(f.method||"get").toLowerCase();',
      '    var q="";',
      '    try{',
      '      if(method==="get")q=new URLSearchParams(new FormData(f)).toString();',
      '    }catch(err){}',
      '    var u=abs(action+(q?(String(action).indexOf("?")>=0?"&":"?")+q:""));',
      '    if(isHttp(u))send(u);',
      '  },true);',
      '  try{',
      '    var desc=Object.getOwnPropertyDescriptor(Location.prototype,"href")||',
      '            Object.getOwnPropertyDescriptor(window.location,"href");',
      '    if(desc&&desc.set){',
      '      Object.defineProperty(window.location,"href",{',
      '        configurable:true,',
      '        get:function(){return desc.get.call(window.location)},',
      '        set:function(v){var u=abs(v);if(isHttp(u)){send(u);return}desc.set.call(window.location,v)}',
      '      });',
      '    }',
      '  }catch(e){}',
      '  var _assign=window.location.assign.bind(window.location);',
      '  var _replace=window.location.replace.bind(window.location);',
      '  try{',
      '    window.location.assign=function(v){var u=abs(v);if(isHttp(u)){send(u);return}_assign(v)};',
      '    window.location.replace=function(v){var u=abs(v);if(isHttp(u)){send(u);return}_replace(v)};',
      '  }catch(e){}',
      '  document.addEventListener("DOMContentLoaded",function(){',
      '    try{',
      '      var m=document.querySelector(\'meta[http-equiv="refresh" i]\');',
      '      if(!m)return;',
      '      var c=m.getAttribute("content")||"";',
      '      var parts=c.split(/;\\s*url\\s*=\\s*/i);',
      '      if(parts.length<2)return;',
      '      var delay=parseFloat(parts[0])||0;',
      '      var u=abs(parts[1].replace(/^["\']|["\']$/g,""));',
      '      if(!isHttp(u))return;',
      '      m.remove();',
      '      setTimeout(function(){send(u)},Math.max(0,delay*1000));',
      '    }catch(e){}',
      '  });',
      '})();',
      '<\/scr' + 'ipt>',
    ].join('\n');

    // ── UI helpers ──────────────────────────────────────────────────────────

    function setStatus(msg, color) {
      status.textContent = msg;
      status.style.color = color || '#555';
      status.title = msg || '';
    }

    function setBusy(on, label) {
      if (spinnerText) spinnerText.textContent = label || 'Loading…';
      spinner.style.display = on ? 'block' : 'none';
      if (cancelBtn) {
        cancelBtn.style.display = on ? '' : 'none';
        cancelBtn.disabled = !on;
      }
      if (goBtn) goBtn.disabled = !!on;
      if (chromeEl) chromeEl.classList.toggle('xf-busy', !!on);
    }

    function showPlaceholder() {
      placeholder.style.display = 'block';
      iframe.style.display = 'none';
      if (rawView) rawView.style.display = 'none';
      spinner.style.display = 'none';
    }

    function showFrame() {
      placeholder.style.display = 'none';
      spinner.style.display = 'none';
      if (viewMode === 'raw' && lastHtml != null && rawView) {
        iframe.style.display = 'none';
        rawView.style.display = 'block';
        rawView.textContent = lastHtml;
      } else {
        if (rawView) rawView.style.display = 'none';
        iframe.style.display = 'block';
      }
    }

    function updateViewToggle() {
      if (!viewToggle) return;
      const hasContent = lastHtml != null;
      viewToggle.disabled = !hasContent;
      viewToggle.style.opacity = hasContent ? '1' : '0.3';
      viewToggle.textContent = viewMode === 'raw' ? 'Rendered' : 'Raw HTML';
      viewToggle.title =
        viewMode === 'raw' ? 'Switch to rendered view' : 'View fetched HTML source';
    }

    function updateRetry() {
      if (!retryBtn) return;
      const show = !!(lastError && currentUrl && methodSel.value === 'proxy');
      retryBtn.style.display = show ? '' : 'none';
    }

    function updateButtons() {
      backBtn.disabled = histIdx <= 0;
      fwdBtn.disabled = histIdx >= navHistory.length - 1;
      reloadBtn.disabled = !currentUrl;
      [backBtn, fwdBtn, reloadBtn].forEach((b) => {
        b.style.opacity = b.disabled ? '0.3' : '1';
      });
      updateViewToggle();
      updateRetry();
    }

    function pushHistory(url) {
      navHistory.splice(histIdx + 1);
      navHistory.push(url);
      histIdx = navHistory.length - 1;
      updateButtons();
    }

    function replaceHistory(url) {
      if (histIdx >= 0 && histIdx < navHistory.length) {
        navHistory[histIdx] = url;
      } else {
        pushHistory(url);
      }
      updateButtons();
    }

    function abortActive() {
      if (activeController) {
        try {
          activeController.abort();
        } catch (e) {
          /* ignore */
        }
        activeController = null;
      }
      if (directWatchTimer) {
        clearTimeout(directWatchTimer);
        directWatchTimer = null;
      }
    }

    function escapeHtml(s) {
      return String(s)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
    }

    // ── URL helpers ─────────────────────────────────────────────────────────

    function normalise(url) {
      url = (url || '').trim();
      if (!url) return '';
      if (/^(javascript|data|blob|file|vbscript):/i.test(url)) return '';
      if (!/^https?:\/\//i.test(url)) url = 'https://' + url;
      try {
        const u = new URL(url);
        if (u.protocol !== 'http:' && u.protocol !== 'https:') return '';
        return u.href;
      } catch (e) {
        return '';
      }
    }

    function isHttpUrl(url) {
      try {
        const u = new URL(url);
        return u.protocol === 'http:' || u.protocol === 'https:';
      } catch (e) {
        return false;
      }
    }

    function getBase(targetUrl) {
      try {
        const u = new URL(targetUrl);
        return u.origin + u.pathname.replace(/[^/]*$/, '');
      } catch (e) {
        return targetUrl;
      }
    }

    function detectFinalUrl(html, fallback) {
      const patterns = [
        /<link[^>]+rel=["']canonical["'][^>]+href=["']([^"']+)["']/i,
        /<link[^>]+href=["']([^"']+)["'][^>]+rel=["']canonical["']/i,
        /<meta[^>]+property=["']og:url["'][^>]+content=["']([^"']+)["']/i,
        /<meta[^>]+content=["']([^"']+)["'][^>]+property=["']og:url["']/i,
        /<base[^>]+href=["']([^"']+)["']/i,
      ];
      for (const re of patterns) {
        const m = html.match(re);
        if (m) {
          try {
            const resolved = new URL(m[1], fallback).href;
            if (isHttpUrl(resolved)) return resolved;
          } catch (e) {
            /* continue */
          }
        }
      }
      return fallback;
    }

    function looksLikeHtml(text) {
      if (!text || typeof text !== 'string') return false;
      const sample = text.slice(0, 4000).toLowerCase();
      if (sample.indexOf('<html') !== -1) return true;
      if (sample.indexOf('<!doctype html') !== -1) return true;
      if (sample.indexOf('<head') !== -1 && sample.indexOf('<body') !== -1) return true;
      // Soft accept: substantial markup
      const tags = (sample.match(/<[a-z][\s\S]*>/g) || []).length;
      return tags >= 3;
    }

    function isProxyErrorPayload(text) {
      if (!text) return true;
      const t = text.trim();
      if (t.length < MIN_HTML_LEN) {
        if (/^\s*\{[\s\S]*"error"/.test(t)) return true;
        if (/error|blocked|rate.?limit|forbidden|not allowed/i.test(t) && t.length < 200)
          return true;
      }
      if (/^\s*\{/.test(t) && /"error"\s*:/.test(t)) return true;
      if (/server-side requests are not allowed/i.test(t)) return true;
      if (/missing required request header|api key|unauthorized/i.test(t) && t.length < 2000)
        return true;
      // Proxy marketing / landing pages returned instead of the target
      if (
        /cors proxy for solving cross-origin|hidemy\.name|download the vpn app/i.test(t) &&
        !/example domain/i.test(t)
      ) {
        return true;
      }
      // Common bot/challenge shells with almost no real content
      if (
        t.length < 2500 &&
        /captcha|cf-browser-verification|attention required|access denied|just a moment/i.test(
          t
        ) &&
        !/<article|<main|role=["']main["']/i.test(t)
      ) {
        // Don't hard-fail every challenge page — only tiny ones
        if (t.length < 800) return true;
      }
      return false;
    }

    function validateFetchedHtml(html) {
      if (html == null || html === '') throw new Error('Empty response from proxy');
      if (html.length > MAX_HTML_CHARS) {
        throw new Error('Response too large (' + Math.round(html.length / 1024) + ' KB)');
      }
      if (isProxyErrorPayload(html)) {
        throw new Error('Proxy returned an error or blocked payload');
      }
      // Allow non-HTML through to raw view, but warn via status later
      return html;
    }

    function injectIntoHtml(html, finalUrl) {
      const baseTag = '<base href="' + getBase(finalUrl).replace(/"/g, '&quot;') + '">';
      html = html.replace(/<base[^>]*>/gi, '');

      if (/<head[\s>]/i.test(html)) {
        html = html.replace(/<head([^>]*)>/i, '<head$1>' + baseTag);
      } else {
        html = baseTag + html;
      }

      if (/<\/body>/i.test(html)) {
        html = html.replace(/<\/body>/i, NAV_INTERCEPTOR + '</body>');
      } else {
        html += NAV_INTERCEPTOR;
      }
      return html;
    }

    function errorPage(message, tips) {
      const tipHtml = (tips || defaultTips())
        .map((t) => '&bull; ' + escapeHtml(t))
        .join('<br>');
      return [
        '<html><body style="margin:0;padding:2rem;background:#0c0c0c;color:#ff5555;font-family:monospace;">',
        '<h3 style="color:#ff5555;margin-top:0;">Failed to load</h3>',
        '<p>' + escapeHtml(message) + '</p>',
        '<p style="color:#888;margin-top:1rem;">Tips:<br>' + tipHtml + '</p>',
        '</body></html>',
      ].join('');
    }

    function defaultTips() {
      return [
        'Check the URL is correct and the site is up',
        'Try another proxy from the dropdown, or Auto',
        'Public proxies rate-limit and get blocked by WAFs — wait and retry',
        'Use Raw HTML if the page fetched but will not render cleanly',
        'Direct iframe only works when the target allows framing',
      ];
    }

    // ── Fetch layer ─────────────────────────────────────────────────────────

    async function fetchOneProxy(proxy, url, signal) {
      const resp = await fetch(proxy.fn(url), { signal });
      if (!resp.ok) throw new Error(proxy.name + ' HTTP ' + resp.status);

      let html;
      let finalUrl = url;

      if (!proxy.raw) {
        const data = await resp.json();
        if (data == null) throw new Error(proxy.name + ' empty JSON');
        if (data.status && typeof data.status.http_code === 'number') {
          const code = data.status.http_code;
          if (code >= 400) throw new Error(proxy.name + ' upstream HTTP ' + code);
        }
        if (!data.contents && data.contents !== '') {
          throw new Error(proxy.name + ' missing contents');
        }
        html = data.contents;
        if (data.status && data.status.url && isHttpUrl(data.status.url)) {
          finalUrl = data.status.url;
        }
      } else {
        html = await resp.text();
        // Some proxies echo error JSON with 200
        finalUrl = url;
      }

      html = validateFetchedHtml(html);
      finalUrl = detectFinalUrl(html, finalUrl);
      return { html, finalUrl, proxyName: proxy.name };
    }

    /**
     * Auto: race all proxies; first valid wins; abort the rest.
     * Pinned: single proxy with timeout.
     */
    async function fetchWithProxyFallback(url, proxyName, parentSignal) {
      const pool =
        proxyName && proxyName !== 'auto'
          ? PROXIES.filter((p) => p.name === proxyName)
          : PROXIES.slice();

      if (pool.length === 0) throw new Error('Unknown proxy: ' + proxyName);

      // Single proxy path
      if (pool.length === 1) {
        const proxy = pool[0];
        setStatus('Trying ' + proxy.name + '…');
        if (spinnerText) spinnerText.textContent = 'Trying ' + proxy.name + '…';
        const ctrl = new AbortController();
        const onParentAbort = () => ctrl.abort();
        if (parentSignal) {
          if (parentSignal.aborted) throw new DOMException('Aborted', 'AbortError');
          parentSignal.addEventListener('abort', onParentAbort, { once: true });
        }
        const timer = setTimeout(() => ctrl.abort(), PROXY_TIMEOUT_MS);
        try {
          return await fetchOneProxy(proxy, url, ctrl.signal);
        } catch (e) {
          if (e.name === 'AbortError') {
            if (parentSignal && parentSignal.aborted) throw e;
            throw new Error(proxy.name + ' timed out');
          }
          throw e;
        } finally {
          clearTimeout(timer);
          if (parentSignal) parentSignal.removeEventListener('abort', onParentAbort);
        }
      }

      // Race path
      setStatus('Racing ' + pool.map((p) => p.name).join(', ') + '…');
      if (spinnerText) spinnerText.textContent = 'Racing proxies…';

      return await new Promise((resolve, reject) => {
        let settled = false;
        let pending = pool.length;
        const errors = [];
        const childControllers = [];

        const cleanup = () => {
          childControllers.forEach((c) => {
            try {
              c.abort();
            } catch (e) {
              /* ignore */
            }
          });
        };

        const onParentAbort = () => {
          if (settled) return;
          settled = true;
          cleanup();
          reject(new DOMException('Aborted', 'AbortError'));
        };

        if (parentSignal) {
          if (parentSignal.aborted) {
            reject(new DOMException('Aborted', 'AbortError'));
            return;
          }
          parentSignal.addEventListener('abort', onParentAbort, { once: true });
        }

        pool.forEach((proxy) => {
          const ctrl = new AbortController();
          childControllers.push(ctrl);
          const timer = setTimeout(() => ctrl.abort(), PROXY_TIMEOUT_MS);

          fetchOneProxy(proxy, url, ctrl.signal)
            .then((result) => {
              clearTimeout(timer);
              if (settled) return;
              settled = true;
              cleanup();
              if (parentSignal) parentSignal.removeEventListener('abort', onParentAbort);
              resolve(result);
            })
            .catch((e) => {
              clearTimeout(timer);
              if (settled) return;
              const msg =
                e.name === 'AbortError'
                  ? proxy.name + ' timed out'
                  : proxy.name + ': ' + (e.message || String(e));
              errors.push(msg);
              pending -= 1;
              setStatus('Waiting… (' + errors.length + '/' + pool.length + ' failed)');
              if (pending <= 0) {
                settled = true;
                if (parentSignal) parentSignal.removeEventListener('abort', onParentAbort);
                reject(new Error('All proxies failed — ' + errors.join('; ')));
              }
            });
        });
      });
    }

    // ── Core load ───────────────────────────────────────────────────────────

    async function loadUrl(url, addToHist, opts) {
      opts = opts || {};
      url = normalise(url);
      if (!url) {
        setStatus('Enter a valid http(s) URL', '#ff5555');
        return;
      }

      abortActive();
      const myGen = ++loadGen;
      const controller = new AbortController();
      activeController = controller;

      urlbar.value = url;
      currentUrl = url;
      lastError = null;
      if (addToHist !== false) pushHistory(url);
      updateButtons();

      setBusy(true, 'Loading…');
      placeholder.style.display = 'none';
      // Keep previous frame visible under spinner only if empty; hide to avoid flash of wrong page
      iframe.style.display = 'none';
      if (rawView) rawView.style.display = 'none';

      const mode = methodSel.value;

      try {
        if (mode === 'proxy') {
          const preferred =
            opts.forceProxy ||
            (opts.skipProxy ? null : proxySelEl.value) ||
            proxySelEl.value;

          let result;
          if (opts.tryNext) {
            // Sequential pass: start after last used proxy (or from the top)
            const names = PROXIES.map((p) => p.name);
            const start = lastProxyUsed ? names.indexOf(lastProxyUsed) : -1;
            const ordered = names
              .slice(start + 1)
              .concat(start >= 0 ? names.slice(0, start + 1) : [])
              .map((n) => PROXIES.find((p) => p.name === n))
              .filter(Boolean);
            let lastErr = null;
            result = null;
            for (const proxy of ordered) {
              if (controller.signal.aborted) throw new DOMException('Aborted', 'AbortError');
              setStatus('Trying ' + proxy.name + '…');
              if (spinnerText) spinnerText.textContent = 'Trying ' + proxy.name + '…';
              try {
                result = await fetchWithProxyFallback(url, proxy.name, controller.signal);
                break;
              } catch (e) {
                if (e.name === 'AbortError') throw e;
                lastProxyUsed = proxy.name;
                lastErr = e;
              }
            }
            if (!result) throw lastErr || new Error('All proxies failed');
          } else {
            result = await fetchWithProxyFallback(url, preferred, controller.signal);
          }

          if (myGen !== loadGen) return;

          const { html, finalUrl, proxyName } = result;
          lastHtml = html;
          lastFinalUrl = finalUrl;
          lastProxyUsed = proxyName;
          lastError = null;

          const resolved = finalUrl && isHttpUrl(finalUrl) ? finalUrl : url;
          if (resolved !== url) {
            urlbar.value = resolved;
            currentUrl = resolved;
            if (addToHist !== false) replaceHistory(resolved);
            else if (histIdx >= 0) navHistory[histIdx] = resolved;
          }

          const htmlOk = looksLikeHtml(html);
          const injected = injectIntoHtml(html, resolved);
          iframe.removeAttribute('src');
          iframe.srcdoc = injected;

          setBusy(false);
          showFrame();

          let msg =
            'Loaded via ' +
            proxyName +
            (resolved !== url ? ' → ' + resolved : ' — ' + url);
          if (!htmlOk) {
            msg += ' (non-HTML payload — try Raw HTML)';
            setStatus(msg, '#ffaa00');
          } else {
            setStatus(msg, '#39ff14');
          }
          updateButtons();
        } else {
          // Direct iframe
          lastHtml = null;
          lastFinalUrl = url;
          lastProxyUsed = null;
          iframe.removeAttribute('srcdoc');
          iframe.src = url;

          setBusy(false);
          showFrame();
          setStatus('Direct iframe — checking frame…', '#888');
          updateButtons();

          // Heuristic: cross-origin framed pages that block often stay blank.
          // We cannot read the document; watch load + delayed note.
          let loadFired = false;
          const onLoad = () => {
            loadFired = true;
            if (myGen !== loadGen) return;
            setStatus(
              'Direct iframe loaded — if blank, target likely sets X-Frame-Options / CSP frame-ancestors',
              '#888'
            );
          };
          iframe.addEventListener('load', onLoad, { once: true });
          directWatchTimer = setTimeout(() => {
            directWatchTimer = null;
            if (myGen !== loadGen) return;
            if (!loadFired) {
              setStatus(
                'Direct iframe — no load event yet; framing may be blocked or slow',
                '#ffaa00'
              );
            }
          }, DIRECT_BLANK_MS);
        }
      } catch (e) {
        if (myGen !== loadGen) return;
        if (e.name === 'AbortError') {
          setBusy(false);
          setStatus('Cancelled', '#888');
          if (!iframe.srcdoc && !iframe.getAttribute('src')) showPlaceholder();
          else showFrame();
          updateButtons();
          return;
        }

        lastError = e;
        lastHtml = null;
        setBusy(false);
        setStatus('Error: ' + e.message, '#ff5555');
        iframe.removeAttribute('src');
        iframe.srcdoc = errorPage(e.message);
        viewMode = 'render';
        showFrame();
        updateButtons();
      } finally {
        if (activeController === controller) activeController = null;
      }
    }

    // ── postMessage from iframe (nav interceptor only) ──────────────────────
    window.addEventListener('message', function (e) {
      if (!e.data || e.data.type !== 'xframe-nav' || !e.data.url) return;
      // Only accept messages from our iframe
      if (e.source !== iframe.contentWindow) return;
      const next = normalise(e.data.url);
      if (!next) {
        setStatus('Blocked non-http(s) navigation from page', '#ffaa00');
        return;
      }
      loadUrl(next, true);
    });

    // ── Window chrome ───────────────────────────────────────────────────────
    const xfSection = xfWindow ? xfWindow.closest('.tool-section') : null;

    function restoreProxyWindow() {
      if (!xfWindow) return;
      xfWindow.style.display = 'block';
      if (xfHeader) {
        xfHeader.style.borderBottomLeftRadius = '0';
        xfHeader.style.borderBottomRightRadius = '0';
        xfHeader.style.borderBottom = 'none';
      }
    }

    function setProxyMaximized(on) {
      if (!xfSection) return;
      xfSection.classList.toggle('is-maximized', on);
      if (btnGreen) btnGreen.title = on ? 'Restore size' : 'Maximize';
    }

    btnYellow.addEventListener('click', () => {
      setProxyMaximized(false);
      xfWindow.style.display = 'none';
      xfHeader.style.borderBottomLeftRadius = '8px';
      xfHeader.style.borderBottomRightRadius = '8px';
      xfHeader.style.borderBottom = '1px solid #39ff14';
    });
    btnGreen.addEventListener('click', () => {
      const wasMinimized = xfWindow && xfWindow.style.display === 'none';
      if (wasMinimized) {
        restoreProxyWindow();
        if (xfSection && !xfSection.classList.contains('is-maximized')) {
          setProxyMaximized(true);
        }
      } else {
        setProxyMaximized(!(xfSection && xfSection.classList.contains('is-maximized')));
      }
    });
    btnRed.addEventListener('click', reset);

    methodSel.addEventListener('change', () => {
      const isProxy = methodSel.value === 'proxy';
      proxySelEl.style.display = isProxy ? '' : 'none';
      if (viewToggle) viewToggle.style.display = isProxy ? '' : 'none';
      updateRetry();
    });

    goBtn.addEventListener('click', () => loadUrl(urlbar.value, true));
    urlbar.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') loadUrl(urlbar.value, true);
    });

    if (cancelBtn) {
      cancelBtn.addEventListener('click', () => {
        abortActive();
        loadGen += 1;
        setBusy(false);
        setStatus('Cancelled', '#888');
        updateButtons();
      });
    }

    if (retryBtn) {
      retryBtn.addEventListener('click', () => {
        if (!currentUrl) return;
        loadUrl(currentUrl, false, { tryNext: true });
      });
    }

    if (viewToggle) {
      viewToggle.addEventListener('click', () => {
        if (lastHtml == null) return;
        viewMode = viewMode === 'raw' ? 'render' : 'raw';
        updateViewToggle();
        showFrame();
      });
    }

    backBtn.addEventListener('click', () => {
      if (histIdx > 0) {
        histIdx--;
        loadUrl(navHistory[histIdx], false);
      }
    });

    fwdBtn.addEventListener('click', () => {
      if (histIdx < navHistory.length - 1) {
        histIdx++;
        loadUrl(navHistory[histIdx], false);
      }
    });

    reloadBtn.addEventListener('click', () => {
      if (currentUrl) loadUrl(currentUrl, false);
    });

    function reset() {
      abortActive();
      loadGen += 1;
      iframe.removeAttribute('srcdoc');
      iframe.removeAttribute('src');
      lastHtml = null;
      lastFinalUrl = null;
      lastProxyUsed = null;
      lastError = null;
      viewMode = 'render';
      urlbar.value = '';
      currentUrl = null;
      navHistory.length = 0;
      histIdx = -1;
      setBusy(false);
      showPlaceholder();
      updateButtons();
      setStatus('Ready — enter a URL above');
    }

    // Initial UI
    proxySelEl.style.display = methodSel.value === 'proxy' ? '' : 'none';
    if (viewToggle) viewToggle.style.display = methodSel.value === 'proxy' ? '' : 'none';
    if (cancelBtn) cancelBtn.style.display = 'none';
    if (retryBtn) retryBtn.style.display = 'none';
    updateButtons();
  });
})();
