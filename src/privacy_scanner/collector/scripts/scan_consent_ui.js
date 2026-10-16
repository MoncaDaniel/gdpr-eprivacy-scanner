// Runs in each frame. Describes the *visible* overlay-like layers of the page
// and the clickable controls inside them: text, geometry and computed styles.
// It is a factual snapshot (ADR-0012): it does not decide what is a consent
// banner or which button means "reject"; the classifier does that later.
//
// Read-only: no clicks, no focus, no scrolling, no style changes.
(limits) => {
  const MAX_CONTROLS = limits.maxControls;
  const MAX_LAYERS = limits.maxLayers;
  const MAX_TEXT = limits.maxText;
  const MAX_LABEL = 160;
  const CONTROL_SELECTOR =
    "button, a[href], input[type=button], input[type=submit], [role=button], [role=link], [onclick]";
  // Names consent platforms give their containers. Used only to find candidate
  // layers that are not fixed-position (inline banners), never as a verdict.
  const NAMED_LAYER = /cookie|consent|gdpr|rgpd|privacy|cmp|didomi|onetrust|optanon|axeptio|cookiebot|cybot|usercentrics|tarteaucitron|cky-|cmplz|qc-cmp|sp_message|truste|iubenda|klaro|osano|termly|sirdata|cookieyes|cookie-law/i;

  const vw = window.innerWidth;
  const vh = window.innerHeight;
  const isTop = (() => {
    try {
      return window.top === window;
    } catch (e) {
      return false;
    }
  })();

  // Collect every element, descending into open shadow roots.
  const all = [];
  const shadowMembers = new WeakSet();
  const walk = (root, inShadow) => {
    for (const el of root.querySelectorAll("*")) {
      all.push(el);
      if (inShadow) shadowMembers.add(el);
      if (el.shadowRoot) walk(el.shadowRoot, true);
    }
  };
  walk(document, false);

  const parentOf = (el) => el.parentElement || (el.getRootNode() && el.getRootNode().host) || null;

  const visible = (el) => {
    if (typeof el.checkVisibility === "function") {
      if (!el.checkVisibility({ opacityProperty: true, visibilityProperty: true })) return false;
    }
    const r = el.getBoundingClientRect();
    return r.width > 0 && r.height > 0;
  };

  const box = (el) => {
    const r = el.getBoundingClientRect();
    return { x: r.x, y: r.y, width: r.width, height: r.height };
  };

  const ownHint = (el) => {
    let s = el.tagName.toLowerCase();
    if (el.id) s += "#" + el.id;
    const cls = typeof el.className === "string" ? el.className.trim().split(/\s+/) : [];
    for (const c of cls.slice(0, 4)) if (c) s += "." + c;
    return s;
  };
  // Inside a shadow root, prefix the host's hint: the host usually carries
  // the consent platform's name (e.g. #usercentrics-root).
  const hint = (el) => {
    const root = el.getRootNode();
    const host = root instanceof ShadowRoot ? root.host : null;
    return ((host ? ownHint(host) + " >> " : "") + ownHint(el)).slice(0, 160);
  };

  const clean = (text) => (text || "").replace(/\s+/g, " ").trim();

  const layerKind = (el) => {
    const style = getComputedStyle(el);
    if (style.position === "fixed") return "fixed";
    if (style.position === "sticky") return "sticky";
    const role = el.getAttribute("role");
    if (
      (el.tagName === "DIALOG" && el.open) ||
      role === "dialog" ||
      role === "alertdialog" ||
      el.getAttribute("aria-modal") === "true"
    )
      return "dialog";
    const name = (el.id || "") + " " + (typeof el.className === "string" ? el.className : "");
    if (NAMED_LAYER.test(name)) return "named";
    return null;
  };

  // A control's layer is its nearest positioned/dialog ancestor; failing
  // that, its nearest ancestor carrying a consent-platform-like name.
  const layerFor = (el) => {
    let named = null;
    for (let cur = parentOf(el); cur && cur !== document.documentElement; cur = parentOf(cur)) {
      if (cur === document.body) break;
      const kind = layerKind(cur);
      if (kind === "fixed" || kind === "sticky" || kind === "dialog") return [cur, kind];
      if (kind === "named" && named === null) named = cur;
    }
    return named ? [named, "named"] : null;
  };

  const backgroundOf = (el) => {
    for (let cur = el; cur; cur = parentOf(cur)) {
      const bg = getComputedStyle(cur).backgroundColor;
      if (bg && bg !== "transparent" && !/rgba\(\s*0,\s*0,\s*0,\s*0\s*\)/.test(bg)) return bg;
    }
    return null;
  };

  const layers = [];
  const layerIds = new Map();
  const controls = [];
  let otherControls = 0;
  let truncated = false;

  const frameLayer = () => {
    // Inside an embedded frame the whole document is the candidate layer
    // (e.g. CMPs that render the banner in a cross-origin iframe).
    if (!layerIds.has(document.body)) {
      layerIds.set(document.body, layers.length);
      layers.push({ el: document.body, kind: "frame" });
    }
    return layerIds.get(document.body);
  };

  for (const el of all) {
    if (!el.matches(CONTROL_SELECTOR)) continue;
    if (!visible(el)) continue;
    const found = layerFor(el);
    let layerId;
    if (found) {
      const [layerEl, kind] = found;
      if (!layerIds.has(layerEl)) {
        if (layers.length >= MAX_LAYERS) {
          truncated = true;
          otherControls++;
          continue;
        }
        layerIds.set(layerEl, layers.length);
        layers.push({ el: layerEl, kind });
      }
      layerId = layerIds.get(layerEl);
    } else if (!isTop && document.body) {
      layerId = frameLayer();
    } else {
      otherControls++;
      continue;
    }
    if (controls.length >= MAX_CONTROLS) {
      truncated = true;
      continue;
    }
    const style = getComputedStyle(el);
    const b = box(el);
    const label = clean(
      el.innerText || el.getAttribute("aria-label") || el.value || el.getAttribute("title") || ""
    );
    controls.push({
      layer_id: layerId,
      tag: el.tagName.toLowerCase(),
      role: el.getAttribute("role"),
      label: label.slice(0, MAX_LABEL),
      aria_label: el.getAttribute("aria-label") ? clean(el.getAttribute("aria-label")).slice(0, MAX_LABEL) : null,
      box: b,
      in_viewport: b.x < vw && b.y < vh && b.x + b.width > 0 && b.y + b.height > 0,
      font_size_px: parseFloat(style.fontSize) || null,
      font_weight: parseInt(style.fontWeight, 10) || null,
      color: style.color || null,
      background_color: backgroundOf(el),
      in_shadow_root: shadowMembers.has(el),
    });
  }

  const outLayers = layers.map(({ el, kind }, id) => {
    const text = clean(el.innerText);
    const z = parseInt(getComputedStyle(el).zIndex, 10);
    return {
      layer_id: id,
      kind,
      element: hint(el),
      box: box(el),
      z_index: Number.isFinite(z) ? z : null,
      text: text.slice(0, MAX_TEXT),
      text_truncated: text.length > MAX_TEXT,
    };
  });

  return {
    viewport: { width: vw, height: vh },
    is_top: isTop,
    layers: outLayers,
    controls,
    other_controls: otherControls,
    truncated,
  };
};
