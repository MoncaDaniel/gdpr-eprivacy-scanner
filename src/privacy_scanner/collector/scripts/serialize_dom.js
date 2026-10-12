// Runs in each frame. Serialises the DOM including *open* shadow roots, which
// is where several consent platforms render their banners. Closed shadow roots
// are, by design, unreachable from page script and are a documented blind spot.
() => {
  const roots = [];
  const walk = (root) => {
    for (const el of root.querySelectorAll("*")) {
      if (el.shadowRoot) {
        roots.push(el.shadowRoot);
        walk(el.shadowRoot);
      }
    }
  };
  const doc = document.documentElement;
  if (!doc) return "";
  walk(document);
  const attrs = Array.from(doc.attributes)
    .map((a) => ` ${a.name}="${a.value.replace(/&/g, "&amp;").replace(/"/g, "&quot;")}"`)
    .join("");
  const inner =
    typeof doc.getHTML === "function" ? doc.getHTML({ shadowRoots: roots }) : doc.innerHTML;
  return `<!DOCTYPE html>\n<html${attrs}>${inner}</html>`;
};
