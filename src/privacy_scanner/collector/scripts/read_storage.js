// Runs in each frame. Reads Web Storage without modifying it.
// Values are truncated for transfer; the true length is reported separately.
(maxValueChars) => {
  const out = { origin: null, entries: [], error: null };
  try {
    out.origin = self.origin;
  } catch (e) {
    out.error = String(e);
    return out;
  }
  for (const area of ["localStorage", "sessionStorage"]) {
    let store;
    try {
      store = self[area];
    } catch (e) {
      continue; // sandboxed or storage-disabled frame
    }
    if (!store) continue;
    for (let i = 0; i < store.length; i++) {
      const key = store.key(i);
      if (key === null) continue;
      const value = store.getItem(key) ?? "";
      out.entries.push({
        area,
        key,
        length: value.length,
        value: value.slice(0, maxValueChars),
      });
    }
  }
  return out;
};
