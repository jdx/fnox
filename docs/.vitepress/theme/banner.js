import "./banner.css";

const ENDPOINT = "https://jdx.dev/banner.json";
const STORAGE_KEY = "jdx-banner-dismissed";

export function initBanner() {
  if (typeof window === "undefined") return;
  fetch(ENDPOINT)
    .then((r) => (r.ok ? r.json() : null))
    .then((b) => {
      if (!b || !b.enabled) return;
      if (isExpired(b.expires)) return;
      if (localStorage.getItem(STORAGE_KEY) === b.id) return;
      render(b);
    })
    .catch(() => {});
}

function isExpired(expires) {
  if (!expires) return false;
  const t = Date.parse(expires);
  if (Number.isNaN(t)) return false;
  return Date.now() >= t;
}

function isHttpUrl(value) {
  try {
    const u = new URL(value, window.location.href);
    return u.protocol === "http:" || u.protocol === "https:";
  } catch {
    return false;
  }
}

function render(b) {
  const el = document.createElement("div");
  el.className = "jdx-banner";
  el.setAttribute("role", "region");
  el.setAttribute("aria-label", "Site announcement");

  const msg = document.createElement("span");
  msg.textContent = b.message;
  el.appendChild(msg);

  if (b.link && isHttpUrl(b.link)) {
    const a = document.createElement("a");
    a.href = b.link;
    a.target = "_blank";
    a.rel = "noopener";
    a.textContent = b.linkText || "Learn more";
    el.appendChild(a);
  }

  const syncHeight = () => {
    document.documentElement.style.setProperty(
      "--vp-layout-top-height",
      `${el.offsetHeight}px`,
    );
  };

  const observer =
    typeof ResizeObserver !== "undefined"
      ? new ResizeObserver(syncHeight)
      : null;

  const btn = document.createElement("button");
  btn.type = "button";
  btn.setAttribute("aria-label", "Dismiss");
  btn.textContent = "\u00d7";
  btn.addEventListener("click", () => {
    localStorage.setItem(STORAGE_KEY, b.id);
    observer?.disconnect();
    el.remove();
    document.documentElement.style.removeProperty("--vp-layout-top-height");
  });
  el.appendChild(btn);

  document.body.prepend(el);

  requestAnimationFrame(syncHeight);
  observer?.observe(el);
}
