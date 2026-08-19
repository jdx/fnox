import "./banner.css";

const ENDPOINT = "https://jdx.dev/banner.json";
const STORAGE_KEY = "jdx-banner-dismissed";
const CACHE_KEY = "jdx-banner-cache";

function getDismissedId() {
  try {
    return localStorage.getItem(STORAGE_KEY);
  } catch {
    return null;
  }
}

export function initBanner() {
  if (typeof window === "undefined") return;
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), 5000);
  fetch(ENDPOINT, { signal: controller.signal })
    .then((r) => (r.ok ? r.json() : null))
    .then((b) => {
      if (
        !b ||
        !b.enabled ||
        isExpired(b.expires) ||
        getDismissedId() === b.id
      ) {
        clearReserved();
        return;
      }
      render(b);
    })
    .catch(clearCurrentReservation)
    .finally(() => window.clearTimeout(timeout));
}

function clearCurrentReservation() {
  document.documentElement.style.removeProperty("--vp-layout-top-height");
}

function clearReserved() {
  clearCurrentReservation();
  try {
    localStorage.removeItem(CACHE_KEY);
  } catch {
    // localStorage unavailable — nothing cached to clear.
  }
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
    try {
      localStorage.setItem(
        CACHE_KEY,
        JSON.stringify({
          id: b.id,
          height: `${el.offsetHeight}px`,
          width: window.innerWidth,
          expires: b.expires ?? null,
        }),
      );
    } catch {
      // localStorage unavailable — skip caching.
    }
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
    try {
      localStorage.setItem(STORAGE_KEY, b.id);
    } catch {
      // Dismiss for this page even when localStorage is unavailable.
    }
    observer?.disconnect();
    el.remove();
    clearReserved();
  });
  el.appendChild(btn);

  document.body.prepend(el);

  requestAnimationFrame(syncHeight);
  observer?.observe(el);
}
