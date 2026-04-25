// https://vitepress.dev/guide/custom-theme
import { h, onMounted } from "vue";
import DefaultTheme from "vitepress/theme";
import { initBanner } from "./banner.js";
import EndevFooter from "./EndevFooter.vue";
import { data as starsData } from "../stars.data";
import "./style.css";

/** @type {import('vitepress').Theme} */
export default {
  extends: DefaultTheme,
  Layout: () => {
    return h(DefaultTheme.Layout, null, {
      "layout-bottom": () => h(EndevFooter),
    });
  },
  enhanceApp({ app, router, siteData }) {
    initBanner();
  },
  setup() {
    onMounted(() => {
      const addStarCount = () => {
        const githubLink = document.querySelector(
          '.VPSocialLinks a[href*="github.com/jdx/fnox"]',
        );
        if (githubLink && !githubLink.querySelector(".star-count")) {
          const starBadge = document.createElement("span");
          starBadge.className = "star-count";
          starBadge.textContent = starsData.stars;
          starBadge.title = "GitHub Stars";
          githubLink.appendChild(starBadge);
        }
      };

      addStarCount();
      setTimeout(addStarCount, 100);
      const observer = new MutationObserver(addStarCount);
      observer.observe(document.body, { childList: true, subtree: true });
    });
  },
};
