// https://vitepress.dev/guide/custom-theme
import { h, onMounted, onUnmounted } from "vue";
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
    let observer;
    onMounted(() => {
      const addStarCount = () => {
        if (!starsData.stars) return false;

        const githubLinks = document.querySelectorAll(
          '.VPSocialLinks a[href*="github.com/jdx/fnox"]',
        );
        githubLinks.forEach((githubLink) => {
          if (!githubLink.querySelector(".star-count")) {
            const starBadge = document.createElement("span");
            starBadge.className = "star-count";
            starBadge.textContent = starsData.stars;
            starBadge.title = "GitHub Stars";
            githubLink.appendChild(starBadge);
          }
        });
        return (
          githubLinks.length > 0 &&
          Array.from(githubLinks).every((link) =>
            link.querySelector(".star-count"),
          )
        );
      };

      if (addStarCount()) return;

      observer = new MutationObserver(() => {
        if (addStarCount()) observer?.disconnect();
      });
      observer.observe(document.querySelector(".VPNav") || document.body, {
        childList: true,
        subtree: true,
      });
    });
    onUnmounted(() => observer?.disconnect());
  },
};
