// https://vitepress.dev/guide/custom-theme
import { h } from "vue";
import DefaultTheme from "vitepress/theme";
import { initBanner } from "./banner.js";
import EndevFooter from "./EndevFooter.vue";
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
};
