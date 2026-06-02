<template>
  <footer class="EndevFooter">
    <span>MIT License</span>
    <span aria-hidden="true">·</span>
    <span>Copyright © {{ year }}</span>
    <span aria-hidden="true">·</span>
    <a class="EndevFooterLink" href="https://en.dev">
      <img
        alt=""
        class="EndevFooterLogo"
        height="28"
        src="https://github.com/endevco.png?size=96"
        width="28"
      />
      <span>en.dev</span>
    </a>
  </footer>
</template>

<script setup>
const year = new Date().getFullYear();
</script>

<style scoped>
.EndevFooter {
  align-items: center;
  border-top: 1px solid var(--vp-c-divider);
  color: var(--vp-c-text-2);
  display: flex;
  flex-wrap: wrap;
  font-size: 14px;
  gap: 8px;
  justify-content: center;
  line-height: 28px;
  margin-top: auto;
  padding: 22px 24px 26px;
  text-align: center;
}
.EndevFooterLink {
  align-items: center;
  color: inherit;
  display: inline-flex;
  gap: 8px;
  line-height: 28px;
  text-decoration: none;
  transition: color 0.2s ease;
}
.EndevFooterLink:hover {
  color: var(--vp-c-brand-1);
}
.EndevFooterLogo {
  border-radius: 8px;
  display: inline-block;
  height: 28px;
  vertical-align: middle;
  width: 28px;
}
</style>
