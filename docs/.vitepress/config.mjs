import { defineConfig } from "vitepress";

export default defineConfig({
  title: "fnox",
  description: "Fort Knox for your secrets",
  base: "/",

  themeConfig: {
    logo: "/logo.svg",

    nav: [
      { text: "Guide", link: "/guide/what-is-fnox" },
      { text: "Providers", link: "/providers/overview" },
      { text: "Reference", link: "/reference/commands" },
    ],

    sidebar: {
      "/guide/": [
        {
          text: "Introduction",
          items: [
            { text: "What is fnox?", link: "/guide/what-is-fnox" },
            { text: "Installation", link: "/guide/installation" },
            { text: "Quick Start", link: "/guide/quick-start" },
            { text: "How It Works", link: "/guide/how-it-works" },
          ],
        },
        {
          text: "Features",
          items: [
            { text: "Shell Integration", link: "/guide/shell-integration" },
            { text: "Profiles", link: "/guide/profiles" },
            { text: "Hierarchical Config", link: "/guide/hierarchical-config" },
            { text: "Local Overrides", link: "/guide/local-overrides" },
            {
              text: "Handling Missing Secrets",
              link: "/guide/missing-secrets",
            },
            { text: "Import/Export", link: "/guide/import-export" },
          ],
        },
        {
          text: "Examples",
          items: [
            { text: "Real-World Setup", link: "/guide/real-world-example" },
          ],
        },
      ],
      "/providers/": [
        {
          text: "Providers",
          items: [{ text: "Overview", link: "/providers/overview" }],
        },
        {
          text: "Encryption (in git)",
          items: [
            { text: "Age Encryption", link: "/providers/age" },
            { text: "AWS KMS", link: "/providers/aws-kms" },
            { text: "Azure Key Vault Keys", link: "/providers/azure-kms" },
            { text: "Google Cloud KMS", link: "/providers/gcp-kms" },
          ],
        },
        {
          text: "Cloud Secret Storage",
          items: [
            { text: "AWS Secrets Manager", link: "/providers/aws-sm" },
            { text: "Azure Key Vault Secrets", link: "/providers/azure-sm" },
            { text: "GCP Secret Manager", link: "/providers/gcp-sm" },
            { text: "HashiCorp Vault", link: "/providers/vault" },
          ],
        },
        {
          text: "Password Managers",
          items: [
            { text: "1Password", link: "/providers/1password" },
            { text: "Bitwarden", link: "/providers/bitwarden" },
          ],
        },
        {
          text: "Local Storage",
          items: [
            { text: "OS Keychain", link: "/providers/keychain" },
            { text: "Plain Text", link: "/providers/plain" },
          ],
        },
      ],
      "/reference/": [
        {
          text: "Reference",
          items: [
            { text: "Commands", link: "/reference/commands" },
            { text: "Environment Variables", link: "/reference/environment" },
            { text: "Configuration", link: "/reference/configuration" },
          ],
        },
      ],
    },

    socialLinks: [{ icon: "github", link: "https://github.com/jdx/fnox" }],

    footer: {
      message: "Released under the MIT License.",
      copyright: "Copyright © 2024-present Jeff Dickey",
    },

    search: {
      provider: "local",
    },
  },
});
