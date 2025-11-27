import { defineConfig } from "vitepress";
import spec from "../cli/commands.json" with { type: "json" };

/**
 * @typedef {Object} Command
 * @property {Record<string, Command & { hide?: boolean; full_cmd: string[] }>} subcommands
 */

/**
 * @param {Command} cmd
 * @returns {string[][]}
 */
function getCommands(cmd) {
  const commands = [];
  for (const [name, sub] of Object.entries(cmd.subcommands)) {
    if (sub.hide) continue;
    commands.push(sub.full_cmd);
    commands.push(...getCommands(sub));
  }
  return commands;
}

const commands = getCommands(spec.cmd);

export default defineConfig({
  title: "fnox",
  description: "Fort Knox for your secrets",
  base: "/",
  appearance: "dark",

  themeConfig: {
    logo: "/logo.svg",

    nav: [
      { text: "Guide", link: "/guide/what-is-fnox" },
      { text: "Providers", link: "/providers/overview" },
      { text: "CLI Reference", link: "/cli/" },
      { text: "Reference", link: "/reference/environment" },
    ],

    sidebar: [
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
      {
        text: "Providers",
        items: [
          { text: "Overview", link: "/providers/overview" },
          {
            text: "Encryption (in git)",
            collapsed: true,
            items: [
              { text: "Age Encryption", link: "/providers/age" },
              { text: "AWS KMS", link: "/providers/aws-kms" },
              { text: "Azure Key Vault Keys", link: "/providers/azure-kms" },
              { text: "Google Cloud KMS", link: "/providers/gcp-kms" },
            ],
          },
          {
            text: "Cloud Secret Storage",
            collapsed: true,
            items: [
              { text: "AWS Secrets Manager", link: "/providers/aws-sm" },
              { text: "Azure Key Vault Secrets", link: "/providers/azure-sm" },
              { text: "GCP Secret Manager", link: "/providers/gcp-sm" },
              { text: "HashiCorp Vault", link: "/providers/vault" },
            ],
          },
          {
            text: "Password Managers & Secret Services",
            collapsed: true,
            items: [
              { text: "1Password", link: "/providers/1password" },
              { text: "Bitwarden", link: "/providers/bitwarden" },
              { text: "Infisical", link: "/providers/infisical" },
            ],
          },
          {
            text: "Local Storage",
            collapsed: true,
            items: [
              { text: "OS Keychain", link: "/providers/keychain" },
              { text: "KeePass", link: "/providers/keepass" },
              { text: "password-store", link: "/providers/password-store" },
              { text: "Plain Text", link: "/providers/plain" },
            ],
          },
        ],
      },
      {
        text: "CLI Reference",
        link: "/cli/",
        items: commands.map((cmd) => ({
          text: cmd.join(" "),
          link: `/cli/${cmd.join("/")}`,
        })),
      },
      {
        text: "Reference",
        items: [
          { text: "Environment Variables", link: "/reference/environment" },
          { text: "Configuration", link: "/reference/configuration" },
        ],
      },
    ],

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
