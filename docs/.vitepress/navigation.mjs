const page = (text, link) => ({ text, link });

const start = {
  text: "Getting started",
  items: [
    page("What is fnox?", "/guide/what-is-fnox"),
    page("Installation", "/guide/installation"),
    page("Quick start", "/guide/quick-start"),
    page("Use an existing vault", "/guide/existing-vault"),
    page("How fnox works", "/guide/how-it-works"),
  ],
};
const reference = {
  text: "Reference",
  items: [
    page("Commands", "/cli/"),
    page("Configuration", "/reference/configuration"),
    page("Environment variables", "/reference/environment"),
    page("fnox env JSON", "/reference/env-json"),
    page("Troubleshooting", "/guide/troubleshooting"),
    page("Contributing", "/contributing"),
  ],
};
const guide = [
  start,
  {
    text: "Daily use",
    items: [
      page("Running commands", "/guide/running-commands"),
      page("Shell integration", "/guide/shell-integration"),
      page("Profiles", "/guide/profiles"),
      page("Config files", "/guide/config-files"),
      page("Missing secrets", "/guide/missing-secrets"),
      page("Import and export", "/guide/import-export"),
      page("Terminal UI", "/guide/tui"),
    ],
  },
  {
    text: "Teams and CI",
    items: [
      page("Team setup", "/guide/teams"),
      page("CI/CD", "/guide/ci"),
      page("Development to production", "/guide/dev-to-production"),
      page("mise", "/guide/mise-integration"),
    ],
  },
  {
    text: "Caching and credentials",
    items: [
      page("Local sync cache", "/guide/sync"),
      page("Memory cache (daemon)", "/guide/daemon"),
      page("Credential leases", "/guide/leases"),
      page("Credential proxy", "/guide/proxy"),
      page("MCP server", "/guide/mcp"),
      page("Audit log", "/guide/audit"),
    ],
  },
  reference,
];
const providerGroups = [
  [
    "Encryption in config",
    [
      ["age", "age"],
      ["FIDO2", "fido2"],
      ["YubiKey", "yubikey"],
      ["AWS KMS", "aws-kms"],
      ["Azure Key Vault Keys", "azure-kms"],
      ["Google Cloud KMS", "gcp-kms"],
    ],
  ],
  [
    "Cloud and hosted stores",
    [
      ["AWS Parameter Store", "aws-ps"],
      ["AWS Secrets Manager", "aws-sm"],
      ["Azure App Configuration", "azure-ac"],
      ["Azure Key Vault Secrets", "azure-sm"],
      ["Google Cloud Secret Manager", "gcp-sm"],
      ["Kubernetes Secrets", "kubernetes"],
      ["Bitwarden Secrets Manager", "bitwarden-sm"],
      ["Doppler", "doppler"],
      ["FOKS", "foks"],
      ["HashiCorp Vault", "vault"],
      ["Keeper Secrets Manager", "keeper-sm"],
    ],
  ],
  [
    "Password managers and services",
    [
      ["1Password", "1password"],
      ["Bitwarden", "bitwarden"],
      ["Enpass", "enpass"],
      ["Infisical", "infisical"],
      ["Passwordstate", "passwordstate"],
      ["Proton Pass", "proton-pass"],
    ],
  ],
  [
    "Local stores and defaults",
    [
      ["OS keychain", "keychain"],
      ["KeePass", "keepass"],
      ["password-store", "password-store"],
      ["gopass", "gopass"],
      ["Plaintext defaults", "plain"],
    ],
  ],
  ["Custom providers", [["Lua plugins", "lua"]]],
];
const providers = [
  {
    text: "Choose a provider",
    items: [page("Provider catalog", "/providers/overview")],
  },
  ...providerGroups.map(([text, entries]) => ({
    text,
    collapsed: false,
    items: entries.map(([name, slug]) => page(name, `/providers/${slug}`)),
  })),
  reference,
];
const leases = [
  {
    text: "Credential leases",
    items: [page("Overview and setup", "/guide/leases")],
  },
  {
    text: "Backends",
    items: [
      ["AWS STS", "aws-sts"],
      ["Azure Token", "azure-token"],
      ["Cloudflare", "cloudflare"],
      ["GCP IAM", "gcp-iam"],
      ["GitHub App", "github-app"],
      ["GitHub OAuth", "github-oauth"],
      ["HashiCorp Vault", "vault"],
      ["Custom command", "command"],
    ].map(([name, slug]) => page(name, `/leases/${slug}`)),
  },
  reference,
];

export function sidebar(commands) {
  const commandGroups = [
    ["Read and run", ["get", "list", "exec", "env", "check", "export", "tui"]],
    [
      "Configure and write",
      [
        "init",
        "set",
        "remove",
        "import",
        "sync",
        "reencrypt",
        "edit",
        "provider",
        "plugin",
        "profiles",
        "config-files",
      ],
    ],
    [
      "Shell and diagnostics",
      [
        "activate",
        "deactivate",
        "completion",
        "doctor",
        "scan",
        "version",
        "sponsors",
      ],
    ],
    ["Caching and agents", ["daemon", "lease", "proxy", "mcp", "audit"]],
  ];
  const cli = [
    {
      text: "CLI reference",
      items: [
        page("Command overview", "/cli/"),
        page("Global settings", "/cli/configuration"),
      ],
    },
    ...commandGroups.map(([text, names]) => ({
      text,
      items: names.map((name) => {
        const children = commands.filter(
          (cmd) => cmd[0] === name && cmd.length > 1,
        );
        return {
          ...page(`fnox ${name}`, `/cli/${name}`),
          ...(children.length
            ? {
                collapsed: true,
                items: children.map((cmd) =>
                  page(cmd.join(" "), `/cli/${cmd.join("/")}`),
                ),
              }
            : {}),
        };
      }),
    })),
    reference,
  ];
  return {
    "/guide/": guide,
    "/providers/": providers,
    "/leases/": leases,
    "/cli/": cli,
    "/reference/": [reference, start],
    "/": guide,
  };
}
