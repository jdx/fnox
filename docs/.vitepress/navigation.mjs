const page = (text, link) => ({ text, link });

const start = {
  text: "Start here",
  items: [
    page("What is fnox?", "/guide/what-is-fnox"),
    page("Installation", "/guide/installation"),
    page("Quick start", "/guide/quick-start"),
    page("Connect a vault", "/guide/golden-path"),
    page("How fnox works", "/guide/how-it-works"),
  ],
};
const reference = {
  text: "Reference",
  items: [
    page("Commands", "/cli/"),
    page("Configuration", "/reference/configuration"),
    page("Environment variables", "/reference/environment"),
    page("Troubleshooting", "/guide/troubleshooting"),
    page("Contributing", "/contributing"),
  ],
};
const guide = [
  start,
  {
    text: "Everyday use",
    items: [
      page("Run commands", "/cli/exec"),
      page("Shell integration", "/guide/shell-integration"),
      page("Profiles", "/guide/profiles"),
      page("Config files and overrides", "/guide/hierarchical-config"),
      page("Missing secrets and defaults", "/guide/missing-secrets"),
      page("Import and export", "/guide/import-export"),
      page("Terminal dashboard", "/guide/tui"),
    ],
  },
  {
    text: "Caching and credentials",
    items: [
      page("Sync a local cache", "/guide/sync"),
      page("Cache in memory", "/guide/daemon"),
      page("Credential leases", "/guide/leases"),
      page("Credential proxy", "/guide/proxy"),
      page("MCP server", "/guide/mcp"),
    ],
  },
  {
    text: "Recipes",
    items: [
      page("mise tasks", "/guide/mise-integration"),
      page("Development to production", "/guide/real-world-example"),
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
      ["Plaintext defaults", "plain"],
    ],
  ],
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
    ["Read and run", ["get", "list", "exec", "check", "export", "tui"]],
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
    ["Caching and agents", ["daemon", "lease", "proxy", "mcp"]],
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
