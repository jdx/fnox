---
description: "Push fnox secrets to HCP Terraform and Terraform Enterprise workspace variables, as sensitive Terraform or environment variables."
---

# HCP Terraform

The `hcp-terraform` target sets [workspace variables](https://developer.hashicorp.com/terraform/cloud-docs/workspaces/variables) in HCP Terraform or Terraform Enterprise through the [variables API](https://developer.hashicorp.com/terraform/cloud-docs/api-docs/workspace-variables). It updates the variable with the same key and category, or creates one.

|                     |                                                       |
| ------------------- | ----------------------------------------------------- |
| Config type         | `hcp-terraform`                                       |
| Requires            | An API token that can write the workspace's variables |
| Readable afterwards | No while `sensitive = true` (the default)             |

## Quick start

```toml
[targets.tfc-prod]
type = "hcp-terraform"
organization = "acme"
workspace = "prod"
category = "env"

[secrets]
AWS_SECRET_ACCESS_KEY = { provider = "op", value = "AWS/prod secret", push = ["tfc-prod"] }
```

## Configuration

| Field          | Default                    | Description                                                               |
| -------------- | -------------------------- | ------------------------------------------------------------------------- |
| `url`          | `https://app.terraform.io` | Base URL of HCP Terraform or your Terraform Enterprise instance.          |
| `organization` | required                   | Organization that owns the workspace.                                     |
| `workspace`    | required                   | Workspace name.                                                           |
| `category`     | required                   | `"terraform"` for an input variable, `"env"` for an environment variable. |
| `sensitive`    | `true`                     | Write the value once and never show it again.                             |
| `hcl`          | `false`                    | Parse the value as HCL instead of a string.                               |
| `description`  | none                       | Description shown in HCP Terraform.                                       |

## Authentication

fnox uses the first token it finds:

1. `TF_TOKEN_<host>`, the variable Terraform itself reads, such as `TF_TOKEN_app_terraform_io`. Periods in the host become `_` and hyphens become `__`.
2. `TFE_TOKEN`.
3. The token `terraform login` saved in `~/.terraform.d/credentials.tfrc.json` (`%APPDATA%\terraform.d\credentials.tfrc.json` on Windows).

## Notes

- HCP Terraform does not let a sensitive variable become non-sensitive, so `sensitive = false` fails for a variable that is already sensitive.
