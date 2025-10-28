# fnox Documentation

This directory contains the VitePress documentation for fnox.

## Local Development

```bash
# Install dependencies
npm install

# Start dev server
npm run docs:dev

# Build for production
npm run docs:build

# Preview production build
npm run docs:preview
```

## Deployment

The documentation is automatically deployed to GitHub Pages on every push to `main` via the `.github/workflows/docs.yml` workflow.

### First-Time Setup

To enable GitHub Pages for this repository:

1. Go to **Settings** → **Pages** in the GitHub repository
2. Under **Source**, select **GitHub Actions**
3. The workflow will automatically deploy on the next push to `main`

The documentation will be available at: https://fnox.jdx.dev/

## Structure

- `docs/` - Documentation root
  - `index.md` - Homepage
  - `guide/` - User guides
  - `providers/` - Provider-specific documentation
  - `reference/` - Reference documentation
  - `.vitepress/` - VitePress configuration
    - `config.mjs` - Site configuration
