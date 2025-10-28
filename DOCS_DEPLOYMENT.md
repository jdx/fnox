# Documentation Deployment Setup

## What Was Done

A GitHub Actions workflow has been created to automatically deploy the VitePress documentation to GitHub Pages on every push to the `main` branch.

### Files Created/Modified

1. **`.github/workflows/docs.yml`** - GitHub Actions workflow for deployment
2. **`docs/README.md`** - Documentation for contributors
3. **`.gitignore`** - Updated to ignore VitePress build artifacts

## How It Works

The workflow:

1. Triggers on every push to `main` (and manual dispatch)
2. Checks out the repository
3. Sets up Node.js 20 with npm caching
4. Installs dependencies (`npm ci`)
5. Builds the VitePress site (`npm run docs:build`)
6. Deploys to GitHub Pages

## First-Time Setup Required

To enable GitHub Pages for this repository, you need to configure it once:

### Step 1: Enable GitHub Pages

1. Go to the repository on GitHub: https://github.com/jdx/fnox
2. Click **Settings** → **Pages** (in the left sidebar)
3. Under **Source**, select **GitHub Actions**
4. Save the changes

### Step 2: Push to Main

Once you push this workflow to the `main` branch, it will automatically:

- Build the documentation
- Deploy to GitHub Pages
- Make it available at: **https://jdx.github.io/fnox/**

## Testing Locally

Before pushing, you can test the documentation locally:

```bash
# Install dependencies (first time only)
npm install

# Start dev server (with hot reload)
npm run docs:dev
# Opens at http://localhost:5173/fnox/

# Build for production (test the build)
npm run docs:build

# Preview production build
npm run docs:preview
```

## Workflow Features

- ✅ **Automatic deployment** on every main push
- ✅ **Manual trigger** via workflow_dispatch (GitHub UI)
- ✅ **Concurrent deployment control** (prevents conflicts)
- ✅ **Proper permissions** for GitHub Pages
- ✅ **Build caching** for faster deployments
- ✅ **Artifact upload** for debugging

## Monitoring Deployments

After setup, you can monitor deployments:

1. Go to **Actions** tab in the GitHub repository
2. Look for "Deploy Docs" workflows
3. Each push to `main` will trigger a deployment
4. Deployment typically takes 1-2 minutes

## Configuration

The documentation is configured for GitHub Pages:

- **Base URL**: `/fnox/` (configured in `docs/.vitepress/config.mjs`)
- **Output Directory**: `docs/.vitepress/dist`
- **Node Version**: 20 (LTS)

## Troubleshooting

### If deployment fails:

1. Check the Actions tab for error details
2. Ensure GitHub Pages is set to "GitHub Actions" source
3. Verify the repository has Pages enabled in Settings
4. Check that the workflow has the necessary permissions

### If site is not accessible:

1. Wait a few minutes after first deployment
2. Clear browser cache
3. Check the Pages URL in Settings → Pages
4. Ensure the workflow completed successfully

## Next Steps

1. Commit all changes:

   ```bash
   git add .
   git commit -m "Add VitePress documentation and GitHub Pages deployment"
   git push origin main
   ```

2. Go to GitHub Settings → Pages and enable GitHub Actions as the source

3. Wait for the workflow to complete (check Actions tab)

4. Visit https://jdx.github.io/fnox/ to see your documentation!

## Maintenance

- Documentation updates are automatic on every main push
- No manual deployment needed
- The workflow will fail if the build fails (protecting production)
- You can manually trigger deployments via the Actions tab (workflow_dispatch)

## Cost

GitHub Pages is **free** for public repositories with unlimited bandwidth.
