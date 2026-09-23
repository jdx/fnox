<script setup>
import { ref } from "vue";

const storage = ref("vault");
const copyStatus = ref("");
async function copyInstall() {
  try {
    await navigator.clipboard.writeText("mise use -g fnox");
    copyStatus.value = "Copied";
  } catch {
    copyStatus.value = "Select the command to copy it";
  }
}
</script>

<template>
  <main class="fnox-home">
    <section class="home-hero" aria-labelledby="home-title">
      <div class="hero-copy">
        <h1 id="home-title">Secret management for development and CI</h1>
        <p class="hero-lead">
          Load secrets from encrypted files, password managers, and cloud
          services into your application’s environment. Configure where each
          value comes from in <code>fnox.toml</code>.
        </p>
        <div class="hero-actions">
          <a class="home-button primary" href="/guide/quick-start"
            >Get started <span aria-hidden="true">↗</span></a
          >
          <a class="home-button secondary" href="/providers/overview"
            >Find your provider <span aria-hidden="true">→</span></a
          >
        </div>
        <div class="install-command">
          <span class="prompt" aria-hidden="true">$</span>
          <code>mise use -g fnox</code>
          <button
            type="button"
            aria-label="Copy installation command"
            @click="copyInstall"
          >
            Copy
          </button>
        </div>
        <p class="install-note" aria-live="polite">
          {{ copyStatus || "Open source · MIT licensed · Built in Rust" }}
        </p>
      </div>
      <div
        class="hero-demo"
        aria-label="Example fnox configuration and command"
      >
        <div class="demo-topbar">
          <div class="demo-file">
            <img src="/logo.svg" alt="" width="24" height="24" /> fnox.toml
          </div>
          <span class="demo-label">COMMIT THE CONFIG</span>
        </div>
        <div
          class="storage-switch"
          role="group"
          aria-label="Example storage model"
        >
          <button
            type="button"
            :aria-pressed="storage === 'vault'"
            @click="storage = 'vault'"
          >
            Vault references
          </button>
          <button
            type="button"
            :aria-pressed="storage === 'encrypted'"
            @click="storage = 'encrypted'"
          >
            Encrypted in git
          </button>
        </div>
        <!-- Keep both examples rendered for VitePress's static-content hydration. -->
        <pre
          v-show="storage === 'vault'"
        ><code><span class="code-comment"># Connect the vault you already use</span>
<span class="code-section">[providers.op]</span>
type = <span class="code-string">"1password"</span>
vault = <span class="code-string">"Engineering"</span>

<span class="code-section">[secrets.DATABASE_URL]</span>
provider = <span class="code-string">"op"</span>
value = <span class="code-string">"Database/url"</span></code></pre>
        <pre
          v-show="storage === 'encrypted'"
        ><code><span class="code-comment"># fnox set writes the ciphertext for you</span>
<span class="code-section">[providers.age]</span>
type = <span class="code-string">"age"</span>
recipients = <span class="code-string">["age1…"]</span>

<span class="code-section">[secrets.DATABASE_URL]</span>
provider = <span class="code-string">"age"</span>
value = <span class="code-string">"YWdlLWVuY3J5cHRpb24…"</span></code></pre>
        <div class="demo-run">
          <span class="demo-label">RUN WITH SECRETS</span>
          <pre><code><span class="prompt">$</span> fnox exec -- npm start</code></pre>
          <p>
            <span aria-hidden="true">↳</span> DATABASE_URL is available to your
            app.
          </p>
        </div>
        <p class="demo-caption">
          {{
            storage === "vault"
              ? "Commit the vault reference without putting the secret value in git."
              : "Ciphertext and recipient are abbreviated. Keep your private key outside git."
          }}
        </p>
      </div>
    </section>

    <section class="provider-strip" aria-label="Supported providers">
      <span class="strip-label">SUPPORTED PROVIDERS</span>
      <div>
        <a href="/providers/age">age</a>
        <a href="/providers/1password">1Password</a>
        <a href="/providers/aws-sm">AWS</a>
        <a href="/providers/azure-sm">Azure</a>
        <a href="/providers/gcp-sm">Google Cloud</a>
        <a href="/providers/bitwarden">Bitwarden</a>
        <a href="/providers/vault">Vault</a>
        <a class="all-providers" href="/providers/overview"
          >All providers <span aria-hidden="true">→</span></a
        >
      </div>
    </section>

    <section class="home-section" aria-labelledby="workflow-title">
      <div class="section-heading">
        <div>
          <h2 id="workflow-title">Choose where secrets are stored</h2>
        </div>
        <p>
          Each secret can use a different provider, so you can combine encrypted
          values with references to your team’s existing vaults.
        </p>
      </div>
      <div class="workflow-grid">
        <a class="workflow" href="/guide/quick-start">
          <span class="workflow-number" aria-hidden="true">01 / ENCRYPT</span>
          <h3>Encrypted values in git</h3>
          <p>
            Encrypt with age, a hardware key, or cloud KMS. Review configuration
            alongside your code and share access through public recipients or
            provider permissions.
          </p>
          <span class="text-link"
            >Start with age <span aria-hidden="true">↗</span></span
          >
        </a>
        <a class="workflow" href="/guide/golden-path">
          <span class="workflow-number" aria-hidden="true">02 / CONNECT</span>
          <h3>Existing vaults</h3>
          <p>
            Reference the secrets your team already manages. Add a personal
            encrypted cache with fnox sync for local, offline access using age.
          </p>
          <span class="text-link"
            >Connect a vault <span aria-hidden="true">↗</span></span
          >
        </a>
        <a class="workflow" href="/guide/profiles">
          <span class="workflow-number" aria-hidden="true">03 / RUN</span>
          <h3>Environment profiles</h3>
          <p>
            Use profiles for development, staging, and production. Change the
            secret source without changing the way you launch your application.
          </p>
          <span class="text-link"
            >Work with profiles <span aria-hidden="true">↗</span></span
          >
        </a>
      </div>
    </section>

    <section class="home-section everyday" aria-labelledby="everyday-title">
      <div class="everyday-intro">
        <h2 id="everyday-title">Use secrets in your workflow</h2>
        <p>
          Load secrets when you enter a project, cache repeated reads, or issue
          temporary credentials when a service supports them.
        </p>
        <a class="text-link" href="/guide/how-it-works"
          >See how fnox works <span aria-hidden="true">→</span></a
        >
      </div>
      <div class="capability-list">
        <a href="/guide/shell-integration"
          ><div>
            <h3>Shell integration</h3>
            <p>
              Shell hooks load and unload values as you move between projects.
            </p>
          </div>
          <span aria-hidden="true">↗</span></a
        >
        <a href="/guide/daemon"
          ><div>
            <h3>In-memory caching</h3>
            <p>
              An opt-in daemon keeps resolved values in memory during your
              session.
            </p>
          </div>
          <span aria-hidden="true">↗</span></a
        >
        <a href="/guide/leases"
          ><div>
            <h3>Temporary credentials</h3>
            <p>
              Create temporary credentials with AWS STS, GitHub Apps, Vault, and
              more.
            </p>
          </div>
          <span aria-hidden="true">↗</span></a
        >
        <a href="/guide/proxy"
          ><div>
            <h3>Credentials for agent requests</h3>
            <p>
              Pass placeholders to an agent and inject real values into matching
              HTTPS requests.
            </p>
          </div>
          <span aria-hidden="true">↗</span></a
        >
      </div>
    </section>

    <section class="home-start" aria-labelledby="start-title">
      <img src="/logo.svg" alt="" width="64" height="64" loading="lazy" />
      <div>
        <h2 id="start-title">Set up your first provider</h2>
        <p>Install fnox, configure a provider, and run your first command.</p>
      </div>
      <a class="home-button primary" href="/guide/quick-start"
        >Follow the quick start <span aria-hidden="true">→</span></a
      >
    </section>
  </main>
</template>
