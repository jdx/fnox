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
        <p class="eyebrow">
          <span aria-hidden="true" class="status-dot"></span> Fort Knox for your
          secrets
        </p>
        <h1 id="home-title">
          Your secrets.<br /><span>Where you need them.</span>
        </h1>
        <p class="hero-lead">
          From your vault to your terminal. Load secrets from encrypted files,
          password managers, and cloud services with one command.
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
              ? "The reference goes in git. The value stays in your vault."
              : "Ciphertext and recipient are abbreviated. Keep your private key outside git."
          }}
        </p>
      </div>
    </section>

    <section class="provider-strip" aria-label="Supported providers">
      <span class="strip-label">BRING YOUR OWN VAULT</span>
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
          <p class="eyebrow">ONE INTERFACE. YOUR INFRASTRUCTURE.</p>
          <h2 id="workflow-title">
            Keep your workflow.<br />Give secrets a home.
          </h2>
        </div>
        <p>
          Choose how to store each value. Your application keeps reading the
          same environment variables.
        </p>
      </div>
      <div class="workflow-grid">
        <a class="workflow" href="/guide/quick-start">
          <span class="workflow-number" aria-hidden="true">01 / ENCRYPT</span>
          <h3>A config you can commit.</h3>
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
          <h3>Your vault, in your terminal.</h3>
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
          <h3>Local today. CI tomorrow.</h3>
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
        <p class="eyebrow">LESS SECRET SHUFFLING</p>
        <h2 id="everyday-title">Ready for the<br />daily routine.</h2>
        <p>
          From a single project to a monorepo, keep secret handling close to the
          tools you use.
        </p>
        <a class="text-link" href="/guide/how-it-works"
          >See how fnox works <span aria-hidden="true">→</span></a
        >
      </div>
      <div class="capability-list">
        <a href="/guide/shell-integration"
          ><div>
            <h3>Enter a directory. Load its secrets.</h3>
            <p>
              Shell hooks load and unload values as you move between projects.
            </p>
          </div>
          <span aria-hidden="true">↗</span></a
        >
        <a href="/guide/daemon"
          ><div>
            <h3>Make repeated reads faster.</h3>
            <p>
              An opt-in daemon keeps resolved values in memory during your
              session.
            </p>
          </div>
          <span aria-hidden="true">↗</span></a
        >
        <a href="/guide/leases"
          ><div>
            <h3>Give credentials an expiry.</h3>
            <p>
              Create temporary credentials with AWS STS, GitHub Apps, Vault, and
              more.
            </p>
          </div>
          <span aria-hidden="true">↗</span></a
        >
        <a href="/guide/proxy"
          ><div>
            <h3>Scope credentials to requests.</h3>
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
        <h2 id="start-title">Start with one secret.</h2>
        <p>Install fnox, configure a provider, and run your first command.</p>
      </div>
      <a class="home-button primary" href="/guide/quick-start"
        >Follow the quick start <span aria-hidden="true">→</span></a
      >
    </section>
  </main>
</template>
