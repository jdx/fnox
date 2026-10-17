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
        <h1 id="home-title">Your secrets, wherever they live</h1>
        <p class="hero-lead">
          fnox reads secrets from encrypted files, password managers, and cloud
          secret stores, and hands them to your program as environment
          variables. One <code>fnox.toml</code> says where each one lives. The
          same command works on your laptop and in CI.
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
          <span class="demo-label">COMMITTED TO GIT</span>
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
            Vault reference
          </button>
          <button
            type="button"
            :aria-pressed="storage === 'encrypted'"
            @click="storage = 'encrypted'"
          >
            Encrypted in git
          </button>
          <button
            type="button"
            :aria-pressed="storage === 'profiles'"
            @click="storage = 'profiles'"
          >
            Dev and prod
          </button>
        </div>
        <!-- Keep every example rendered for VitePress's static-content hydration. -->
        <pre
          v-show="storage === 'vault'"
        ><code><span class="code-comment"># Point at the vault you already use</span>
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
recipients = [<span class="code-string">"age1…"</span>]

<span class="code-section">[secrets.DATABASE_URL]</span>
provider = <span class="code-string">"age"</span>
value = <span class="code-string">"YWdl…"</span></code></pre>
        <pre
          v-show="storage === 'profiles'"
        ><code><span class="code-comment"># Development: encrypted in git</span>
<span class="code-section">[secrets.DATABASE_URL]</span>
provider = <span class="code-string">"age"</span>
value = <span class="code-string">"YWdl…"</span>

<span class="code-comment"># Production: AWS Secrets Manager</span>
<span class="code-section">[profiles.production.secrets.DATABASE_URL]</span>
provider = <span class="code-string">"aws"</span>
value = <span class="code-string">"db-url"</span></code></pre>
        <div class="demo-run">
          <span class="demo-label">RUN</span>
          <pre><code><span class="prompt">$</span> {{
            storage === "profiles"
              ? "fnox exec -P production -- ./deploy"
              : "fnox exec -- npm start"
          }}</code></pre>
          <p>
            <span aria-hidden="true">↳</span> Your app reads
            <code>DATABASE_URL</code> as usual.
          </p>
        </div>
        <p class="demo-caption">
          {{
            storage === "vault"
              ? "Only the item reference is committed. Each person reads it with their own vault login."
              : storage === "encrypted"
                ? "Only ciphertext and public keys are committed. Private keys stay on each machine."
                : "Same app, same variable. The profile picks the source. Provider blocks omitted."
          }}
        </p>
      </div>
    </section>

    <section class="provider-strip" aria-label="Supported providers">
      <span class="strip-label">WORKS WITH</span>
      <div>
        <a href="/providers/1password">1Password</a>
        <a href="/providers/bitwarden">Bitwarden</a>
        <a href="/providers/aws-sm">AWS</a>
        <a href="/providers/gcp-sm">Google Cloud</a>
        <a href="/providers/azure-sm">Azure</a>
        <a href="/providers/vault">HashiCorp Vault</a>
        <a href="/providers/doppler">Doppler</a>
        <a href="/providers/age">age</a>
        <a href="/providers/keychain">OS keychain</a>
        <a class="all-providers" href="/providers/overview"
          >All providers <span aria-hidden="true">→</span></a
        >
      </div>
    </section>

    <section class="home-section" aria-labelledby="workflow-title">
      <div class="section-heading">
        <div>
          <h2 id="workflow-title">Pick your starting point</h2>
        </div>
        <p>
          Each secret names its own provider, so you can start one way and mix
          in another later.
        </p>
      </div>
      <div class="workflow-grid">
        <a class="workflow" href="/guide/quick-start">
          <span class="workflow-number" aria-hidden="true">01 / ENCRYPT</span>
          <h3>No vault yet</h3>
          <p>
            Encrypt secrets into <code>fnox.toml</code> with age, a YubiKey, or
            a cloud KMS key. With age, share access by adding teammates' public
            keys.
          </p>
          <span class="text-link"
            >Quick start <span aria-hidden="true">↗</span></span
          >
        </a>
        <a class="workflow" href="/guide/existing-vault">
          <span class="workflow-number" aria-hidden="true">02 / CONNECT</span>
          <h3>A team vault</h3>
          <p>
            Commit references to 1Password, Bitwarden, AWS, or Vault items.
            Cache them locally with <code>fnox sync</code> for fast, offline
            reads.
          </p>
          <span class="text-link"
            >Use an existing vault <span aria-hidden="true">↗</span></span
          >
        </a>
        <a class="workflow" href="/guide/ci">
          <span class="workflow-number" aria-hidden="true">03 / SHIP</span>
          <h3>CI and production</h3>
          <p>
            Give the runner one credential and run the same
            <code>fnox exec</code>. Use profiles to switch to production
            sources.
          </p>
          <span class="text-link"
            >Set up CI <span aria-hidden="true">↗</span></span
          >
        </a>
      </div>
    </section>

    <section class="home-section everyday" aria-labelledby="everyday-title">
      <div class="everyday-intro">
        <h2 id="everyday-title">Built for daily work</h2>
        <p>
          Secrets load when you enter a project, stay fast when your vault is
          remote, and stay out of reach of tools that shouldn't have them.
        </p>
        <a class="text-link" href="/guide/how-it-works"
          >How fnox works <span aria-hidden="true">→</span></a
        >
      </div>
      <div class="capability-list">
        <a href="/guide/shell-integration"
          ><div>
            <h3>Shell integration</h3>
            <p>
              Load a project's secrets on <code>cd</code> and unload them when
              you leave. Bash, Zsh, Fish, Nushell, and PowerShell.
            </p>
          </div>
          <span aria-hidden="true">↗</span></a
        >
        <a href="/guide/sync"
          ><div>
            <h3>Offline cache</h3>
            <p>
              Keep an encrypted copy of vault secrets on your machine,
              optionally behind Touch ID or a YubiKey.
            </p>
          </div>
          <span aria-hidden="true">↗</span></a
        >
        <a href="/guide/leases"
          ><div>
            <h3>Short-lived credentials</h3>
            <p>
              Hand commands temporary AWS, GCP, Azure, GitHub, or Vault
              credentials instead of long-lived keys.
            </p>
          </div>
          <span aria-hidden="true">↗</span></a
        >
        <a href="/guide/proxy"
          ><div>
            <h3>Safe for AI agents</h3>
            <p>
              Give an agent placeholders and inject real credentials only into
              the API requests you allow.
            </p>
          </div>
          <span aria-hidden="true">↗</span></a
        >
      </div>
    </section>

    <section class="home-start" aria-labelledby="start-title">
      <img src="/logo.svg" alt="" width="64" height="64" loading="lazy" />
      <div>
        <h2 id="start-title">Encrypt your first secret</h2>
        <p>Five minutes, no account required.</p>
      </div>
      <a class="home-button primary" href="/guide/quick-start"
        >Follow the quick start <span aria-hidden="true">→</span></a
      >
    </section>
  </main>
</template>
