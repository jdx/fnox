---
description: "A static design proposal for pairing Secure Enclave decryption with the fnox memory cache."
---

# Touch ID session unlock concept

<style>
.touch-concept { --gold: var(--vp-c-brand-1); --line: var(--vp-c-divider); --muted: var(--vp-c-text-2); color: var(--vp-c-text-1); }
.touch-concept .brand { display: flex; align-items: center; gap: 12px; margin: 2rem 0 3rem; }
.touch-concept .brand img { width: 42px; height: 42px; }
.touch-concept .brand span { color: var(--muted); font-size: 13px; }
.touch-concept .eyebrow { color: var(--gold); font-size: 12px; font-weight: 700; letter-spacing: .13em; text-transform: uppercase; }
.touch-concept h2 { max-width: 680px; font-size: clamp(34px, 6vw, 55px); line-height: 1.04; letter-spacing: -.045em; }
.touch-concept .intro { max-width: 660px; color: var(--vp-c-text-2); font-size: 17px; }
.touch-concept .layout { display: grid; grid-template-columns: minmax(0, 1.05fr) minmax(0, .95fr); gap: 18px; margin-top: 30px; }
.touch-concept .card { padding: 22px; border: 1px solid var(--line); border-radius: 14px; background: var(--vp-c-bg-alt); min-width: 0; overflow-wrap: anywhere; }
.touch-concept .card h3 { margin-top: 0; }
.touch-concept .state { color: var(--vp-c-brand-1); font-weight: 650; }
.touch-concept dl { margin: 16px 0 0; }
.touch-concept .row { display: flex; justify-content: space-between; gap: 16px; padding: 12px 0; border-top: 1px solid var(--line); }
.touch-concept dt { color: var(--muted); }
.touch-concept dd { margin: 0; min-width: 0; overflow-wrap: anywhere; text-align: right; font-weight: 550; }
.touch-concept button { width: 100%; margin-top: 18px; padding: 11px; border: 1px solid var(--vp-button-brand-border); border-radius: 8px; background: var(--vp-button-brand-bg); color: var(--vp-button-brand-text); font: inherit; font-weight: 750; }
.touch-concept .callout { border-left: 2px solid var(--gold); padding: 2px 0 2px 14px; color: var(--vp-c-text-2); }
.touch-concept ol { padding-left: 20px; color: var(--vp-c-text-2); }
.touch-concept li { padding: 5px 0; }
.touch-concept .badge { display: inline-block; padding: 5px 9px; border: 1px solid var(--line); border-radius: 99px; color: var(--vp-c-brand-1); font-size: 11px; font-weight: 700; letter-spacing: .08em; text-transform: uppercase; }
.touch-concept .note { margin-top: 22px; color: var(--muted); font-size: 12px; }
@media (max-width: 700px) { .touch-concept .layout { grid-template-columns: 1fr; } }
</style>

<div class="touch-concept">
  <div class="brand"><img src="/logo.svg" alt="" width="42" height="42" decoding="async" /><div><strong>fnox</strong><br /><span>Credential session · concept</span></div></div>
  <p class="eyebrow">Touch ID session unlock</p>

  <h2>Reuse cached secrets.<br />Approve new reads when needed.</h2>

  <p class="intro">A proposed view for combining Secure Enclave decryption with fnox’s optional memory daemon. Secrets stay out of the interface; macOS owns the biometric prompt.</p>

  <div class="layout">
    <section class="card">
      <h3>Local session</h3>
      <p class="state">● Unlocked · stored in memory</p>
      <dl>
        <div class="row"><dt>Profile</dt><dd>work</dd></div>
        <div class="row"><dt>Unlock method</dt><dd>Secure Enclave</dd></div>
        <div class="row"><dt>Idle timeout</dt><dd>8 hours</dd></div>
        <div class="row"><dt>Cached values</dt><dd>3 secrets</dd></div>
      </dl>
      <button type="button" disabled aria-describedby="concept-note">Clear session cache</button>
    </section>
    <section class="card">
      <h3>What happens</h3>
      <p class="callout"><strong>First read:</strong> the encrypted local cache is decrypted by age-plugin-se. macOS may ask for Touch ID, according to the key’s access policy.</p>
      <ol>
        <li>The daemon keeps cacheable resolved values in RAM. A secret or original provider with <code>daemon_cache = false</code> is resolved again on each read.</li>
        <li>Reads for the same purpose can reuse a matching cache entry without another biometric check.</li>
        <li>Uncached values, changed profile/configuration/credentials/environment, or an explicit refresh can prompt again.</li>
        <li>Clear or stop the daemon to drop cached values.</li>
      </ol>
      <span class="badge">Native biometric prompt</span>
    </section>
  </div>
  <p class="note" id="concept-note">Static design proposal only; this is not an implemented fnox screen and the button is illustrative. Real Touch ID confirmation must be provided by macOS.</p>
</div>
