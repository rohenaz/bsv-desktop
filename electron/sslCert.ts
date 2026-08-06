import { app, dialog, net, BrowserWindow } from 'electron';
import path from 'path';
import fs from 'fs';
import os from 'os';
import forge from 'node-forge';
import { execFile } from 'child_process';
import { promisify } from 'util';

const execFileAsync = promisify(execFile);

interface CertificateKeyPair {
  cert: string;
  key: string;
  certPath: string;
}

/**
 * Generates or loads a self-signed certificate for HTTPS server
 * Certificate is cached in user data directory for reuse
 */
export async function generateSelfSignedCert(): Promise<CertificateKeyPair> {
  const userDataPath = app.getPath('userData');
  const certDir = path.join(userDataPath, 'certs');
  const certPath = path.join(certDir, 'server.crt');
  const keyPath = path.join(certDir, 'server.key');

  // Check if certificate already exists and is valid
  if (fs.existsSync(certPath) && fs.existsSync(keyPath)) {
    try {
      const cert = fs.readFileSync(certPath, 'utf8');
      const key = fs.readFileSync(keyPath, 'utf8');

      // Parse and validate certificate expiration
      const forgeCert = forge.pki.certificateFromPem(cert);
      const now = new Date();

      if (forgeCert.validity.notAfter > now) {
        console.log('Using existing SSL certificate');
        return { cert, key, certPath };
      } else {
        console.log('Existing certificate expired, generating new one');
      }
    } catch (error) {
      console.log('Failed to load existing certificate, generating new one:', error);
    }
  }

  // Generate new certificate
  console.log('Generating new self-signed SSL certificate...');

  // Create directory if it doesn't exist
  if (!fs.existsSync(certDir)) {
    fs.mkdirSync(certDir, { recursive: true });
  }

  // Generate key pair
  const keys = forge.pki.rsa.generateKeyPair(2048);

  // Create certificate
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = '01';

  // Valid for 1 year
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);

  // Set certificate attributes
  const attrs = [
    { name: 'commonName', value: 'localhost' },
    { name: 'countryName', value: 'US' },
    { shortName: 'ST', value: 'California' },
    { name: 'localityName', value: 'San Francisco' },
    { name: 'organizationName', value: 'BSV Desktop' },
    { shortName: 'OU', value: 'Development' }
  ];

  cert.setSubject(attrs);
  cert.setIssuer(attrs);

  // Add extensions
  cert.setExtensions([
    {
      name: 'basicConstraints',
      cA: false
    },
    {
      name: 'keyUsage',
      digitalSignature: true,
      keyEncipherment: true
    },
    {
      name: 'extKeyUsage',
      serverAuth: true
    },
    {
      name: 'subjectAltName',
      altNames: [
        {
          type: 2, // DNS
          value: 'localhost'
        },
        {
          type: 7, // IP
          ip: '127.0.0.1'
        }
      ]
    }
  ]);

  // Self-sign certificate
  cert.sign(keys.privateKey, forge.md.sha256.create());

  // Convert to PEM format
  const certPem = forge.pki.certificateToPem(cert);
  const keyPem = forge.pki.privateKeyToPem(keys.privateKey);

  // Save to disk
  fs.writeFileSync(certPath, certPem);
  fs.writeFileSync(keyPath, keyPem);

  console.log('SSL certificate generated and saved');

  return {
    cert: certPem,
    key: keyPem,
    certPath
  };
}

/**
 * SHA-1 thumbprint of a PEM certificate, lowercase hex.
 *
 * This is the identifier certutil prints as "Cert Hash(sha1)" and accepts as a
 * certificate ID, so it lets us ask Windows about the exact certificate we are
 * serving rather than about anything that happens to share a name.
 */
export function getCertSha1Thumbprint(certPem: string): string {
  const cert = forge.pki.certificateFromPem(certPem);
  const der = forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes();
  return forge.md.sha1.create().update(der).digest().toHex().toLowerCase();
}

/**
 * Distinguishes "certutil ran and said the certificate is not there" from
 * "certutil could not run at all".
 *
 * NTE_NOT_FOUND (0x80090011 / -2146893807) is certutil's genuine answer for an
 * absent certificate. Anything else — ENOENT because the binary is missing, a
 * WDAC/AppLocker denial, an EDR kill — means we learned nothing and should try
 * another route rather than reporting the certificate as untrusted.
 */
function isMissingCertError(error: unknown): boolean {
  const err = error as { code?: number | string; stdout?: string; stderr?: string };

  // Windows exit codes are DWORDs, and whether this one surfaces signed or
  // unsigned is not worth depending on, so accept both. The output check below
  // is the reliable signal: certutil always prints the code.
  if (err?.code === -2146893807 || err?.code === 2148073489) return true;

  const output = `${err?.stdout ?? ''}${err?.stderr ?? ''}`;
  return output.includes('0x80090011') || output.includes('NTE_NOT_FOUND');
}

/** Runs a PowerShell one-liner, resolving its trimmed stdout. */
async function runPowerShell(script: string): Promise<string> {
  const { stdout } = await execFileAsync('powershell', [
    '-NoProfile',
    '-NonInteractive',
    '-ExecutionPolicy', 'Bypass',
    '-Command', script
  ]);
  return stdout.trim();
}

/** Single-quoted PowerShell literal, with embedded quotes escaped. */
function psQuote(value: string): string {
  return `'${value.replace(/'/g, "''")}'`;
}

/**
 * certutil-free trust lookup, for machines where certutil is blocked.
 */
async function isCertInStoreViaPowerShell(thumbprint: string): Promise<boolean> {
  try {
    const out = await runPowerShell(
      `if (Test-Path ${psQuote(`Cert:\\CurrentUser\\Root\\${thumbprint.toUpperCase()}`)}) { 'FOUND' } else { 'MISSING' }`
    );
    return out.includes('FOUND');
  } catch (error) {
    console.error('PowerShell trust check also unavailable:', error);
    return false;
  }
}

/**
 * Reports whether group policy restricts user-installed root certificates.
 *
 * This is only ever used to explain a failure we have already observed, never
 * to predict one: the exact flag semantics are not worth guessing at, but the
 * mere presence of the policy is a strong hint about why a certificate that
 * installed successfully is still not being honoured.
 */
async function hasUserRootRestrictionPolicy(): Promise<boolean> {
  try {
    const { stdout } = await execFileAsync('reg', [
      'query',
      'HKLM\\SOFTWARE\\Policies\\Microsoft\\SystemCertificates\\Root\\ProtectedRoots',
      '/v', 'Flags'
    ]);
    return stdout.includes('Flags');
  } catch {
    return false;
  }
}

/**
 * Local wallet bridge ports.
 *
 * Defined here rather than in httpServer so the trust probe below and the
 * listeners cannot drift apart: a probe pointed at a port nobody serves would
 * fail silently and look like a trust problem. httpServer imports these.
 */
export const HTTPS_BRIDGE_PORT = 2121;
export const HTTP_BRIDGE_PORT = 3321;

/** Probed to verify trust for real. Any HTTP response means TLS was accepted. */
const HTTPS_PROBE_URL = `https://127.0.0.1:${HTTPS_BRIDGE_PORT}/manifest.json`;
const HTTPS_PROBE_TIMEOUT_MS = 5_000;

/**
 * Asks the question that actually matters: does a real client accept our HTTPS
 * endpoint?
 *
 * Electron's net module uses Chromium's network stack, which validates against
 * the Windows certificate store exactly like the browsers and web apps that
 * talk to the bridge. Node's own https client would not — it uses its bundled
 * CA list and ignores the Windows store entirely, so it cannot answer this.
 *
 * This is ground truth, and it is why it runs before any store inspection.
 * Store-based checks are heuristics about a store, and on managed Windows
 * machines the store can say "installed" while the certificate is still not
 * honoured — most notably when group policy forbids user-installed root CAs
 * from being used for validation, in which case the install genuinely succeeds
 * and is then quietly ignored. Probing the endpoint cannot be fooled by that.
 *
 * Returns null when the probe is inconclusive (server not up, timed out), so
 * callers can fall back to inspecting the store rather than treating an
 * unknown as untrusted and prompting needlessly.
 */
async function isCertAcceptedByClients(): Promise<boolean | null> {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (result: boolean | null) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(result);
    };

    const timer = setTimeout(() => finish(null), HTTPS_PROBE_TIMEOUT_MS);

    let request: Electron.ClientRequest;
    try {
      request = net.request({ method: 'GET', url: HTTPS_PROBE_URL });
    } catch (error) {
      console.log('Certificate probe could not be started:', error);
      finish(null);
      return;
    }

    // Any HTTP response at all means the TLS handshake was accepted; the status
    // code is irrelevant.
    request.on('response', (response) => {
      response.on('data', () => { /* drain */ });
      response.on('end', () => { /* no-op */ });
      finish(true);
    });

    request.on('error', (error: Error & { code?: string }) => {
      const code = error.code ?? '';
      // Connection-level failures mean the server is not reachable yet, which
      // says nothing about trust. Certificate failures are a real answer.
      if (code === 'ECONNREFUSED' || code === 'ECONNRESET' || code === 'ENOTFOUND') {
        console.log(`Certificate probe inconclusive (${code}): bridge not reachable`);
        finish(null);
        return;
      }
      console.log(`Certificate probe rejected the endpoint: ${code || error.message}`);
      finish(false);
    });

    try {
      request.end();
    } catch (error) {
      console.log('Certificate probe could not be sent:', error);
      finish(null);
    }
  });
}

/**
 * Checks if the certificate is trusted by the system
 */
async function isCertTrusted(certPath: string): Promise<boolean> {
  try {
    if (process.platform === 'darwin') {
      // macOS: Check if cert is in user keychain (CN is "localhost", not org name)
      const loginKeychain = path.join(os.homedir(), 'Library/Keychains/login.keychain-db');
      await execFileAsync('security', ['find-certificate', '-c', 'localhost', '-p', loginKeychain]);
      // Also verify it's actually trusted, not just present
      await execFileAsync('security', ['verify-cert', '-c', certPath, '-p', 'ssl', '-s', 'localhost']);
      return true;
    } else if (process.platform === 'win32') {
      // Windows: look the certificate up in the user's trusted root store by its
      // SHA-1 thumbprint.
      //
      // This used to search for "BSV Desktop", which never matched: certutil
      // resolves a name-style certificate ID against the common name, and the
      // CN here is "localhost" — "BSV Desktop" is only the organization. The
      // lookup therefore failed with NTE_NOT_FOUND even when the certificate
      // was installed and valid, execFileAsync rejected on the non-zero exit,
      // and the app re-prompted on every single launch.
      //
      // The thumbprint is also exact, so a stale localhost certificate left in
      // the store by an earlier install can no longer be mistaken for the one
      // we are actually serving, and it is not localized — matching on
      // certutil's human-readable output breaks on non-English Windows.
      const thumbprint = getCertSha1Thumbprint(fs.readFileSync(certPath, 'utf8'));

      try {
        const { stdout } = await execFileAsync('certutil', ['-user', '-verifystore', 'Root', thumbprint]);
        return stdout.toLowerCase().includes(thumbprint);
      } catch (certutilError) {
        // certutil.exe is a well-known dual-use binary and is routinely blocked
        // by WDAC, AppLocker or endpoint security on managed machines, where it
        // fails the same way a missing certificate does. Confirm via PowerShell
        // before concluding anything.
        if (!isMissingCertError(certutilError)) {
          console.log('certutil unavailable for trust check, falling back to PowerShell');
          return await isCertInStoreViaPowerShell(thumbprint);
        }
        return false;
      }
    } else {
      // Linux: Various cert stores, hard to check reliably
      return false;
    }
  } catch {
    return false;
  }
}

/** How long to wait for the main window before prompting anyway. */
const WINDOW_VISIBLE_TIMEOUT_MS = 15_000;

/**
 * Resolves once the main window is actually on screen.
 *
 * The trust prompt used to appear before the app window did: the window is
 * created with `show: false` and only shown on 'ready-to-show', which waits for
 * the renderer's first paint, while the certificate work starts immediately
 * after createWindow(). On a cold start the dialog reliably won the race, so
 * the first thing a new user saw was an unexplained certificate prompt floating
 * over the desktop with no application behind it — and most people dismissed
 * it, leaving the HTTPS substrate untrusted.
 *
 * Falls through after a timeout so a window that never paints can never leave
 * the user unable to trust the certificate at all.
 */
async function waitForWindowVisible(window: BrowserWindow): Promise<void> {
  if (window.isDestroyed() || window.isVisible()) {
    return;
  }

  await new Promise<void>((resolve) => {
    let settled = false;
    const done = () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      window.off('show', done);
      window.off('closed', done);
      resolve();
    };

    const timer = setTimeout(() => {
      console.log('Main window not visible after timeout, showing certificate prompt anyway');
      done();
    }, WINDOW_VISIBLE_TIMEOUT_MS);

    window.once('show', done);
    window.once('closed', done);
  });
}

/**
 * Shows a message box parented to the main window when one is available, so the
 * dialog is window-modal and visibly attached to the app rather than being a
 * free-floating top-level window with its own taskbar entry.
 */
async function showDialog(
  parentWindow: BrowserWindow | null | undefined,
  options: Electron.MessageBoxOptions
): Promise<Electron.MessageBoxReturnValue> {
  if (parentWindow && !parentWindow.isDestroyed()) {
    return dialog.showMessageBox(parentWindow, options);
  }
  return dialog.showMessageBox(options);
}

/**
 * Outcome of offering to install the certificate.
 *
 * Kept distinct because they warrant different follow-up: only an attempted
 * install is worth verifying, and only a verified-failed install is worth
 * warning about. Telling a user who chose "Not Now" that their connection is
 * broken would be scolding them for a decision they deliberately made.
 */
type InstallOutcome = 'installed' | 'declined' | 'failed';

/**
 * Attempts to install the certificate to the system trust store
 */
async function installCertificate(
  certPath: string,
  parentWindow?: BrowserWindow | null
): Promise<InstallOutcome> {
  const platform = process.platform;

  let instructions = '';
  let canAutoInstall = false;

  if (platform === 'darwin') {
    canAutoInstall = true;
    instructions = `To trust the certificate, you'll be prompted to enter your password to add it to the system keychain.

Certificate location: ${certPath}`;
  } else if (platform === 'win32') {
    canAutoInstall = true;
    instructions = `To trust the certificate, you'll be prompted to add it to the Trusted Root Certification Authorities store.

Certificate location: ${certPath}`;
  } else {
    // Linux
    instructions = `To trust the certificate, please run the following commands:

sudo cp "${certPath}" /usr/local/share/ca-certificates/bsv-desktop.crt
sudo update-ca-certificates

Certificate location: ${certPath}`;
  }

  const response = await showDialog(parentWindow, {
    type: 'info',
    title: 'SSL Certificate Trust',
    message: 'BSV Desktop uses HTTPS for secure communication',
    detail: instructions,
    buttons: canAutoInstall ? ['Trust Certificate', 'Not Now'] : ['OK'],
    defaultId: 0,
    cancelId: 1
  });

  // User clicked "Not Now" or dismissed
  if (response.response !== 0) {
    return 'declined';
  }

  if (!canAutoInstall) {
    return 'declined'; // Linux: instructions shown, nothing installed for them
  }

  try {
    if (platform === 'darwin') {
      // macOS: add-trusted-cert with -d flag adds to admin trust settings (needs auth prompt)
      // First try without sudo — works if user has keychain access
      const loginKeychain = path.join(os.homedir(), 'Library/Keychains/login.keychain-db');
      try {
        await execFileAsync('security', [
          'add-trusted-cert', '-d', '-r', 'trustRoot', '-k', loginKeychain, certPath
        ]);
      } catch (firstErr) {
        console.log('Direct trust failed, trying with osascript admin prompt...');
        // Use osascript to prompt for admin password. The inner shell script runs
        // `security` with administrator privileges; build it from a JSON-quoted
        // path so shell metacharacters in certPath cannot break out of the string.
        const innerCmd =
          'security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain '
          + JSON.stringify(certPath);
        await execFileAsync('osascript', [
          '-e', `do shell script ${JSON.stringify(innerCmd)} with administrator privileges`
        ]);
      }

      return 'installed';
    } else if (platform === 'win32') {
      // Windows: Import to Trusted Root store.
      try {
        await execFileAsync('certutil', ['-addstore', '-user', 'Root', certPath]);
      } catch (certutilError) {
        // certutil is commonly blocked by WDAC/AppLocker/EDR on managed
        // machines. PowerShell's PKI module reaches the same store without it.
        console.log('certutil could not install the certificate, falling back to PowerShell:', certutilError);
        await runPowerShell(
          `Import-Certificate -FilePath ${psQuote(certPath)} -CertStoreLocation Cert:\\CurrentUser\\Root | Out-Null`
        );
      }

      return 'installed';
    }
  } catch (error) {
    console.error('Failed to install certificate:', error);

    await showDialog(parentWindow, {
      type: 'error',
      title: 'Certificate Installation Failed',
      message: 'Failed to install the certificate automatically.',
      detail: `Please manually trust the certificate at:\n${certPath}\n\nError: ${error}`,
      buttons: ['OK']
    });

    return 'failed';
  }

  return 'installed';
}

/**
 * Prompts user to trust the certificate if not already trusted.
 *
 * Pass the main window so the prompt can wait for it and parent itself to it.
 * Without that, the prompt appears before the app does on a cold start.
 */
export async function ensureCertTrusted(
  certPath: string,
  parentWindow?: BrowserWindow | null
): Promise<void> {
  // Ask a real client first. If the endpoint already works there is nothing to
  // fix, whatever any certificate store happens to say.
  const accepted = await isCertAcceptedByClients();
  if (accepted === true) {
    console.log('Certificate accepted by the network stack, nothing to do');
    return;
  }

  // Inconclusive probe (bridge not reachable yet) falls back to the store.
  const trusted = accepted === null ? await isCertTrusted(certPath) : false;

  if (trusted) {
    console.log('Certificate already trusted');
    return;
  }

  // Only wait once we know we actually need to prompt — the common case is
  // already-trusted, and that must stay a silent no-op.
  if (parentWindow && !parentWindow.isDestroyed()) {
    await waitForWindowVisible(parentWindow);
    if (parentWindow.isDestroyed()) {
      console.log('Main window closed before the certificate prompt could be shown');
      return;
    }
  }

  console.log('Certificate not trusted, attempting to install...');
  const outcome = await installCertificate(certPath, parentWindow);

  // 'declined' is the user's call and needs no follow-up; 'failed' already
  // showed its own error. Only an attempted install is worth verifying.
  if (outcome !== 'installed') {
    return;
  }

  // Verify against a real client again, not just the store. On managed Windows
  // machines the two can disagree: the certificate is genuinely in the store
  // and genuinely not honoured.
  const nowAccepted = await isCertAcceptedByClients();
  if (nowAccepted === true) {
    console.log('Certificate successfully installed and verified');
    return;
  }

  if (nowAccepted === null && await isCertTrusted(certPath)) {
    console.log('Certificate installed; endpoint not reachable to confirm end to end');
    return;
  }

  console.log('Certificate install reported success but verification failed');
  await explainVerificationFailure(certPath, parentWindow);
}

/**
 * Tells the user why a certificate that installed cleanly still is not trusted.
 *
 * Without this the app looks like it silently did nothing: the install succeeds,
 * the prompt disappears, and connectivity stays broken with no explanation. The
 * usual cause on a corporate or university machine is a policy that forbids
 * user-installed root CAs from being used for validation, which no amount of
 * retrying will overcome — it needs an administrator.
 */
async function explainVerificationFailure(
  certPath: string,
  parentWindow?: BrowserWindow | null
): Promise<void> {
  const policyRestricted = process.platform === 'win32' && await hasUserRootRestrictionPolicy();

  const detail = policyRestricted
    ? 'The certificate was installed, but this device has a policy that prevents '
      + 'user-installed root certificates from being trusted, so it is being ignored.\n\n'
      + 'An administrator will need to deploy the certificate for you, or allow '
      + 'user-installed root certificates.\n\n'
      + `Certificate location: ${certPath}`
    : 'The certificate was installed, but the secure local connection is still '
      + 'being rejected. This is usually caused by security software or device '
      + 'management policy on this machine.\n\n'
      + `Certificate location: ${certPath}`;

  await showDialog(parentWindow, {
    type: 'warning',
    title: 'Certificate Not Trusted',
    message: 'BSV Desktop could not establish a trusted local connection',
    detail,
    buttons: ['OK']
  });
}
