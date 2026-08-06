import { app, dialog, BrowserWindow } from 'electron';
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
      const { stdout } = await execFileAsync('certutil', ['-user', '-verifystore', 'Root', thumbprint]);
      return stdout.toLowerCase().includes(thumbprint);
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
 * Attempts to install the certificate to the system trust store
 * Returns true if successful or user dismissed, false if failed
 */
async function installCertificate(
  certPath: string,
  parentWindow?: BrowserWindow | null
): Promise<boolean> {
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
    return true;
  }

  if (!canAutoInstall) {
    return true; // Just showed instructions
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

      return true;
    } else if (platform === 'win32') {
      // Windows: Import to Trusted Root store
      await execFileAsync('certutil', ['-addstore', '-user', 'Root', certPath]);

      // await dialog.showMessageBox({
      //   type: 'info',
      //   title: 'Certificate Installed',
      //   message: 'The SSL certificate has been successfully installed and trusted.',
      //   buttons: ['OK']
      // });

      return true;
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

    return false;
  }

  return true;
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
  const trusted = await isCertTrusted(certPath);

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
  const success = await installCertificate(certPath, parentWindow);

  if (success) {
    // Verify it actually worked
    const nowTrusted = await isCertTrusted(certPath);
    if (nowTrusted) {
      console.log('Certificate successfully installed and verified');
    } else {
      console.log('Certificate install reported success but verification failed');
    }
  }
}
