import { app, clipboard, dialog } from 'electron';
import path from 'path';
import fs from 'fs';
import os from 'os';
import forge from 'node-forge';
import { execFile } from 'child_process';
import { promisify } from 'util';

const execFileAsync = promisify(execFile);

// Linux trust store locations. The system store is read by OpenSSL-based
// clients; the NSS user db is what Chrome/Chromium actually consult for
// user-added anchors, so we write to both when the tooling is available.
const LINUX_CA_DIR = '/usr/local/share/ca-certificates';
const LINUX_CA_PATH = path.join(LINUX_CA_DIR, 'bsv-desktop.crt');
const LINUX_NSSDB_DIR = path.join(os.homedir(), '.pki', 'nssdb');
const LINUX_NSSDB = `sql:${LINUX_NSSDB_DIR}`;
const NSS_NICKNAME = 'BSV Desktop localhost';

/** The commands a user would run by hand, shown when automation is unavailable. */
function linuxManualCommand(certPath: string): string {
  return [
    `sudo cp "${certPath}" ${LINUX_CA_PATH}`,
    'sudo update-ca-certificates'
  ].join('\n');
}

/** SHA-256 fingerprint of a PEM certificate, lowercase hex. */
function certFingerprint(pem: string): string {
  const parsed = forge.pki.certificateFromPem(pem);
  const der = forge.asn1.toDer(forge.pki.certificateToAsn1(parsed)).getBytes();
  const md = forge.md.sha256.create();
  md.update(der);
  return md.digest().toHex();
}

async function hasCommand(command: string): Promise<boolean> {
  try {
    await execFileAsync('which', [command]);
    return true;
  } catch {
    return false;
  }
}

/** Single-quote a string for safe interpolation into an sh -c script. */
function shQuote(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

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
      // Windows: Check if cert is in trusted root store
      const { stdout } = await execFileAsync('certutil', ['-user', '-verifystore', 'Root', 'BSV Desktop']);
      return stdout.includes('BSV Desktop');
    } else {
      return await isCertTrustedLinux(certPath);
    }
  } catch {
    return false;
  }
}

/**
 * Linux trust check. Compares the SHA-256 fingerprint of the cert we generated
 * against whatever is installed, so a stale anchor from a previous cert (e.g.
 * after expiry regeneration) correctly reports as untrusted.
 */
async function isCertTrustedLinux(certPath: string): Promise<boolean> {
  let expected: string;
  try {
    expected = certFingerprint(fs.readFileSync(certPath, 'utf8'));
  } catch {
    return false;
  }

  // System store (OpenSSL clients, and Chrome via the p11-kit NSS module)
  try {
    if (fs.existsSync(LINUX_CA_PATH)) {
      if (certFingerprint(fs.readFileSync(LINUX_CA_PATH, 'utf8')) === expected) {
        return true;
      }
    }
  } catch {
    // Unreadable or malformed anchor — fall through to the NSS check
  }

  // NSS user db (Chrome/Chromium)
  try {
    const { stdout } = await execFileAsync('certutil', [
      '-d', LINUX_NSSDB, '-L', '-n', NSS_NICKNAME, '-a'
    ]);
    if (certFingerprint(stdout) === expected) {
      return true;
    }
  } catch {
    // certutil missing, db absent, or nickname not present
  }

  return false;
}

/**
 * Adds the cert to the per-user NSS db that Chrome/Chromium read.
 * Requires libnss3-tools; no root needed. Returns false if unavailable.
 */
async function installCertLinuxNss(certPath: string): Promise<boolean> {
  if (!(await hasCommand('certutil'))) {
    return false;
  }

  fs.mkdirSync(LINUX_NSSDB_DIR, { recursive: true });

  if (!fs.existsSync(path.join(LINUX_NSSDB_DIR, 'cert9.db'))) {
    await execFileAsync('certutil', ['-d', LINUX_NSSDB, '-N', '--empty-password']);
  }

  // Remove any anchor from a previous cert before adding the current one
  try {
    await execFileAsync('certutil', ['-d', LINUX_NSSDB, '-D', '-n', NSS_NICKNAME]);
  } catch {
    // Nothing to remove
  }

  // 'P,,' is trusted-peer for SSL, which is what this cert needs: it is a
  // self-signed leaf (CA:FALSE), not a CA, so 'C,,' would have NSS try to
  // build a chain through it and fail.
  await execFileAsync('certutil', [
    '-d', LINUX_NSSDB, '-A', '-t', 'P,,', '-n', NSS_NICKNAME, '-i', certPath
  ]);
  return true;
}

/**
 * Copies the cert into the system trust store via a single pkexec prompt.
 * Returns false if pkexec is unavailable.
 */
async function installCertLinuxSystem(certPath: string): Promise<boolean> {
  if (!(await hasCommand('pkexec'))) {
    return false;
  }

  const script = [
    `mkdir -p ${shQuote(LINUX_CA_DIR)}`,
    `install -m 644 ${shQuote(certPath)} ${shQuote(LINUX_CA_PATH)}`,
    'update-ca-certificates'
  ].join(' && ');

  await execFileAsync('pkexec', ['sh', '-c', script]);
  return true;
}

/**
 * Attempts to install the certificate to the system trust store
 * Returns true if successful or user dismissed, false if failed
 */
async function installCertificate(certPath: string): Promise<boolean> {
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
    // Linux: auto-install needs pkexec (system store) or certutil (NSS/Chrome).
    // Without either there is nothing to automate, so fall back to instructions.
    canAutoInstall = (await hasCommand('pkexec')) || (await hasCommand('certutil'));
    instructions = canAutoInstall
      ? `To trust the certificate, you'll be prompted for your password to add it to the system trust store.

Certificate location: ${certPath}`
      : `To trust the certificate, please run the following commands:

${linuxManualCommand(certPath)}

Certificate location: ${certPath}`;
  }

  const manualLinuxFallback = platform !== 'darwin' && platform !== 'win32' && !canAutoInstall;

  const buttons = canAutoInstall
    ? ['Trust Certificate', 'Not Now']
    : manualLinuxFallback ? ['Copy Command', 'OK'] : ['OK'];

  const response = await dialog.showMessageBox({
    type: 'info',
    title: 'SSL Certificate Trust',
    message: 'BSV Desktop uses HTTPS for secure communication',
    detail: instructions,
    buttons,
    defaultId: 0,
    cancelId: buttons.length - 1
  });

  // Linux without automation: offer the command via the clipboard, since the
  // text in this dialog is not selectable on GTK.
  if (manualLinuxFallback) {
    if (response.response === 0) {
      clipboard.writeText(linuxManualCommand(certPath));
    }
    return true;
  }

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
    } else {
      // Linux: write to both stores. The NSS db covers Chrome/Chromium and
      // needs no root, so try it first — if it succeeds we still attempt the
      // system store, but a pkexec failure there is no longer fatal.
      let nssInstalled = false;
      try {
        nssInstalled = await installCertLinuxNss(certPath);
      } catch (nssError) {
        console.error('Failed to add certificate to NSS db:', nssError);
      }

      try {
        await installCertLinuxSystem(certPath);
      } catch (systemError) {
        // pkexec exits 126 when the user dismisses the auth dialog — that is a
        // deliberate choice, not a failure worth an error popup.
        if ((systemError as { code?: number }).code === 126) {
          console.log('User dismissed the pkexec authentication prompt');
          return true;
        }
        if (!nssInstalled) {
          throw systemError;
        }
        console.error('System trust store install failed, NSS db succeeded:', systemError);
      }

      return true;
    }
  } catch (error) {
    console.error('Failed to install certificate:', error);

    const isLinux = platform !== 'darwin' && platform !== 'win32';
    const manualCommand = linuxManualCommand(certPath);

    const failure = await dialog.showMessageBox({
      type: 'error',
      title: 'Certificate Installation Failed',
      message: 'Failed to install the certificate automatically.',
      detail: isLinux
        ? `Run these commands to trust it manually:\n\n${manualCommand}\n\nError: ${error}`
        : `Please manually trust the certificate at:\n${certPath}\n\nError: ${error}`,
      buttons: isLinux ? ['Copy Command', 'OK'] : ['OK'],
      defaultId: 0,
      cancelId: isLinux ? 1 : 0
    });

    if (isLinux && failure.response === 0) {
      clipboard.writeText(manualCommand);
    }

    return false;
  }

  return true;
}

/**
 * Prompts user to trust the certificate if not already trusted
 */
export async function ensureCertTrusted(certPath: string): Promise<void> {
  const trusted = await isCertTrusted(certPath);

  if (trusted) {
    console.log('Certificate already trusted');
    return;
  }

  console.log('Certificate not trusted, attempting to install...');
  const success = await installCertificate(certPath);

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
