// Optional empirical Chromium oracle for the 30-certificate matrix.
//
// For every row this starts a loopback HTTPS server and drives the Chromium
// binary headlessly against the certificate's own DNS name (pinned to
// 127.0.0.1). A per-leaf --ignore-certificate-errors-spki-list pin bypasses
// only trust/name errors; TLS-layer keyUsage enforcement
// (ERR_SSL_KEY_USAGE_INCOMPATIBLE) is still observed. Chain-level defects
// (CA keyCertSign / name constraints) are masked by the pin and are therefore
// corroborated by Go/OpenSSL plus the documented Chromium/NSS codes instead.
//
//   node probe.mjs
//
// Env:
//   CHROME_BIN  path to a Chromium/Google Chrome binary
//   LD_LIBRARY_PATH may need the directory containing libasound.so.2

import { spawn } from 'node:child_process';
import { createHash, X509Certificate } from 'node:crypto';
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import https from 'node:https';
import { readdirSync } from 'node:fs';

const here = dirname(fileURLToPath(import.meta.url));
const accDir = join(here, '..');
const corpus = join(accDir, 'corpus');
const report = JSON.parse(readFileSync(join(accDir, 'report.json'), 'utf8'));

function locateChrome() {
  if (process.env.CHROME_BIN && existsSync(process.env.CHROME_BIN)) return process.env.CHROME_BIN;
  const root = join(homedir(), '.cache', 'ms-playwright');
  for (const dir of readdirSync(root).filter((d) => d.startsWith('chromium-'))) {
    const candidate = join(root, dir, 'chrome-linux64', 'chrome');
    if (existsSync(candidate)) return candidate;
  }
  for (const p of ['/usr/bin/chromium', '/usr/bin/chromium-browser', '/usr/bin/google-chrome']) {
    if (existsSync(p)) return p;
  }
  throw new Error('No Chromium binary found; set CHROME_BIN or run `npx playwright install chromium`.');
}

const chrome = locateChrome();

function startServer(row) {
  const nn = String(row.n).padStart(2, '0');
  const base = `${nn}-${row.id}`;
  const leaf = readFileSync(join(corpus, `${base}.leaf.pem`));
  const key = readFileSync(join(corpus, `${base}.leaf.key`));
  const ca = readFileSync(join(corpus, `${base}.ca.pem`));
  return new Promise((resolve) => {
    const server = https.createServer(
      { key, cert: Buffer.concat([leaf, Buffer.from('\n'), ca]) },
      (_req, res) => res.end('ok'),
    );
    server.listen(0, '127.0.0.1', () => resolve({ server, port: server.address().port, leaf }));
  });
}

function leafPin(leafPem) {
  const cert = new X509Certificate(leafPem);
  const spki = cert.publicKey.export({ type: 'spki', format: 'der' });
  return createHash('sha256').update(spki).digest('base64');
}

function runChrome({ dns, port, pin }) {
  const args = [
    '--headless=new',
    '--no-sandbox',
    '--disable-gpu',
    '--no-proxy-server',
    `--ignore-certificate-errors-spki-list=${pin}`,
    `--host-resolver-rules=MAP ${dns} 127.0.0.1`,
    '--dump-dom',
    `https://${dns}:${port}/`,
  ];
  return new Promise((resolve) => {
    const child = spawn(chrome, args, { stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '';
    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      resolve({ ok: false, error: 'TIMEOUT' });
    }, 25000);
    child.stdout.on('data', (d) => (out += d));
    child.stderr.on('data', (d) => (out += d));
    child.on('close', () => {
      clearTimeout(timer);
      if (out.includes('>ok<')) return resolve({ ok: true, error: '' });
      const m = out.match(/Page load failed: net::(ERR_[A-Z0-9_]+)/);
      if (m) return resolve({ ok: false, error: m[1] });
      const m2 = out.match(/net_error (-?\d+)/);
      if (m2) return resolve({ ok: false, error: `net_error_${m2[1]}` });
      return resolve({ ok: false, error: 'UNKNOWN' });
    });
  });
}

const observations = [];
for (const row of report.rows) {
  const { server, port, leaf } = await startServer(row);
  const pin = leafPin(leaf);
  const result = await runChrome({ dns: row.dns, port, pin });
  await new Promise((r) => server.close(r));
  observations.push({ id: row.id, navigationOk: result.ok, chromiumError: result.error });
  const expected = row.browser_reject_expected ? 'reject' : 'accept';
  const observed = result.ok ? 'accept' : result.error;
  console.log(`${String(row.n).padStart(2)} ${row.id.padEnd(26)} expected=${expected.padEnd(6)} observed=${observed}`);
}

writeFileSync(join(here, 'results.json'), JSON.stringify(observations, null, 2));
console.log(`\nwrote ${observations.length} observations to browser/results.json`);
