import { chromium } from 'playwright';
import { createServer } from 'node:http';
import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

const PORT = Number(process.env.FORGE_BROWSER_PORT || '8091');
const ARTIFACT_DIR = process.env.FORGE_BROWSER_ARTIFACT_DIR || 'artifacts/screenshots';

type CaptureRequest = {
  campaign_id?: string;
  target_url?: string;
  finding_type?: string;
};

function writeJson(res: any, status: number, payload: unknown): void {
  const body = JSON.stringify(payload);
  res.writeHead(status, {
    'content-type': 'application/json',
    'content-length': Buffer.byteLength(body).toString(),
  });
  res.end(body);
}

async function readRequestBody(req: any): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk)));
  }
  return Buffer.concat(chunks).toString('utf-8');
}

async function handleCapture(req: any, res: any): Promise<void> {
  const raw = await readRequestBody(req);
  const data: CaptureRequest = raw ? JSON.parse(raw) : {};

  const targetUrl = (data.target_url || '').trim();
  if (!targetUrl) {
    writeJson(res, 400, { error: 'target_url is required' });
    return;
  }

  const campaignId = (data.campaign_id || 'unknown').trim();
  const findingType = (data.finding_type || 'finding').replace(/[^a-zA-Z0-9_-]/g, '_');

  await mkdir(ARTIFACT_DIR, { recursive: true });
  const filename = `${campaignId}-${findingType}-${Date.now()}.png`;
  const filePath = join(ARTIFACT_DIR, filename);

  const browser = await chromium.launch({ headless: true });
  try {
    const page = await browser.newPage();
    await page.goto(targetUrl, { waitUntil: 'domcontentloaded', timeout: 20000 });
    await page.screenshot({ path: filePath, fullPage: true });
    await writeFile(join(ARTIFACT_DIR, `${filename}.meta.json`), JSON.stringify(data, null, 2));
  } finally {
    await browser.close();
  }

  writeJson(res, 200, { path: filePath });
}

const server = createServer(async (req, res) => {
  if (!req.url) {
    writeJson(res, 404, { error: 'not found' });
    return;
  }

  if (req.method === 'GET' && req.url === '/healthz') {
    writeJson(res, 200, { status: 'ok', component: 'forge-browser-agent' });
    return;
  }

  if (req.method === 'POST' && req.url === '/capture') {
    try {
      await handleCapture(req, res);
      return;
    } catch (error) {
      const message = error instanceof Error ? error.message : 'capture failed';
      writeJson(res, 500, { error: message });
      return;
    }
  }

  writeJson(res, 404, { error: 'not found' });
});

server.listen(PORT, '127.0.0.1', () => {
  // eslint-disable-next-line no-console
  console.log(`forge-browser-agent listening on 127.0.0.1:${PORT}`);
});
