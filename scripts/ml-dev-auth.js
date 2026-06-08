const fs = require('fs');
const path = require('path');
const { chromium } = require('../mercadolivre-affiliate-scraper/node_modules/playwright');

const loginUrl = 'https://www.mercadolivre.com.br/entrar?go=https%3A%2F%2Fwww.mercadolivre.com.br%2Fafiliados%2Fhub';
const homeUrl = 'https://www.mercadolivre.com.br/afiliados/hub';
const dataDir = path.resolve(__dirname, '..', 'data', 'ml-dev-auth-profile');
const storageStatePath = path.resolve(__dirname, '..', 'data', 'mercadolivre-affiliate-storage-state.dev.json');

function ensureDir(filePath) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
}

async function saveState(context, page, reason) {
  try {
    ensureDir(storageStatePath);
    const state = await context.storageState();
    fs.writeFileSync(storageStatePath, JSON.stringify(state, null, 2), 'utf8');
    const title = await page.title().catch(() => '');
    console.log(`[ml-auth] storage state salvo (${reason}) em ${storageStatePath}`);
    console.log(`[ml-auth] url=${page.url()} title=${title}`);
  } catch (error) {
    console.error('[ml-auth] falha ao salvar storage state:', error.message);
  }
}

async function trySaveIfMercadoLivre(context, page, reason) {
  try {
    const url = page.url();
    if (!url.includes('mercadolivre.com.br') && !url.includes('mercadolivre.com')) {
      return;
    }

    await saveState(context, page, reason);
  } catch (error) {
    console.error('[ml-auth] falha ao tentar salvar sessao do ML:', error.message);
  }
}

async function main() {
  ensureDir(path.join(dataDir, '.keep'));

  const context = await chromium.launchPersistentContext(dataDir, {
    headless: false,
    channel: 'chrome',
    viewport: { width: 1366, height: 900 },
    args: ['--start-maximized']
  });

  const page = context.pages()[0] || await context.newPage();

  console.log('[ml-auth] abrindo login do Mercado Livre...');
  await page.goto(loginUrl, { waitUntil: 'domcontentloaded', timeout: 60000 });

  const saver = setInterval(async () => {
    await trySaveIfMercadoLivre(context, page, 'intervalo');
  }, 5000);

  page.on('framenavigated', async frame => {
    if (frame !== page.mainFrame()) return;
    const url = frame.url();
    if (url.includes('mercadolivre.com.br') || url.includes('mercadolivre.com')) {
      await saveState(context, page, 'navegacao');
    }
    if (url.includes('/afiliados/hub') || url.includes('/afiliados')) {
      console.log('[ml-auth] login detectado. Pode fechar o navegador quando terminar.');
    }
  });

  page.on('load', async () => {
    await trySaveIfMercadoLivre(context, page, 'load');
  });

  context.on('close', async () => {
    clearInterval(saver);
  });

  process.on('SIGINT', async () => {
    clearInterval(saver);
    await trySaveIfMercadoLivre(context, page, 'encerramento');
    await context.close();
    process.exit(0);
  });

  console.log('[ml-auth] faça o login manualmente no navegador aberto.');
  console.log('[ml-auth] quando chegar no hub de afiliados, a sessao sera salva automaticamente.');
}

main().catch(error => {
  console.error('[ml-auth] erro fatal:', error);
  process.exit(1);
});
