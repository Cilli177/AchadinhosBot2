const fs = require('fs');
const path = require('path');
const { chromium } = require('../mercadolivre-affiliate-scraper/node_modules/playwright');

const loginUrl = 'https://www.mercadolivre.com.br/entrar?go=https%3A%2F%2Fwww.mercadolivre.com.br%2Fafiliados%2Fhub';
const homeUrl = 'https://www.mercadolivre.com.br/afiliados/hub';
const dataDir = 'D:\\Achadinhos\\data\\ml-prod-visible-profile';
const storageStatePath = 'D:\\Achadinhos\\data\\mercadolivre-affiliate-storage-state.visible.json';

function ensureDir(targetPath) {
  fs.mkdirSync(path.dirname(targetPath), { recursive: true });
}

async function saveState(context, page, reason) {
  ensureDir(storageStatePath);
  const state = await context.storageState();
  fs.writeFileSync(storageStatePath, JSON.stringify(state, null, 2), 'utf8');
  const title = await page.title().catch(() => '');
  console.log(`[ml-prod-auth] storage salvo (${reason}) em ${storageStatePath}`);
  console.log(`[ml-prod-auth] url=${page.url()} title=${title}`);
}

async function trySave(context, page, reason) {
  const url = page.url();
  if (url.includes('mercadolivre.com') || url.includes('mercadolivre.com.br')) {
    await saveState(context, page, reason).catch(error =>
      console.error('[ml-prod-auth] falha ao salvar storage:', error.message));
  }
}

async function main() {
  ensureDir(path.join(dataDir, '.keep'));

  const context = await chromium.launchPersistentContext(dataDir, {
    headless: false,
    viewport: { width: 1440, height: 900 },
    args: [
      '--start-maximized',
      '--disable-blink-features=AutomationControlled'
    ]
  });

  const page = context.pages()[0] || await context.newPage();

  console.log('[ml-prod-auth] abrindo login/hub Mercado Livre...');
  await page.goto(homeUrl, { waitUntil: 'domcontentloaded', timeout: 60000 }).catch(async () => {
    await page.goto(loginUrl, { waitUntil: 'domcontentloaded', timeout: 60000 });
  });

  const saver = setInterval(() => {
    trySave(context, page, 'intervalo');
  }, 5000);

  page.on('framenavigated', async frame => {
    if (frame !== page.mainFrame()) return;
    await trySave(context, page, 'navegacao');
    if (frame.url().includes('/afiliados')) {
      console.log('[ml-prod-auth] hub detectado. Pode fechar o navegador quando terminar.');
    }
  });

  page.on('load', () => {
    trySave(context, page, 'load');
  });

  process.on('SIGINT', async () => {
    clearInterval(saver);
    await trySave(context, page, 'encerramento');
    await context.close();
    process.exit(0);
  });

  console.log('[ml-prod-auth] faca o login manualmente no navegador aberto.');
  console.log('[ml-prod-auth] quando chegar no hub, a sessao sera salva automaticamente.');
}

main().catch(error => {
  console.error('[ml-prod-auth] erro fatal:', error);
  process.exit(1);
});
