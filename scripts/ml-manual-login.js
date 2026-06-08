const fs = require('fs');
const path = require('path');
const { chromium } = require('../mercadolivre-affiliate-scraper/node_modules/playwright');

const repoRoot = path.resolve(__dirname, '..');
const userDataDir = path.join(repoRoot, 'data', 'ml-visible-profile');
const statePath = path.join(repoRoot, 'data', 'mercadolivre-affiliate-storage-state.visible.json');
const loginUrl = 'https://www.mercadolivre.com.br/entrar?go=https%3A%2F%2Fwww.mercadolivre.com.br%2Fafiliados%2Fhub';
const homeUrl = 'https://www.mercadolivre.com.br/afiliados/hub';

(async () => {
  fs.mkdirSync(path.dirname(statePath), { recursive: true });
  const context = await chromium.launchPersistentContext(userDataDir, {
    headless: false,
    viewport: { width: 1440, height: 900 },
    locale: 'pt-BR',
    timezoneId: 'America/Sao_Paulo',
    userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36'
  });

  const page = context.pages()[0] || await context.newPage();
  await page.goto(loginUrl, { waitUntil: 'domcontentloaded', timeout: 60000 });

  console.log('ML_LOGIN_BROWSER_READY');
  console.log('Conclua o login/captcha no navegador. Esta automacao nao vai recarregar a pagina.');
  console.log('Quando terminar e estiver no hub de afiliados, feche esta janela do navegador para salvar a sessao.');

  await new Promise(resolve => {
    context.on('close', resolve);
  });

  const saveContext = await chromium.launchPersistentContext(userDataDir, { headless: true });
  await saveContext.storageState({ path: statePath });
  await saveContext.close();
  console.log(`ML_STORAGE_STATE_SAVED=${statePath}`);
})();
