const fs = require('fs');
const path = require('path');
const readline = require('readline');
const { chromium } = require('../mercadolivre-affiliate-scraper/node_modules/playwright');

const prodDataDir = 'D:\\Achadinhos\\data';
const profileDir = path.join(prodDataDir, 'ml-prod-visible-profile');
const storageStatePath = path.join(prodDataDir, 'mercadolivre-affiliate-storage-state.json');
const homeUrl = 'https://www.mercadolivre.com.br/afiliados/hub';
const maxOffers = 5;

function ensureDir(targetPath) {
  fs.mkdirSync(path.dirname(targetPath), { recursive: true });
}

function ask(question) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise(resolve => rl.question(question, answer => {
    rl.close();
    resolve(answer);
  }));
}

function normalizeText(value) {
  return String(value || '').replace(/\s+/g, ' ').trim();
}

function parsePrice(text) {
  if (!text) return 0;
  const cleaned = String(text).replace(/[^\d,]/g, '');
  const normalized = cleaned.replace(/\./g, '').replace(',', '.');
  const value = Number(normalized);
  return Number.isFinite(value) ? value : 0;
}

function parseCommission(text) {
  if (!text) return 0;
  const match = String(text).match(/(\d+[\.,]?\d*)/);
  if (!match) return 0;
  const value = Number(match[1].replace(',', '.'));
  return Number.isFinite(value) ? value : 0;
}

async function saveState(context, page, reason) {
  ensureDir(storageStatePath);
  const state = await context.storageState();
  fs.writeFileSync(storageStatePath, JSON.stringify(state, null, 2), 'utf8');
  console.log(`[ml-prod-visible] storage state salvo (${reason}) em ${storageStatePath}`);
  console.log(`[ml-prod-visible] url=${page.url()}`);
}

async function clickExtraGains(page) {
  const selectors = [
    "button:has-text('Ganhos extras')",
    "[role='tab']:has-text('Ganhos extras')",
    "a:has-text('Ganhos extras')"
  ];

  for (const selector of selectors) {
    const target = page.locator(selector).first();
    if (await target.count().catch(() => 0)) {
      await target.scrollIntoViewIfNeeded().catch(() => {});
      await target.click({ timeout: 3000 }).catch(() => {});
      await page.waitForTimeout(1800);
      console.log(`[ml-prod-visible] cliquei em Ganhos extras com seletor: ${selector}`);
      return true;
    }
  }

  console.log('[ml-prod-visible] botao Ganhos extras nao encontrado.');
  return false;
}

async function collectVisibleOffers(page, max = maxOffers) {
  for (let i = 0; i < 10; i++) {
    await page.evaluate(() => window.scrollTo(0, document.body.scrollHeight)).catch(() => {});
    await page.waitForTimeout(700);
  }

  await page.evaluate(() => window.scrollTo(0, 0)).catch(() => {});
  await page.waitForTimeout(700);

  const cards = page.locator('li.poly-card');
  const count = await cards.count();
  const offers = [];

  for (let i = 0; i < count && offers.length < max; i++) {
    const card = cards.nth(i);
    const title = normalizeText(await card.locator('.poly-component__title, h2, h3').first().textContent().catch(() => ''));
    const priceText = normalizeText(await card.locator('.poly-price__current .andes-money-amount__fraction, .andes-money-amount__fraction, [data-testid=\"price\"], [data-testid=\"price-current\"]').first().textContent().catch(() => ''));

    let commissionText = '';
    for (const sel of ['[data-testid="commission"]', '[data-testid="extra-profit"]', '.poly-component__label', '.poly-card__commission', 'span', 'p']) {
      const texts = await card.locator(sel).allTextContents().catch(() => []);
      const found = texts.map(normalizeText).find(t => /%|ganho|comiss/i.test(t));
      if (found) {
        commissionText = found;
        break;
      }
    }

    if (!title || !priceText) {
      continue;
    }

    offers.push({
      index: i + 1,
      title,
      priceText,
      commissionText,
      price: parsePrice(priceText),
      commission: parseCommission(commissionText)
    });
  }

  return offers;
}

async function main() {
  ensureDir(path.join(profileDir, '.keep'));

  const context = await chromium.launchPersistentContext(profileDir, {
    headless: false,
    channel: 'chrome',
    viewport: { width: 1440, height: 900 },
    args: ['--start-maximized']
  });

  const page = context.pages()[0] || await context.newPage();
  console.log('[ml-prod-visible] abrindo hub de afiliados...');
  await page.goto(homeUrl, { waitUntil: 'domcontentloaded', timeout: 60000 });
  await page.waitForTimeout(2500);

  console.log('[ml-prod-visible] faca o login manualmente no navegador.');
  await ask('[ml-prod-visible] quando estiver no hub, pressione Enter aqui...');

  await saveState(context, page, 'manual-login');
  await clickExtraGains(page);
  const offers = await collectVisibleOffers(page, maxOffers);

  console.log('\n[ml-prod-visible] primeiras ofertas visiveis:');
  for (const offer of offers) {
    console.log(`- #${offer.index} | ${offer.title}`);
    console.log(`  preco=${offer.priceText} | comissao=${offer.commissionText}`);
  }

  console.log('\n[ml-prod-visible] deixe o navegador aberto se quiser acompanhar.');
  console.log('[ml-prod-visible] pressione Ctrl+C nesta janela para encerrar.');

  process.on('SIGINT', async () => {
    await saveState(context, page, 'encerramento');
    await context.close();
    process.exit(0);
  });
}

main().catch(error => {
  console.error('[ml-prod-visible] erro fatal:', error);
  process.exit(1);
});
