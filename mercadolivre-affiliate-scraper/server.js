const express = require('express')
const fs = require('fs')
const path = require('path')
const { chromium } = require('playwright')

const app = express()
app.use(express.json({ limit: '2mb' }))

let browser = null
let browserLock = null

async function getBrowser(headless = true) {
  if (browser?.isConnected()) return browser
  if (browserLock) return browserLock

  browserLock = chromium.launch({
    headless,
    args: [
      '--no-sandbox',
      '--disable-setuid-sandbox',
      '--disable-dev-shm-usage',
      '--disable-infobars',
      '--window-size=1440,900',
      '--disable-extensions',
      '--disable-background-networking',
      '--disable-default-apps',
      '--mute-audio',
      '--disable-blink-features=AutomationControlled'
    ]
  }).then(b => {
    browser = b
    browserLock = null
    console.log('Chromium iniciado para Mercado Livre Afiliados.')
    return b
  }).catch(err => {
    browserLock = null
    throw err
  })

  return browserLock
}

function nowStamp() {
  return new Date().toISOString().replace(/[:.]/g, '-')
}

async function tryFill(page, selectors, value) {
  if (!value) return false
  for (const selector of selectors) {
    const locator = page.locator(selector).first()
    if (await locator.count()) {
      try {
        await locator.fill(value, { timeout: 2500 })
        return true
      } catch {}
    }
  }
  return false
}

async function tryClick(page, selectors) {
  for (const selector of selectors) {
    const locator = page.locator(selector).first()
    if (await locator.count()) {
      try {
        await locator.click({ timeout: 2500 })
        return true
      } catch {}
    }
  }
  return false
}

async function readPageTitleSafely(page) {
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      return await page.title()
    } catch (error) {
      const message = String(error?.message || '')
      if (!message.includes('Execution context was destroyed')) {
        throw error
      }

      await page.waitForLoadState('domcontentloaded', { timeout: 5000 }).catch(() => {})
      await page.waitForTimeout(300)
    }
  }

  return ''
}

async function readBodyTextSafely(page) {
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      return ((await page.locator('body').textContent().catch(() => '')) || '').toLowerCase()
    } catch (error) {
      const message = String(error?.message || '')
      if (!message.includes('Execution context was destroyed')) {
        throw error
      }

      await page.waitForLoadState('domcontentloaded', { timeout: 5000 }).catch(() => {})
      await page.waitForTimeout(300)
    }
  }

  return ''
}

async function detectAuth(page) {
  const url = page.url()
  const title = await readPageTitleSafely(page)
  const text = await readBodyTextSafely(page)
  const authHints = [
    'código',
    'codigo',
    'qr',
    'escaneie',
    'escanea',
    'verificação',
    'verificacao',
    'autenticador',
    'confirmar identidade',
    'confirmar que é você',
    'confirmar que e voce'
  ]

  const authRequired = authHints.some(hint => text.includes(hint))
    || url.includes('/autenticacao')
    || url.includes('/seguranca')

  return {
    authRequired,
    authModeDetected: authRequired ? 'code-or-qr' : null,
    pageTitle: title,
    currentUrl: url
  }
}

async function saveFailureScreenshot(page) {
  try {
    const dir = '/app/data/mercadolivre-affiliate-scout'
    fs.mkdirSync(dir, { recursive: true })
    const filePath = path.join(dir, `failure-${nowStamp()}.png`)
    await page.screenshot({ path: filePath, fullPage: true })
    return filePath
  } catch {
    return null
  }
}

function normalizeUrl(url) {
  if (!url || typeof url !== 'string') return null
  const trimmed = url.trim()
  if (!trimmed) return null
  if (trimmed.startsWith('//')) return `https:${trimmed}`
  if (trimmed.startsWith('/')) return `https://www.mercadolivre.com.br${trimmed}`
  return trimmed
}

function parsePercent(text) {
  if (!text || typeof text !== 'string') return 0
  const match = text.match(/(\d+(?:[.,]\d+)?)\s*%/)
  return match ? Number(match[1].replace(',', '.')) || 0 : 0
}

function parsePrice(text) {
  if (!text || typeof text !== 'string') return 0
  const normalized = text.replace(/[^\d,]/g, '').replace(',', '.')
  return Number(normalized) || 0
}

function isAcceptedByCommissionTiers(price, commission, settings) {
  if (commission >= Number(settings.minCommissionPercent || 0)) return true
  if (Number(settings.tier1MinPrice || 0) > 0 &&
    price >= Number(settings.tier1MinPrice || 0) &&
    commission >= Number(settings.tier1MinCommissionPercent || 0)) return true
  if (Number(settings.tier2MinPrice || 0) > 0 &&
    price >= Number(settings.tier2MinPrice || 0) &&
    commission >= Number(settings.tier2MinCommissionPercent || 0)) return true
  if (Number(settings.tier3MinPrice || 0) > 0 &&
    price >= Number(settings.tier3MinPrice || 0) &&
    commission >= Number(settings.tier3MinCommissionPercent || 0)) return true
  return false
}

function extractUrlsFromText(value) {
  if (!value || typeof value !== 'string') return []
  const matches = value.match(/https?:\/\/[^\s"'<>]+/gi) || []
  return Array.from(new Set(matches.map(normalizeUrl).filter(Boolean)))
}

async function collectCardDiagnostics(card) {
  try {
    return await card.evaluate((node) => {
      const normalize = (value) => typeof value === 'string' ? value.trim() : ''
      const rootAttrs = {}
      for (const attr of Array.from(node.attributes || [])) {
        rootAttrs[attr.name] = attr.value
      }

      const anchors = Array.from(node.querySelectorAll('a')).slice(0, 12).map(anchor => ({
        text: normalize(anchor.textContent).slice(0, 180),
        href: anchor.getAttribute('href'),
        ariaLabel: anchor.getAttribute('aria-label'),
        title: anchor.getAttribute('title'),
        target: anchor.getAttribute('target'),
        dataTestId: anchor.getAttribute('data-testid')
      }))

      const buttons = Array.from(node.querySelectorAll('button,[role="button"]')).slice(0, 12).map(button => ({
        text: normalize(button.textContent).slice(0, 180),
        ariaLabel: button.getAttribute('aria-label'),
        title: button.getAttribute('title'),
        dataTestId: button.getAttribute('data-testid')
      }))

      const descendantsWithAttrs = Array.from(node.querySelectorAll('*'))
        .filter(el => Array.from(el.attributes || []).some(attr =>
          attr.name.startsWith('data-') ||
          attr.name === 'href' ||
          attr.name === 'src' ||
          attr.name === 'onclick'))
        .slice(0, 20)
        .map(el => {
          const attrs = {}
          for (const attr of Array.from(el.attributes || [])) {
            attrs[attr.name] = attr.value
          }
          return {
            tag: el.tagName,
            text: normalize(el.textContent).slice(0, 120),
            attrs
          }
        })

      return {
        text: normalize(node.textContent).slice(0, 1200),
        html: (node.outerHTML || '').slice(0, 12000),
        rootAttrs,
        anchors,
        buttons,
        descendantsWithAttrs
      }
    })
  } catch (error) {
    return { error: error.message }
  }
}

function collectUrlsFromDiagnostics(diagnostics) {
  const candidates = new Set()
  const push = (value) => {
    for (const url of extractUrlsFromText(value)) {
      candidates.add(url)
    }
  }

  push(diagnostics?.html)
  push(diagnostics?.text)

  for (const anchor of diagnostics?.anchors || []) {
    push(anchor?.href)
    push(anchor?.ariaLabel)
    push(anchor?.title)
  }

  const attrSources = [
    diagnostics?.rootAttrs,
    ...(diagnostics?.descendantsWithAttrs || []).map(item => item?.attrs || {})
  ]

  for (const attrs of attrSources) {
    if (!attrs || typeof attrs !== 'object') continue
    for (const [key, value] of Object.entries(attrs)) {
      if (!value) continue
      if (key.startsWith('data-') || key === 'href' || key === 'src' || key === 'onclick') {
        push(value)
      }
    }
  }

  return Array.from(candidates)
}

function persistDebugArtifact(name, payload) {
  try {
    const dir = '/app/data/mercadolivre-affiliate-scout'
    fs.mkdirSync(dir, { recursive: true })
    const filePath = path.join(dir, `${name}-${nowStamp()}.json`)
    fs.writeFileSync(filePath, JSON.stringify(payload, null, 2), 'utf8')
    return filePath
  } catch {
    return null
  }
}

async function extractMoneyText(root, selector) {
  const container = root.locator(selector).first()
  if (!await container.count().catch(() => 0)) {
    return null
  }

  const fraction = (await container.locator('.andes-money-amount__fraction').first().textContent({ timeout: 1200 }).catch(() => null))?.trim() || null
  if (!fraction) {
    return null
  }

  const cents = (await container.locator('.andes-money-amount__cents').first().textContent({ timeout: 1200 }).catch(() => null))?.trim() || null
  return cents ? `${fraction},${cents}` : fraction
}

async function tryExtractShareUrl(page, card, settings) {
  try {
    await card.scrollIntoViewIfNeeded({ timeout: 2000 }).catch(() => {})

    const shareSelectors = [
      settings.shareButtonSelector,
      "button:has-text('Compartilhar oferta')",
      "button:has-text('Compartilhar')",
      "button[aria-label*='Compartilhar']",
      "[data-testid='share-offer']"
    ].filter(Boolean)

    let shareBtn = null
    for (const selector of shareSelectors) {
      const locator = card.locator(selector).first()
      if (await locator.count().catch(() => 0)) {
        shareBtn = locator
        break
      }
    }

    if (!shareBtn) return null

    await page.evaluate(async () => {
      try {
        await navigator.clipboard.writeText('')
      } catch {}
    }).catch(() => {})

    await shareBtn.click({ timeout: 2500 }).catch(() => {})
    await page.waitForTimeout(1200)

    const fieldSelectors = [
      settings.sharedLinkSelector,
      "input[value^='http']",
      "input[value^='https']",
      "textarea"
    ].filter(Boolean)

    for (const selector of fieldSelectors) {
      const input = page.locator(selector).first()
      if (await input.count().catch(() => 0)) {
        const raw = await input.inputValue({ timeout: 1500 }).catch(async () =>
          await input.textContent({ timeout: 1500 }).catch(() => null))
        const normalized = normalizeUrl(raw)
        if (normalized) {
          await closeShareModal(page)
          return normalized
        }
      }
    }

    const actionSelectors = [
      settings.shareActionSelector,
      "button:has-text('Copiar link')",
      "button:has-text('Gerar link')",
      "button:has-text('Copiar')",
      "[data-testid='copy-link']",
      "[data-testid='copy-affiliate-link']",
      "[data-testid='share-offer-link']"
    ].filter(Boolean)

    for (const selector of actionSelectors) {
      const copyBtn = page.locator(selector).first()
      if (await copyBtn.count().catch(() => 0)) {
        await copyBtn.click({ timeout: 2000 }).catch(() => {})
        await page.waitForTimeout(700)
        const clipboardUrl = await page.evaluate(() => navigator.clipboard.readText()).catch(() => null)
        const normalizedClipboardUrl = normalizeUrl(clipboardUrl)
        if (normalizedClipboardUrl) {
          await closeShareModal(page)
          return normalizedClipboardUrl
        }
      }
    }

    await closeShareModal(page)
    return null
  } catch (e) {
    console.log('Share flow error:', e.message)
    await closeShareModal(page)
    return null
  }
}

async function closeShareModal(page) {
  await page.keyboard.press('Escape').catch(() => {})
  await page.waitForTimeout(250)
  const closeSelectors = [
    "button:has-text('Fechar')",
    "[aria-label='Fechar']",
    ".andes-modal__close-button"
  ]
  for (const selector of closeSelectors) {
    const closeBtn = page.locator(selector).first()
    if (await closeBtn.count().catch(() => 0)) {
      await closeBtn.click({ timeout: 1000 }).catch(() => {})
      await page.waitForTimeout(250)
      break
    }
  }
}

async function tryActivateExtraGains(page) {
  const selectors = [
    "button:has-text('Ganhos extras')",
    "[role='tab']:has-text('Ganhos extras')",
    "a:has-text('Ganhos extras')",
    "button:has-text('Extra')",
    "[role='tab']:has-text('Extra')",
    "[data-testid='extra-profit']",
    ":text('Ganhos extras')"
  ]

  for (const selector of selectors) {
    try {
      const target = page.locator(selector).first()
      if (await target.count().catch(() => 0)) {
        await target.scrollIntoViewIfNeeded({ timeout: 1500 }).catch(() => {})
        if (await target.isVisible().catch(() => false)) {
          await target.click({ timeout: 2000 }).catch(() => {})
          await page.waitForTimeout(1500)
          console.log(`Activated extra gains selector: ${selector}`)
          return true
        }
      }
    } catch {}
  }

  console.log('Extra gains selector not found; continuing with default listing.')
  return false
}

async function tryResolveProductUrlByNavigation(page, card) {
  const candidateSelectors = [
    null,
    "a[href*='/p/']",
    "a[href*='MLB']",
    'a',
    'article',
    'section'
  ]

  for (const selector of candidateSelectors) {
    try {
      const target = selector ? card.locator(selector).first() : card
      if (selector && !await target.count().catch(() => 0)) {
        continue
      }

      await target.scrollIntoViewIfNeeded({ timeout: 1500 }).catch(() => {})
      const currentUrl = page.url()
      const popupPromise = page.context().waitForEvent('page', { timeout: 2500 }).catch(() => null)
      await target.click({ timeout: 2500, force: true }).catch(() => {})
      const popup = await popupPromise
      if (popup) {
        await popup.waitForLoadState('domcontentloaded', { timeout: 5000 }).catch(() => {})
        const popupUrl = normalizeUrl(popup.url())
        await popup.close().catch(() => {})
        if (popupUrl && popupUrl !== currentUrl && !popupUrl.includes('/afiliados/hub')) {
          return popupUrl
        }
      }

      await page.waitForTimeout(1200)
      const navigatedUrl = normalizeUrl(page.url())

      if (navigatedUrl && navigatedUrl !== currentUrl && !navigatedUrl.includes('/afiliados/hub')) {
        await page.goBack({ waitUntil: 'domcontentloaded', timeout: 15000 }).catch(() => {})
        await page.waitForTimeout(1000)
        return navigatedUrl
      }

      if (page.url() !== currentUrl) {
        await page.goBack({ waitUntil: 'domcontentloaded', timeout: 15000 }).catch(() => {})
        await page.waitForTimeout(1000)
      }
    } catch {}
  }

  return null
}

async function tryResolveProductUrlFromDiagnostics(card) {
  const diagnostics = await collectCardDiagnostics(card)
  const candidates = collectUrlsFromDiagnostics(diagnostics)
  return {
    diagnostics,
    candidates,
    resolvedUrl: candidates.find(url =>
      url.includes('mercadolivre.com') ||
      url.includes('meli.la') ||
      url.includes('/p/') ||
      /MLB\d+/i.test(url)) || null
  }
}

app.get('/health', (req, res) => {
  res.json({ ok: true, browserReady: browser?.isConnected() ?? false })
})

app.post('/test', async (req, res) => {
  const settings = req.body || {}
  const loginUrl = (settings.loginUrl || 'https://www.mercadolivre.com.br/entrar?go=https%3A%2F%2Fwww.mercadolivre.com.br%2Fafiliados%2Fhub').trim()
  const homeUrl = (settings.homeUrl || 'https://www.mercadolivre.com.br/afiliados/hub').trim()
  const offerCardSelector = settings.offerCardSelector || "li.poly-card, [data-testid='recommendation-card']"
  const offerLinkSelector = settings.offerLinkSelector || "a.poly-component__title, a[href*='/p/']"
  const offerTitleSelector = settings.offerTitleSelector || '.poly-component__title, h2, h3'
  const offerPriceSelector = settings.offerPriceSelector || '.poly-price__current .andes-money-amount__fraction, .andes-money-amount__fraction'
  const offerImageSelector = settings.offerImageSelector || '.poly-component__picture, img'
  const offerCommissionSelector = settings.offerCommissionSelector || ".poly-component__label, .poly-card__commission, [data-testid='commission']"
  const unlimitedRun = Number(settings.maxOffersPerRun || 0) <= 0
  const maxOffersPerRun = unlimitedRun ? Number.MAX_SAFE_INTEGER : Math.max(1, Math.min(Number(settings.maxOffersPerRun || 1), 500))
  const candidateLimit = Math.max(1, Math.min(Number(settings.candidateLimit || (unlimitedRun ? 120 : maxOffersPerRun * 10)), 120))
  const cardScanLimit = Math.max(candidateLimit, Math.min(candidateLimit * 3, 360))

  let context = null
  let page = null

  try {
    const b = await getBrowser(settings.headless !== false)
    const contextOptions = {
      userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
      locale: 'pt-BR',
      timezoneId: 'America/Sao_Paulo',
      viewport: { width: 1440, height: 900 },
      extraHTTPHeaders: { 'Accept-Language': 'pt-BR,pt;q=0.9,en;q=0.8' }
    }

    if (settings.usePersistentSession) {
      if (settings.storageStateJson && settings.storageStateJson !== '********') {
        try {
          contextOptions.storageState = JSON.parse(settings.storageStateJson)
        } catch {}
      } else if (settings.storageStatePath && require('fs').existsSync(settings.storageStatePath)) {
        try {
          contextOptions.storageState = JSON.parse(require('fs').readFileSync(settings.storageStatePath, 'utf8'))
        } catch (e) {
          console.error('Failed to load storageState from path:', e)
        }
      }
    }

    context = await b.newContext(contextOptions)
    await context.grantPermissions(['clipboard-read', 'clipboard-write'])
    page = await context.newPage()

    console.log('Navigating to homeUrl...', homeUrl)
    await page.goto(homeUrl, { waitUntil: 'domcontentloaded', timeout: 30000 })
    await page.waitForTimeout(2500)

    let auth = await detectAuth(page)
    console.log('Auth detected:', auth)

    if (auth.authRequired || page.url().includes('/entrar')) {
      console.log('Auth is still required, navigating to loginUrl...', loginUrl)
      await page.goto(loginUrl, { waitUntil: 'domcontentloaded', timeout: 30000 })
      await page.waitForTimeout(1500)

      await tryFill(page, [
        "input[type='email']",
        "input[name='login']",
        "input[name='user_id']",
        "input[autocomplete='username']"
      ], settings.loginUser)

      await tryClick(page, [
        "button[type='submit']",
        "button:has-text('Continuar')",
        "button:has-text('Entrar')"
      ])

      await page.waitForTimeout(2000)

      await tryFill(page, [
        "input[type='password']",
        "input[name='password']",
        "input[autocomplete='current-password']"
      ], settings.loginPassword)

      await tryClick(page, [
        "button[type='submit']",
        "button:has-text('Entrar')",
        "button:has-text('Continuar')"
      ])

      await page.waitForTimeout(3000)

      if (settings.twoFactorCode && settings.twoFactorCode !== '********') {
        await tryFill(page, [
          "input[inputmode='numeric']",
          "input[name='code']",
          "input[name='otp']",
          "input[autocomplete='one-time-code']"
        ], settings.twoFactorCode)

        await tryClick(page, [
          "button[type='submit']",
          "button:has-text('Confirmar')",
          "button:has-text('Continuar')"
        ])

        await page.waitForTimeout(2500)
      }

      await page.goto(homeUrl, { waitUntil: 'domcontentloaded', timeout: 30000 })
      await page.waitForTimeout(2500)
      auth = await detectAuth(page)
      console.log('Post-login auth detected:', auth)
    }

    const loggedIn = !auth.authRequired && !page.url().includes('/entrar')
    console.log('Ultimately logged in:', loggedIn)
    if (!loggedIn) {
      const screenshotPath = settings.saveScreenshotsOnFailure ? await saveFailureScreenshot(page) : null
      await context.close()
      return res.json({
        success: false,
        loggedIn: false,
        authRequired: true,
        authModeDetected: auth.authModeDetected || settings.authMode || 'code-or-qr',
        currentUrl: auth.currentUrl,
        screenshotPath,
        offers: [],
        message: 'Login ainda exige código ou leitura de QR code.',
        pageTitle: auth.pageTitle
      })
    }

    const minCommission = Number(settings.minCommissionPercent || 0)
    const maxRetries = 3
    let offers = []

    if (settings.forceRefreshBeforeScan === true) {
      console.log('Force refresh before scan requested. Reloading affiliate hub...')
      await page.reload({ waitUntil: 'domcontentloaded', timeout: 30000 })
      await page.waitForTimeout(3000)
    }

    for (let attempt = 0; attempt < maxRetries; attempt++) {
      if (attempt > 0) {
        console.log(`[Retry ${attempt}] No qualifying offers found. Reloading page...`)
        await page.reload({ waitUntil: 'domcontentloaded', timeout: 30000 })
        await page.waitForTimeout(3000)
      }

      await tryActivateExtraGains(page).catch(() => {})

      try {
        let lastHeight = 0
        for (let s = 0; s < 16; s++) {
          await page.evaluate(() => window.scrollTo(0, document.body.scrollHeight))
          await page.waitForTimeout(900)
          const newHeight = await page.evaluate(() => document.body.scrollHeight)
          if (newHeight === lastHeight) break
          lastHeight = newHeight
        }
        await page.evaluate(() => window.scrollTo(0, 0))
        await page.waitForTimeout(800)
      } catch {}

      try {
        const carouselNextSelectors = [
          "button.andes-carousel-snapped__control--next",
          "button[aria-label='Siguiente'], button[aria-label='Próximo'], button[aria-label='Next']",
          '.slick-next',
          '.andes-carousel-snapped__control--next',
          'button.poly-component__carousel-next',
          "[class*='carousel'] button[class*='next']",
          "[class*='carousel'] [class*='arrow-right']",
          "[class*='carousel'] [class*='control--next']"
        ]
        const carouselContainers = page.locator("[class*='carousel'], [class*='recommendations'], [class*='slick']")
        const containerCount = await carouselContainers.count().catch(() => 0)
        console.log(`Found ${containerCount} carousel containers, advancing arrows...`)

        for (let ci = 0; ci < Math.min(containerCount, 4); ci++) {
          const container = carouselContainers.nth(ci)
          await container.scrollIntoViewIfNeeded({ timeout: 2000 }).catch(() => {})
          for (let click = 0; click < 4; click++) {
            let clicked = false
            for (const arrowSel of carouselNextSelectors) {
              try {
                const arrow = container.locator(arrowSel).first()
                if (await arrow.count() > 0 && await arrow.isVisible().catch(() => false)) {
                  await arrow.click({ timeout: 1500 })
                  await page.waitForTimeout(500)
                  clicked = true
                  break
                }
              } catch {}
            }
            if (!clicked) break
          }
        }

        await page.evaluate(() => window.scrollTo(0, 0))
        await page.waitForTimeout(500)
      } catch (e) {
        console.log('Carousel arrow navigation error (non-fatal):', e.message)
      }

        const cardSelectors = [
          'li.poly-card',
          "[data-testid='recommendation-card']",
          "[data-testid='affiliate-offer-card']",
          "[data-testid='recommendation-card'] li",
          "[data-testid='affiliate-offer-card'] li",
          '.recommendations-carousel .slick-slide',
          '.hub-recommendations__list > li',
          "[class*='card'][class*='offer']",
          'article',
          offerCardSelector
        ]

        let cards = null
        let totalCards = 0
        const selectorScores = []
        for (const sel of Array.from(new Set(cardSelectors.filter(Boolean)))) {
          try {
            const candidate = page.locator(sel)
            const count = await candidate.count()
            if (count > 0 && count <= 1000) {
              selectorScores.push({ sel, count })
              if (count > totalCards) {
                cards = candidate
                totalCards = count
              }
            }
          } catch {}
        }

        if (selectorScores.length > 0) {
          const summary = selectorScores
            .sort((a, b) => b.count - a.count)
            .slice(0, 6)
            .map(item => `"${item.sel}" → ${item.count}`)
            .join(' | ')
          console.log(`Card selectors ranked: ${summary}`)
        }

        if (cards && totalCards > 0) {
          const selected = selectorScores.find(item => item.count === totalCards)
          console.log(`Card selector selected: "${selected?.sel || 'unknown'}" → ${totalCards} cards`)
        }

        if (!cards || totalCards === 0) {
        console.log('No card container found, falling back to link extraction')
        const links = page.locator("a[href*='/p/'], a[href*='mercadolivre.com.br/'][href*='MLB']")
        const linkCount = await links.count()
        for (let i = 0; i < Math.min(linkCount, candidateLimit); i++) {
          const href = await links.nth(i).getAttribute('href').catch(() => null)
          const txt = (await links.nth(i).textContent().catch(() => ''))?.trim()
          const normalizedHref = normalizeUrl(href)
          if (normalizedHref) {
            offers.push({
              title: txt || null,
              productUrl: normalizedHref,
              sharedUrl: null,
              priceText: null,
              commissionText: null,
              imageUrl: null
            })
          }
        }
      } else {
        const cardsToProcess = Math.min(totalCards, cardScanLimit)
        console.log(`Processing up to ${cardsToProcess}/${totalCards} cards with minCommission ${minCommission}% and candidateLimit ${candidateLimit}`)
          for (let i = 0; i < cardsToProcess; i += 1) {
            const card = cards.nth(i)

          let title = null
          for (const sel of [offerTitleSelector, '.poly-component__title', 'h2', 'h3', "[class*='title']", "p[class*='name']"]) {
            title = (await card.locator(sel).first().textContent({ timeout: 1200 }).catch(() => null))?.trim() || null
            if (title) break
          }

          let priceText = null
          for (const selector of ['.poly-price__current', '.andes-money-amount--current', "[data-testid='price-current']", "[data-testid='price']"]) {
            priceText = await extractMoneyText(card, selector)
            if (priceText) break
          }

          if (!priceText) {
            for (const sel of [offerPriceSelector, '.poly-price__current .andes-money-amount__fraction', '.andes-money-amount--current .andes-money-amount__fraction', '.andes-money-amount__fraction', "[class*='price']"]) {
              priceText = (await card.locator(sel).first().textContent({ timeout: 1200 }).catch(() => null))?.trim() || null
              if (priceText) break
            }
          }

          let commissionText = null
          let extractedCommVal = 0
          for (const sel of [offerCommissionSelector, "[class*='commission']", "[data-testid='commission']", "[class*='label']", 'span', 'p']) {
            const candidates = card.locator(sel)
            const cnt = await candidates.count().catch(() => 0)
            for (let j = 0; j < Math.min(cnt, 5); j++) {
              const text = (await candidates.nth(j).textContent({ timeout: 800 }).catch(() => null))?.trim() || ''
              if (text.includes('%')) {
                commissionText = text
                extractedCommVal = parsePercent(text)
                break
              }
            }
            if (commissionText) break
          }

          const extractedPriceValue = parsePrice(priceText)
          if (!isAcceptedByCommissionTiers(extractedPriceValue, extractedCommVal, settings)) {
            continue
          }

          let imageUrl = null
          for (const sel of [offerImageSelector, '.poly-component__picture img', "img[src*='mlstatic']", "img[src^='http']"]) {
            imageUrl = await card.locator(sel).first().getAttribute('src', { timeout: 1200 }).catch(async () =>
              await card.locator(sel).first().getAttribute('data-src', { timeout: 1200 }).catch(() => null))
            imageUrl = normalizeUrl(imageUrl)
            if (imageUrl && !imageUrl.includes('svg')) break
          }

          let productUrl = null
          for (const sel of [offerLinkSelector, "a[href*='/p/']", "a[href*='MLB']", 'a']) {
            productUrl = await card.locator(sel).first().getAttribute('href', { timeout: 1200 }).catch(() => null)
            productUrl = normalizeUrl(productUrl)
            if (productUrl) break
          }

          let sharedUrl = null
          if (settings.requireShareButtonFlow !== false) {
            sharedUrl = await tryExtractShareUrl(page, card, settings)
          }

            const diagnosticsResult = (!productUrl && !sharedUrl)
              ? await tryResolveProductUrlFromDiagnostics(card)
              : { diagnostics: null, candidates: [], resolvedUrl: null }

            const finalProductUrl = productUrl || sharedUrl || diagnosticsResult.resolvedUrl
            const navigatedProductUrl = finalProductUrl || await tryResolveProductUrlByNavigation(page, card)
            const finalSharedUrl = sharedUrl || diagnosticsResult.resolvedUrl || navigatedProductUrl || productUrl

            if (!navigatedProductUrl && !finalSharedUrl) {
              let debugPath = null
              if (i === 0) {
                debugPath = persistDebugArtifact('card-debug', {
                  title,
                  priceText,
                  commissionText,
                  offerCardSelector,
                  offerLinkSelector,
                  diagnostics: diagnosticsResult.diagnostics,
                  urlCandidates: diagnosticsResult.candidates
                })
              }

              console.log(`Skipping card ${i}: no product/shared URL found${debugPath ? ` (debug: ${debugPath})` : ''}`)
              continue
            }

          offers.push({
            title,
            productUrl: navigatedProductUrl,
            sharedUrl: finalSharedUrl,
            priceText,
            commissionText,
            imageUrl
          })

          if (offers.length >= candidateLimit) break
        }
      }

      if (offers.length >= candidateLimit) {
        console.log(`Found ${offers.length} qualifying offers on attempt ${attempt + 1}`)
        break
      }

      console.log(`Attempt ${attempt + 1}: 0 qualifying offers found (totalCards scanned: ${totalCards})`)
    }

    offers = offers
      .sort((a, b) => {
        const commissionDelta = parsePercent(b.commissionText) - parsePercent(a.commissionText)
        if (commissionDelta !== 0) return commissionDelta
        return parsePrice(b.priceText) - parsePrice(a.priceText)
      })
      .slice(0, candidateLimit)

    const finalTitle = await page.title().catch(() => null)
    await context.close()
    return res.json({
      success: offers.length > 0,
      loggedIn: true,
      authRequired: false,
      authModeDetected: null,
      currentUrl: page.url(),
      screenshotPath: null,
      offers,
      message: offers.length > 0
        ? 'Hub acessado com sucesso. Ofertas coletadas para validacao.'
        : 'Login concluido, mas nenhuma oferta foi encontrada com os seletores atuais.',
      pageTitle: finalTitle
    })
  } catch (err) {
    const screenshotPath = page && settings.saveScreenshotsOnFailure ? await saveFailureScreenshot(page) : null
    try { await context?.close() } catch {}
    return res.json({
      success: false,
      loggedIn: false,
      authRequired: null,
      authModeDetected: null,
      currentUrl: page?.url?.() || null,
      screenshotPath,
      offers: [],
      message: err.message || 'falha desconhecida',
      pageTitle: null
    })
  }
})

process.on('SIGTERM', async () => {
  try { await browser?.close() } catch {}
  process.exit(0)
})

process.on('SIGINT', async () => {
  try { await browser?.close() } catch {}
  process.exit(0)
})

const PORT = parseInt(process.env.PORT || '3002', 10)
app.listen(PORT, () => console.log(`Mercado Livre Affiliate scraper na porta :${PORT}`))

getBrowser().catch(err => console.error('Falha no warm-up do browser ML:', err.message))
