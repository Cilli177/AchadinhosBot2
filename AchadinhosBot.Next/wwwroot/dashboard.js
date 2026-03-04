let currentRole = null;
    let logsAutoTimer = null;

    async function api(url, method = 'GET', body = null) {
      const res = await fetch(url, {
        method,
        credentials: 'include',
        headers: { 'content-type': 'application/json' },
        body: body ? JSON.stringify(body) : undefined
      });

      let data = {};
      try { data = await res.json(); } catch (error) { console.debug('Resposta sem JSON para', url, error); }
      if (!res.ok) throw { status: res.status, data };
      return data;
    }

    function showAuthState(authenticated, username = '', role = '') {
      document.getElementById('loginCard').classList.toggle('hidden', authenticated);
      document.getElementById('panel').classList.toggle('hidden', !authenticated);
      if (authenticated) {
        currentRole = role;
        document.getElementById('sessionInfo').textContent = `Autenticado como ${username} (${role})`;
        document.getElementById('saveBtn').disabled = role !== 'admin';
        showSection('ops');
      }
    }

    function showSection(name) {
      const sections = ['ops', 'connections', 'route', 'linkresponder', 'mercadolivre', 'instagram', 'instagram-publish', 'instagram-story', 'bio-growth', 'autoreplies', 'logs', 'playground', 'debug'];
      sections.forEach(s => {
        const el = document.getElementById(`section-${s}`);
        if (el) el.classList.toggle('hidden', s !== name);
      });
      document.querySelectorAll('.nav button').forEach(btn => {
        btn.classList.toggle('active', btn.getAttribute('data-tab') === name);
      });
      if (name === 'logs') {
        startLogsAutoRefresh();
      } else {
        stopLogsAutoRefresh();
      }
      if (name === 'linkresponder') {
        loadResponderLogs();
        loadResponderClicks();
      }
      if (name === 'mercadolivre') {
        loadMercadoLivrePending();
      }
      if (name === 'instagram') {
        loadInstaAiLogs();
      }
      if (name === 'instagram-publish') {
        loadInstagramDrafts();
        loadInstagramComments();
        loadInstagramPublishLogs();
      }
      if (name === 'bio-growth') {
        refreshBioLinksPreview();
        loadBioFunnel();
      }
    }

    function formatTs(ts) {
      if (!ts) return '-';
      const d = new Date(ts);
      if (Number.isNaN(d.getTime())) return ts;
      return d.toLocaleString();
    }

    function escapeHtml(text) {
      return String(text || '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
    }

    function shortId(text) {
      const s = String(text || '');
      if (s.length <= 18) return s;
      return `${s.slice(0, 6)}…${s.slice(-6)}`;
    }

    function getGeminiApiKeyRowsFromDom() {
      return Array.from(document.querySelectorAll('#geminiApiKeyRows input[data-gemini-key="1"]'))
        .map(input => String(input.value || '').trim());
    }

    function renderGeminiApiKeyRows(values) {
      const container = document.getElementById('geminiApiKeyRows');
      if (!container) return;
      const rows = (values || [])
        .map(v => String(v || '').trim());
      const effective = rows.length > 0 ? rows : [''];
      container.innerHTML = effective.map((value, index) => `
    <div class="row" style="margin-top:8px;">
      <input type="password" data-gemini-key="1" placeholder="Chave Gemini ${index + 1} (AIza...)" value="${escapeHtml(value)}" />
      <button class="secondary" type="button" onclick="removeGeminiApiKeyRow(${index})">- Remover</button>
    </div>
  `).join('');
    }

    function addGeminiApiKeyRow() {
      const current = getGeminiApiKeyRowsFromDom();
      current.push('');
      renderGeminiApiKeyRows(current);
    }

    function removeGeminiApiKeyRow(index) {
      const current = getGeminiApiKeyRowsFromDom();
      if (current.length <= 1) {
        renderGeminiApiKeyRows(['']);
        return;
      }

      const safeIndex = Math.max(0, Math.min(index, current.length - 1));
      current.splice(safeIndex, 1);
      renderGeminiApiKeyRows(current);
    }

    function collectGeminiApiKeysFromUi() {
      return getGeminiApiKeyRowsFromDom()
        .map(v => v.trim())
        .filter(Boolean);
    }

    function renderSourceBadge(source) {
      const s = String(source || '-');
      const map = {
        AutoReply: 'ok',
        WhatsAppResponder: 'warn',
        TelegramResponder: 'ok',
        TelegramUserbotResponder: 'warn'
      };
      const cls = map[s] || 'muted';
      return `<span class="badge ${cls}">${escapeHtml(s)}</span>`;
    }

    function loadTheme() {
      const saved = localStorage.getItem('theme') || 'dark';
      document.body.setAttribute('data-theme', saved);
    }

    function toggleTheme() {
      const current = document.body.getAttribute('data-theme') || 'dark';
      const next = current === 'dark' ? 'light' : 'dark';
      document.body.setAttribute('data-theme', next);
      localStorage.setItem('theme', next);
    }

    function setButtonBusy(idOrEl, busy, label) {
      const btn = typeof idOrEl === 'string' ? document.getElementById(idOrEl) : idOrEl;
      if (!btn) return;
      if (busy) {
        btn.dataset.originalText = btn.textContent;
        btn.textContent = label || 'Processando...';
        btn.disabled = true;
      } else {
        btn.textContent = btn.dataset.originalText || btn.textContent;
        btn.disabled = false;
      }
    }

    function getInstaPromptPresetTemplates() {
      return {
        profissional: `Atue como um Copywriter Especialista em Marketing de Afiliados e Social Media Manager.\n\nObjetivo: Criar um post para Instagram (Legenda e Roteiro de Stories) focado em atrair novos seguidores atraves de um \"achadinho\" irresistivel e converter vendas imediatas.\n\nPersona do Publico: Brasileiros que buscam custo-beneficio, amam tecnologia/casa organizada e confiam em recomendacoes de especialistas em promocoes (estilo \"Rei das Ofertas\").\n\nDiretrizes de Escrita:\n\nGancho (Hook): Comece com uma frase que ataque uma dor ou desejo imediato.\n\nCorpo: Use bullet points para destacar 3 beneficios principais (linguagem simples, sem \"technobabble\").\n\nLinguagem: Natural, amigavel, brasileira e persuasiva. Evite palavras muito formais.\n\nGatilhos Mentais: Use Escassez (estoque voa), Curadoria (eu selecionei o melhor) e Facilidade (link direto).\n\nCTA (Chamada para Acao): Direcione o seguidor para comentar uma palavra-chave para receber o link ou clicar na Bio.\n\nEstrutura de Entrega:\n\nLegenda do Post: (Gancho + Beneficios + CTA).\n\nRoteiro de 3 Stories: (1: O problema/curiosidade, 2: A solucao/demonstracao, 3: Oferta + Link).\n\nSugestao de 3 Hashtags estrategicas.\n\nDados do Produto:\n{{format}}\n\nDados:\nEntrada: {{input}}\nLink afiliado: {{link}}\nContexto da oferta: {{context}}\n\nRodape (se houver): {{footer}}`,
        premium: `Voce e um copywriter premium de afiliados no Brasil.\nCrie um post MUITO profissional, persuasivo e humano.\nEvite genericidade e repeticoes. Use beneficios reais.\nCrie legendas CLARAMENTE diferentes entre si.\nNao invente preco ou specs.\n\n{{format}}\n\nDados:\nEntrada: {{input}}\nLink afiliado: {{link}}\nContexto da oferta: {{context}}\n\nRodape (se houver): {{footer}}`,
        agressivo: `Voce e um copywriter focado em conversao e urgencia.\nCrie um post de afiliados com CTA forte e claro.\nUse tom direto, gatilhos de urgencia e escassez sem inventar preco.\nCrie legendas CLARAMENTE diferentes entre si.\n\n{{format}}\n\nDados:\nEntrada: {{input}}\nLink afiliado: {{link}}\nContexto da oferta: {{context}}\n\nRodape (se houver): {{footer}}`,
        minimalista: `Voce e um copywriter minimalista.\nCrie um post curto, elegante e objetivo.\nPoucos emojis, foco no beneficio principal.\nCrie legendas CLARAMENTE diferentes entre si.\n\n{{format}}\n\nDados:\nEntrada: {{input}}\nLink afiliado: {{link}}\nContexto da oferta: {{context}}\n\nRodape (se houver): {{footer}}`
      };
    }

    function getDefaultInstaCaptionTemplates() {
      return [
        'Oferta em destaque: {title}\\n\\n{lead}\\n\\nComente "{keyword}" para receber o link.\\n\\n{hashtags}',
        'Oferta: {title}\\n\\nPontos principais:\\n- {bullet1}\\n- {bullet2}\\n- {bullet3}\\n\\nComente "{keyword}" para receber o link.\\n\\n{hashtags}',
        'Oferta do dia: {title}\\n\\n{short}\\n\\nComente "{keyword}" para receber o link.\\n\\n{hashtags}'
      ];
    }

    function downloadInstaImages(encoded) {
      try {
        const urls = JSON.parse(decodeURIComponent(encoded));
        if (!Array.isArray(urls) || urls.length === 0) return;
        urls.forEach(u => window.open(u, '_blank'));
      } catch (error) {
        console.warn('Falha ao abrir imagens do Instagram.', error);
      }
    }

    async function copyInstaImages(encoded) {
      try {
        const urls = JSON.parse(decodeURIComponent(encoded));
        if (!Array.isArray(urls) || urls.length === 0) return;
        await navigator.clipboard.writeText(urls.join('\n'));
      } catch (error) {
        console.warn('Falha ao copiar URLs de imagens do Instagram.', error);
      }
    }

    function applyInstaPromptPreset() {
      const preset = document.getElementById('instaPromptPreset')?.value || 'premium';
      const textarea = document.getElementById('instaPrompt');
      if (!textarea) return;
      if (preset === 'custom') return;
      const templates = getInstaPromptPresetTemplates();
      textarea.value = templates[preset] || templates.premium;
    }

    async function runInstaAiTest() {
      const result = document.getElementById('instaTestResult');
      if (result) result.textContent = 'Testando...';
      const input = document.getElementById('instaTestInput')?.value || '';
      const context = document.getElementById('instaTestContext')?.value || '';
      try {
        const payload = { input, context };
        const data = await api('/api/instagram/test', 'POST', payload);
        if (result) result.textContent = data?.text || 'Sem resposta.';
      } catch (e) {
        if (result) result.textContent = e?.data?.error || e?.message || 'Erro no teste.';
      }
    }

    async function loadInstaAiLogs() {
      const target = document.getElementById('instaAiLogs');
      if (target) target.textContent = 'Carregando...';
      const q = document.getElementById('instaAiLogSearch')?.value || '';
      try {
        const data = await api('/api/logs/instagram-ai' + (q ? ('?q=' + encodeURIComponent(q)) : ''), 'GET');
        const items = data.items || [];
        if (!target) return;
        if (items.length === 0) {
          target.innerHTML = '<div class="muted">Nenhum log.</div>';
          return;
        }
        const rows = items.map(i => {
          const status = i.success ? '<span class="badge ok">OK</span>' : '<span class="badge bad">ERRO</span>';
          const urls = Array.isArray(i.imageUrls) ? i.imageUrls : [];
          const encoded = encodeURIComponent(JSON.stringify(urls));
          const imageActions = urls.length > 0
            ? `<div class="log-actions">
             <button class="secondary" onclick="downloadInstaImages('${encoded}')">Baixar imagens</button>
             <button class="secondary" onclick="copyInstaImages('${encoded}')">Copiar URLs</button>
           </div>`
            : '';
          const thumbs = urls.length > 0
            ? `<div class="log-thumbs">${urls.map(u => `<img src="${escapeHtml(u)}" alt="img" />`).join('')}</div>`
            : '';
          return `
        <div class="log-row">
          <div class="log-time">${escapeHtml(formatTs(i.timestamp))}</div>
          <div class="log-store">${escapeHtml(i.provider)} / ${escapeHtml(i.model || '-')} ${status}</div>
          <div class="log-msg">
            <div><strong>Entrada:</strong> ${escapeHtml(i.inputSnippet || '-')}</div>
            <div><strong>Erro:</strong> ${escapeHtml(i.error || '-')}</div>
            <div><strong>Vars:</strong> ${escapeHtml(String(i.variations || 0))} | <strong>Imagens:</strong> ${escapeHtml(String(i.imageCount || 0))} | <strong>Score:</strong> ${escapeHtml(String(i.qualityScore || 0))} | <strong>Ms:</strong> ${escapeHtml(String(i.durationMs || 0))}</div>
            <div><strong>Notas:</strong> ${escapeHtml(i.qualityNotes || '-')}</div>
            ${imageActions}
            ${thumbs}
          </div>
        </div>`;
        }).join('');
        target.innerHTML = rows;
      } catch (e) {
        if (target) target.textContent = e?.data?.error || e?.message || 'Erro ao carregar logs.';
      }
    }

    async function clearInstaAiLogs() {
      if (currentRole !== 'admin') return;
      await api('/api/logs/instagram-ai/clear', 'POST', {});
      await loadInstaAiLogs();
    }

    async function checkSession() {
      try {
        const me = await api('/auth/me');
        showAuthState(true, me.username || 'admin', me.role || 'operator');
        await loadSettings();
      } catch {
        showAuthState(false);
      }
    }

    async function login() {
      const username = document.getElementById('username').value;
      const password = document.getElementById('password').value;

      try {
        const r = await api('/auth/login', 'POST', { username, password });
        document.getElementById('loginStatus').textContent = r.success ? 'Login efetuado.' : 'Falha no login';
        document.getElementById('loginStatus').className = 'status ok';
        await checkSession();
      } catch (e) {
        const msg = e?.status === 423 ? 'Conta bloqueada temporariamente' : 'Credenciais inválidas';
        document.getElementById('loginStatus').textContent = msg;
        document.getElementById('loginStatus').className = 'status bad';
      }
    }

    async function logout() {
      await api('/auth/logout', 'POST', {});
      showAuthState(false);
    }

    function setChipStatus(id, text, state) {
      const el = document.getElementById(id);
      if (!el) return;
      el.textContent = text;
      el.className = `chip ${state}`;
    }

    function setHealthBadge(id, text, state) {
      const el = document.getElementById(id);
      if (!el) return;
      el.textContent = text;
      el.className = `badge ${state}`;
    }

    function lockTelegramStatus(message, state) {
      const statusEl = document.getElementById('telegramStatus');
      const detailEl = document.getElementById('telegramStatusDetail');
      const safeMessage = message || 'Sem detalhes.';
      window.__telegramStatusLockUntil = Date.now() + 15000;
      window.__telegramStatusLockedText = safeMessage;
      window.__telegramStatusLockedState = state || 'warn';
      if (statusEl) {
        statusEl.textContent = safeMessage;
        statusEl.className = 'status ' + (state || 'warn');
      }
      if (detailEl) {
        detailEl.textContent = safeMessage;
        detailEl.className = 'status ' + (state || 'warn');
      }
    }

    function setEnvironmentBadge(runtimeEnvironment) {
      const envPill = document.getElementById('envPill');
      if (!envPill) return;

      const rawEnv = (runtimeEnvironment || '').trim();
      const host = (window.location.host || '').toLowerCase();
      const inferredEnv = host.includes('dev') || host.includes('localhost') || host.includes('127.0.0.1')
        ? 'Development'
        : 'Production';
      const effectiveEnv = rawEnv || inferredEnv;
      const normalized = effectiveEnv.toLowerCase();

      envPill.className = 'pill env-pill';
      if (normalized.includes('dev')) {
        envPill.classList.add('env-dev');
      } else if (normalized.includes('prod')) {
        envPill.classList.add('env-prod');
      } else {
        envPill.classList.add('env-other');
      }

      envPill.textContent = `Ambiente: ${effectiveEnv}`;
    }

    function renderSettings(s) {
      window.__settingsCache = s;
      setEnvironmentBadge(s.runtimeEnvironment);
      const now = Date.now();
      const lockUntil = window.__telegramStatusLockUntil || 0;
      const isLocked = now < lockUntil;
      const telegramStatusText = s.integrations.telegram.connected
        ? `Conectado (${s.integrations.telegram.identifier || 'sem id'})`
        : 'Não conectado';
      const telegramStatusState = s.integrations.telegram.connected ? 'ok' : 'warn';
      if (!isLocked) {
        const telegramStatusEl = document.getElementById('telegramStatus');
        if (telegramStatusEl) {
          telegramStatusEl.textContent = telegramStatusText;
          telegramStatusEl.className = 'status ' + telegramStatusState;
        }
      }
      const telegramDetail = document.getElementById('telegramStatusDetail');
      if (telegramDetail) {
        if (isLocked) {
          telegramDetail.textContent = window.__telegramStatusLockedText || telegramStatusText;
          telegramDetail.className = 'status ' + (window.__telegramStatusLockedState || telegramStatusState);
        } else {
          telegramDetail.textContent = telegramStatusText;
          telegramDetail.className = 'status ' + telegramStatusState;
        }
      }

      document.getElementById('whatsappStatus').textContent = s.integrations.whatsApp.connected
        ? `Conectado (${s.integrations.whatsApp.identifier || 'sem id'})`
        : 'Não conectado';
      document.getElementById('whatsappStatus').className = 'status ' + (s.integrations.whatsApp.connected ? 'ok' : 'warn');

      const ml = s.integrations?.mercadoLivre || {};
      const mlConnected = !!ml.connected;
      const mlStatus = document.getElementById('mercadoLivreStatus');
      if (mlStatus) {
        mlStatus.textContent = mlConnected
          ? `Conectado (${ml.identifier || 'sem id'})`
          : 'Não validado';
        mlStatus.className = 'status ' + (mlConnected ? 'ok' : 'warn');
      }

      setChipStatus('chipTelegramBot', s.integrations.telegram.connected ? 'Telegram Bot: Conectado' : 'Telegram Bot: Offline', s.integrations.telegram.connected ? 'ok' : 'warn');
      setChipStatus('chipWhatsApp', s.integrations.whatsApp.connected ? 'WhatsApp: Conectado' : 'WhatsApp: Offline', s.integrations.whatsApp.connected ? 'ok' : 'warn');
      setChipStatus('chipMercadoLivre', mlConnected ? 'Mercado Livre: Conectado' : 'Mercado Livre: Nao validado', mlConnected ? 'ok' : 'warn');
      setChipStatus('chipUserbot', 'Telegram Userbot: Conectando...', 'warn');
      setHealthBadge('healthTelegramBot', s.integrations.telegram.connected ? 'Telegram Bot OK' : 'Telegram Bot Offline', s.integrations.telegram.connected ? 'ok' : 'bad');
      setHealthBadge('healthWhatsApp', s.integrations.whatsApp.connected ? 'WhatsApp OK' : 'WhatsApp Offline', s.integrations.whatsApp.connected ? 'ok' : 'bad');

      document.getElementById('rules').value = (s.autoReplies || [])
        .map(r => `${r.trigger} => ${r.responseTemplate}`)
        .join('\n');
      const autoRepliesEnabled = document.getElementById('autoRepliesEnabled');
      if (autoRepliesEnabled) autoRepliesEnabled.checked = s.autoRepliesSettings?.enabled ?? true;

      document.getElementById('autoConvert').checked = !!s.linkAutomation.autoConvertIncomingLinks;
      document.getElementById('autoSend').checked = !!s.linkAutomation.autoSendToDestinationChannel;
      document.getElementById('destinationChannel').value = s.linkAutomation.destinationChannel || '';
      document.getElementById('userbotEnabled').checked = !!s.telegramForwarding?.enabled;
      document.getElementById('userbotDestinationId').value = s.telegramForwarding?.destinationChatId || '';
      document.getElementById('userbotAppendShein').checked = !!s.telegramForwarding?.appendSheinCode;
      document.getElementById('userbotFooter').value = s.telegramForwarding?.footerText || '';
      document.getElementById('waForwardEnabled').checked = !!s.whatsAppForwarding?.enabled;
      document.getElementById('waFromMeOnly').checked = s.whatsAppForwarding?.processFromMeOnly ?? true;
      const waSendMedia = document.getElementById('waSendMedia');
      if (waSendMedia) waSendMedia.checked = s.whatsAppForwarding?.sendMediaEnabled ?? true;
      document.getElementById('waFooter').value = s.whatsAppForwarding?.footerText || '';
      document.getElementById('waAppendShein').checked = s.whatsAppForwarding?.appendSheinCode ?? true;
      if (s.whatsAppForwarding?.instanceName) {
        document.getElementById('waInstanceName').value = s.whatsAppForwarding.instanceName;
      }
      const responder = s.linkResponder || {};
      const responderEnabled = document.getElementById('responderEnabled');
      if (responderEnabled) responderEnabled.checked = !!responder.enabled;
      const responderWhatsApp = document.getElementById('responderWhatsApp');
      if (responderWhatsApp) responderWhatsApp.checked = responder.allowWhatsApp ?? true;
      const responderTelegramBot = document.getElementById('responderTelegramBot');
      if (responderTelegramBot) responderTelegramBot.checked = !!responder.allowTelegramBot;
      const responderTelegramUserbot = document.getElementById('responderTelegramUserbot');
      if (responderTelegramUserbot) responderTelegramUserbot.checked = !!responder.allowTelegramUserbot;
      const responderWaPrivate = document.getElementById('responderWaPrivate');
      if (responderWaPrivate) responderWaPrivate.checked = responder.whatsAppAllowPrivate ?? true;
      const responderWaGroups = document.getElementById('responderWaGroups');
      if (responderWaGroups) responderWaGroups.checked = !!responder.whatsAppAllowGroups;
      const responderTgPrivate = document.getElementById('responderTgPrivate');
      if (responderTgPrivate) responderTgPrivate.checked = responder.telegramAllowPrivate ?? true;
      const responderTgGroups = document.getElementById('responderTgGroups');
      if (responderTgGroups) responderTgGroups.checked = !!responder.telegramAllowGroups;
      const responderWaIds = document.getElementById('responderWaIds');
      if (responderWaIds) responderWaIds.value = (responder.whatsAppChatIds || []).join('\n');
      const responderTgIds = document.getElementById('responderTgIds');
      if (responderTgIds) responderTgIds.value = (responder.telegramChatIds || []).join('\n');
      const responderTemplate = document.getElementById('responderTemplate');
      if (responderTemplate) responderTemplate.value = responder.replyTemplate || '';
      const responderFailTemplate = document.getElementById('responderFailTemplate');
      if (responderFailTemplate) responderFailTemplate.value = responder.replyOnFailure || '';
      const responderAppendShein = document.getElementById('responderAppendShein');
      if (responderAppendShein) responderAppendShein.checked = responder.appendSheinCode ?? true;
      const responderTracking = document.getElementById('responderTracking');
      if (responderTracking) responderTracking.checked = responder.trackingEnabled ?? true;
      const responderFooter = document.getElementById('responderFooter');
      if (responderFooter) responderFooter.value = responder.footerText || '';
      const mlCompliance = s.mercadoLivreCompliance || {};
      const mlCompEnabled = document.getElementById('mlCompEnabled');
      if (mlCompEnabled) mlCompEnabled.checked = !!mlCompliance.enabled;
      const mlCompBlockAuto = document.getElementById('mlCompBlockAuto');
      if (mlCompBlockAuto) mlCompBlockAuto.checked = mlCompliance.blockAutoFlows ?? true;
      const mlCompRequireApproval = document.getElementById('mlCompRequireApproval');
      if (mlCompRequireApproval) mlCompRequireApproval.checked = mlCompliance.requireManualApproval ?? true;
      const mlCompWhitelistEnabled = document.getElementById('mlCompWhitelistEnabled');
      if (mlCompWhitelistEnabled) mlCompWhitelistEnabled.checked = !!mlCompliance.enforceChannelWhitelist;
      const mlCompBlockUnknown = document.getElementById('mlCompBlockUnknown');
      if (mlCompBlockUnknown) mlCompBlockUnknown.checked = mlCompliance.blockWhenChannelUnknown ?? true;
      const mlCompAllowedChannels = document.getElementById('mlCompAllowedChannels');
      if (mlCompAllowedChannels) mlCompAllowedChannels.value = (mlCompliance.allowedChannels || []).join('\n');
      const insta = s.instagramPosts || {};
      const instaEnabled = document.getElementById('instaEnabled');
      if (instaEnabled) instaEnabled.checked = insta.enabled ?? true;
      const instaAllowWhatsApp = document.getElementById('instaAllowWhatsApp');
      if (instaAllowWhatsApp) instaAllowWhatsApp.checked = insta.allowWhatsApp ?? true;
      const instaAllowTelegramBot = document.getElementById('instaAllowTelegramBot');
      if (instaAllowTelegramBot) instaAllowTelegramBot.checked = !!insta.allowTelegramBot;
      const instaAllowTelegramUserbot = document.getElementById('instaAllowTelegramUserbot');
      if (instaAllowTelegramUserbot) instaAllowTelegramUserbot.checked = !!insta.allowTelegramUserbot;
      const instaWaPrivate = document.getElementById('instaWaPrivate');
      if (instaWaPrivate) instaWaPrivate.checked = insta.whatsAppAllowPrivate ?? true;
      const instaWaGroups = document.getElementById('instaWaGroups');
      if (instaWaGroups) instaWaGroups.checked = insta.whatsAppAllowGroups ?? false;
      const instaWaIds = document.getElementById('instaWaIds');
      if (instaWaIds) instaWaIds.value = (insta.whatsAppChatIds || []).join('\n');
      const instaTgPrivate = document.getElementById('instaTgPrivate');
      if (instaTgPrivate) instaTgPrivate.checked = insta.telegramAllowPrivate ?? true;
      const instaTgGroups = document.getElementById('instaTgGroups');
      if (instaTgGroups) instaTgGroups.checked = insta.telegramAllowGroups ?? true;
      const instaTgIds = document.getElementById('instaTgIds');
      if (instaTgIds) instaTgIds.value = (insta.telegramChatIds || []).join('\n');
      const instaContextMode = document.getElementById('instaContextMode');
      if (instaContextMode) {
        let mode = 'Off';
        if (typeof insta.offerContextMode === 'number') {
          mode = insta.offerContextMode === 1 ? 'Suggestion' : insta.offerContextMode === 2 ? 'ExtraPost' : 'Off';
        } else if (typeof insta.offerContextMode === 'string') {
          mode = insta.offerContextMode;
        } else if (insta.useOfferContext) {
          mode = 'ExtraPost';
        }
        instaContextMode.value = mode;
      }
      const instaTriggers = document.getElementById('instaTriggers');
      if (instaTriggers) instaTriggers.value = (insta.triggers || []).join('\n');
      const instaFooter = document.getElementById('instaFooter');
      if (instaFooter) instaFooter.value = insta.footerText || '';

      const instaUseAi = document.getElementById('instaUseAi');
      if (instaUseAi) instaUseAi.checked = !!insta.useAi;
      const openai = s.openAI || {};
      const openaiKey = document.getElementById('openaiApiKey');
      if (openaiKey) openaiKey.value = openai.apiKey ? '********' : '';
      const openaiModel = document.getElementById('openaiModel');
      if (openaiModel) openaiModel.value = openai.model || 'gpt-4o-mini';
      const openaiTemp = document.getElementById('openaiTemp');
      if (openaiTemp) openaiTemp.value = (openai.temperature ?? 0.7);
      const openaiMaxTokens = document.getElementById('openaiMaxTokens');
      if (openaiMaxTokens) openaiMaxTokens.value = (openai.maxOutputTokens ?? 700);
      const instaPrompt = document.getElementById('instaPrompt');
      if (instaPrompt) {
        instaPrompt.value = insta.promptTemplate || '';
        if (!instaPrompt.value) {
          const preset = (insta.promptPreset || 'premium');
          const templates = getInstaPromptPresetTemplates();
          if (templates[preset]) {
            instaPrompt.value = templates[preset];
          }
        }
      }
      const instaPreset = document.getElementById('instaPromptPreset');
      if (instaPreset) instaPreset.value = insta.promptPreset || 'premium';
      const instaVariations = document.getElementById('instaVariations');
      if (instaVariations) instaVariations.value = insta.variationsCount ?? 2;
      const captionTemplates = Array.isArray(insta.captionTemplates) && insta.captionTemplates.length > 0
        ? insta.captionTemplates
        : getDefaultInstaCaptionTemplates();
      const instaCaptionTemplate1 = document.getElementById('instaCaptionTemplate1');
      if (instaCaptionTemplate1) instaCaptionTemplate1.value = captionTemplates[0] || getDefaultInstaCaptionTemplates()[0];
      const instaCaptionTemplate2 = document.getElementById('instaCaptionTemplate2');
      if (instaCaptionTemplate2) instaCaptionTemplate2.value = captionTemplates[1] || getDefaultInstaCaptionTemplates()[1];
      const instaCaptionTemplate3 = document.getElementById('instaCaptionTemplate3');
      if (instaCaptionTemplate3) instaCaptionTemplate3.value = captionTemplates[2] || getDefaultInstaCaptionTemplates()[2];
      const instaAiProvider = document.getElementById('instaAiProvider');
      if (instaAiProvider) instaAiProvider.value = insta.aiProvider || 'openai';
      const instaUltraPrompt = document.getElementById('instaUltraPrompt');
      if (instaUltraPrompt) instaUltraPrompt.checked = !!insta.useUltraPrompt;
      const instaShortName = document.getElementById('instaShortName');
      if (instaShortName) instaShortName.checked = !!insta.useShortProductName;
      const instaBenefits = document.getElementById('instaBenefits');
      if (instaBenefits) instaBenefits.checked = !!insta.useBenefitBullets;
      const instaImageDownload = document.getElementById('instaImageDownload');
      if (instaImageDownload) instaImageDownload.checked = !!insta.useImageDownload;

      const gemini = s.gemini || {};
      const maskedKeys = Array.isArray(gemini.apiKeys) ? gemini.apiKeys : [];
      if (maskedKeys.length > 0) {
        renderGeminiApiKeyRows(maskedKeys);
      } else if (gemini.apiKey) {
        renderGeminiApiKeyRows(['********']);
      } else {
        renderGeminiApiKeyRows(['']);
      }
      const geminiModel = document.getElementById('geminiModel');
      if (geminiModel) geminiModel.value = gemini.model || 'gemini-2.5-flash';
      const geminiMaxTokens = document.getElementById('geminiMaxTokens');
      if (geminiMaxTokens) geminiMaxTokens.value = String(gemini.maxOutputTokens ?? 1200);
      const igPub = s.instagramPublish || {};
      const igPubEnabled = document.getElementById('igPubEnabled');
      if (igPubEnabled) igPubEnabled.checked = igPub.enabled ?? true;
      const igPubToken = document.getElementById('igPubToken');
      if (igPubToken) igPubToken.value = igPub.accessToken ? '********' : '';
      const igPubUserId = document.getElementById('igPubUserId');
      if (igPubUserId) igPubUserId.value = igPub.instagramUserId || '';
      const igPubBaseUrl = document.getElementById('igPubBaseUrl');
      if (igPubBaseUrl) igPubBaseUrl.value = igPub.graphBaseUrl || 'https://graph.facebook.com/v19.0';
      const igPubVerify = document.getElementById('igPubVerifyToken');
      if (igPubVerify) igPubVerify.value = igPub.verifyToken || '';
      const igPubReplyTemplate = document.getElementById('igPubReplyTemplate');
      if (igPubReplyTemplate) igPubReplyTemplate.value = igPub.replyTemplate || 'Aqui esta o link: {link}';
      const igPubReplyNoMatch = document.getElementById('igPubReplyNoMatch');
      if (igPubReplyNoMatch) igPubReplyNoMatch.value = igPub.replyNoMatchTemplate || 'Comente a palavra correta para receber o link.';
      const igPubAutoReplyEnabled = document.getElementById('igPubAutoReplyEnabled');
      if (igPubAutoReplyEnabled) igPubAutoReplyEnabled.checked = igPub.autoReplyEnabled ?? true;
      const igPubAutoReplyOnlyKeyword = document.getElementById('igPubAutoReplyOnlyKeyword');
      if (igPubAutoReplyOnlyKeyword) igPubAutoReplyOnlyKeyword.checked = igPub.autoReplyOnlyOnKeywordMatch ?? true;
      const igPubAutoDmEnabled = document.getElementById('igPubAutoDmEnabled');
      if (igPubAutoDmEnabled) igPubAutoDmEnabled.checked = !!igPub.autoDmEnabled;
      const igPubDmProvider = document.getElementById('igPubDmProvider');
      if (igPubDmProvider) igPubDmProvider.value = igPub.dmProvider || 'meta';
      const igPubDmFallbackManyChat = document.getElementById('igPubDmFallbackManyChat');
      if (igPubDmFallbackManyChat) igPubDmFallbackManyChat.checked = igPub.dmFallbackToManyChatOnError ?? true;
      const igPubDmTemplate = document.getElementById('igPubDmTemplate');
      if (igPubDmTemplate) igPubDmTemplate.value = igPub.dmTemplate || 'Oi {name}! Aqui esta seu link: {link}';
      const igPubManyChatWebhookUrl = document.getElementById('igPubManyChatWebhookUrl');
      if (igPubManyChatWebhookUrl) igPubManyChatWebhookUrl.value = igPub.manyChatWebhookUrl || '';
      const igPubManyChatApiKey = document.getElementById('igPubManyChatApiKey');
      if (igPubManyChatApiKey) igPubManyChatApiKey.value = igPub.manyChatApiKey ? '********' : '';
      const igAutoRequireOfficial = document.getElementById('igAutoRequireOfficial');
      if (igAutoRequireOfficial) igAutoRequireOfficial.checked = igPub.autoPilotRequireOfficialProductData ?? true;
      const igAutoMinImageMatch = document.getElementById('igAutoMinImageMatch');
      if (igAutoMinImageMatch) igAutoMinImageMatch.value = String(igPub.autoPilotMinimumImageMatchScore ?? 80);
      const igAutoRequireAi = document.getElementById('igAutoRequireAi');
      if (igAutoRequireAi) igAutoRequireAi.checked = igPub.autoPilotRequireAiCaption ?? true;
      const igStoryAutoEnabled = document.getElementById('igStoryAutoEnabled');
      if (igStoryAutoEnabled) igStoryAutoEnabled.checked = !!igPub.storyAutoPilotEnabled;
      const igStoryInterval = document.getElementById('igStoryInterval');
      if (igStoryInterval) igStoryInterval.value = String(igPub.storyAutoPilotIntervalMinutes ?? 240);
      const igStoryTopCount = document.getElementById('igStoryTopCount');
      if (igStoryTopCount) igStoryTopCount.value = String(igPub.storyAutoPilotTopCount ?? 2);
      const igStoryLookback = document.getElementById('igStoryLookback');
      if (igStoryLookback) igStoryLookback.value = String(igPub.storyAutoPilotLookbackHours ?? 24);
      const igStoryRepeatWindow = document.getElementById('igStoryRepeatWindow');
      if (igStoryRepeatWindow) igStoryRepeatWindow.value = String(igPub.storyAutoPilotRepeatWindowHours ?? 24);
      const igStorySendApproval = document.getElementById('igStorySendApproval');
      if (igStorySendApproval) igStorySendApproval.checked = igPub.storyAutoPilotSendForApproval ?? true;
      const igStoryApprovalChannel = document.getElementById('igStoryApprovalChannel');
      if (igStoryApprovalChannel) igStoryApprovalChannel.value = igPub.storyAutoPilotApprovalChannel || 'whatsapp';
      const igStoryApprovalTelegramChatId = document.getElementById('igStoryApprovalTelegramChatId');
      if (igStoryApprovalTelegramChatId) igStoryApprovalTelegramChatId.value = String(igPub.storyAutoPilotApprovalTelegramChatId ?? 0);
      const igStoryApprovalWhatsAppGroupId = document.getElementById('igStoryApprovalWhatsAppGroupId');
      if (igStoryApprovalWhatsAppGroupId) igStoryApprovalWhatsAppGroupId.value = igPub.storyAutoPilotApprovalWhatsAppGroupId || '';
      const igStoryApprovalWhatsAppInstance = document.getElementById('igStoryApprovalWhatsAppInstance');
      if (igStoryApprovalWhatsAppInstance) igStoryApprovalWhatsAppInstance.value = igPub.storyAutoPilotApprovalWhatsAppInstanceName || '';
      const bioHub = s.bioHub || {};
      const bioHubEnabled = document.getElementById('bioHubEnabled');
      if (bioHubEnabled) bioHubEnabled.checked = bioHub.enabled ?? true;
      const bioHubBrandName = document.getElementById('bioHubBrandName');
      if (bioHubBrandName) bioHubBrandName.value = bioHub.brandName || 'Rei das Ofertas';
      const bioHubHeadline = document.getElementById('bioHubHeadline');
      if (bioHubHeadline) bioHubHeadline.value = bioHub.headline || 'Achadinhos em destaque';
      const bioHubSubheadline = document.getElementById('bioHubSubheadline');
      if (bioHubSubheadline) bioHubSubheadline.value = bioHub.subheadline || 'Toque no botao para abrir a oferta.';
      const bioHubButtonLabel = document.getElementById('bioHubButtonLabel');
      if (bioHubButtonLabel) bioHubButtonLabel.value = bioHub.buttonLabel || 'Abrir oferta';
      const bioHubMaxItems = document.getElementById('bioHubMaxItems');
      if (bioHubMaxItems) bioHubMaxItems.value = String(bioHub.maxItems ?? 40);
      const bioHubDefaultSource = document.getElementById('bioHubDefaultSource');
      if (bioHubDefaultSource) bioHubDefaultSource.value = bioHub.defaultSource || 'bio';
      const bioHubDefaultCampaign = document.getElementById('bioHubDefaultCampaign');
      if (bioHubDefaultCampaign) bioHubDefaultCampaign.value = bioHub.defaultCampaign || '';
      const bioHubPublicBaseUrl = document.getElementById('bioHubPublicBaseUrl');
      if (bioHubPublicBaseUrl) bioHubPublicBaseUrl.value = bioHub.publicBaseUrl || s.publicBaseUrl || '';
      const tgWaEnabled = document.getElementById('tgWaEnabled');
      if (tgWaEnabled) tgWaEnabled.checked = !!s.telegramToWhatsApp?.enabled;
      document.getElementById('waForwardEnabled').onchange = scheduleWhatsAppSave;
      document.getElementById('waFromMeOnly').onchange = scheduleWhatsAppSave;
      if (waSendMedia) waSendMedia.onchange = scheduleWhatsAppSave;
      document.getElementById('waAppendShein').onchange = scheduleWhatsAppSave;
      document.getElementById('waFooter').onchange = scheduleWhatsAppSave;
      document.getElementById('waInstanceName').onchange = scheduleWhatsAppSave;
      const waStatus = document.getElementById('waForwardStatus');
      if (waStatus) {
        waStatus.textContent = s.whatsAppForwarding?.enabled ? 'Repasse ativo' : 'Repasse inativo';
        waStatus.className = 'status ' + (s.whatsAppForwarding?.enabled ? 'ok' : 'warn');
      }
      const sourceStatus = document.getElementById('waSourceSaveStatus');
      if (sourceStatus && s.whatsAppForwarding?.sourceChatIds) {
        sourceStatus.textContent = `Origem: ${s.whatsAppForwarding.sourceChatIds.length} grupo(s)`;
        sourceStatus.className = 'status muted';
      }

      document.getElementById('debug').textContent = JSON.stringify(s, null, 2);
      document.getElementById('statStatus').textContent = 'Online';
      refreshBioLinksPreview();
    }

    async function loadSettings() {
      const s = await api('/api/settings');
      renderSettings(s);
      await loadUserbotChats();
      await loadWhatsAppGroups();
      renderTelegramToWhatsAppRoute();
      await loadConversionLogs();
      await loadMediaFailures();
    }

    function renderResponderLogs(items) {
      const tbody = document.getElementById('responderLogBody');
      if (!tbody) return;
      if (!items || items.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="muted">Sem dados.</td></tr>';
        return;
      }
      tbody.innerHTML = items.map(i => `
    <tr>
      <td>${formatTs(i.timestamp)}</td>
      <td title="${escapeHtml(i.originChatRef || i.originChatId || '-')}">${shortId(i.originChatRef || i.originChatId || '-')}</td>
      <td>${renderSourceBadge(i.source || '-')}</td>
      <td>${i.success ? 'OK' : 'Falha'}</td>
      <td>${escapeHtml(i.originalUrl || '')}</td>
      <td>${escapeHtml(i.convertedUrl || '')}</td>
      <td>${i.clicks ?? 0}</td>
    </tr>
  `).join('');
    }

    async function loadResponderLogs() {
      const q = document.getElementById('responderLogSearch')?.value || '';
      const res = await api(`/api/logs/conversions?limit=200&q=${encodeURIComponent(q)}`);
      const clicksRes = await api(`/api/logs/clicks?limit=500&q=${encodeURIComponent(q)}`);
      const clickMap = new Map();
      (clicksRes.items || []).forEach(c => {
        const key = c.trackingId;
        if (!key) return;
        clickMap.set(key, (clickMap.get(key) || 0) + 1);
      });
      const items = (res.items || []).filter(i =>
        ['AutoReply', 'WhatsAppResponder', 'TelegramResponder', 'TelegramUserbotResponder'].includes(i.source)
      ).map(i => {
        const trackingIds = i.trackingIds || [];
        const clicks = trackingIds.reduce((sum, id) => sum + (clickMap.get(id) || 0), 0);
        return { ...i, clicks };
      });
      renderResponderLogs(items);
    }

    function renderResponderClicks(items) {
      const tbody = document.getElementById('responderClickBody');
      if (!tbody) return;
      if (!items || items.length === 0) {
        tbody.innerHTML = '<tr><td colspan="3" class="muted">Sem dados.</td></tr>';
        return;
      }
      tbody.innerHTML = items.map(i => `
    <tr>
      <td>${formatTs(i.timestamp)}</td>
      <td>${i.trackingId}</td>
      <td>${escapeHtml(i.targetUrl || '')}</td>
    </tr>
  `).join('');
    }

    async function loadResponderClicks() {
      const q = document.getElementById('responderClickSearch')?.value || '';
      const res = await api(`/api/logs/clicks?limit=200&q=${encodeURIComponent(q)}`);
      renderResponderClicks(res.items || []);
    }

    async function clearResponderClicks() {
      await api('/api/logs/clicks/clear', 'POST', {});
      await loadResponderClicks();
    }

    function startLogsAutoRefresh() {
      if (logsAutoTimer) return;
      loadConversionLogs();
      loadMediaFailures();
      logsAutoTimer = setInterval(() => {
        loadConversionLogs();
        loadMediaFailures();
      }, 15000);
    }

    function stopLogsAutoRefresh() {
      if (!logsAutoTimer) return;
      clearInterval(logsAutoTimer);
      logsAutoTimer = null;
    }

    function parseRules(text) {
      return text
        .split('\n')
        .map(l => l.trim())
        .filter(Boolean)
        .map((line, idx) => {
          const parts = line.split('=>');
          const trigger = (parts[0] || '').trim();
          const response = (parts.slice(1).join('=>') || '').trim();
          return {
            id: crypto.randomUUID(),
            name: `Regra ${idx + 1}`,
            trigger,
            responseTemplate: response,
            enabled: true
          }
        })
        .filter(r => r.trigger && r.responseTemplate);
    }

    function parseManualIds() {
      const text = document.getElementById('userbotManualIds').value || '';
      const parts = text.split(/[,\n\r\t ]+/).map(p => p.trim()).filter(Boolean);
      const ids = [];
      for (const p of parts) {
        const num = Number(p);
        if (!Number.isNaN(num) && Number.isFinite(num)) ids.push(num);
      }
      return ids;
    }

    function parseManualIdsById(id) {
      const text = document.getElementById(id)?.value || '';
      const parts = text.split(/[,\n\r\t ]+/).map(p => p.trim()).filter(Boolean);
      const ids = [];
      for (const p of parts) {
        const num = Number(p);
        if (!Number.isNaN(num) && Number.isFinite(num)) ids.push(num);
      }
      return ids;
    }

    function parseWhatsAppManualIds(id) {
      const text = document.getElementById(id)?.value || '';
      return text.split(/[,\n\r\t ]+/).map(p => p.trim()).filter(Boolean);
    }

    function parseLines(id) {
      const text = document.getElementById(id)?.value || '';
      return text
        .split(/\r?\n/)
        .map(x => x.trim())
        .filter(Boolean);
    }

    async function saveMercadoLivreCompliance() {
      if (currentRole !== 'admin') return;
      const status = document.getElementById('mlCompSaveStatus');
      if (status) {
        status.textContent = 'Salvando...';
        status.className = 'status warn';
      }

      const existing = await api('/api/settings');
      existing.mercadoLivreCompliance = existing.mercadoLivreCompliance || {};
      existing.mercadoLivreCompliance.enabled = document.getElementById('mlCompEnabled')?.checked ?? false;
      existing.mercadoLivreCompliance.blockAutoFlows = document.getElementById('mlCompBlockAuto')?.checked ?? true;
      existing.mercadoLivreCompliance.requireManualApproval = document.getElementById('mlCompRequireApproval')?.checked ?? true;
      existing.mercadoLivreCompliance.enforceChannelWhitelist = document.getElementById('mlCompWhitelistEnabled')?.checked ?? false;
      existing.mercadoLivreCompliance.blockWhenChannelUnknown = document.getElementById('mlCompBlockUnknown')?.checked ?? true;
      existing.mercadoLivreCompliance.allowedChannels = parseLines('mlCompAllowedChannels');

      try {
        await api('/api/settings', 'PUT', existing);
        if (status) {
          status.textContent = 'Compliance salvo.';
          status.className = 'status ok';
        }
        await loadSettings();
        await loadMercadoLivrePending();
      } catch (e) {
        if (status) {
          const message = e?.data?.errors ? e.data.errors.join(' | ') : (e?.data?.error || e?.message || 'Erro ao salvar.');
          status.textContent = message;
          status.className = 'status bad';
        }
      }
    }

    function renderMercadoLivrePending(items) {
      const tbody = document.getElementById('mlPendingBody');
      const count = document.getElementById('mlPendingCount');
      if (!tbody) return;

      if (!items || items.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="muted">Sem pendências.</td></tr>';
        if (count) count.textContent = '0 item(s)';
        return;
      }

      if (count) count.textContent = `${items.length} item(ns)`;
      tbody.innerHTML = items.map(item => {
        const status = String(item.status || '').toLowerCase();
        const badgeClass = status === 'pending' ? 'warn' : (status === 'approved' ? 'ok' : 'bad');
        const urls = (item.extractedUrls || []).join('\n');
        const channel = [item.originChatRef || item.originChatId || '-', item.destinationChatRef || item.destinationChatId || '-'].join(' -> ');
        const actions = status === 'pending'
          ? `<button class="secondary" onclick="approveMercadoLivrePending('${item.id}')">Aprovar</button>
         <button class="danger" onclick="rejectMercadoLivrePending('${item.id}')">Rejeitar</button>`
          : `<span class="muted">${escapeHtml(item.reviewedBy || '-')}</span>`;

        return `
      <tr>
        <td>${formatTs(item.createdAt)}</td>
        <td><span class="badge ${badgeClass}">${escapeHtml(item.status || '-')}</span></td>
        <td>${escapeHtml(item.source || '-')}</td>
        <td><small>${escapeHtml(channel)}</small></td>
        <td><small>${escapeHtml(item.reason || '-')}</small></td>
        <td><small>${escapeHtml(urls || '-')}</small></td>
        <td>
          ${actions}
          ${item.convertedText ? `<button class="copy-btn" data-copy="${encodeURIComponent(item.convertedText)}">Copiar convertido</button>` : ''}
        </td>
      </tr>
    `;
      }).join('');

      document.querySelectorAll('#mlPendingBody .copy-btn').forEach(btn => {
        btn.addEventListener('click', async (ev) => {
          const text = decodeURIComponent(ev.currentTarget.getAttribute('data-copy') || '');
          if (!text) return;
          try {
            await navigator.clipboard.writeText(text);
          } catch {
            const ta = document.createElement('textarea');
            ta.value = text;
            document.body.appendChild(ta);
            ta.select();
            document.execCommand('copy');
            document.body.removeChild(ta);
          }
        });
      });
    }

    async function loadMercadoLivrePending() {
      try {
        const status = document.getElementById('mlPendingStatus')?.value ?? 'pending';
        const query = new URLSearchParams();
        if (status) query.set('status', status);
        query.set('limit', '300');
        const payload = await api('/api/mercadolivre/pending?' + query.toString());
        renderMercadoLivrePending(payload.items || []);
      } catch {
        renderMercadoLivrePending([]);
      }
    }

    async function approveMercadoLivrePending(id) {
      if (currentRole !== 'admin') return;
      const note = prompt('Observação de aprovação (opcional):', '') || '';
      const sendNow = confirm('Enviar o texto aprovado para o(s) destino(s) agora?');
      try {
        const result = await api(`/api/mercadolivre/pending/${id}/approve`, 'POST', { note, sendNow });
        await loadMercadoLivrePending();
        await loadConversionLogs();
        if (sendNow) {
          const sent = result?.sentTargets ?? 0;
          const failures = (result?.sendFailures || []).length;
          if (failures > 0) {
            alert(`Aprovado. Envio: ${sent} sucesso(s), ${failures} falha(s).`);
          }
        }
      } catch (e) {
        alert(e?.data?.error || e?.message || 'Erro ao aprovar pendência.');
      }
    }

    async function rejectMercadoLivrePending(id) {
      if (currentRole !== 'admin') return;
      const note = prompt('Motivo da rejeição (opcional):', '') || '';
      try {
        await api(`/api/mercadolivre/pending/${id}/reject`, 'POST', { note });
        await loadMercadoLivrePending();
      } catch (e) {
        alert(e?.data?.error || e?.message || 'Erro ao rejeitar pendência.');
      }
    }

    async function saveSettings() {
      if (currentRole !== 'admin') return;

      const existing = await api('/api/settings');
      existing.autoReplies = parseRules(document.getElementById('rules').value);
      existing.autoRepliesSettings = existing.autoRepliesSettings || {};
      existing.autoRepliesSettings.enabled = document.getElementById('autoRepliesEnabled')?.checked ?? true;
      existing.linkAutomation.autoConvertIncomingLinks = document.getElementById('autoConvert').checked;
      existing.linkAutomation.autoSendToDestinationChannel = document.getElementById('autoSend').checked;
      existing.linkAutomation.destinationChannel = document.getElementById('destinationChannel').value;
      existing.telegramForwarding = existing.telegramForwarding || {};
      existing.telegramForwarding.enabled = document.getElementById('userbotEnabled').checked;
      existing.telegramForwarding.destinationChatId = Number(document.getElementById('userbotDestinationId').value || 0);
      existing.telegramForwarding.appendSheinCode = document.getElementById('userbotAppendShein').checked;
      existing.telegramForwarding.footerText = document.getElementById('userbotFooter').value || '';

      existing.whatsAppForwarding = existing.whatsAppForwarding || {};
      existing.whatsAppForwarding.enabled = document.getElementById('waForwardEnabled').checked;
      existing.whatsAppForwarding.processFromMeOnly = document.getElementById('waFromMeOnly').checked;
      existing.whatsAppForwarding.footerText = document.getElementById('waFooter').value || '';
      existing.whatsAppForwarding.appendSheinCode = document.getElementById('waAppendShein').checked;
      const waSendMedia = document.getElementById('waSendMedia');
      if (waSendMedia) existing.whatsAppForwarding.sendMediaEnabled = waSendMedia.checked;

      const selected = Array.from(document.querySelectorAll("input[data-userbot-chat=\"1\"]:checked"))
        .map(el => Number(el.value));
      const manual = parseManualIds();
      const merged = Array.from(new Set([...selected, ...manual]));
      existing.telegramForwarding.sourceChatIds = merged;

      const result = await api('/api/settings', 'PUT', existing);
      if (result.errors && result.errors.length) {
        document.getElementById('saveStatus').textContent = result.errors.join(' | ');
        document.getElementById('saveStatus').className = 'status bad';
      } else {
        document.getElementById('saveStatus').textContent = 'Configurações salvas.';
        document.getElementById('saveStatus').className = 'status ok';
      }
      await loadSettings();
    }

    async function saveTelegramToWhatsAppRoute() {
      if (currentRole !== 'admin') return;
      const status = document.getElementById('tgWaSaveStatus');
      if (status) {
        status.textContent = 'Salvando rota...';
        status.className = 'status warn';
      }

      const existing = await api('/api/settings');
      persistActiveTgWaRouteFromUi();
      const routes = (window.__tgWaRoutes || []).map(route => ({
        name: (route.name || 'Rota Telegram -> WhatsApp').trim() || 'Rota Telegram -> WhatsApp',
        enabled: !!route.enabled,
        sourceChatIds: Array.from(new Set((route.sourceChatIds || []).map(Number).filter(x => Number.isFinite(x)))),
        destinationGroupIds: Array.from(new Set((route.destinationGroupIds || []).map(String).filter(Boolean)))
      }));
      existing.telegramToWhatsAppRoutes = routes;

      existing.telegramToWhatsApp = existing.telegramToWhatsApp || {};
      const firstRoute = routes[0];
      existing.telegramToWhatsApp.enabled = firstRoute ? !!firstRoute.enabled : false;
      existing.telegramToWhatsApp.sourceChatIds = firstRoute ? firstRoute.sourceChatIds : [];
      existing.telegramToWhatsApp.destinationGroupIds = firstRoute ? firstRoute.destinationGroupIds : [];

      try {
        await api('/api/settings', 'PUT', existing);
        if (status) {
          status.textContent = 'Rota salva.';
          status.className = 'status ok';
        }
      } catch (e) {
        if (status) {
          status.textContent = e.data?.errors ? e.data.errors.join(' | ') : 'Erro ao salvar.';
          status.className = 'status bad';
        }
      }
    }

    async function saveLinkResponder() {
      if (currentRole !== 'admin') return;
      const status = document.getElementById('responderSaveStatus');
      if (status) {
        status.textContent = 'Salvando...';
        status.className = 'status warn';
      }

      const existing = await api('/api/settings');
      existing.linkResponder = existing.linkResponder || {};
      existing.linkResponder.enabled = document.getElementById('responderEnabled')?.checked ?? false;
      existing.linkResponder.allowWhatsApp = document.getElementById('responderWhatsApp')?.checked ?? true;
      existing.linkResponder.allowTelegramBot = document.getElementById('responderTelegramBot')?.checked ?? false;
      existing.linkResponder.allowTelegramUserbot = document.getElementById('responderTelegramUserbot')?.checked ?? false;
      existing.linkResponder.whatsAppAllowPrivate = document.getElementById('responderWaPrivate')?.checked ?? true;
      existing.linkResponder.whatsAppAllowGroups = document.getElementById('responderWaGroups')?.checked ?? false;
      existing.linkResponder.telegramAllowPrivate = document.getElementById('responderTgPrivate')?.checked ?? true;
      existing.linkResponder.telegramAllowGroups = document.getElementById('responderTgGroups')?.checked ?? false;
      existing.linkResponder.whatsAppChatIds = parseWhatsAppManualIds('responderWaIds');
      existing.linkResponder.telegramChatIds = parseManualIdsById('responderTgIds');
      existing.linkResponder.replyTemplate = document.getElementById('responderTemplate')?.value || '';
      existing.linkResponder.replyOnFailure = document.getElementById('responderFailTemplate')?.value || '';
      existing.linkResponder.appendSheinCode = document.getElementById('responderAppendShein')?.checked ?? true;
      existing.linkResponder.trackingEnabled = document.getElementById('responderTracking')?.checked ?? true;
      existing.linkResponder.footerText = document.getElementById('responderFooter')?.value || '';

      try {
        await api('/api/settings', 'PUT', existing);
        if (status) {
          status.textContent = 'Gatilho salvo.';
          status.className = 'status ok';
        }
        await loadSettings();
      } catch (e) {
        if (status) {
          status.textContent = `Erro: ${e?.data?.error || e.message || 'Falha ao salvar'}`;
          status.className = 'status bad';
        }
      }
    }

    async function saveInstagramSettings() {
      if (currentRole !== 'admin') return;
      const status = document.getElementById('instaSaveStatus');
      if (status) {
        status.textContent = 'Salvando...';
        status.className = 'status warn';
      }

      const existing = await api('/api/settings');
      existing.instagramPosts = existing.instagramPosts || {};
      existing.instagramPosts.enabled = document.getElementById('instaEnabled')?.checked ?? true;
      existing.instagramPosts.allowWhatsApp = document.getElementById('instaAllowWhatsApp')?.checked ?? true;
      existing.instagramPosts.allowTelegramBot = document.getElementById('instaAllowTelegramBot')?.checked ?? false;
      existing.instagramPosts.allowTelegramUserbot = document.getElementById('instaAllowTelegramUserbot')?.checked ?? false;
      existing.instagramPosts.whatsAppAllowPrivate = document.getElementById('instaWaPrivate')?.checked ?? true;
      existing.instagramPosts.whatsAppAllowGroups = document.getElementById('instaWaGroups')?.checked ?? false;
      existing.instagramPosts.whatsAppChatIds = parseWhatsAppManualIds('instaWaIds');
      existing.instagramPosts.telegramAllowPrivate = document.getElementById('instaTgPrivate')?.checked ?? true;
      existing.instagramPosts.telegramAllowGroups = document.getElementById('instaTgGroups')?.checked ?? true;
      existing.instagramPosts.telegramChatIds = parseManualIdsById('instaTgIds');
      const instaContextMode = document.getElementById('instaContextMode')?.value || 'Off';
      const instaContextMap = { Off: 0, Suggestion: 1, ExtraPost: 2 };
      existing.instagramPosts.offerContextMode = instaContextMap[instaContextMode] ?? 0;
      existing.instagramPosts.useOfferContext = instaContextMode === 'ExtraPost';
      existing.instagramPosts.useAi = document.getElementById('instaUseAi')?.checked ?? false;
      existing.instagramPosts.useUltraPrompt = document.getElementById('instaUltraPrompt')?.checked ?? false;
      existing.instagramPosts.useShortProductName = document.getElementById('instaShortName')?.checked ?? false;
      existing.instagramPosts.useBenefitBullets = document.getElementById('instaBenefits')?.checked ?? false;
      existing.instagramPosts.useImageDownload = document.getElementById('instaImageDownload')?.checked ?? false;
      existing.instagramPosts.variationsCount = parseInt(document.getElementById('instaVariations')?.value || '2', 10);
      existing.instagramPosts.promptPreset = document.getElementById('instaPromptPreset')?.value || 'premium';
      existing.instagramPosts.aiProvider = document.getElementById('instaAiProvider')?.value || 'openai';
      existing.instagramPosts.triggers = parseLines('instaTriggers');
      existing.instagramPosts.footerText = document.getElementById('instaFooter')?.value || '';
      existing.instagramPosts.promptTemplate = document.getElementById('instaPrompt')?.value || '';
      const defaultCaptionTemplates = getDefaultInstaCaptionTemplates();
      existing.instagramPosts.captionTemplates = [
        (document.getElementById('instaCaptionTemplate1')?.value || defaultCaptionTemplates[0]).trim(),
        (document.getElementById('instaCaptionTemplate2')?.value || defaultCaptionTemplates[1]).trim(),
        (document.getElementById('instaCaptionTemplate3')?.value || defaultCaptionTemplates[2]).trim()
      ];

      existing.openAI = existing.openAI || {};
      existing.openAI.apiKey = document.getElementById('openaiApiKey')?.value || '';
      existing.openAI.model = document.getElementById('openaiModel')?.value || 'gpt-4o-mini';
      existing.openAI.temperature = parseFloat(document.getElementById('openaiTemp')?.value || '0.7');
      existing.openAI.maxOutputTokens = parseInt(document.getElementById('openaiMaxTokens')?.value || '700', 10);

      existing.gemini = existing.gemini || {};
      const geminiKeys = collectGeminiApiKeysFromUi();
      existing.gemini.apiKey = geminiKeys[0] || '';
      existing.gemini.apiKeys = geminiKeys;
      existing.gemini.model = document.getElementById('geminiModel')?.value || 'gemini-2.5-flash';
      existing.gemini.maxOutputTokens = parseInt(document.getElementById('geminiMaxTokens')?.value || '1200', 10);

      try {
        await api('/api/settings', 'PUT', existing);
        if (status) {
          status.textContent = 'Instagram salvo.';
          status.className = 'status ok';
        }
        await loadSettings();
      } catch (e) {
        if (status) {
          status.textContent = `Erro: ${e?.data?.error || e.message || 'Falha ao salvar'}`;
          status.className = 'status bad';
        }
      }
    }

    async function saveInstagramPublishSettings() {
      if (currentRole !== 'admin') return;
      const status = document.getElementById('igPubSaveStatus');
      if (status) {
        status.textContent = 'Salvando...';
        status.className = 'status warn';
      }

      const existing = await api('/api/settings');
      existing.instagramPublish = existing.instagramPublish || {};
      existing.instagramPublish.enabled = document.getElementById('igPubEnabled')?.checked ?? true;
      existing.instagramPublish.accessToken = document.getElementById('igPubToken')?.value || '';
      existing.instagramPublish.instagramUserId = document.getElementById('igPubUserId')?.value || '';
      existing.instagramPublish.graphBaseUrl = document.getElementById('igPubBaseUrl')?.value || 'https://graph.facebook.com/v19.0';
      existing.instagramPublish.verifyToken = document.getElementById('igPubVerifyToken')?.value || '';
      existing.instagramPublish.replyTemplate = document.getElementById('igPubReplyTemplate')?.value || 'Aqui esta o link: {link}';
      existing.instagramPublish.replyNoMatchTemplate = document.getElementById('igPubReplyNoMatch')?.value || 'Comente a palavra correta para receber o link.';
      existing.instagramPublish.autoReplyEnabled = document.getElementById('igPubAutoReplyEnabled')?.checked ?? true;
      existing.instagramPublish.autoReplyOnlyOnKeywordMatch = document.getElementById('igPubAutoReplyOnlyKeyword')?.checked ?? true;
      existing.instagramPublish.autoDmEnabled = document.getElementById('igPubAutoDmEnabled')?.checked ?? false;
      existing.instagramPublish.dmProvider = document.getElementById('igPubDmProvider')?.value || 'meta';
      existing.instagramPublish.dmFallbackToManyChatOnError = document.getElementById('igPubDmFallbackManyChat')?.checked ?? true;
      existing.instagramPublish.dmTemplate = document.getElementById('igPubDmTemplate')?.value || 'Oi {name}! Aqui esta seu link: {link}';
      existing.instagramPublish.manyChatWebhookUrl = document.getElementById('igPubManyChatWebhookUrl')?.value || '';
      existing.instagramPublish.manyChatApiKey = document.getElementById('igPubManyChatApiKey')?.value || '';
      existing.instagramPublish.autoPilotRequireOfficialProductData = document.getElementById('igAutoRequireOfficial')?.checked ?? true;
      existing.instagramPublish.autoPilotMinimumImageMatchScore = parseInt(document.getElementById('igAutoMinImageMatch')?.value || '80', 10) || 80;
      existing.instagramPublish.autoPilotRequireAiCaption = document.getElementById('igAutoRequireAi')?.checked ?? true;

      try {
        await api('/api/settings', 'PUT', existing);
        if (status) {
          status.textContent = 'Configuracoes salvas.';
          status.className = 'status ok';
        }
        await loadSettings();
      } catch (e) {
        if (status) {
          status.textContent = e?.data?.error || e?.message || 'Erro ao salvar.';
          status.className = 'status bad';
        }
      }
    }

    async function saveInstagramStorySettings() {
      if (currentRole !== 'admin') return;
      const status = document.getElementById('igStoryStatus');
      if (status) {
        status.textContent = 'Salvando...';
        status.className = 'status warn';
      }

      const existing = await api('/api/settings');
      existing.instagramPublish = existing.instagramPublish || {};
      existing.instagramPublish.storyAutoPilotEnabled = document.getElementById('igStoryAutoEnabled')?.checked ?? false;
      existing.instagramPublish.storyAutoPilotIntervalMinutes = parseInt(document.getElementById('igStoryInterval')?.value || '240', 10);
      existing.instagramPublish.storyAutoPilotTopCount = parseInt(document.getElementById('igStoryTopCount')?.value || '2', 10);
      existing.instagramPublish.storyAutoPilotLookbackHours = parseInt(document.getElementById('igStoryLookback')?.value || '24', 10);
      existing.instagramPublish.storyAutoPilotRepeatWindowHours = parseInt(document.getElementById('igStoryRepeatWindow')?.value || '24', 10);
      existing.instagramPublish.storyAutoPilotSendForApproval = document.getElementById('igStorySendApproval')?.checked ?? true;
      existing.instagramPublish.storyAutoPilotApprovalChannel = document.getElementById('igStoryApprovalChannel')?.value || 'whatsapp';
      existing.instagramPublish.storyAutoPilotApprovalTelegramChatId = parseInt(document.getElementById('igStoryApprovalTelegramChatId')?.value || '0', 10) || 0;
      existing.instagramPublish.storyAutoPilotApprovalWhatsAppGroupId = document.getElementById('igStoryApprovalWhatsAppGroupId')?.value || '';
      existing.instagramPublish.storyAutoPilotApprovalWhatsAppInstanceName = document.getElementById('igStoryApprovalWhatsAppInstance')?.value || '';

      try {
        await api('/api/settings', 'PUT', existing);
        if (status) {
          status.textContent = 'AutoStory salvo.';
          status.className = 'status ok';
        }
        await loadSettings();
      } catch (e) {
        if (status) {
          status.textContent = e?.data?.error || e?.message || 'Erro ao salvar.';
          status.className = 'status bad';
        }
      }
    }

    async function loadApiDiagnostics() {
      const status = document.getElementById('apiDiagStatus');
      const result = document.getElementById('apiDiagResult');
      if (status) {
        status.textContent = 'Carregando...';
        status.className = 'status warn';
      }
      if (result) {
        result.textContent = '';
      }

      try {
        const payload = await api('/api/diagnostics/apis');
        if (result) {
          result.textContent = JSON.stringify(payload, null, 2);
        }
        if (status) {
          status.textContent = 'Status atualizado.';
          status.className = 'status ok';
        }
      } catch (e) {
        if (result) {
          result.textContent = e?.data?.error || e?.message || 'Falha ao obter diagnostico.';
        }
        if (status) {
          status.textContent = 'Erro ao carregar.';
          status.className = 'status bad';
        }
      }
    }

    function buildBioLinksFromUi() {
      const manualBase = (document.getElementById('bioHubPublicBaseUrl')?.value || '').trim();
      const configuredBase = (manualBase || window.__settingsCache?.publicBaseUrl || '').trim();
      const runtimeBase = (window.location.origin || '').trim();
      const base = (configuredBase || runtimeBase).replace(/\/$/, '');
      const source = (document.getElementById('bioHubDefaultSource')?.value || 'bio').trim() || 'bio';
      const campaign = (document.getElementById('bioHubDefaultCampaign')?.value || '').trim();
      const feedCampaign = campaign || 'insta-feed';
      const storyCampaign = campaign || 'insta-story';
      const manychatCampaign = campaign || 'manychat';
      const encode = encodeURIComponent;

      const linkBase = `${base}/bio?src=${encode(source)}`;
      return [
        { label: 'Instagram Bio', url: campaign ? `${linkBase}&camp=${encode(campaign)}` : linkBase },
        { label: 'Story CTA', url: `${base}/bio?src=instagram-story&camp=${encode(storyCampaign)}` },
        { label: 'ManyChat DM', url: `${base}/bio?src=manychat&camp=${encode(manychatCampaign)}` },
        { label: 'Feed Comentario', url: `${base}/bio?src=instagram-feed&camp=${encode(feedCampaign)}` },
        { label: 'Catalogo Site', url: `${base}/catalogo` },
        { label: 'Item Exemplo', url: `${base}/item/42` }
      ];
    }

    function copyToClipboard(text) {
      if (!text) return;
      navigator.clipboard.writeText(text).catch(() => {
        const area = document.createElement('textarea');
        area.value = text;
        document.body.appendChild(area);
        area.select();
        document.execCommand('copy');
        document.body.removeChild(area);
      });
    }

    function refreshBioLinksPreview() {
      const body = document.getElementById('bioLinksTableBody');
      if (!body) return;
      const items = buildBioLinksFromUi();
      body.innerHTML = items.map((item, index) => `
    <tr>
      <td>${escapeHtml(item.label)}</td>
      <td><small>${escapeHtml(item.url)}</small></td>
      <td>
        <button class="secondary" onclick="window.open(decodeURIComponent('${encodeURIComponent(item.url)}'), '_blank')">Abrir</button>
        <button class="secondary" onclick="copyToClipboard(decodeURIComponent('${encodeURIComponent(item.url)}'))">Copiar</button>
      </td>
    </tr>
  `).join('');
    }

    async function saveBioHubSettings() {
      if (currentRole !== 'admin') return;
      const status = document.getElementById('bioHubStatus');
      if (status) {
        status.textContent = 'Salvando...';
        status.className = 'status warn';
      }

      const existing = await api('/api/settings');
      existing.bioHub = existing.bioHub || {};
      existing.bioHub.enabled = document.getElementById('bioHubEnabled')?.checked ?? true;
      existing.bioHub.brandName = document.getElementById('bioHubBrandName')?.value || 'Rei das Ofertas';
      existing.bioHub.headline = document.getElementById('bioHubHeadline')?.value || 'Achadinhos em destaque';
      existing.bioHub.subheadline = document.getElementById('bioHubSubheadline')?.value || 'Toque no botao para abrir a oferta.';
      existing.bioHub.buttonLabel = document.getElementById('bioHubButtonLabel')?.value || 'Abrir oferta';
      existing.bioHub.maxItems = parseInt(document.getElementById('bioHubMaxItems')?.value || '40', 10);
      existing.bioHub.defaultSource = document.getElementById('bioHubDefaultSource')?.value || 'bio';
      existing.bioHub.defaultCampaign = document.getElementById('bioHubDefaultCampaign')?.value || '';
      existing.bioHub.publicBaseUrl = document.getElementById('bioHubPublicBaseUrl')?.value || '';

      try {
        await api('/api/settings', 'PUT', existing);
        if (status) {
          status.textContent = 'Bio Hub salvo.';
          status.className = 'status ok';
        }
        refreshBioLinksPreview();
      } catch (e) {
        if (status) {
          status.textContent = e?.data?.errors ? e.data.errors.join(' | ') : (e?.data?.error || e?.message || 'Erro ao salvar.');
          status.className = 'status bad';
        }
      }
    }

    async function syncCatalogNow() {
      if (currentRole !== 'admin') return;
      const status = document.getElementById('bioHubStatus');
      if (status) {
        status.textContent = 'Sincronizando catalogo...';
        status.className = 'status warn';
      }
      try {
        const res = await api('/api/catalog/sync', 'POST', {});
        const result = res?.result || {};
        if (status) {
          status.textContent = `Catalogo sincronizado. Criados: ${result.created || 0}, atualizados: ${result.updated || 0}, ativos: ${result.totalActive || 0}.`;
          status.className = 'status ok';
        }
      } catch (e) {
        if (status) {
          status.textContent = e?.data?.error || e?.message || 'Erro ao sincronizar catalogo.';
          status.className = 'status bad';
        }
      }
    }

    async function loadBioFunnel() {
      const status = document.getElementById('bioFunnelStatus');
      const totals = document.getElementById('bioFunnelTotals');
      const sources = document.getElementById('bioFunnelSources');
      const campaigns = document.getElementById('bioFunnelCampaigns');
      const hours = document.getElementById('bioFunnelHours')?.value || '168';
      if (status) {
        status.textContent = 'Carregando...';
        status.className = 'status warn';
      }

      try {
        const data = await api(`/api/logs/funnel?hours=${encodeURIComponent(hours)}`);
        const total = data?.totals || {};
        if (totals) {
          totals.textContent = [
            `Janela: ${data?.windowHours || hours}h`,
            `Cliques: ${total.clicks ?? 0}`,
            `Conversoes: ${total.conversions ?? 0}`,
            `Conversoes OK: ${total.successfulConversions ?? 0}`,
            `Conversoes afiliadas: ${total.affiliatedConversions ?? 0}`
          ].join('\\n');
        }

        if (sources) {
          const lines = (data?.bySource || []).slice(0, 8).map(x => `${x.source}: ${x.clicks} cliques (${x.uniqueLinks} links)`);
          sources.textContent = lines.length ? lines.join('\\n') : 'Sem cliques no periodo.';
        }

        if (campaigns) {
          const lines = (data?.byCampaign || []).slice(0, 10).map(x => `${x.campaign}: ${x.clicks} cliques (${x.uniqueLinks} links)`);
          campaigns.textContent = lines.length ? lines.join('\\n') : 'Sem campanhas no periodo.';
        }

        if (status) {
          status.textContent = 'Funnel atualizado.';
          status.className = 'status ok';
        }
      } catch (e) {
        if (status) {
          status.textContent = e?.data?.error || e?.message || 'Erro ao carregar funnel.';
          status.className = 'status bad';
        }
        if (totals) totals.textContent = 'Falha ao carregar.';
        if (sources) sources.textContent = 'Falha ao carregar.';
        if (campaigns) campaigns.textContent = 'Falha ao carregar.';
      }
    }

    async function runInstagramAutoStory(dryRun) {
      if (currentRole !== 'admin') return;
      const status = document.getElementById('igStoryStatus');
      if (status) {
        status.textContent = dryRun ? 'Executando dry-run...' : 'Executando AutoStory...';
        status.className = 'status warn';
      }

      const payload = {
        postType: 'story',
        topCount: parseInt(document.getElementById('igStoryTopCount')?.value || '2', 10),
        lookbackHours: parseInt(document.getElementById('igStoryLookback')?.value || '24', 10),
        repeatWindowHours: parseInt(document.getElementById('igStoryRepeatWindow')?.value || '24', 10),
        sendForApproval: document.getElementById('igStorySendApproval')?.checked ?? true,
        approvalChannel: document.getElementById('igStoryApprovalChannel')?.value || 'whatsapp',
        approvalTelegramChatId: parseInt(document.getElementById('igStoryApprovalTelegramChatId')?.value || '0', 10) || 0,
        approvalWhatsAppGroupId: document.getElementById('igStoryApprovalWhatsAppGroupId')?.value || '',
        approvalWhatsAppInstanceName: document.getElementById('igStoryApprovalWhatsAppInstance')?.value || '',
        dryRun: !!dryRun
      };

      try {
        const res = await api('/api/instagram/autostory/run', 'POST', payload);
        if (status) {
          status.textContent = res?.message || 'AutoStory executado.';
          status.className = res?.success ? 'status ok' : 'status bad';
        }
        await loadInstagramDrafts();
        await loadInstagramPublishLogs();
      } catch (e) {
        if (status) {
          status.textContent = e?.data?.error || e?.message || 'Erro ao executar AutoStory.';
          status.className = 'status bad';
        }
      }
    }

    async function testInstagramPublish() {
      if (currentRole !== 'admin') return;
      const status = document.getElementById('igPubSaveStatus');
      if (status) {
        status.textContent = 'Testando...';
        status.className = 'status warn';
      }
      try {
        await api('/api/instagram/publish/test', 'POST', {});
        if (status) {
          status.textContent = 'Conexao OK.';
          status.className = 'status ok';
        }
        await loadInstagramPublishLogs();
      } catch (e) {
        if (status) {
          status.textContent = e?.data?.error || e?.message || 'Falha no teste.';
          status.className = 'status bad';
        }
      }
    }

    function parseCtas(text) {
      const lines = (text || '').split(/\n/).map(l => l.trim()).filter(Boolean);
      const ctas = [];
      for (const line of lines) {
        const parts = line.split('=>').map(p => p.trim());
        if (parts.length >= 2 && parts[0] && parts[1]) {
          ctas.push({ keyword: parts[0], link: parts.slice(1).join('=>') });
        }
      }
      return ctas;
    }

    function normalizeQuickCta(value) {
      const raw = String(value || '').trim().toUpperCase();
      if (!raw) return 'LINK';
      return raw.replace(/\s+/g, '_');
    }

    function buildIgQuickCommands() {
      const input = (document.getElementById('igQuickInput')?.value || '').trim();
      const cta = normalizeQuickCta(document.getElementById('igQuickCta')?.value || '');
      const image = (document.getElementById('igQuickImage')?.value || '').trim();
      if (!input) return '';

      const lines = [];
      lines.push(`/ig criar ${input} cta=${cta}`);
      if (image) {
        lines.push(`/ig imagem ultimo ${image}`);
      }
      lines.push('/leg 1 ultimo');
      lines.push('/ig formatar ultimo');
      lines.push('/ig revisar ultimo');
      lines.push('/ig confirmar ultimo');
      return lines.join('\n');
    }

    function buildIgFastCommand() {
      const input = (document.getElementById('igQuickInput')?.value || '').trim();
      const cta = normalizeQuickCta(document.getElementById('igQuickCta')?.value || '');
      const image = (document.getElementById('igQuickImage')?.value || '').trim();
      if (!input) return '';
      const imagePart = image ? ` img=${image}` : '';
      return `/ig rapido ${input} cta=${cta}${imagePart}`;
    }

    function setIgQuickStatus(text, cls) {
      const el = document.getElementById('igQuickStatus');
      if (!el) return;
      el.textContent = text;
      el.className = `status ${cls || 'muted'}`;
    }

    async function copyToClipboardSafe(text) {
      if (!text) return false;
      try {
        if (navigator.clipboard && navigator.clipboard.writeText) {
          await navigator.clipboard.writeText(text);
          return true;
        }
      } catch (error) {
        console.warn('Falha ao copiar para clipboard (API).', error);
      }

      const temp = document.createElement('textarea');
      temp.value = text;
      document.body.appendChild(temp);
      temp.select();
      const ok = document.execCommand('copy');
      document.body.removeChild(temp);
      return ok;
    }

    function generateIgQuickCommands() {
      const commands = buildIgQuickCommands();
      const target = document.getElementById('igQuickCommands');
      if (target) {
        target.value = commands;
      }
      if (!commands) {
        setIgQuickStatus('Informe produto/link para gerar comandos.', 'bad');
        return;
      }
      setIgQuickStatus('Comandos gerados.', 'ok');
    }

    async function copyIgQuickCommands() {
      const target = document.getElementById('igQuickCommands');
      const commands = (target?.value || buildIgQuickCommands()).trim();
      if (!commands) {
        setIgQuickStatus('Nada para copiar. Gere os comandos primeiro.', 'bad');
        return;
      }
      const copied = await copyToClipboardSafe(commands);
      setIgQuickStatus(copied ? 'Comandos copiados.' : 'Nao foi possivel copiar.', copied ? 'ok' : 'bad');
    }

    async function copyIgFastCommand() {
      const command = buildIgFastCommand();
      if (!command) {
        setIgQuickStatus('Informe produto/link para montar /ig rapido.', 'bad');
        return;
      }
      const copied = await copyToClipboardSafe(command);
      setIgQuickStatus(copied ? 'Comando /ig rapido copiado.' : 'Nao foi possivel copiar.', copied ? 'ok' : 'bad');
    }

    async function saveInstagramDraft(publishNow) {
      if (currentRole !== 'admin') return;
      const status = document.getElementById('igDraftStatus');
      if (status) {
        status.textContent = publishNow ? 'Publicando...' : 'Salvando...';
        status.className = 'status warn';
      }
      const payload = {
        productName: document.getElementById('igDraftProduct')?.value || '',
        caption: document.getElementById('igDraftCaption')?.value || '',
        hashtags: document.getElementById('igDraftHashtags')?.value || '',
        imageUrls: (document.getElementById('igDraftImages')?.value || '').split(/\n/).map(l => l.trim()).filter(Boolean),
        ctas: parseCtas(document.getElementById('igDraftCtas')?.value || '')
      };
      try {
        const res = await api('/api/instagram/publish/drafts', 'POST', payload);
        if (publishNow && res.id) {
          await publishInstagramDraft(res.id);
        }
        if (status) {
          status.textContent = publishNow ? 'Publicado.' : 'Rascunho salvo.';
          status.className = 'status ok';
        }
        await loadInstagramDrafts();
      } catch (e) {
        if (status) {
          status.textContent = e?.data?.error || e?.message || 'Erro.';
          status.className = 'status bad';
        }
      }
    }

    async function loadInstagramDrafts() {
      const target = document.getElementById('igDraftList');
      if (target) target.textContent = 'Carregando...';
      try {
        const data = await api('/api/instagram/publish/drafts', 'GET');
        const items = data.items || [];
        if (!target) return;
        if (items.length === 0) {
          target.innerHTML = '<div class="muted">Nenhum rascunho.</div>';
          return;
        }
        const rows = items.map(d => `
      <div class="log-row">
        <div class="log-time">${escapeHtml(formatTs(d.createdAt))}</div>
        <div class="log-store">${escapeHtml(d.productName || 'Post')}</div>
        <div class="log-msg">
          <div><strong>Status:</strong> ${escapeHtml(d.status || '-')}</div>
          <div><strong>Imagens:</strong> ${escapeHtml(String((d.imageUrls || []).length))}</div>
          <div><strong>CTA:</strong> ${escapeHtml(String((d.ctas || []).length))}</div>
          <div class="row">
            <button class="secondary" onclick="publishInstagramDraft('${d.id}')">Publicar</button>
          </div>
          ${d.error ? `<div class="status bad">Erro: ${escapeHtml(d.error)}</div>` : ''}
        </div>
      </div>
    `).join('');
        target.innerHTML = rows;
      } catch (e) {
        if (target) target.textContent = e?.data?.error || e?.message || 'Erro ao carregar.';
      }
    }

    async function publishInstagramDraft(id) {
      try {
        await api(`/api/instagram/publish/drafts/${id}/publish`, 'POST', {});
        await loadInstagramDrafts();
      } catch (e) {
        console.error(e);
      }
    }

    async function loadInstagramComments() {
      const target = document.getElementById('igCommentList');
      if (target) target.textContent = 'Carregando...';
      try {
        const data = await api('/api/instagram/comments/pending', 'GET');
        const items = data.items || [];
        if (!target) return;
        if (items.length === 0) {
          target.innerHTML = '<div class="muted">Nenhum comentario pendente.</div>';
          return;
        }
        const rows = items.map(c => `
      <div class="log-row">
        <div class="log-time">${escapeHtml(formatTs(c.timestamp))}</div>
        <div class="log-store">${escapeHtml(c.from || 'usuario')}</div>
        <div class="log-msg">
          <div><strong>Comentario:</strong> ${escapeHtml(c.text || '')}</div>
          <textarea id="igReply_${c.id}" rows="2">${escapeHtml(c.suggestedReply || '')}</textarea>
          <div class="row">
            <button onclick="approveInstagramComment('${c.id}')">Aprovar</button>
            <button class="secondary" onclick="rejectInstagramComment('${c.id}')">Rejeitar</button>
          </div>
        </div>
      </div>
    `).join('');
        target.innerHTML = rows;
      } catch (e) {
        if (target) target.textContent = e?.data?.error || e?.message || 'Erro ao carregar.';
      }
    }

    async function approveInstagramComment(id) {
      const message = document.getElementById(`igReply_${id}`)?.value || '';
      await api(`/api/instagram/comments/${id}/approve`, 'POST', { message });
      await loadInstagramComments();
    }

    async function rejectInstagramComment(id) {
      await api(`/api/instagram/comments/${id}/reject`, 'POST', {});
      await loadInstagramComments();
    }

    async function loadInstagramPublishLogs() {
      const target = document.getElementById('igPubLogs');
      if (target) target.textContent = 'Carregando...';
      const q = document.getElementById('igPubLogSearch')?.value || '';
      try {
        const data = await api('/api/logs/instagram-publish' + (q ? ('?q=' + encodeURIComponent(q)) : ''), 'GET');
        const items = data.items || [];
        if (!target) return;
        if (items.length === 0) {
          target.innerHTML = '<div class="muted">Nenhum log.</div>';
          return;
        }
        const rows = items.map(i => `
      <div class="log-row">
        <div class="log-time">${escapeHtml(formatTs(i.timestamp))}</div>
        <div class="log-store">${escapeHtml(i.action || '-')} ${i.success ? '<span class="badge ok">OK</span>' : '<span class="badge bad">ERRO</span>'}</div>
        <div class="log-msg">
          <div><strong>Draft:</strong> ${escapeHtml(i.draftId || '-')}</div>
          <div><strong>Media:</strong> ${escapeHtml(i.mediaId || '-')}</div>
          <div><strong>Erro:</strong> ${escapeHtml(i.error || '-')}</div>
          <div><strong>Detalhes:</strong> ${escapeHtml(i.details || '-')}</div>
          ${i.mediaId ? `<div class="row"><button class="secondary" onclick="checkInstagramStatus('${i.mediaId}')">Verificar status</button></div>` : ''}
        </div>
      </div>
    `).join('');
        target.innerHTML = rows;
      } catch (e) {
        if (target) target.textContent = e?.data?.error || e?.message || 'Erro ao carregar.';
      }
    }

    async function clearInstagramPublishLogs() {
      if (currentRole !== 'admin') return;
      await api('/api/logs/instagram-publish/clear', 'POST', {});
      await loadInstagramPublishLogs();
    }

    async function checkInstagramStatus(mediaId) {
      if (!mediaId) return;
      try {
        const res = await api(`/api/instagram/publish/status/${mediaId}`, 'GET');
        const data = res?.data ? JSON.stringify(res.data, null, 2) : res?.data;
        alert(data || 'Status OK');
        await loadInstagramPublishLogs();
      } catch (e) {
        alert(e?.data?.error || e?.message || 'Falha ao consultar status.');
      }
    }

    function parseLines(id) {
      const text = document.getElementById(id)?.value || '';
      return text.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
    }

    async function connectTelegram() {
      setButtonBusy('btnTelegramConnect', true, 'Validando...');
      try {
        const botToken = (document.getElementById('telegramBotToken')?.value || '').trim();
        const r = await api('/api/integrations/telegram/connect', 'POST', { botToken: botToken || null });
        const message = r.success
          ? `Conectado (${r.username || 'ok'})`
          : `Erro: ${r.message || 'Falha na conexão'}`;
        lockTelegramStatus(message, r.success ? 'ok' : 'bad');
      } catch (e) {
        const message = `Erro: ${e.data?.error || e.message || 'Falha na requisição'}`;
        lockTelegramStatus(message, 'bad');
      }
      await loadSettings();
      setButtonBusy('btnTelegramConnect', false);
    }

    async function connectMercadoLivre() {
      setButtonBusy('btnMercadoLivreConnect', true, 'Validando...');
      try {
        const r = await api('/api/integrations/mercadolivre/connect', 'POST', {});
        const status = document.getElementById('mercadoLivreStatus');
        if (status) {
          status.textContent = r.success
            ? `Conectado (${r.userId || 'sem id'})`
            : `Falha: ${r.message || 'OAuth nao configurado'}`;
          status.className = 'status ' + (r.success ? 'ok' : 'bad');
        }
      } catch (e) {
        const status = document.getElementById('mercadoLivreStatus');
        if (status) {
          status.textContent = `Erro: ${e.data?.error || e.message || 'Falha na requisicao'}`;
          status.className = 'status bad';
        }
      }
      await loadSettings();
      setButtonBusy('btnMercadoLivreConnect', false);
    }

    async function connectWhatsApp() {
      setButtonBusy('btnWhatsAppConnect', true, 'Gerando QR...');
      try {
        const instanceName = document.getElementById('waInstanceName').value || null;
        const r = await api('/api/integrations/whatsapp/connect', 'POST', { instanceName });
        if (r.qrCode) {
          document.getElementById('qrImage').src = r.qrCode;
          document.getElementById('qrImage').classList.remove('hidden');
          document.getElementById('qrHint').classList.remove('hidden');
          document.getElementById('whatsappStatus').textContent = 'QR gerado. Aguardando leitura...';
          document.getElementById('whatsappStatus').className = 'status warn';
        } else if (r.success) {
          document.getElementById('whatsappStatus').textContent = r.message || 'Instância já conectada.';
          document.getElementById('whatsappStatus').className = 'status ok';
        } else {
          document.getElementById('whatsappStatus').textContent = `Erro: ${r.message || 'Falha ao gerar QR'}`;
          document.getElementById('whatsappStatus').className = 'status bad';
        }
      } catch (e) {
        document.getElementById('whatsappStatus').textContent = `Erro: ${e.data?.error || e.message || 'Falha na requisição'}`;
        document.getElementById('whatsappStatus').className = 'status bad';
      }
      setButtonBusy('btnWhatsAppConnect', false);
      setTimeout(loadSettings, 4000);
    }

    async function createWhatsAppInstance() {
      const instanceName = document.getElementById('waInstanceName').value || '';
      if (!instanceName.trim()) {
        document.getElementById('whatsappStatus').textContent = 'Informe o Instance Name.';
        document.getElementById('whatsappStatus').className = 'status bad';
        return;
      }
      try {
        const r = await api('/api/integrations/whatsapp/instance', 'POST', { instanceName });
        if (r.qrCode) {
          document.getElementById('qrImage').src = r.qrCode;
          document.getElementById('qrImage').classList.remove('hidden');
          document.getElementById('qrHint').classList.remove('hidden');
          document.getElementById('whatsappStatus').textContent = r.message || 'Instância criada. QR gerado.';
          document.getElementById('whatsappStatus').className = 'status warn';
        } else if (r.success) {
          document.getElementById('whatsappStatus').textContent = r.message || 'Instância criada com sucesso.';
          document.getElementById('whatsappStatus').className = 'status ok';
        } else {
          document.getElementById('whatsappStatus').textContent = `Erro: ${r.message || 'Falha ao criar instância'}`;
          document.getElementById('whatsappStatus').className = 'status bad';
        }
      } catch (e) {
        document.getElementById('whatsappStatus').textContent = `Erro: ${e.data?.error || e.message || 'Falha na requisição'}`;
        document.getElementById('whatsappStatus').className = 'status bad';
      }
    }

    async function runPlayground() {
      const text = document.getElementById('playgroundText').value;
      const result = await api('/api/playground/preview', 'POST', { text });
      document.getElementById('playgroundResult').textContent = JSON.stringify(result, null, 2);
    }

    async function applyUserbotAuth() {
      const statusEl = document.getElementById('userbotAuthStatus');
      if (currentRole !== 'admin') {
        if (statusEl) {
          statusEl.textContent = 'Permissão insuficiente para atualizar credenciais.';
          statusEl.className = 'status bad';
        }
        return;
      }

      const phoneRaw = (document.getElementById('userbotAuthPhone')?.value || '').trim();
      const codeRaw = (document.getElementById('userbotAuthCode')?.value || '').trim();
      const passwordRaw = (document.getElementById('userbotAuthPassword')?.value || '').trim();
      const forceReconnect = !!document.getElementById('userbotForceReconnect')?.checked;

      const payload = {
        phoneNumber: phoneRaw ? phoneRaw : null,
        verificationCode: codeRaw ? codeRaw : null,
        password: passwordRaw ? passwordRaw : null,
        forceReconnect
      };

      if (!payload.phoneNumber && !payload.verificationCode && !payload.password && !payload.forceReconnect) {
        if (statusEl) {
          statusEl.textContent = 'Informe ao menos um campo ou marque reconexão.';
          statusEl.className = 'status bad';
        }
        return;
      }

      setButtonBusy('btnUserbotAuthApply', true, 'Aplicando...');
      if (statusEl) {
        statusEl.textContent = 'Enviando credenciais...';
        statusEl.className = 'status warn';
      }

      try {
        const res = await api('/api/telegram/userbot/auth', 'POST', payload);
        if (statusEl) {
          statusEl.textContent = res?.message || 'Credenciais aplicadas.';
          statusEl.className = 'status ok';
        }
        const codeEl = document.getElementById('userbotAuthCode');
        if (codeEl) codeEl.value = '';
        setTimeout(loadUserbotChats, 1200);
      } catch (e) {
        if (statusEl) {
          statusEl.textContent = e?.data?.message || e?.data?.error || e?.message || 'Falha ao atualizar credenciais.';
          statusEl.className = 'status bad';
        }
      } finally {
        setButtonBusy('btnUserbotAuthApply', false);
      }
    }

    function renderUserbotChats(payload, settings) {
      const container = document.getElementById('userbotChats');
      const status = document.getElementById('userbotStatus');
      const search = document.getElementById('userbotSearch');
      const selectedCount = document.getElementById('userbotSelectedCount');
      const chips = document.getElementById('userbotSelectedChips');
      if (!payload || !payload.chats) {
        container.textContent = 'Nenhum grupo carregado.';
        status.textContent = 'Userbot indisponível';
        status.className = 'status bad';
        setChipStatus('chipUserbot', 'Telegram Userbot: Indisponível', 'bad');
        setHealthBadge('healthUserbot', 'Userbot Indisponível', 'bad');
        return;
      }

      status.textContent = payload.ready ? `Conectado (${payload.chats.length} chats)` : 'Conectando...';
      status.className = 'status ' + (payload.ready ? 'ok' : 'warn');
      setChipStatus('chipUserbot', payload.ready ? 'Telegram Userbot: Conectado' : 'Telegram Userbot: Conectando...', payload.ready ? 'ok' : 'warn');
      setHealthBadge('healthUserbot', payload.ready ? 'Userbot OK' : 'Userbot Conectando', payload.ready ? 'ok' : 'warn');
      const statUserbot = document.getElementById('statUserbot');
      if (statUserbot) statUserbot.textContent = payload.ready ? 'Online' : 'Conectando...';

      if (payload.chats.length === 0) {
        container.textContent = 'Nenhum grupo carregado.';
        return;
      }

      const sourceIds = (settings?.telegramForwarding?.sourceChatIds || []).map(Number);
      const selected = new Set(sourceIds);
      const availableIds = new Set(payload.chats.map(c => Number(c.id)));
      const manualOnly = sourceIds.filter(id => !availableIds.has(id));
      document.getElementById('userbotManualIds').value = manualOnly.join('\n');

      const filteredChats = (query) => {
        const q = (query || '').toLowerCase().trim();
        return payload.chats.filter(c => {
          if (!q) return true;
          return (c.title || '').toLowerCase().includes(q) || String(c.id).includes(q);
        });
      };

      const renderList = (list) => {
        container.innerHTML = `<div class="chat-list">` + list.map(c => `
      <label class="chat-item">
        <input type="checkbox" data-userbot-chat="1" value="${c.id}" ${selected.has(c.id) ? 'checked' : ''} />
        <div>
          <div class="chat-title">${c.title}</div>
          <div class="chat-meta">${c.type} | ${c.id}</div>
        </div>
      </label>
  `).join('') + `</div>`;
        const count = Array.from(document.querySelectorAll("input[data-userbot-chat=\"1\"]:checked")).length;
        if (selectedCount) selectedCount.textContent = count.toString();
        container.onchange = () => {
          const updated = Array.from(document.querySelectorAll("input[data-userbot-chat=\"1\"]:checked")).length;
          if (selectedCount) selectedCount.textContent = updated.toString();
          renderSelectedChips();
          scheduleUserbotSave();
        };
        renderSelectedChips();
      };

      renderList(filteredChats(search?.value));
      if (search) {
        search.oninput = () => renderList(filteredChats(search.value));
      }
    }

    function renderSelectedChips() {
      const chips = document.getElementById('userbotSelectedChips');
      if (!chips) return;
      const selected = Array.from(document.querySelectorAll("input[data-userbot-chat=\"1\"]:checked"))
        .map(el => el.value);
      chips.innerHTML = selected.map(id => `<span class="pill" style="margin-right:6px;">${id}</span>`).join(' ');
    }

    function selectAllUserbotChats() {
      document.querySelectorAll("input[data-userbot-chat=\"1\"]").forEach(el => el.checked = true);
      renderSelectedChips();
      scheduleUserbotSave();
    }

    function clearUserbotSelection() {
      document.querySelectorAll("input[data-userbot-chat=\"1\"]").forEach(el => el.checked = false);
      renderSelectedChips();
      scheduleUserbotSave();
    }

    let userbotSaveTimer = null;
    function scheduleUserbotSave() {
      if (userbotSaveTimer) clearTimeout(userbotSaveTimer);
      userbotSaveTimer = setTimeout(() => saveUserbotSelection(), 400);
    }

    async function saveUserbotSelection() {
      if (currentRole !== 'admin') {
        const el = document.getElementById('userbotSaveStatus');
        if (el) {
          el.textContent = 'Permissão insuficiente para salvar.';
          el.className = 'status bad';
        }
        return;
      }

      const el = document.getElementById('userbotSaveStatus');
      if (el) {
        el.textContent = 'Salvando seleção...';
        el.className = 'status warn';
      }

      const existing = await api('/api/settings');
      existing.telegramForwarding = existing.telegramForwarding || {};
      existing.telegramForwarding.enabled = document.getElementById('userbotEnabled').checked;
      existing.telegramForwarding.destinationChatId = Number(document.getElementById('userbotDestinationId').value || 0);
      existing.telegramForwarding.appendSheinCode = document.getElementById('userbotAppendShein').checked;
      existing.telegramForwarding.footerText = document.getElementById('userbotFooter').value || '';
      const selected = Array.from(document.querySelectorAll("input[data-userbot-chat=\"1\"]:checked"))
        .map(el => Number(el.value));
      const manual = parseManualIds();
      existing.telegramForwarding.sourceChatIds = Array.from(new Set([...selected, ...manual]));

      try {
        await api('/api/settings', 'PUT', existing);
        if (el) {
          el.textContent = 'Seleção salva.';
          el.className = 'status ok';
        }
      } catch (e) {
        if (el) {
          el.textContent = e.data?.errors ? e.data.errors.join(' | ') : 'Erro ao salvar.';
          el.className = 'status bad';
        }
      }
    }

    async function loadUserbotChats() {
      try {
        const [payload, settings] = await Promise.all([api('/api/telegram/userbot/chats'), api('/api/settings')]);
        window.__userbotPayload = payload;
        renderUserbotChats(payload, settings);
        renderTelegramToWhatsAppRoute();
        document.getElementById('statUserbot').textContent = payload.ready ? 'Conectado' : 'Conectando...';
      } catch (e) {
        document.getElementById('userbotStatus').textContent = 'Erro ao carregar userbot';
        document.getElementById('userbotStatus').className = 'status bad';
        document.getElementById('statUserbot').textContent = 'Erro';
      }
    }

    async function refreshUserbotChats() {
      try {
        const payload = await api('/api/telegram/userbot/refresh', 'POST', {});
        const settings = await api('/api/settings');
        window.__userbotPayload = payload;
        renderUserbotChats(payload, settings);
        renderTelegramToWhatsAppRoute();
      } catch (e) {
        document.getElementById('userbotStatus').textContent = 'Erro ao atualizar grupos';
        document.getElementById('userbotStatus').className = 'status bad';
      }
    }

    function showAllUserbotChats() {
      const search = document.getElementById('userbotSearch');
      if (search) search.value = '';
      if (window.__userbotPayload && window.__settingsCache) {
        renderUserbotChats(window.__userbotPayload, window.__settingsCache);
      } else {
        loadUserbotChats();
      }
    }

    function renderWhatsAppGroups(payload, settings) {
      const routes = (window.__waRoutes && window.__waRoutes.length > 0)
        ? window.__waRoutes
        : buildWhatsAppRoutes(settings || window.__settingsCache || {});
      window.__waRoutes = routes;
      if (typeof window.__waRouteIndex !== 'number' || window.__waRouteIndex < 0 || window.__waRouteIndex >= routes.length) {
        window.__waRouteIndex = 0;
      }
      renderWhatsAppRoutePicker();
      applyActiveWhatsAppRouteToUi();

      renderWhatsAppList({
        containerId: 'waSourceGroups',
        searchId: 'waSourceSearch',
        selectedCountId: 'waSourceSelectedCount',
        selectedChipsId: 'waSourceSelectedChips',
        checkboxAttr: 'data-wa-source',
        manualIdsId: 'waManualSourceIds',
        selectedSet: window.__waSelection.source
      }, payload);

      renderWhatsAppList({
        containerId: 'waGroups',
        searchId: 'waDestSearch',
        selectedCountId: 'waSelectedCount',
        selectedChipsId: 'waSelectedChips',
        checkboxAttr: 'data-wa-group',
        manualIdsId: 'waManualIds',
        selectedSet: window.__waSelection.dest
      }, payload);
    }

    function renderTelegramToWhatsAppRoute() {
      const settings = window.__settingsCache;
      if (!settings) return;
      window.__tgWaRoutes = buildTgWaRoutes(settings);
      if (typeof window.__tgWaRouteIndex !== 'number' || window.__tgWaRouteIndex < 0 || window.__tgWaRouteIndex >= window.__tgWaRoutes.length) {
        window.__tgWaRouteIndex = 0;
      }
      renderTgWaRoutePicker();
      applyActiveTgWaRouteToUi();
      renderTgWaSourceList();
      renderTgWaDestList();
    }

    function buildWhatsAppRoutes(settings) {
      const routes = (settings?.whatsAppForwardingRoutes || []).map(r => ({
        name: (r?.name || 'Rota WhatsApp').trim(),
        enabled: !!r?.enabled,
        processFromMeOnly: r?.processFromMeOnly ?? true,
        sourceChatIds: Array.from(new Set((r?.sourceChatIds || []).map(String).filter(Boolean))),
        destinationGroupIds: Array.from(new Set((r?.destinationGroupIds || []).map(String).filter(Boolean))),
        appendSheinCode: r?.appendSheinCode ?? true,
        sendMediaEnabled: r?.sendMediaEnabled ?? true,
        footerText: r?.footerText || '',
        instanceName: (r?.instanceName || '').trim() || null
      }));
      if (routes.length > 0) return routes;

      const legacy = settings?.whatsAppForwarding || {};
      return [{
        name: 'Rota principal',
        enabled: !!legacy.enabled,
        processFromMeOnly: legacy.processFromMeOnly ?? true,
        sourceChatIds: Array.from(new Set((legacy.sourceChatIds || []).map(String).filter(Boolean))),
        destinationGroupIds: Array.from(new Set((legacy.destinationGroupIds || []).map(String).filter(Boolean))),
        appendSheinCode: legacy.appendSheinCode ?? true,
        sendMediaEnabled: legacy.sendMediaEnabled ?? true,
        footerText: legacy.footerText || '',
        instanceName: (legacy.instanceName || '').trim() || null
      }];
    }

    function getActiveWhatsAppRoute() {
      const routes = window.__waRoutes || [];
      if (routes.length === 0) return null;
      const idx = Math.max(0, Math.min(window.__waRouteIndex || 0, routes.length - 1));
      window.__waRouteIndex = idx;
      return routes[idx];
    }

    function persistActiveWhatsAppRouteFromUi() {
      const route = getActiveWhatsAppRoute();
      if (!route) return;
      route.name = (document.getElementById('waRouteName')?.value || route.name || 'Rota WhatsApp').trim() || 'Rota WhatsApp';
      route.enabled = document.getElementById('waForwardEnabled')?.checked ?? false;
      route.processFromMeOnly = document.getElementById('waFromMeOnly')?.checked ?? true;
      route.appendSheinCode = document.getElementById('waAppendShein')?.checked ?? true;
      route.sendMediaEnabled = document.getElementById('waSendMedia')?.checked ?? true;
      route.footerText = document.getElementById('waFooter')?.value || '';
      route.instanceName = (document.getElementById('waInstanceName')?.value || '').trim() || null;
      const sourceSelected = Array.from((window.__waSelection?.source || new Set()).values());
      const sourceManual = parseWhatsAppManualIds('waManualSourceIds');
      route.sourceChatIds = Array.from(new Set([...sourceSelected, ...sourceManual]));
      const destSelected = Array.from((window.__waSelection?.dest || new Set()).values());
      const destManual = parseWhatsAppManualIds('waManualIds');
      route.destinationGroupIds = Array.from(new Set([...destSelected, ...destManual]));
    }

    function applyActiveWhatsAppRouteToUi() {
      const route = getActiveWhatsAppRoute();
      if (!route) return;
      const routeName = document.getElementById('waRouteName');
      if (routeName) routeName.value = route.name || 'Rota WhatsApp';
      const waForwardEnabled = document.getElementById('waForwardEnabled');
      if (waForwardEnabled) waForwardEnabled.checked = !!route.enabled;
      const waFromMeOnly = document.getElementById('waFromMeOnly');
      if (waFromMeOnly) waFromMeOnly.checked = route.processFromMeOnly ?? true;
      const waAppendShein = document.getElementById('waAppendShein');
      if (waAppendShein) waAppendShein.checked = route.appendSheinCode ?? true;
      const waSendMedia = document.getElementById('waSendMedia');
      if (waSendMedia) waSendMedia.checked = route.sendMediaEnabled ?? true;
      const waFooter = document.getElementById('waFooter');
      if (waFooter) waFooter.value = route.footerText || '';
      const waInstanceName = document.getElementById('waInstanceName');
      if (waInstanceName) waInstanceName.value = route.instanceName || '';
      window.__waSelection = {
        source: new Set((route.sourceChatIds || []).map(String)),
        dest: new Set((route.destinationGroupIds || []).map(String))
      };
    }

    function renderWhatsAppRoutePicker() {
      const picker = document.getElementById('waRoutePicker');
      if (!picker) return;
      const routes = window.__waRoutes || [];
      picker.innerHTML = routes.map((route, idx) => `<option value="${idx}">${route.name || `Rota ${idx + 1}`}</option>`).join('');
      picker.value = String(window.__waRouteIndex || 0);
    }

    function switchWhatsAppRoute() {
      persistActiveWhatsAppRouteFromUi();
      const picker = document.getElementById('waRoutePicker');
      const idx = Number(picker?.value || 0);
      const routes = window.__waRoutes || [];
      if (routes.length === 0) return;
      window.__waRouteIndex = Math.max(0, Math.min(idx, routes.length - 1));
      applyActiveWhatsAppRouteToUi();
      if (window.__waPayload) {
        renderWhatsAppGroups(window.__waPayload, window.__settingsCache || {});
      }
    }

    function addWhatsAppRoute() {
      persistActiveWhatsAppRouteFromUi();
      window.__waRoutes = window.__waRoutes || [];
      window.__waRoutes.push({
        name: `Rota ${window.__waRoutes.length + 1}`,
        enabled: true,
        processFromMeOnly: document.getElementById('waFromMeOnly')?.checked ?? true,
        sourceChatIds: [],
        destinationGroupIds: [],
        appendSheinCode: document.getElementById('waAppendShein')?.checked ?? true,
        sendMediaEnabled: document.getElementById('waSendMedia')?.checked ?? true,
        footerText: document.getElementById('waFooter')?.value || '',
        instanceName: (document.getElementById('waInstanceName')?.value || '').trim() || null
      });
      window.__waRouteIndex = window.__waRoutes.length - 1;
      renderWhatsAppRoutePicker();
      applyActiveWhatsAppRouteToUi();
      if (window.__waPayload) {
        renderWhatsAppGroups(window.__waPayload, window.__settingsCache || {});
      }
    }

    function removeWhatsAppRoute() {
      window.__waRoutes = window.__waRoutes || [];
      if (window.__waRoutes.length <= 1) {
        alert('Mantenha pelo menos 1 rota.');
        return;
      }
      const idx = Math.max(0, Math.min(window.__waRouteIndex || 0, window.__waRoutes.length - 1));
      window.__waRoutes.splice(idx, 1);
      window.__waRouteIndex = Math.max(0, idx - 1);
      renderWhatsAppRoutePicker();
      applyActiveWhatsAppRouteToUi();
      if (window.__waPayload) {
        renderWhatsAppGroups(window.__waPayload, window.__settingsCache || {});
      }
    }

    function renameWhatsAppRoute() {
      const route = getActiveWhatsAppRoute();
      if (!route) return;
      route.name = (document.getElementById('waRouteName')?.value || route.name || 'Rota WhatsApp').trim() || 'Rota WhatsApp';
      renderWhatsAppRoutePicker();
    }

    function buildTgWaRoutes(settings) {
      const routes = (settings?.telegramToWhatsAppRoutes || []).map(r => ({
        name: (r?.name || 'Rota Telegram -> WhatsApp').trim(),
        enabled: !!r?.enabled,
        sourceChatIds: Array.from(new Set((r?.sourceChatIds || []).map(Number).filter(x => Number.isFinite(x)))),
        destinationGroupIds: Array.from(new Set((r?.destinationGroupIds || []).map(String).filter(Boolean)))
      }));
      if (routes.length > 0) return routes;

      const legacy = settings?.telegramToWhatsApp || {};
      return [{
        name: 'Rota Telegram principal',
        enabled: !!legacy.enabled,
        sourceChatIds: Array.from(new Set((legacy.sourceChatIds || []).map(Number).filter(x => Number.isFinite(x)))),
        destinationGroupIds: Array.from(new Set((legacy.destinationGroupIds || []).map(String).filter(Boolean)))
      }];
    }

    function getActiveTgWaRoute() {
      const routes = window.__tgWaRoutes || [];
      if (routes.length === 0) return null;
      const idx = Math.max(0, Math.min(window.__tgWaRouteIndex || 0, routes.length - 1));
      window.__tgWaRouteIndex = idx;
      return routes[idx];
    }

    function persistActiveTgWaRouteFromUi() {
      const route = getActiveTgWaRoute();
      if (!route) return;
      route.name = (document.getElementById('tgWaRouteName')?.value || route.name || 'Rota Telegram -> WhatsApp').trim() || 'Rota Telegram -> WhatsApp';
      route.enabled = document.getElementById('tgWaEnabled')?.checked ?? false;
      const srcSelected = Array.from((window.__tgWaSelection?.source || new Set()).values()).map(Number).filter(x => Number.isFinite(x));
      const srcManual = parseManualIdsById('tgWaSourceManual');
      route.sourceChatIds = Array.from(new Set([...srcSelected, ...srcManual]));
      const destSelected = Array.from((window.__tgWaSelection?.dest || new Set()).values());
      const destManual = parseWhatsAppManualIds('tgWaDestManual');
      route.destinationGroupIds = Array.from(new Set([...destSelected, ...destManual]));
    }

    function applyActiveTgWaRouteToUi() {
      const route = getActiveTgWaRoute();
      if (!route) return;
      const routeName = document.getElementById('tgWaRouteName');
      if (routeName) routeName.value = route.name || 'Rota Telegram -> WhatsApp';
      const tgWaEnabled = document.getElementById('tgWaEnabled');
      if (tgWaEnabled) tgWaEnabled.checked = !!route.enabled;
      window.__tgWaSelection = {
        source: new Set((route.sourceChatIds || []).map(String)),
        dest: new Set((route.destinationGroupIds || []).map(String))
      };
    }

    function renderTgWaRoutePicker() {
      const picker = document.getElementById('tgWaRoutePicker');
      if (!picker) return;
      const routes = window.__tgWaRoutes || [];
      picker.innerHTML = routes.map((route, idx) => `<option value="${idx}">${route.name || `Rota ${idx + 1}`}</option>`).join('');
      picker.value = String(window.__tgWaRouteIndex || 0);
    }

    function switchTgWaRoute() {
      persistActiveTgWaRouteFromUi();
      const picker = document.getElementById('tgWaRoutePicker');
      const idx = Number(picker?.value || 0);
      const routes = window.__tgWaRoutes || [];
      if (routes.length === 0) return;
      window.__tgWaRouteIndex = Math.max(0, Math.min(idx, routes.length - 1));
      applyActiveTgWaRouteToUi();
      renderTgWaSourceList();
      renderTgWaDestList();
    }

    function addTgWaRoute() {
      persistActiveTgWaRouteFromUi();
      window.__tgWaRoutes = window.__tgWaRoutes || [];
      window.__tgWaRoutes.push({
        name: `Rota ${window.__tgWaRoutes.length + 1}`,
        enabled: true,
        sourceChatIds: [],
        destinationGroupIds: []
      });
      window.__tgWaRouteIndex = window.__tgWaRoutes.length - 1;
      renderTgWaRoutePicker();
      applyActiveTgWaRouteToUi();
      renderTgWaSourceList();
      renderTgWaDestList();
    }

    function removeTgWaRoute() {
      window.__tgWaRoutes = window.__tgWaRoutes || [];
      if (window.__tgWaRoutes.length <= 1) {
        alert('Mantenha pelo menos 1 rota.');
        return;
      }
      const idx = Math.max(0, Math.min(window.__tgWaRouteIndex || 0, window.__tgWaRoutes.length - 1));
      window.__tgWaRoutes.splice(idx, 1);
      window.__tgWaRouteIndex = Math.max(0, idx - 1);
      renderTgWaRoutePicker();
      applyActiveTgWaRouteToUi();
      renderTgWaSourceList();
      renderTgWaDestList();
    }

    function renameTgWaRoute() {
      const route = getActiveTgWaRoute();
      if (!route) return;
      route.name = (document.getElementById('tgWaRouteName')?.value || route.name || 'Rota Telegram -> WhatsApp').trim() || 'Rota Telegram -> WhatsApp';
      renderTgWaRoutePicker();
    }

    function renderTgWaSourceList() {
      const container = document.getElementById('tgWaSourceList');
      const search = document.getElementById('tgWaSourceSearch');
      const countEl = document.getElementById('tgWaSourceCount');
      const chips = document.getElementById('tgWaSourceChips');
      const manualEl = document.getElementById('tgWaSourceManual');
      const payload = window.__userbotPayload;
      const selected = window.__tgWaSelection?.source || new Set();

      if (!payload || !payload.chats) {
        if (manualEl) manualEl.value = Array.from(selected.values()).join('\n');
        if (countEl) countEl.textContent = selected.size.toString();
        if (chips) chips.innerHTML = Array.from(selected.values()).map(id => `<span class="pill" style="margin-right:6px;">${id}</span>`).join(' ');
        if (container) container.textContent = 'Nenhum grupo carregado.';
        return;
      }

      const availableIds = new Set(payload.chats.map(c => String(c.id)));
      const manualOnly = Array.from(selected.values()).filter(id => !availableIds.has(id));
      if (manualEl) manualEl.value = manualOnly.join('\n');

      const filtered = (query) => {
        const q = (query || '').toLowerCase().trim();
        return payload.chats.filter(c => {
          if (!q) return true;
          return (c.title || '').toLowerCase().includes(q) || String(c.id).includes(q);
        });
      };

      const renderList = (list) => {
        container.innerHTML = `<div class="chat-list">` + list.map(c => `
      <label class="chat-item">
        <input type="checkbox" data-tgwa-source="1" value="${c.id}" ${selected.has(String(c.id)) ? 'checked' : ''} />
        <div>
          <div class="chat-title">${c.title}</div>
          <div class="chat-meta">${c.type} | ${c.id}</div>
        </div>
      </label>
    `).join('') + `</div>`;
        if (countEl) countEl.textContent = selected.size.toString();
        container.onchange = (ev) => {
          const target = ev.target;
          if (!target || !target.matches('input[data-tgwa-source="1"]')) return;
          const value = String(target.value);
          if (target.checked) selected.add(value);
          else selected.delete(value);
          if (countEl) countEl.textContent = selected.size.toString();
          renderTgWaChips();
        };
        renderTgWaChips();
      };

      renderList(filtered(search?.value));
      if (search) {
        search.oninput = () => renderList(filtered(search.value));
      }
    }

    function renderTgWaDestList() {
      const container = document.getElementById('tgWaDestList');
      const search = document.getElementById('tgWaDestSearch');
      const countEl = document.getElementById('tgWaDestCount');
      const chips = document.getElementById('tgWaDestChips');
      const manualEl = document.getElementById('tgWaDestManual');
      const payload = window.__waPayload;
      const selected = window.__tgWaSelection?.dest || new Set();

      if (!payload || !payload.groups) {
        if (manualEl) manualEl.value = Array.from(selected.values()).join('\n');
        if (countEl) countEl.textContent = selected.size.toString();
        if (chips) chips.innerHTML = Array.from(selected.values()).map(id => `<span class="pill" style="margin-right:6px;">${id}</span>`).join(' ');
        if (container) container.textContent = 'Nenhum grupo carregado.';
        return;
      }

      const availableIds = new Set(payload.groups.map(g => String(g.id)));
      const manualOnly = Array.from(selected.values()).filter(id => !availableIds.has(id));
      if (manualEl) manualEl.value = manualOnly.join('\n');

      const filtered = (query) => {
        const q = (query || '').toLowerCase().trim();
        return payload.groups.filter(g => {
          if (!q) return true;
          return (g.name || '').toLowerCase().includes(q) || String(g.id).includes(q);
        });
      };

      const renderList = (list) => {
        container.innerHTML = `<div class="chat-list">` + list.map(g => `
      <label class="chat-item">
        <input type="checkbox" data-tgwa-dest="1" value="${g.id}" ${selected.has(String(g.id)) ? 'checked' : ''} />
        <div>
          <div class="chat-title">${g.name}</div>
          <div class="chat-meta">${g.type || 'group'} | ${g.id}</div>
        </div>
      </label>
    `).join('') + `</div>`;
        if (countEl) countEl.textContent = selected.size.toString();
        container.onchange = (ev) => {
          const target = ev.target;
          if (!target || !target.matches('input[data-tgwa-dest="1"]')) return;
          const value = String(target.value);
          if (target.checked) selected.add(value);
          else selected.delete(value);
          if (countEl) countEl.textContent = selected.size.toString();
          renderTgWaChips();
        };
        renderTgWaChips();
      };

      renderList(filtered(search?.value));
      if (search) {
        search.oninput = () => renderList(filtered(search.value));
      }
    }

    function renderTgWaChips() {
      const src = document.getElementById('tgWaSourceChips');
      const dest = document.getElementById('tgWaDestChips');
      const srcSelected = Array.from((window.__tgWaSelection?.source || new Set()).values());
      const destSelected = Array.from((window.__tgWaSelection?.dest || new Set()).values());
      if (src) src.innerHTML = srcSelected.map(id => `<span class="pill" style="margin-right:6px;">${id}</span>`).join(' ');
      if (dest) dest.innerHTML = destSelected.map(id => `<span class="pill" style="margin-right:6px;">${id}</span>`).join(' ');
    }

    function selectAllTgWaSource() {
      const set = window.__tgWaSelection?.source;
      const payload = window.__userbotPayload;
      if (!set || !payload || !payload.chats) return;
      payload.chats.forEach(c => set.add(String(c.id)));
      renderTgWaSourceList();
    }

    function clearTgWaSource() {
      const set = window.__tgWaSelection?.source;
      if (set) set.clear();
      renderTgWaSourceList();
    }

    function showAllTgWaSource() {
      const search = document.getElementById('tgWaSourceSearch');
      if (search) search.value = '';
      renderTgWaSourceList();
    }

    function selectAllTgWaDest() {
      const set = window.__tgWaSelection?.dest;
      const payload = window.__waPayload;
      if (!set || !payload || !payload.groups) return;
      payload.groups.forEach(g => set.add(String(g.id)));
      renderTgWaDestList();
    }

    function clearTgWaDest() {
      const set = window.__tgWaSelection?.dest;
      if (set) set.clear();
      renderTgWaDestList();
    }

    function showAllTgWaDest() {
      const search = document.getElementById('tgWaDestSearch');
      if (search) search.value = '';
      renderTgWaDestList();
    }

    function renderWhatsAppList(config, payload) {
      const container = document.getElementById(config.containerId);
      const search = document.getElementById(config.searchId);
      const selectedCount = document.getElementById(config.selectedCountId);
      const manualEl = document.getElementById(config.manualIdsId);
      const selectedSet = config.selectedSet || new Set();
      const selectedIds = Array.from(selectedSet);
      const chipsEl = document.getElementById(config.selectedChipsId);
      const baseSelected = selectedIds;
      if (!payload || !payload.groups || payload.groups.length === 0) {
        if (manualEl) manualEl.value = baseSelected.join('\n');
        if (selectedCount) selectedCount.textContent = baseSelected.length.toString();
        if (chipsEl) chipsEl.innerHTML = baseSelected.map(id => `<span class="pill" style="margin-right:6px;">${id}</span>`).join(' ');
        container.textContent = 'Nenhum grupo carregado.';
        return;
      }

      const selected = selectedSet;
      const availableIds = new Set(payload.groups.map(g => String(g.id)));
      const manualOnly = baseSelected.filter(id => !availableIds.has(id));
      if (manualEl) manualEl.value = manualOnly.join('\n');

      const filteredGroups = (query) => {
        const q = (query || '').toLowerCase().trim();
        return payload.groups.filter(g => {
          if (!q) return true;
          return (g.name || '').toLowerCase().includes(q) || String(g.id).includes(q);
        });
      };

      const renderList = (list) => {
        container.innerHTML = `<div class="chat-list">` + list.map(g => `
      <label class="chat-item">
        <input type="checkbox" ${config.checkboxAttr}="1" value="${g.id}" ${selected.has(String(g.id)) ? 'checked' : ''} />
        <div>
          <div class="chat-title">${g.name}</div>
          <div class="chat-meta">${g.type || 'group'} | ${g.id}</div>
        </div>
      </label>
    `).join('') + `</div>`;
        if (selectedCount) selectedCount.textContent = selected.size.toString();
        container.onchange = (ev) => {
          const target = ev.target;
          if (!target || !target.matches(`input[${config.checkboxAttr}="1"]`)) return;
          const value = String(target.value);
          if (target.checked) selected.add(value);
          else selected.delete(value);
          if (selectedCount) selectedCount.textContent = selected.size.toString();
          renderWhatsAppChips();
          scheduleWhatsAppSave();
        };
        renderWhatsAppChips();
      };

      renderList(filteredGroups(search?.value));
      if (search) {
        search.oninput = () => renderList(filteredGroups(search.value));
      }
    }

    function renderWhatsAppChips() {
      const destChips = document.getElementById('waSelectedChips');
      const sourceChips = document.getElementById('waSourceSelectedChips');
      const destSelected = Array.from((window.__waSelection?.dest || new Set()).values());
      const sourceSelected = Array.from((window.__waSelection?.source || new Set()).values());
      if (destChips) destChips.innerHTML = destSelected.map(id => `<span class="pill" style="margin-right:6px;">${id}</span>`).join(' ');
      if (sourceChips) sourceChips.innerHTML = sourceSelected.map(id => `<span class="pill" style="margin-right:6px;">${id}</span>`).join(' ');
    }

    function selectAllWhatsAppGroups() {
      const set = window.__waSelection?.dest;
      if (set) {
        document.querySelectorAll("input[data-wa-group=\"1\"]").forEach(el => {
          el.checked = true;
          set.add(String(el.value));
        });
      }
      renderWhatsAppChips();
      scheduleWhatsAppSave();
    }

    function clearWhatsAppSelection() {
      const set = window.__waSelection?.dest;
      if (set) set.clear();
      document.querySelectorAll("input[data-wa-group=\"1\"]").forEach(el => el.checked = false);
      renderWhatsAppChips();
      scheduleWhatsAppSave();
    }

    function selectAllWhatsAppSourceGroups() {
      const set = window.__waSelection?.source;
      if (set) {
        document.querySelectorAll("input[data-wa-source=\"1\"]").forEach(el => {
          el.checked = true;
          set.add(String(el.value));
        });
      }
      renderWhatsAppChips();
      scheduleWhatsAppSave();
    }

    function clearWhatsAppSourceSelection() {
      const set = window.__waSelection?.source;
      if (set) set.clear();
      document.querySelectorAll("input[data-wa-source=\"1\"]").forEach(el => el.checked = false);
      renderWhatsAppChips();
      scheduleWhatsAppSave();
    }

    let waSaveTimer = null;
    function scheduleWhatsAppSave() {
      if (waSaveTimer) clearTimeout(waSaveTimer);
      waSaveTimer = setTimeout(() => saveWhatsAppSelection(), 400);
    }

    async function saveWhatsAppSelection() {
      if (currentRole !== 'admin') {
        const el = document.getElementById('waSaveStatus');
        if (el) {
          el.textContent = 'Permissao insuficiente para salvar.';
          el.className = 'status bad';
        }
        return;
      }

      const el = document.getElementById('waSaveStatus');
      if (el) {
        el.textContent = 'Salvando selecao...';
        el.className = 'status warn';
      }

      const existing = await api('/api/settings');
      persistActiveWhatsAppRouteFromUi();
      const routes = (window.__waRoutes || []).map(route => ({
        name: (route.name || 'Rota WhatsApp').trim() || 'Rota WhatsApp',
        enabled: !!route.enabled,
        processFromMeOnly: route.processFromMeOnly ?? true,
        sourceChatIds: Array.from(new Set((route.sourceChatIds || []).map(String).filter(Boolean))),
        destinationGroupIds: Array.from(new Set((route.destinationGroupIds || []).map(String).filter(Boolean))),
        appendSheinCode: route.appendSheinCode ?? true,
        sendMediaEnabled: route.sendMediaEnabled ?? true,
        footerText: route.footerText || '',
        instanceName: (route.instanceName || '').trim() || null
      }));
      existing.whatsAppForwardingRoutes = routes;

      existing.whatsAppForwarding = existing.whatsAppForwarding || {};
      const firstRoute = routes[0];
      existing.whatsAppForwarding.enabled = firstRoute ? !!firstRoute.enabled : false;
      existing.whatsAppForwarding.processFromMeOnly = firstRoute ? (firstRoute.processFromMeOnly ?? true) : true;
      existing.whatsAppForwarding.footerText = firstRoute ? (firstRoute.footerText || '') : '';
      existing.whatsAppForwarding.appendSheinCode = firstRoute ? (firstRoute.appendSheinCode ?? true) : true;
      existing.whatsAppForwarding.sendMediaEnabled = firstRoute ? (firstRoute.sendMediaEnabled ?? true) : true;
      existing.whatsAppForwarding.destinationGroupIds = firstRoute ? firstRoute.destinationGroupIds : [];
      existing.whatsAppForwarding.sourceChatIds = firstRoute ? firstRoute.sourceChatIds : [];
      existing.whatsAppForwarding.instanceName = firstRoute ? firstRoute.instanceName : null;

      try {
        await api('/api/settings', 'PUT', existing);
        if (el) {
          el.textContent = 'Selecao salva.';
          el.className = 'status ok';
        }
        const sourceEl = document.getElementById('waSourceSaveStatus');
        if (sourceEl) {
          sourceEl.textContent = 'Selecao salva.';
          sourceEl.className = 'status ok';
        }
      } catch (e) {
        if (el) {
          el.textContent = e.data?.errors ? e.data.errors.join(' | ') : 'Erro ao salvar.';
          el.className = 'status bad';
        }
        const sourceEl = document.getElementById('waSourceSaveStatus');
        if (sourceEl) {
          sourceEl.textContent = e.data?.errors ? e.data.errors.join(' | ') : 'Erro ao salvar.';
          sourceEl.className = 'status bad';
        }
      }
    }

    async function loadWhatsAppGroups() {
      try {
        const instanceName = document.getElementById('waInstanceName').value || null;
        const [payload, settings] = await Promise.all([
          api('/api/whatsapp/groups' + (instanceName ? ('?instanceName=' + encodeURIComponent(instanceName)) : '')),
          api('/api/settings')
        ]);
        window.__waPayload = payload;
        renderWhatsAppGroups(payload, settings);
        renderTelegramToWhatsAppRoute();
      } catch (e) {
        let settings = null;
        try {
          settings = await api('/api/settings');
        } catch (fallbackError) {
          console.debug('Nao foi possivel carregar settings no fallback.', fallbackError);
        }
        if (settings) {
          renderWhatsAppGroups({ groups: [] }, settings);
        }
        const container = document.getElementById('waGroups');
        const sourceContainer = document.getElementById('waSourceGroups');
        if (container) container.textContent = 'Erro ao carregar grupos. Selecao salva mantida.';
        if (sourceContainer) sourceContainer.textContent = 'Erro ao carregar grupos. Selecao salva mantida.';
      }
    }

    async function refreshWhatsAppGroups() {
      await loadWhatsAppGroups();
    }

    function showAllWhatsAppGroups() {
      const search = document.getElementById('waDestSearch');
      if (search) search.value = '';
      if (window.__waPayload && window.__settingsCache) {
        renderWhatsAppGroups(window.__waPayload, window.__settingsCache);
      } else {
        loadWhatsAppGroups();
      }
    }

    function showAllWhatsAppSourceGroups() {
      const search = document.getElementById('waSourceSearch');
      if (search) search.value = '';
      if (window.__waPayload && window.__settingsCache) {
        renderWhatsAppGroups(window.__waPayload, window.__settingsCache);
      } else {
        loadWhatsAppGroups();
      }
    }

    function normalizeDestRef(dest) {
      return (dest || '').replace(/\s+/g, '');
    }

    function buildMediaIndex(items) {
      const index = {};
      if (!items) return index;
      items.forEach(item => {
        const origin = item.originChatId ?? '';
        const dest = normalizeDestRef(item.destinationChatRef || '');
        const key = `${origin}|${dest}`;
        if (!index[key]) index[key] = [];
        index[key].push(item);
      });
      Object.keys(index).forEach(key => {
        index[key].sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
      });
      return index;
    }

    function getMediaStatusForLog(log) {
      if (!window.__mediaIndex) return null;
      const origin = log.originChatId ?? '';
      const dest = normalizeDestRef(log.destinationChatRef || '');
      const key = `${origin}|${dest}`;
      const candidates = window.__mediaIndex[key] || window.__mediaIndex[`${origin}|`];
      if (!candidates || candidates.length === 0 || !log.timestamp) return null;
      const target = new Date(log.timestamp).getTime();
      const windowMs = 10 * 60 * 1000;
      let best = null;
      let bestDelta = Number.MAX_SAFE_INTEGER;
      for (const entry of candidates) {
        if (!entry.timestamp) continue;
        const ts = new Date(entry.timestamp).getTime();
        const delta = Math.abs(ts - target);
        if (delta <= windowMs && delta < bestDelta) {
          best = entry;
          bestDelta = delta;
        }
      }
      return best;
    }

    function formatMediaBadge(media) {
      if (!media) return '<span class="badge muted">-</span>';
      if (media.reason === 'media_disabled_text_only') return '<span class="badge warn">Desativado</span>';
      if (media.reason === 'media_missing_text_only') return '<span class="badge warn">Sem mídia</span>';
      return media.success ? '<span class="badge ok">OK</span>' : '<span class="badge bad">Falha</span>';
    }

    function renderConversionLogs(items) {
      const tbody = document.getElementById('logTableBody');
      if (!items || items.length === 0) {
        tbody.innerHTML = '<tr><td colspan="14" class="muted">Nenhum log encontrado.</td></tr>';
        return;
      }

      window.__lastConversionLogs = items;
      tbody.innerHTML = items.map(item => {
        const when = item.timestamp ? new Date(item.timestamp).toLocaleString() : '-';
        const status = item.success ? '<span class="badge ok">Sucesso</span>' : '<span class="badge bad">Falha</span>';
        const clicks = (item.clicks ?? '-') === 0 ? '0' : (item.clicks ?? '-');
        const validationOk = item.isAffiliated !== false;
        const validationBadge = validationOk
          ? '<span class="badge ok">OK</span>'
          : '<span class="badge bad">Invalido</span>';
        const correctionApplied = !!item.affiliateCorrected;
        const correctionBadge = correctionApplied
          ? '<span class="badge warn">Corrigido</span>'
          : '<span class="badge muted">-</span>';
        const correctionNote = item.affiliateCorrectionNote || '';
        const errorText = item.error || item.validationError || '';
        const errorBadge = errorText
          ? `<button class="secondary log-error" data-error="${encodeURIComponent(errorText)}">Ver erro</button>`
          : '<span class="muted">-</span>';
        const origin = item.originChatRef || item.originChatId || '-';
        const dest = item.destinationChatRef || item.destinationChatId || '-';
        const originDest = `${origin} -> ${dest}`;
        const rowClass = validationOk ? '' : 'invalid';
        const original = item.originalUrl || '-';
        const converted = item.convertedUrl || '-';
        const mediaInfo = getMediaStatusForLog(item);
        const mediaBadge = formatMediaBadge(mediaInfo);
        const mediaDetail = mediaInfo?.reason || '-';
        return `
      <tr class="${rowClass}">
        <td><small>${item.id || '-'}</small></td>
        <td>${when}</td>
        <td>${item.store || '-'}</td>
        <td>${status}</td>
        <td>${mediaBadge}<div class="muted"><small>${mediaDetail}</small></div></td>
        <td>${clicks}</td>
        <td>${validationBadge}</td>
        <td>${correctionBadge}<div class="muted"><small>${correctionNote || '-'}</small></div></td>
        <td>${errorBadge}</td>
        <td><small>${originDest}</small></td>
        <td><small>${original}</small></td>
        <td><small>${converted}</small></td>
        <td>
          <button class="copy-btn" data-copy="${encodeURIComponent(original)}">Copiar original</button>
          <button class="copy-btn" data-copy="${encodeURIComponent(converted)}">Copiar convertido</button>
        </td>
        <td>${item.elapsedMs ?? '-'}</td>
      </tr>
    `;
      }).join('');

      document.querySelectorAll('.log-error').forEach(btn => {
        btn.addEventListener('click', (ev) => {
          const err = decodeURIComponent(ev.currentTarget.getAttribute('data-error') || '');
          if (err) alert(err);
        });
      });

      document.querySelectorAll('.copy-btn').forEach(btn => {
        btn.addEventListener('click', async (ev) => {
          const val = decodeURIComponent(ev.currentTarget.getAttribute('data-copy') || '');
          if (!val || val === '-') return;
          try {
            await navigator.clipboard.writeText(val);
          } catch {
            const area = document.createElement('textarea');
            area.value = val;
            document.body.appendChild(area);
            area.select();
            document.execCommand('copy');
            document.body.removeChild(area);
          }
        });
      });
    }

    async function loadConversionLogs() {
      try {
        const store = document.getElementById('logStore').value;
        const q = document.getElementById('logSearch').value;
        const limit = document.getElementById('logLimit').value || '200';
        const successFilter = document.getElementById('logSuccess').value;
        const params = new URLSearchParams();
        if (store) params.set('store', store);
        if (q) params.set('q', q);
        if (limit) params.set('limit', limit);
        const payload = await api('/api/logs/conversions?' + params.toString());
        let items = payload.items || [];
        if (successFilter !== '') {
          const expected = successFilter === 'true';
          items = items.filter(i => !!i.success === expected);
        }
        const invalid = items.filter(i => i.isAffiliated === false);
        const corrected = items.filter(i => i.affiliateCorrected);
        document.getElementById('logStatus').textContent = `Exibindo ${items.length} registros.`;
        const alert = document.getElementById('logAlert');
        if (invalid.length > 0 || corrected.length > 0) {
          const parts = [];
          if (invalid.length > 0) parts.push(`Atenção: ${invalid.length} link(s) inválido(s) sem afiliado.`);
          if (corrected.length > 0) parts.push(`Correções aplicadas: ${corrected.length}.`);
          alert.textContent = parts.join(' ');
          alert.classList.remove('hidden');
        } else {
          alert.textContent = '';
          alert.classList.add('hidden');
        }
        const statLogs = document.getElementById('statLogs');
        if (statLogs) statLogs.textContent = items.length.toString();
        const badge = document.getElementById('logsBadge');
        if (badge) {
          if (invalid.length > 0) {
            badge.textContent = invalid.length.toString();
            badge.classList.remove('hidden');
          } else {
            badge.textContent = '0';
            badge.classList.add('hidden');
          }
        }
        renderConversionLogs(items);
      } catch (e) {
        document.getElementById('logStatus').textContent = 'Erro ao carregar logs.';
      }
    }

    async function loadMediaFailures() {
      try {
        const payload = await api('/api/logs/media?limit=50');
        const items = payload.items || [];
        window.__mediaLogCache = items;
        window.__mediaIndex = buildMediaIndex(items);
        const alert = document.getElementById('mediaAlert');
        const tbody = document.getElementById('mediaTableBody');
        if (!tbody) return;
        if (alert) {
          if (items.length === 0) {
            alert.textContent = '';
            alert.classList.add('hidden');
          } else {
            const latest = items[0];
            alert.textContent = `Log de mídia: ${items.length}. Última: ${new Date(latest.timestamp).toLocaleString()} (${latest.destinationChatRef || '-'})`;
            alert.classList.remove('hidden');
          }
        }
        const healthMedia = document.getElementById('healthMedia');
        const healthMediaDetail = document.getElementById('healthMediaDetail');
        if (healthMedia) {
          if (items.length === 0) {
            healthMedia.textContent = 'Sem dados';
            healthMedia.className = 'badge muted';
            if (healthMediaDetail) healthMediaDetail.textContent = '-';
          } else {
            const latest = items[0];
            healthMedia.textContent = latest.success ? 'OK' : 'Falha';
            healthMedia.className = 'badge ' + (latest.success ? 'ok' : 'bad');
            if (healthMediaDetail) {
              healthMediaDetail.textContent = `${latest.reason || '-'} | ${latest.detail || '-'}`;
            }
          }
        }
        if (tbody) {
          if (items.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" class="muted">Nenhum registro recente.</td></tr>';
          } else {
            tbody.innerHTML = items.map(item => {
              const when = item.timestamp ? new Date(item.timestamp).toLocaleString() : '-';
              const origin = item.originChatId || '-';
              const dest = item.destinationChatRef || '-';
              const reason = item.reason || '-';
              const detail = item.detail || '-';
              const status = item.success ? '<span class="badge ok">OK</span>' : '<span class="badge bad">Falha</span>';
              const line = `${when} | ${origin} -> ${dest} | ${item.success ? 'OK' : 'Falha'} | ${reason} | ${detail}`;
              return `
            <tr>
              <td>${when}</td>
              <td><small>${origin}</small></td>
              <td><small>${dest}</small></td>
              <td>${status}</td>
              <td>${reason}</td>
              <td><small>${detail}</small></td>
              <td><button class="copy-btn copy-media" data-copy="${encodeURIComponent(line)}">Copiar linha</button></td>
            </tr>
          `;
            }).join('');
            document.querySelectorAll('.copy-media').forEach(btn => {
              btn.addEventListener('click', async (ev) => {
                const val = decodeURIComponent(ev.currentTarget.getAttribute('data-copy') || '');
                if (!val) return;
                try {
                  await navigator.clipboard.writeText(val);
                } catch {
                  const area = document.createElement('textarea');
                  area.value = val;
                  document.body.appendChild(area);
                  area.select();
                  document.execCommand('copy');
                  document.body.removeChild(area);
                }
              });
            });
          }
        }
        if (window.__lastConversionLogs) {
          renderConversionLogs(window.__lastConversionLogs);
        }
      } catch {
        // ignore
      }
    }

    async function clearConversionLogs() {
      await api('/api/logs/conversions/clear', 'POST', {});
      await loadConversionLogs();
    }

    async function clearMediaFailures() {
      await api('/api/logs/media/clear', 'POST', {});
      await loadMediaFailures();
    }

    loadTheme();
    setEnvironmentBadge(null);
    checkSession();