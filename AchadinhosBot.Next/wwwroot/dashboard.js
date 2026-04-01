let currentRole = null;
let logsAutoTimer = null;
let waCurrentGroupParticipants = [];
let waAdminGroupsCache = null;
let waAdminGroupsByInstanceCache = new Map();
let waParticipantsCache = new Map();
let waAutomationCache = null;
let waAutomationQueueCache = null;
let waInstancesCache = null;
let waScheduleEditState = null;
let waQrPollTimer = null;
let waQrPollInstanceName = null;
let opsOverviewTimer = null;
let currentOfferNormalizationRunId = null;
const WA_MANUAL_COPY_MAX_PARTICIPANTS = 50;
let waOutreachLogsTimer = null;
let waOutreachLastOperationId = null;
const WA_ENGAGEMENT_PLAN_STORAGE_KEY = 'waEngagementPlan:v1';
const WA_OUTREACH_PITCH_PRESETS = {
  direto: 'Grupo oficial com ofertas verificadas, links revisados e menos spam. O foco e receber oportunidade real com seguranca.',
  amigavel: 'Nosso grupo oficial e moderado, com ofertas validadas e links revisados para mais seguranca e menos ruido no seu WhatsApp.',
  premium: 'No grupo oficial voce recebe oportunidades filtradas e confiaveis primeiro, com curadoria e padrao de qualidade mais alto.',
  'seguranca-forte': 'Antes de qualquer oferta, validamos origem e qualidade dos links para reduzir risco de golpe. O grupo oficial existe para isso.'
};

// Safety Helpers for DOM interaction
function setSafeVal(id, val) {
  const el = document.getElementById(id);
  if (el) el.value = val;
}
function setSafeChecked(id, checked) {
  const el = document.getElementById(id);
  if (el) el.checked = !!checked;
}
function setSafeText(id, text) {
  const el = document.getElementById(id);
  if (el) el.textContent = text;
}
function setSafeClass(id, cls) {
  const el = document.getElementById(id);
  if (el) el.className = cls;
}

function getConfiguredPublicBaseUrl() {
  const raw = window.__settingsCache?.bioHub?.publicBaseUrl || '';
  return String(raw).trim().replace(/\/+$/, '');
}

function looksLikeInternalHost(hostname) {
  const host = String(hostname || '').toLowerCase();
  return host === 'localhost'
    || host === '127.0.0.1'
    || host === '0.0.0.0'
    || host === 'host.docker.internal'
    || host.endsWith('.local')
    || host.endsWith('.internal');
}

function buildPublicUrl(path) {
  const publicBaseUrl = getConfiguredPublicBaseUrl();
  if (publicBaseUrl) {
    return new URL(path, publicBaseUrl.endsWith('/') ? publicBaseUrl : `${publicBaseUrl}/`).toString();
  }

  const origin = window.location?.origin || '';
  try {
    const parsed = new URL(origin);
    if (looksLikeInternalHost(parsed.hostname)) {
      return null;
    }
    return new URL(path, origin).toString();
  } catch {
    return null;
  }
}

function isPublicAbsoluteUrl(value) {
  if (!value) return false;
  try {
    const parsed = new URL(value);
    return parsed.protocol === 'https:' || parsed.protocol === 'http:';
  } catch {
    return false;
  }
}

function hideWhatsAppQr() {
  const card = document.getElementById('waQrCard');
  const image = document.getElementById('qrImage');
  const hint = document.getElementById('qrHint');
  const badge = document.getElementById('qrStateBadge');
  if (card) card.classList.add('hidden');
  if (image) {
    image.classList.add('hidden');
    image.removeAttribute('src');
  }
  if (hint) hint.classList.add('hidden');
  if (badge) {
    badge.textContent = 'Aguardando QR';
    badge.className = 'badge warn';
  }
}

function getWhatsAppQrValue(payload) {
  return payload?.qrCode || payload?.qrCodeBase64 || null;
}

function showWhatsAppQr(qrCode, hintText = 'Escaneie com o WhatsApp para concluir a conexão.') {
  const card = document.getElementById('waQrCard');
  const image = document.getElementById('qrImage');
  const hint = document.getElementById('qrHint');
  const badge = document.getElementById('qrStateBadge');
  if (!card || !image) return;
  image.src = qrCode;
  image.classList.remove('hidden');
  card.classList.remove('hidden');
  if (hint) {
    hint.textContent = hintText;
    hint.classList.remove('hidden');
  }
  if (badge) {
    badge.textContent = 'QR disponível';
    badge.className = 'badge warn';
  }
}

function stopWhatsAppQrPolling() {
  if (waQrPollTimer) {
    clearInterval(waQrPollTimer);
    waQrPollTimer = null;
  }
  waQrPollInstanceName = null;
}

async function refreshWhatsAppQrSnapshot(options = {}) {
  const instanceName = (options.instanceName ?? document.getElementById('waInstanceName')?.value ?? '').trim();
  const silent = options.silent !== false;

  try {
    const query = instanceName ? `?instanceName=${encodeURIComponent(instanceName)}` : '';
    const snapshot = await api(`/api/integrations/whatsapp/status${query}`);
    const qrValue = getWhatsAppQrValue(snapshot);
    const status = document.getElementById('whatsappStatus');

    if (snapshot.connected) {
      hideWhatsAppQr();
      stopWhatsAppQrPolling();
      if (status) {
        status.textContent = snapshot.message || 'Instância conectada.';
        status.className = 'status ok';
      }
      return snapshot;
    }

    if (qrValue) {
      showWhatsAppQr(qrValue, snapshot.message || 'Escaneie com o WhatsApp para concluir a conexão.');
      if (status) {
        status.textContent = snapshot.message || 'QR disponível. Aguardando leitura...';
        status.className = 'status warn';
      }
      return snapshot;
    }

    if (!silent && status) {
      status.textContent = snapshot.message || 'Instância desconectada.';
      status.className = 'status bad';
    }

    return snapshot;
  } catch (e) {
    if (!silent) {
      const status = document.getElementById('whatsappStatus');
      if (status) {
        status.textContent = `Erro: ${e.data?.error || e.message || 'Falha na requisição'}`;
        status.className = 'status bad';
      }
    }
    return null;
  }
}

function startWhatsAppQrPolling(instanceName) {
  const normalizedInstance = (instanceName || '').trim();
  if (waQrPollTimer && waQrPollInstanceName === normalizedInstance) {
    return;
  }

  stopWhatsAppQrPolling();
  waQrPollInstanceName = normalizedInstance;
  waQrPollTimer = setInterval(() => {
    refreshWhatsAppQrSnapshot({ instanceName: waQrPollInstanceName, silent: true });
  }, 5000);
}

function renderScheduledMessagePreview() {
  const preview = document.getElementById('waMessageSchedulePreview');
  if (!preview) return;

  const name = (document.getElementById('waMessageScheduleName')?.value || '').trim();
  const targetSelect = document.getElementById('waMessageScheduleTargetGroup');
  const targetGroupLabel = targetSelect?.selectedOptions?.[0]?.textContent?.trim() || 'Grupo destino';
  const text = (document.getElementById('waMessageScheduleText')?.value || '').trim();
  const imageUrl = (document.getElementById('waMessageScheduleImageUrl')?.value || '').trim();
  const messageHtml = text
    ? escapeHtml(text).replace(/\n/g, '<br />')
    : '<span class="muted">Sem mensagem ainda.</span>';
  const imageHtml = imageUrl
    ? `<a href="${escapeHtml(imageUrl)}" target="_blank" rel="noopener noreferrer" class="scheduled-preview-image-link">
        <img src="${escapeHtml(imageUrl)}" alt="Preview" onerror="this.style.display='none';" />
      </a>`
    : '';
  const linkHint = text.match(/https?:\/\/[^\s<]+/i)?.[0] || '';

  preview.innerHTML = `
    <div class="scheduled-preview-shell">
      <div class="scheduled-preview-head">
        <div>
          <strong>${escapeHtml(name || 'Mensagem agendada')}</strong><br />
          <small class="muted">${escapeHtml(targetGroupLabel)}</small>
        </div>
        <span class="badge muted">${imageUrl ? 'Com imagem' : 'Texto apenas'}</span>
      </div>
      ${imageHtml}
      <div class="scheduled-preview-message">${messageHtml}</div>
      ${linkHint ? `<div class="scheduled-preview-linkhint"><small class="muted">Link detectado:</small><br /><code>${escapeHtml(linkHint)}</code></div>` : ''}
    </div>
  `;
}

function updateScheduledMessagePreview() {
  renderScheduledMessagePreview();
}

async function uploadScheduledMessageImage(file) {
  if (!file) return;

  const status = document.getElementById('waMessageScheduleStatus');
  if (status) {
    status.textContent = 'Enviando imagem...';
    status.className = 'status muted';
  }

  const formData = new FormData();
  formData.append('file', file, file.name || 'image.png');

  const res = await fetch('/api/admin/media/upload', {
    method: 'POST',
    credentials: 'include',
    body: formData
  });

  let data = {};
  try { data = await res.json(); } catch {}
  if (!res.ok) throw { status: res.status, data };

  const imageUrlEl = document.getElementById('waMessageScheduleImageUrl');
  if (imageUrlEl) {
    imageUrlEl.value = data.publicUrl || '';
  }
  renderScheduledMessagePreview();
  return data;
}

async function uploadScheduledMessageImageFromInput() {
  const fileInput = document.getElementById('waMessageScheduleImageFile');
  const file = fileInput?.files?.[0];
  if (!file) {
    const status = document.getElementById('waMessageScheduleStatus');
    if (status) {
      status.textContent = 'Selecione um arquivo de imagem primeiro.';
      status.className = 'status warn';
    }
    return;
  }

  try {
    await uploadScheduledMessageImage(file);
    const status = document.getElementById('waMessageScheduleStatus');
    if (status) {
      status.textContent = 'Imagem carregada e vinculada ao modelo.';
      status.className = 'status ok';
    }
  } catch (err) {
    const status = document.getElementById('waMessageScheduleStatus');
    if (status) {
      status.textContent = err?.data?.error || 'Falha ao carregar a imagem.';
      status.className = 'status warn';
    }
  }
}

async function pasteScheduledMessageImage() {
  const status = document.getElementById('waMessageScheduleStatus');
  if (!navigator.clipboard?.read) {
    if (status) {
      status.textContent = 'Seu navegador nao permite colar imagem por clipboard. Use o arquivo.';
      status.className = 'status warn';
    }
    return;
  }

  try {
    const items = await navigator.clipboard.read();
    for (const item of items) {
      const imageType = item.types.find(t => t.startsWith('image/'));
      if (!imageType) continue;
      const blob = await item.getType(imageType);
      const ext = imageType.split('/')[1] || 'png';
      const file = new File([blob], `clipboard.${ext === 'jpeg' ? 'jpg' : ext}`, { type: imageType });
      await uploadScheduledMessageImage(file);
      if (status) {
        status.textContent = 'Imagem colada da area de transferencia.';
        status.className = 'status ok';
      }
      return;
    }

    if (status) {
      status.textContent = 'Nenhuma imagem foi encontrada na area de transferencia.';
      status.className = 'status warn';
    }
  } catch (err) {
    if (status) {
      status.textContent = err?.message || 'Falha ao colar a imagem.';
      status.className = 'status warn';
    }
  }
}

function refreshBioLinksPreview() {
  console.debug('refreshBioLinksPreview nao implementado nesta versao.');
}


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
  document.body.classList.toggle('unauthenticated', !authenticated);
  const loginCard = document.getElementById('loginCard');
  if (loginCard) loginCard.classList.toggle('hidden', authenticated);
  const panel = document.getElementById('panel');
  if (panel) panel.classList.toggle('hidden', !authenticated);
  
  if (authenticated) {
    currentRole = role;
    setSafeText('sessionInfo', `Autenticado como ${username} (${role})`);
    const saveBtn = document.getElementById('saveBtn');
    if (saveBtn) saveBtn.disabled = (role !== 'admin');
    const waFooterSaveBtn = document.getElementById('btnSaveWaFooter');
    if (waFooterSaveBtn) waFooterSaveBtn.disabled = (role !== 'admin');
    const waSafetySaveBtn = document.getElementById('btnSaveWaSafetySettings');
    if (waSafetySaveBtn) waSafetySaveBtn.disabled = (role !== 'admin');
    showSection(localStorage.getItem('activeTab') || 'overview');
  }
}

function showSection(name) {
  const sections = ['overview', 'ops', 'connections', 'route', 'linkresponder', 'mercadolivre', 'instagram', 'agents', 'offers', 'ai-lab', 'instagram-publish', 'instagram-story', 'bio-growth', 'autoreplies', 'logs', 'playground', 'debug', 'analytics', 'wa-monitoring', 'engagement-plan', 'wa-outreach'];
  sections.forEach(s => {
    const el = document.getElementById(`section-${s}`);
    if (el) el.classList.toggle('hidden', s !== name);
  });
  localStorage.setItem('activeTab', name);
  document.querySelectorAll('.nav button').forEach(btn => {
    btn.classList.toggle('active', btn.getAttribute('data-tab') === name);
  });
  if (name === 'overview') {
    loadOperationalOverview();
    startOperationalOverviewAutoRefresh();
  } else {
    stopOperationalOverviewAutoRefresh();
  }
  if (name === 'logs') {
    startLogsAutoRefresh();
  } else {
    stopLogsAutoRefresh();
  }
  if (name === 'analytics') {
    loadAnalyticsSummary();
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
  if (name === 'agents') {
    hydrateAgentUiState().then(() => {
      restoreAgentUiState();
      loadAgentAiUsage();
      loadOfferCuration();
      loadAgentChannelTargets().then(() => loadWhatsAppOfferScout());
    });
  }
  if (name === 'offers') {
    loadOfferNormalizationRuns();
    if (currentOfferNormalizationRunId) {
      loadOfferNormalizationRun(currentOfferNormalizationRunId);
    }
  }
  if (name === 'ai-lab') {
    document.getElementById('aiLabResults').innerHTML = '';
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
  if (name === 'wa-monitoring') {
    loadMonitorGroups();
    loadMembershipEvents();
    loadWhatsAppAutomation();
  }
  if (name === 'engagement-plan') {
    loadEngagementPlan();
    refreshEngagementPlanSummary();
  }
  if (name === 'wa-outreach') {
    refreshInstanceBoundGroupSelectors();
    startOutreachLogsAutoRefresh();
  } else {
    stopOutreachLogsAutoRefresh();
  }
}

function stopOutreachLogsAutoRefresh() {
  if (waOutreachLogsTimer) {
    clearInterval(waOutreachLogsTimer);
    waOutreachLogsTimer = null;
  }
}

function startOutreachLogsAutoRefresh() {
  stopOutreachLogsAutoRefresh();
  loadOutreachProgressLogs(true);
  loadOutreachScheduleList();
  waOutreachLogsTimer = setInterval(() => {
    if (localStorage.getItem('activeTab') === 'wa-outreach') {
      loadOutreachProgressLogs(true);
    }
  }, 5000);
}

function renderAgentActionBadge(action) {
  const normalized = String(action || '').trim().toLowerCase();
  const map = {
    convert_link: { label: 'Converter link', cls: 'warn' },
    add_to_catalog: { label: 'Adicionar ao catalogo', cls: 'ok' },
    highlight_on_bio: { label: 'Destacar na bio', cls: 'warn' },
    create_instagram_draft: { label: 'Criar draft IG', cls: 'ok' },
    review_and_publish: { label: 'Revisar e publicar', cls: 'warn' },
    review: { label: 'Revisar', cls: 'muted' },
    no_action: { label: 'Sem acao', cls: 'muted' }
  };
  const item = map[normalized] || { label: normalized || 'Sem acao', cls: 'muted' };
  return `<span class="badge ${item.cls}">${escapeHtml(item.label)}</span>`;
}

function renderCatalogTargetsBadge(item) {
  const tags = [];
  if (item.inCatalogDev) tags.push('<span class="badge ok">DEV</span>');
  if (item.inCatalogProd) tags.push('<span class="badge warn">PROD</span>');
  if (!item.inCatalogDev && !item.inCatalogProd && item.suggestedCatalogTarget && item.suggestedCatalogTarget !== 'none') {
    tags.push(`<span class="badge muted">Sug.: ${escapeHtml(String(item.suggestedCatalogTarget).toUpperCase())}</span>`);
  }
  return tags.length > 0 ? tags.join(' ') : '<span class="muted">Fora do catalogo</span>';
}

function buildAgentAdminUrl(item, sourceChannel) {
  const params = new URLSearchParams();
  if (item?.draftId) {
    params.set('draftId', item.draftId);
  }
  if (item?.messageId) {
    params.set('messageId', item.messageId);
  }
  if (sourceChannel) {
    params.set('sourceChannel', sourceChannel);
  }
  if (item?.suggestedPostType) {
    params.set('postType', item.suggestedPostType);
  }
  const query = params.toString();
  return query ? `/conversor-admin?${query}` : '/conversor-admin';
}

async function agentOpenWhatsAppAdmin(messageId, sourceChannel, suggestedPostType = 'feed', draftId = '', requiresLinkConversion = false) {
  const params = new URLSearchParams();
  if (draftId) params.set('draftId', draftId);
  if (messageId) params.set('messageId', messageId);
  if (sourceChannel || getAgentSourceChannel()) params.set('sourceChannel', sourceChannel || getAgentSourceChannel());
  if (suggestedPostType) params.set('postType', suggestedPostType);
  if (requiresLinkConversion) params.set('deepAnalyze', '1');
  const query = params.toString();
  window.open(query ? `/conversor-admin?${query}` : '/conversor-admin', '_blank');
}

function formatAgentDetails(item) {
  const reasons = Array.isArray(item.reasons) && item.reasons.length > 0
    ? item.reasons.map(x => `• ${escapeHtml(x)}`).join('<br />')
    : '<span class="muted">Sem justificativa.</span>';
  const source = item.decisionSource
    ? `<div style="margin-top:8px;"><strong>Decisao:</strong> ${escapeHtml(item.decisionSource)}${item.decisionProvider ? ` (${escapeHtml(item.decisionProvider)})` : ''}</div>`
    : '';
  const memory = item.lastOperatorFeedback || item.lastAppliedAction || item.lastOutcome
    ? `<div style="margin-top:8px;"><strong>Memoria:</strong> ${escapeHtml(item.lastOperatorFeedback || 'sem feedback')}${item.lastAppliedAction ? ` | ultima acao: ${escapeHtml(item.lastAppliedAction)}` : ''}${item.lastOutcome ? ` | outcome: ${escapeHtml(item.lastOutcome)}` : ''}${item.lastDecisionAt ? ` | ${escapeHtml(formatTs(item.lastDecisionAt))}` : ''}</div>`
    : '';
  const aiReasoning = item.aiReasoning
    ? `<div style="margin-top:8px;"><strong>IA:</strong><br />${escapeHtml(item.aiReasoning)}</div>`
    : '';
  const risks = Array.isArray(item.risks) && item.risks.length > 0
    ? `<div style="margin-top:8px;"><strong>Riscos:</strong><br />${item.risks.map(x => `• ${escapeHtml(x)}`).join('<br />')}</div>`
    : '';
  return `${reasons}${source}${memory}${aiReasoning}${risks}`;
}

function buildOfferAgentHighlights(items) {
  const highlights = document.getElementById('offerAgentHighlights');
  if (!highlights) return;

  if (!Array.isArray(items) || items.length === 0) {
    highlights.innerHTML = '';
    return;
  }

  const topScore = items[0]?.score || 0;
  const addToCatalog = items.filter(x => x.recommendedAction === 'add_to_catalog').length;
  const bio = items.filter(x => x.recommendedAction === 'highlight_on_bio').length;
  const review = items.filter(x => x.recommendedAction === 'review_and_publish' || x.recommendedAction === 'review').length;

  const cards = [
    { label: 'Melhor score', value: topScore, hint: 'prioridade operacional' },
    { label: 'Catalogo', value: addToCatalog, hint: 'entradas ou refresh sugeridos' },
    { label: 'Bio', value: bio, hint: 'destaques sugeridos' },
    { label: 'Revisao', value: review, hint: 'itens para operador revisar' }
  ];

  highlights.innerHTML = cards.map(card => `
    <div class="card" style="padding:16px; text-align:center;">
      <div class="muted" style="font-size:12px; font-weight:600; text-transform:uppercase;">${card.label}</div>
      <div style="font-size:26px; font-weight:800; color:var(--accent); margin-top:6px;">${card.value}</div>
      <div class="muted" style="font-size:11px; margin-top:4px;">${card.hint}</div>
    </div>
  `).join('');
}

async function loadAgentAiUsage() {
  const summary = document.getElementById('agentAiUsageSummary');
  const cards = document.getElementById('agentAiUsageCards');
  const hours = Number(document.getElementById('agentAiUsageHours')?.value || 24);

  if (summary) {
    summary.className = 'status muted';
    summary.textContent = 'Carregando monitoramento da IA...';
  }
  if (cards) cards.innerHTML = '';

  try {
    const data = await api(`/api/analytics/summary?hours=${encodeURIComponent(hours)}`);
    const ai = data?.summary?.instagramAi || {};
    const providers = Array.isArray(ai.providers) ? ai.providers : [];
    const budgetProviders = Array.isArray(data?.aiUsageBudget?.providers) ? data.aiUsageBudget.providers : [];
    const topProvider = providers[0] || null;
    const estimatedUsedTokens = Math.round(providers.reduce((acc, provider) => {
      const total = Number(provider.total || 0);
      const avgLatency = Number(provider.avgLatencyMs || 0);
      return acc + (total * Math.max(1, avgLatency / 20));
    }, 0));
    const configuredBudget = budgetProviders.find(provider => Number(provider.monthlyCallLimit || 0) > 0) || null;
    const leadBudget = topProvider
      ? budgetProviders.find(provider => String(provider.provider || '').toLowerCase() === String(topProvider.provider || '').toLowerCase())
      : configuredBudget;
    const totalEstimatedCost = budgetProviders.reduce((acc, provider) => acc + Number(provider.estimatedCostUsd || 0), 0);

    if (summary) {
      summary.className = 'status ok';
      summary.textContent = configuredBudget
        ? `IA usada nas ultimas ${hours}h. Limites configurados detectados no backend.`
        : `IA usada nas ultimas ${hours}h. Limite restante ainda nao configurado no backend.`;
    }

    if (cards) {
      const items = [
        { label: 'Chamadas IA', value: ai.total || 0, hint: `requisicoes nas ultimas ${hours}h` },
        { label: 'Sucesso', value: `${ai.successRate || 0}%`, hint: `${ai.success || 0} execucoes bem-sucedidas` },
        { label: 'Latencia media', value: `${Math.round(ai.avgLatencyMs || 0)} ms`, hint: 'tempo medio por geracao' },
        { label: 'Qualidade media', value: `${Math.round(ai.avgQualityScore || 0)}`, hint: 'score medio das saidas' },
        { label: 'Provider lider', value: topProvider?.provider || '-', hint: topProvider ? `${topProvider.total} chamadas` : 'sem dados' },
        { label: 'Custo estimado', value: totalEstimatedCost > 0 ? `$${totalEstimatedCost.toFixed(2)}` : '$0.00', hint: 'estimativa por chamada configurada' },
        configuredBudget
          ? {
              label: 'Saldo',
              value: `${leadBudget?.remainingCalls ?? configuredBudget.remainingCalls}`,
              hint: `${leadBudget?.provider || configuredBudget.provider}: limite ${leadBudget?.monthlyCallLimit || configuredBudget.monthlyCallLimit}/janela`
            }
          : { label: 'Saldo', value: 'Nao configurado', hint: `uso estimado ${estimatedUsedTokens} tokens-equivalentes` }
      ];

      const providerRows = budgetProviders.length
        ? `
          <div class="card" style="padding:16px; grid-column:1 / -1;">
            <div class="muted" style="font-size:12px; font-weight:700; text-transform:uppercase; margin-bottom:10px;">Providers</div>
            <div style="display:grid; gap:10px;">
              ${budgetProviders.map(provider => `
                <div style="display:grid; grid-template-columns: 1.2fr .8fr .8fr .8fr; gap:10px; align-items:center; border:1px solid rgba(0,0,0,.06); border-radius:12px; padding:10px 12px;">
                  <div><strong>${escapeHtml(String(provider.provider || '-').toUpperCase())}</strong><div class="muted" style="font-size:11px;">usadas ${escapeHtml(String(provider.usedCalls || 0))}</div></div>
                  <div><strong>${escapeHtml(String(provider.remainingCalls ?? 0))}</strong><div class="muted" style="font-size:11px;">restantes</div></div>
                  <div><strong>${escapeHtml(String(provider.monthlyCallLimit ?? 0))}</strong><div class="muted" style="font-size:11px;">limite</div></div>
                  <div><strong>${Number(provider.estimatedCostUsd || 0) > 0 ? escapeHtml(`$${Number(provider.estimatedCostUsd || 0).toFixed(2)}`) : '$0.00'}</strong><div class="muted" style="font-size:11px;">custo est.</div></div>
                </div>
              `).join('')}
            </div>
          </div>
        `
        : '';

      cards.innerHTML = items.map(card => `
        <div class="card" style="padding:16px; text-align:center;">
          <div class="muted" style="font-size:12px; font-weight:600; text-transform:uppercase;">${card.label}</div>
          <div style="font-size:26px; font-weight:800; color:var(--accent); margin-top:6px;">${escapeHtml(String(card.value))}</div>
          <div class="muted" style="font-size:11px; margin-top:4px;">${escapeHtml(card.hint)}</div>
        </div>
      `).join('') + providerRows;
    }
  } catch (e) {
    if (summary) {
      summary.className = 'status bad';
      summary.textContent = e?.data?.error || e?.message || 'Erro ao carregar monitoramento da IA.';
    }
    if (cards) cards.innerHTML = '';
  }
}

async function loadOfferCuration() {
  const body = document.getElementById('offerAgentBody');
  const summary = document.getElementById('offerAgentSummary');
  const highlights = document.getElementById('offerAgentHighlights');
  if (body) body.innerHTML = '<tr><td colspan="8" class="muted">Carregando recomendacoes...</td></tr>';
  if (summary) summary.textContent = 'Executando agente...';
  if (highlights) highlights.innerHTML = '';

  try {
    const payload = {
      hoursWindow: Number(document.getElementById('agentHoursWindow')?.value || 72),
      maxItems: Number(document.getElementById('agentMaxItems')?.value || 10),
      includeDrafts: !!document.getElementById('agentIncludeDrafts')?.checked,
      includeScheduled: !!document.getElementById('agentIncludeScheduled')?.checked,
      includePublished: !!document.getElementById('agentIncludePublished')?.checked
    };

    const data = await api('/api/agents/offers/curate', 'POST', payload);
    const items = Array.isArray(data.suggestions) ? data.suggestions : [];

    if (summary) {
      summary.className = 'status ok';
      summary.textContent = data.summary || 'Analise concluida.';
    }

    buildOfferAgentHighlights(items);

    if (!body) return;
    if (items.length === 0) {
      body.innerHTML = '<tr><td colspan="8" class="muted">Nenhuma recomendacao relevante nesta janela.</td></tr>';
      return;
    }

    body.innerHTML = items.map(item => {
      const canAddToCatalog = item.recommendedAction === 'add_to_catalog' || (!item.inCatalogDev && !item.inCatalogProd && item.status === 'published');
      const canHighlightOnBio = item.status === 'published' && !item.isHighlightedOnBio;
      const canPublishNow = item.status !== 'published' && item.hasOfferUrl && item.hasMedia;
      const canReschedule = item.status !== 'published';
      const catalogTarget = item.suggestedCatalogTarget && item.suggestedCatalogTarget !== 'none'
        ? item.suggestedCatalogTarget
        : 'prod';
      return `
        <tr>
          <td><strong>${escapeHtml(String(item.score || 0))}</strong></td>
          <td>
            <div><strong>${escapeHtml(item.productName || 'Sem nome')}</strong></div>
            <div class="muted">${escapeHtml(shortId(item.draftId || ''))}</div>
          </td>
          <td><span class="badge muted">${escapeHtml(item.status || '-')}</span></td>
          <td>${renderAgentActionBadge(item.recommendedAction)}</td>
          <td>${renderCatalogTargetsBadge(item)}</td>
          <td>${escapeHtml(String(item.recentClicks || 0))}</td>
          <td style="min-width:280px;">${formatAgentDetails(item)}</td>
          <td>
            <div style="display:flex; gap:8px; flex-wrap:wrap;">
              ${canAddToCatalog ? `<button class="secondary" onclick="agentAddToCatalog('${escapeHtml(item.draftId)}', '${escapeHtml(catalogTarget)}')">Adicionar ao catalogo</button>` : ''}
              ${canHighlightOnBio ? `<button class="secondary" onclick="agentHighlightOnBio('${escapeHtml(item.draftId)}')">Destacar na bio</button>` : ''}
              ${canPublishNow ? `<button class="secondary" onclick="agentPublishDraftNow('${escapeHtml(item.draftId)}', '${escapeHtml(catalogTarget)}')">Publicar agora</button>` : ''}
              ${canReschedule ? `<button class="secondary" onclick="agentRescheduleDraft('${escapeHtml(item.draftId)}', '${escapeHtml(item.scheduledFor || '')}')">Reagendar</button>` : ''}
              <button class="secondary" onclick="window.open('/conversor-admin?draftId=${escapeHtml(item.draftId)}', '_blank')">Abrir draft</button>
            </div>
          </td>
        </tr>
      `;
    }).join('');
  } catch (e) {
    if (summary) {
      summary.className = 'status bad';
      summary.textContent = e?.data?.error || e?.message || 'Erro ao executar o agente.';
    }
    if (body) body.innerHTML = '<tr><td colspan="8" class="bad">Falha ao carregar recomendacoes do agente.</td></tr>';
  }
}

async function agentAddToCatalog(draftId, catalogTarget) {
  try {
    const response = await api('/api/admin/add-to-catalog', 'POST', { draftId, catalogTarget });
    const target = response?.target || catalogTarget || 'prod';
    showToast(`Catalogo atualizado para ${String(target).toUpperCase()}.`, 'success');
    await loadOfferCuration();
  } catch (e) {
    showToast(e?.data?.error || e?.message || 'Falha ao atualizar catalogo.', 'error');
  }
}

async function agentHighlightOnBio(draftId) {
  try {
    await api('/api/admin/highlight-on-bio', 'POST', { draftId });
    showToast('Oferta marcada como destaque na bio.', 'success');
    await loadOfferCuration();
  } catch (e) {
    showToast(e?.data?.error || e?.message || 'Falha ao destacar oferta na bio.', 'error');
  }
}

async function agentPublishDraftNow(draftId, catalogTarget = 'prod') {
  try {
    const response = await api('/api/admin/publish-instagram-now', 'POST', {
      draftId,
      sendToCatalog: true,
      catalogTarget
    });
    showToast(`Publicacao executada. MediaId: ${response?.mediaId || 'ok'}.`, 'success');
    await Promise.all([loadOfferCuration(), loadWhatsAppOfferScout()]);
  } catch (e) {
    showToast(e?.data?.error || e?.message || 'Falha ao publicar draft agora.', 'error');
  }
}

function toLocalDateTimeInputValue(value) {
  if (!value) return '';
  const dt = new Date(value);
  if (Number.isNaN(dt.getTime())) return '';
  return new Date(dt.getTime() - dt.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
}

async function agentRescheduleDraft(draftId, currentScheduledFor = '') {
  const suggested = toLocalDateTimeInputValue(currentScheduledFor) || toLocalDateTimeInputValue(new Date(Date.now() + 60 * 60 * 1000).toISOString());
  const value = window.prompt('Novo agendamento (YYYY-MM-DDTHH:mm). Deixe vazio para voltar para draft.', suggested);
  if (value === null) return;

  try {
    const scheduledFor = value.trim() ? new Date(value.trim()).toISOString() : null;
    const response = await api('/api/admin/reschedule-draft', 'POST', { draftId, scheduledFor });
    const label = response?.scheduledFor ? formatTs(response.scheduledFor) : 'sem agendamento';
    showToast(`Draft atualizado: ${label}.`, 'success');
    await Promise.all([loadOfferCuration(), loadWhatsAppOfferScout()]);
  } catch (e) {
    showToast(e?.data?.error || e?.message || 'Falha ao reagendar draft.', 'error');
  }
}

function buildWhatsAppScoutHighlights(items) {
  const highlights = document.getElementById('waScoutHighlights');
  if (!highlights) return;

  if (!Array.isArray(items) || items.length === 0) {
    highlights.innerHTML = '';
    return;
  }

  const topScore = items[0]?.score || 0;
  const drafts = items.filter(x => x.recommendedAction === 'create_instagram_draft').length;
  const catalog = items.filter(x => x.recommendedAction === 'add_to_catalog').length;
  const review = items.filter(x => x.recommendedAction === 'review_and_publish' || x.recommendedAction === 'review').length;

  const cards = [
    { label: 'Melhor score', value: topScore, hint: 'prioridade operacional' },
    { label: 'Draft IG', value: drafts, hint: 'posts dos canais ainda sem draft' },
    { label: 'Catalogo', value: catalog, hint: 'itens prontos para catalogo' },
    { label: 'Revisao', value: review, hint: 'itens para operador revisar' }
  ];

  highlights.innerHTML = cards.map(card => `
    <div class="card" style="padding:16px; text-align:center;">
      <div class="muted" style="font-size:12px; font-weight:600; text-transform:uppercase;">${card.label}</div>
      <div style="font-size:26px; font-weight:800; color:var(--accent); margin-top:6px;">${card.value}</div>
      <div class="muted" style="font-size:11px; margin-top:4px;">${card.hint}</div>
    </div>
  `).join('');
}

function parseAgentTargetIds() {
  const source = getAgentSourceChannel();
  return String(document.getElementById('waScoutTargetIds')?.value || '')
    .split(/[\r\n,;]+/)
    .map(x => x.trim())
    .map(x => normalizeAgentChatId(x, source))
    .filter(Boolean);
}

function getAgentSourceChannel() {
  return document.getElementById('waScoutSourceChannel')?.value || 'telegram';
}

const AGENT_UI_STATE_KEY = 'achadinhos.agent.channels.ui.v1';
let agentUiStateHydrated = false;

function loadAgentUiState() {
  try {
    const raw = localStorage.getItem(AGENT_UI_STATE_KEY);
    return raw ? JSON.parse(raw) : {};
  } catch {
    return {};
  }
}

function mergeAgentUiStates(localState, serverState) {
  const localManual = localState?.manualTargetIdsBySource && typeof localState.manualTargetIdsBySource === 'object'
    ? localState.manualTargetIdsBySource
    : {};
  const serverManual = serverState?.manualTargetIdsBySource && typeof serverState.manualTargetIdsBySource === 'object'
    ? serverState.manualTargetIdsBySource
    : {};
  const mergedManual = { ...serverManual, ...localManual };

  return {
    sourceChannel: localState?.sourceChannel || serverState?.sourceChannel || 'telegram',
    selectionMode: localState?.selectionMode || serverState?.selectionMode || 'saved_history',
    hoursWindow: Number(localState?.hoursWindow || serverState?.hoursWindow || 168),
    maxItems: Number(localState?.maxItems || serverState?.maxItems || 10),
    includeAiReasoning: !!(localState?.includeAiReasoning ?? serverState?.includeAiReasoning),
    useAiDecision: !!(localState?.useAiDecision ?? serverState?.useAiDecision),
    manualTargetIdsBySource: mergedManual
  };
}

function saveAgentUiState(partial = {}) {
  const current = loadAgentUiState();
  const next = { ...current, ...partial };
  localStorage.setItem(AGENT_UI_STATE_KEY, JSON.stringify(next));
  return next;
}

async function hydrateAgentUiState() {
  if (agentUiStateHydrated) return loadAgentUiState();
  const localState = loadAgentUiState();
  try {
    const state = await api('/api/agents/channel-monitor-ui-state');
    const merged = mergeAgentUiStates(localState, state || {});
    localStorage.setItem(AGENT_UI_STATE_KEY, JSON.stringify(merged));
  } catch {
    localStorage.setItem(AGENT_UI_STATE_KEY, JSON.stringify(localState || {}));
  }
  agentUiStateHydrated = true;
  return loadAgentUiState();
}

async function persistAgentUiStateToServer() {
  const state = loadAgentUiState();
  try {
    await api('/api/agents/channel-monitor-ui-state', 'POST', state);
  } catch {
  }
}

function readAgentManualTargetIdsBySource() {
  const state = loadAgentUiState();
  return state.manualTargetIdsBySource && typeof state.manualTargetIdsBySource === 'object'
    ? state.manualTargetIdsBySource
    : {};
}

function writeAgentManualTargetIdsForSource(sourceChannel, ids) {
  const all = readAgentManualTargetIdsBySource();
  all[String(sourceChannel || getAgentSourceChannel())] = Array.isArray(ids) ? ids : [];
  saveAgentUiState({ manualTargetIdsBySource: all });
}

function applyAgentUiState(state) {
  const source = state.sourceChannel || 'telegram';
  const sourceEl = document.getElementById('waScoutSourceChannel');
  const modeEl = document.getElementById('waScoutSelectionMode');
  const hoursEl = document.getElementById('waScoutHoursWindow');
  const maxItemsEl = document.getElementById('waScoutMaxItems');
  const aiReasoningEl = document.getElementById('waScoutUseAiReasoning');
  const aiDecisionEl = document.getElementById('waScoutUseAiDecision');
  const targetIdsEl = document.getElementById('waScoutTargetIds');
  const manualBySource = readAgentManualTargetIdsBySource();

  if (sourceEl) sourceEl.value = source;
  if (modeEl && state.selectionMode) modeEl.value = state.selectionMode;
  if (hoursEl && state.hoursWindow) hoursEl.value = String(state.hoursWindow);
  if (maxItemsEl && state.maxItems) maxItemsEl.value = String(state.maxItems);
  if (aiReasoningEl) aiReasoningEl.checked = !!state.includeAiReasoning;
  if (aiDecisionEl) aiDecisionEl.checked = !!state.useAiDecision;
  if (targetIdsEl) {
    const ids = Array.isArray(manualBySource[source]) ? manualBySource[source] : [];
    targetIdsEl.value = ids.join('\n');
  }
}

function restoreAgentUiState() {
  applyAgentUiState(loadAgentUiState());
}

function rememberAgentUiSelections() {
  const source = getAgentSourceChannel();
  saveAgentUiState({
    sourceChannel: source,
    selectionMode: document.getElementById('waScoutSelectionMode')?.value || 'saved_history',
    hoursWindow: Number(document.getElementById('waScoutHoursWindow')?.value || 168),
    maxItems: Number(document.getElementById('waScoutMaxItems')?.value || 10),
    includeAiReasoning: !!document.getElementById('waScoutUseAiReasoning')?.checked,
    useAiDecision: !!document.getElementById('waScoutUseAiDecision')?.checked
  });
  writeAgentManualTargetIdsForSource(source, parseAgentTargetIds());
  persistAgentUiStateToServer();
}

function getAgentTargetSet(sourceChannel) {
  const source = String(sourceChannel || getAgentSourceChannel());
  if (!window.__waScoutTargetsBySource) window.__waScoutTargetsBySource = {};
  if (!window.__waScoutTargetsBySource[source]) {
    window.__waScoutTargetsBySource[source] = new Set();
  }
  return window.__waScoutTargetsBySource[source];
}

function getAgentSavedSelections(sourceChannel) {
  const source = String(sourceChannel || getAgentSourceChannel());
  if (!window.__waScoutSavedSelectionsBySource) window.__waScoutSavedSelectionsBySource = {};
  return Array.isArray(window.__waScoutSavedSelectionsBySource[source]) ? window.__waScoutSavedSelectionsBySource[source] : [];
}

function setAgentSavedSelections(sourceChannel, items) {
  const source = String(sourceChannel || getAgentSourceChannel());
  if (!window.__waScoutSavedSelectionsBySource) window.__waScoutSavedSelectionsBySource = {};
  window.__waScoutSavedSelectionsBySource[source] = Array.isArray(items) ? items : [];
  window.__waScoutTargetsBySource = window.__waScoutTargetsBySource || {};
  window.__waScoutTargetsBySource[source] = new Set(window.__waScoutSavedSelectionsBySource[source].map(x => String(x.chatId || x.ChatId || '')));
}

function getAgentAvailableTargets(sourceChannel) {
  const source = String(sourceChannel || getAgentSourceChannel());
  return source === 'telegram'
    ? ((window.__userbotPayload?.chats || []).map(c => ({ id: String(c.id), title: c.title, meta: c.type || 'telegram' })))
    : ((window.__waPayload?.groups || []).map(g => ({ id: String(g.id), title: g.name, meta: g.type || 'whatsapp' })));
}

function buildAgentVisibleTargets(sourceChannel) {
  const source = String(sourceChannel || getAgentSourceChannel());
  const available = getAgentAvailableTargets(source);
  const saved = getAgentSavedSelections(source);
  const manual = parseAgentTargetIds();
  const map = new Map();

  available.forEach(item => {
    map.set(String(item.id), { id: String(item.id), title: item.title || String(item.id), meta: item.meta || source });
  });

  saved.forEach(item => {
    const id = String(item.chatId || item.ChatId || '');
    if (!id) return;
    if (!map.has(id)) {
      map.set(id, { id, title: item.title || item.Title || id, meta: `${source} salvo` });
    }
  });

  manual.forEach(id => {
    const normalizedId = normalizeAgentChatId(id, source);
    if (!normalizedId) return;
    if (!map.has(normalizedId)) {
      map.set(normalizedId, { id: normalizedId, title: normalizedId, meta: `${source} manual` });
    }
  });

  return Array.from(map.values());
}

function normalizeAgentChatId(value, sourceChannel) {
  const raw = String(value || '').trim();
  if (!raw) return '';
  if (String(sourceChannel || getAgentSourceChannel()) !== 'telegram') return raw;
  if (raw.startsWith('-100')) return raw;
  if (/^\d+$/.test(raw)) return `-100${raw}`;
  if (/^-\d+$/.test(raw)) return `-100${raw.slice(1)}`;
  return raw;
}

function setAgentTargetSaveStatus(text, type = 'muted') {
  const el = document.getElementById('waScoutTargetSaveStatus');
  if (!el) return;
  el.textContent = text;
  el.className = `status ${type}`;
}

function syncAgentTargetIdsFromSelection() {
  const selected = Array.from(getAgentTargetSet());
  const targetIds = document.getElementById('waScoutTargetIds');
  if (targetIds) targetIds.value = selected.join('\n');
}

let agentTargetSaveTimer = null;
function scheduleAgentTargetManualSave() {
  if (agentTargetSaveTimer) clearTimeout(agentTargetSaveTimer);
  setAgentTargetSaveStatus('Salvando selecao digitada...', 'warn');
  rememberAgentUiSelections();
  renderAgentChannelTargets();
  agentTargetSaveTimer = setTimeout(async () => {
    await persistAgentChannelTargets();
    renderAgentChannelTargets();
  }, 400);
}

async function loadSavedAgentChannelTargets(sourceChannel) {
  const source = String(sourceChannel || getAgentSourceChannel());
  const data = await api(`/api/agents/channel-monitor-selections?sourceChannel=${encodeURIComponent(source)}`);
  setAgentSavedSelections(source, Array.isArray(data.items) ? data.items : []);
  const targetIds = document.getElementById('waScoutTargetIds');
  const currentManual = parseAgentTargetIds();
  if (targetIds && currentManual.length === 0 && Array.isArray(data.items) && data.items.length > 0) {
    const restoredIds = data.items
      .map(item => normalizeAgentChatId(item.chatId || item.ChatId || '', source))
      .filter(Boolean);
    targetIds.value = restoredIds.join('\n');
    writeAgentManualTargetIdsForSource(source, restoredIds);
    saveAgentUiState({ sourceChannel: source });
  }
  setAgentTargetSaveStatus(`Selecao salva: ${Array.isArray(data.items) ? data.items.length : 0} grupo(s).`, 'ok');
}

async function persistAgentChannelTargets() {
  const source = getAgentSourceChannel();
  const selected = new Set(getAgentTargetSet(source));
  parseAgentTargetIds().forEach(id => selected.add(String(id)));
  rememberAgentUiSelections();

  const titleMap = new Map(getAgentAvailableTargets(source).map(item => [String(item.id), item.title || String(item.id)]));
  const payload = {
    sourceChannel: source,
    selections: Array.from(selected).map(chatId => ({
      sourceChannel: source,
      chatId,
      title: titleMap.get(String(chatId)) || String(chatId)
    }))
  };

  const data = await api('/api/agents/channel-monitor-selections', 'POST', payload);
  setAgentSavedSelections(source, Array.isArray(data.items) ? data.items : []);
  syncAgentTargetIdsFromSelection();
  setAgentTargetSaveStatus(`Selecao salva automaticamente: ${Array.isArray(data.items) ? data.items.length : 0} grupo(s).`, 'ok');
}

async function clearAgentChannelTargets() {
  const source = getAgentSourceChannel();
  if (window.__waScoutTargetsBySource) {
    window.__waScoutTargetsBySource[source] = new Set();
  }
  setAgentSavedSelections(source, []);
  await api('/api/agents/channel-monitor-selections', 'POST', { sourceChannel: source, selections: [] });
  const picker = document.getElementById('waScoutTargetPicker');
  if (picker) picker.innerHTML = 'Selecao limpa.';
  const targetIds = document.getElementById('waScoutTargetIds');
  if (targetIds) targetIds.value = '';
  writeAgentManualTargetIdsForSource(source, []);
  rememberAgentUiSelections();
  setAgentTargetSaveStatus('Selecao limpa e salva.', 'ok');
}

async function toggleAllAgentChannelTargets(checked) {
  const source = getAgentSourceChannel();
  const selected = getAgentTargetSet(source);
  const items = getAgentAvailableTargets(source);
  selected.clear();
  if (checked) {
    items.forEach(item => selected.add(String(item.id)));
  }
  syncAgentTargetIdsFromSelection();
  renderAgentChannelTargets();
  await persistAgentChannelTargets();
}

async function loadAgentChannelTargets() {
  const sourceChannel = getAgentSourceChannel();
  rememberAgentUiSelections();
  renderAgentChannelTargets();
  if (sourceChannel === 'telegram' && !window.__userbotPayload) {
    await loadUserbotChats();
  }
  if (sourceChannel === 'whatsapp' && !window.__waPayload) {
    await loadWhatsAppGroups();
  }
  await loadSavedAgentChannelTargets(sourceChannel);
  renderAgentChannelTargets();
}

function renderAgentChannelTargets() {
  const picker = document.getElementById('waScoutTargetPicker');
  if (!picker) return;

  const sourceChannel = getAgentSourceChannel();
  const selected = getAgentTargetSet(sourceChannel);
  const saved = getAgentSavedSelections(sourceChannel);
  const savedById = new Map(saved.map(item => [String(item.chatId || item.ChatId || ''), item]));
  const items = buildAgentVisibleTargets(sourceChannel);

  if (!items || items.length === 0) {
    picker.innerHTML = sourceChannel === 'whatsapp'
      ? '<span class="muted">Nenhum grupo carregado. No DEV o WhatsApp depende da Evolution; se ela estiver fora, a lista nao aparece.</span>'
      : '<span class="muted">Nenhum grupo carregado. Verifique se o userbot do Telegram esta conectado.</span>';
    return;
  }

  picker.innerHTML = `<div class="muted" style="margin-bottom:8px;">${sourceChannel === 'telegram' ? 'Chats Telegram visiveis' : 'Grupos WhatsApp visiveis'}: ${items.length}</div><div class="chat-list">` + items.map(item => `
    <label class="chat-item">
      <input type="checkbox" data-agent-target="1" value="${escapeHtml(item.id)}" ${selected.has(String(item.id)) ? 'checked' : ''} />
      <div>
        <div class="chat-title">${escapeHtml(item.title || item.id)}</div>
        <div class="chat-meta">${escapeHtml(item.meta)} | ${escapeHtml(item.id)}${savedById.has(String(item.id)) ? ` | monitorado desde ${escapeHtml(formatTs(savedById.get(String(item.id)).selectedAtUtc || savedById.get(String(item.id)).SelectedAtUtc || ''))}` : ''}</div>
      </div>
    </label>
  `).join('') + `</div>`;

  picker.onchange = async (ev) => {
    const target = ev.target;
    if (!target || !target.matches('input[data-agent-target="1"]')) return;
    const value = String(target.value);
    if (target.checked) selected.add(value);
    else selected.delete(value);
    syncAgentTargetIdsFromSelection();
    rememberAgentUiSelections();
    await persistAgentChannelTargets();
    renderAgentChannelTargets();
  };

  syncAgentTargetIdsFromSelection();
}

async function loadWhatsAppOfferScout() {
  const body = document.getElementById('waScoutBody');
  const summary = document.getElementById('waScoutSummary');
  const highlights = document.getElementById('waScoutHighlights');
  if (body) body.innerHTML = '<tr><td colspan="7" class="muted">Carregando oportunidades...</td></tr>';
  if (summary) summary.textContent = 'Executando agente...';
  if (highlights) highlights.innerHTML = '';

  try {
    rememberAgentUiSelections();
    const payload = {
      sourceChannel: getAgentSourceChannel(),
      targetSelectionMode: document.getElementById('waScoutSelectionMode')?.value || 'saved_history',
      targetChatIds: parseAgentTargetIds(),
      hoursWindow: Number(document.getElementById('waScoutHoursWindow')?.value || 168),
      maxItems: Number(document.getElementById('waScoutMaxItems')?.value || 10),
      includeAiReasoning: !!document.getElementById('waScoutUseAiReasoning')?.checked,
      useAiDecision: !!document.getElementById('waScoutUseAiDecision')?.checked
    };

    await persistAgentChannelTargets();
    const data = await api('/api/agents/whatsapp/offers/scout', 'POST', payload);
    const items = Array.isArray(data.suggestions) ? data.suggestions : [];
    const warnings = Array.isArray(data.warnings) ? data.warnings : [];

    if (summary) {
      summary.className = warnings.length > 0 ? 'status warn' : 'status ok';
      const channel = data.sourceChannel || payload.sourceChannel || 'whatsapp';
      const mode = data.targetSelectionMode || payload.targetSelectionMode || 'saved_history';
      const warningText = warnings.length > 0 ? ` Avisos: ${warnings.join(' | ')}` : '';
      summary.textContent = `${data.summary || 'Analise concluida.'} Fonte: ${channel}. Modo: ${mode}. Logs: ${data.sourceMessagesAvailable || 0}.${warningText}`;
    }

    buildWhatsAppScoutHighlights(items);

    if (!body) return;
    if (items.length === 0) {
      body.innerHTML = '<tr><td colspan="7" class="muted">Nenhuma oportunidade relevante nesta janela.</td></tr>';
      return;
    }

    body.innerHTML = items.map(item => {
      const canCreateDraft = item.recommendedAction === 'create_instagram_draft' && !item.hasExistingDraft;
      const canAddToCatalog = item.recommendedAction === 'add_to_catalog' && item.existingDraftId;
      const canReviewAndPublish = item.recommendedAction === 'review_and_publish' && item.existingDraftId;
      const canConvertLink = item.recommendedAction === 'convert_link';
      const canDeepAnalyze = true;
      const decisionTag = item.decisionSource === 'ai_guarded'
        ? `<span class="badge ok">IA ${escapeHtml(item.decisionProvider || '')}</span>`
        : `<span class="badge muted">${escapeHtml(item.decisionSource || 'heuristic')}</span>`;
      return `
        <tr>
          <td><strong>${escapeHtml(String(item.score || 0))}</strong></td>
          <td>
            <div><strong>${escapeHtml(item.productName || 'Oferta do canal')}</strong></div>
            <div class="muted">${escapeHtml(shortId(item.messageId || ''))}</div>
            <div class="muted">Origem: ${escapeHtml(item.sourceGroupTitle || item.targetChatId || '-')}</div>
            <div class="muted">${escapeHtml(item.captionPreview || '')}</div>
            <div class="muted">IG ${escapeHtml(String(item.instagramScore || 0))} | Cat ${escapeHtml(String(item.catalogScore || 0))} | CTA ${escapeHtml(item.suggestedKeyword || '-')}</div>
            <div class="muted">Formato: ${escapeHtml(item.suggestedPostType || 'feed')} | Midia: ${escapeHtml(item.mediaKind || 'text')}</div>
            ${item.requiresLinkConversion ? `<div class="muted">Conversao pendente${item.originalOfferUrl ? ` | ${escapeHtml(item.originalOfferUrl)}` : ''}</div>` : ''}
            <div style="margin-top:6px;">${decisionTag}</div>
          </td>
          <td>${renderAgentActionBadge(item.recommendedAction)}</td>
          <td>${renderCatalogTargetsBadge(item)}</td>
          <td>${escapeHtml(String(item.recentClicks || 0))}</td>
          <td style="min-width:280px;">${formatAgentDetails(item)}</td>
          <td>
            <div style="display:flex; gap:8px; flex-wrap:wrap;">
              ${canDeepAnalyze ? `<button class="secondary" onclick="agentDeepAnalyzeOffer('${escapeHtml(item.messageId)}', '${escapeHtml(data.sourceChannel || getAgentSourceChannel())}')">${item.requiresLinkConversion ? 'Converter + IA' : 'Analisar com IA'}</button>` : ''}
              ${canConvertLink ? `<button class="secondary" onclick="agentApplyWhatsAppRecommendation('${escapeHtml(item.messageId)}', 'convert_link', null, false, false, '${escapeHtml(item.suggestedPostType || 'feed')}', '${escapeHtml(data.sourceChannel || getAgentSourceChannel())}')">Converter link</button>` : ''}
              ${canCreateDraft ? `<button class="secondary" onclick="agentApplyWhatsAppRecommendation('${escapeHtml(item.messageId)}', '${escapeHtml(item.recommendedAction)}', null, false, false, '${escapeHtml(item.suggestedPostType || 'feed')}', '${escapeHtml(data.sourceChannel || getAgentSourceChannel())}')">Aplicar recomendacao</button>` : ''}
              ${canCreateDraft ? `<button class="secondary" onclick="agentCreateInstagramDraftFromWhatsApp('${escapeHtml(item.messageId)}', true, false, '${escapeHtml(item.suggestedPostType || 'feed')}', '${escapeHtml(data.sourceChannel || getAgentSourceChannel())}')">Criar draft IA</button>` : ''}
              ${canCreateDraft ? `<button class="secondary" onclick="agentCreateInstagramDraftFromWhatsApp('${escapeHtml(item.messageId)}', true, true, '${escapeHtml(item.suggestedPostType || 'feed')}', '${escapeHtml(data.sourceChannel || getAgentSourceChannel())}')">IA + catalogo</button>` : ''}
              ${canAddToCatalog ? `<button class="secondary" onclick="agentApplyWhatsAppRecommendation('${escapeHtml(item.messageId)}', '${escapeHtml(item.recommendedAction)}', '${escapeHtml(item.existingDraftId)}', false, true, '${escapeHtml(item.suggestedPostType || 'feed')}', '${escapeHtml(data.sourceChannel || getAgentSourceChannel())}')">Aplicar recomendacao</button>` : ''}
              ${canReviewAndPublish ? `<button class="secondary" onclick="agentApplyWhatsAppRecommendation('${escapeHtml(item.messageId)}', '${escapeHtml(item.recommendedAction)}', '${escapeHtml(item.existingDraftId)}', false, false, '${escapeHtml(item.suggestedPostType || 'feed')}', '${escapeHtml(data.sourceChannel || getAgentSourceChannel())}')">Aplicar recomendacao</button>` : ''}
              <button class="secondary" onclick="agentSendWhatsAppFeedback('${escapeHtml(item.messageId)}', 'accepted', '${escapeHtml(item.recommendedAction || '')}', '${escapeHtml(item.recommendedAction || '')}', '${escapeHtml(item.existingDraftId || '')}')">Aceita</button>
              <button class="secondary" onclick="agentSendWhatsAppFeedback('${escapeHtml(item.messageId)}', 'rejected', '${escapeHtml(item.recommendedAction || '')}', '', '${escapeHtml(item.existingDraftId || '')}')">Rejeita</button>
              <button class="secondary" onclick="agentSendWhatsAppFeedback('${escapeHtml(item.messageId)}', 'edited', '${escapeHtml(item.recommendedAction || '')}', '', '${escapeHtml(item.existingDraftId || '')}')">Editou</button>
              <button class="secondary" onclick="agentOpenWhatsAppAdmin('${escapeHtml(item.messageId || '')}', '${escapeHtml(data.sourceChannel || getAgentSourceChannel())}', '${escapeHtml(item.suggestedPostType || 'feed')}', '${escapeHtml(item.existingDraftId || '')}', ${item.requiresLinkConversion ? 'true' : 'false'})">Abrir admin</button>
            </div>
          </td>
        </tr>
      `;
    }).join('');
  } catch (e) {
    if (summary) {
      const source = getAgentSourceChannel();
      const fallback = source === 'whatsapp'
        ? 'Falha ao carregar oportunidades. O WhatsApp DEV depende da Evolution e ela pode estar indisponivel.'
        : 'Falha ao carregar oportunidades do Telegram.';
      summary.className = 'status bad';
      summary.textContent = e?.data?.error || e?.message || fallback;
    }
    if (body) body.innerHTML = '<tr><td colspan="7" class="bad">Falha ao carregar oportunidades dos canais.</td></tr>';
  }
}

async function agentDeepAnalyzeOffer(messageId, sourceChannel = null) {
  const params = new URLSearchParams({
    messageId,
    sourceChannel: sourceChannel || getAgentSourceChannel(),
    createDraft: '1',
    useAiReasoning: '1'
  });
  window.open(`/agent-analysis.html?${params.toString()}`, '_blank');
}

async function agentCreateInstagramDraftFromWhatsApp(messageId, useAiCaption = false, sendToCatalog = false, suggestedPostType = 'feed', sourceChannel = null) {
  try {
    const response = await api('/api/admin/apply-channel-offer-recommendation', 'POST', {
      messageId,
      recommendedAction: 'create_instagram_draft',
      sourceChannel: sourceChannel || getAgentSourceChannel(),
      useAiCaption,
      sendToCatalog,
      catalogTarget: sendToCatalog ? 'prod' : null,
      suggestedPostType
    });
    const mode = useAiCaption ? 'com IA' : 'manual';
    showToast(`Draft criado (${mode}): ${response?.draftId || 'ok'}.`, 'success');
    await Promise.all([loadWhatsAppOfferScout(), loadOfferCuration()]);
  } catch (e) {
    showToast(e?.data?.error || e?.message || 'Falha ao criar draft a partir do WhatsApp.', 'error');
  }
}

async function agentApplyWhatsAppRecommendation(messageId, recommendedAction, existingDraftId = null, useAiCaption = false, sendToCatalog = false, suggestedPostType = 'feed', sourceChannel = null) {
  try {
    const response = await api('/api/admin/apply-channel-offer-recommendation', 'POST', {
      messageId,
      recommendedAction,
      sourceChannel: sourceChannel || getAgentSourceChannel(),
      existingDraftId,
      useAiCaption,
      sendToCatalog,
      catalogTarget: sendToCatalog ? 'prod' : null,
      suggestedPostType
    });
    showToast(`Recomendacao aplicada: ${response?.action || recommendedAction}.`, 'success');
    await Promise.all([loadWhatsAppOfferScout(), loadOfferCuration()]);
  } catch (e) {
    showToast(e?.data?.error || e?.message || 'Falha ao aplicar recomendacao do agente.', 'error');
  }
}

async function agentSendWhatsAppFeedback(messageId, feedback, recommendedAction = '', appliedAction = '', existingDraftId = '') {
  try {
    await api('/api/admin/agents/whatsapp/feedback', 'POST', {
      messageId,
      feedback,
      recommendedAction: recommendedAction || null,
      appliedAction: appliedAction || null,
      existingDraftId: existingDraftId || null
    });
    showToast(`Feedback registrado: ${feedback}.`, 'success');
    await loadWhatsAppOfferScout();
  } catch (e) {
    showToast(e?.data?.error || e?.message || 'Falha ao registrar feedback.', 'error');
  }
}

async function seedAgentChannelTestLog() {
  const sourceChannel = getAgentSourceChannel();
  const targetIds = parseAgentTargetIds();
  const chatId = targetIds[0];
  if (!chatId) {
    showToast('Selecione ou digite ao menos um grupo antes de criar o log de teste.', 'error');
    return;
  }

  try {
    await persistAgentChannelTargets();
    const response = await api('/api/agents/channel-monitor-seed-log', 'POST', {
      sourceChannel,
      chatId,
      title: 'Oferta seed do agente'
    });
    showToast(`Log de teste criado para ${response.chatId}.`, 'success');
    await loadWhatsAppOfferScout();
  } catch (e) {
    showToast(e?.data?.error || e?.message || 'Falha ao criar log de teste.', 'error');
  }
}

function formatTs(ts) {
  if (!ts) return '-';
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return ts;
  return d.toLocaleString();
}

function formatRelativeTime(ts) {
  if (!ts) return 'agora';
  const date = new Date(ts);
  if (Number.isNaN(date.getTime())) return 'agora';
  const diffMs = Date.now() - date.getTime();
  const diffMin = Math.round(diffMs / 60000);
  if (Math.abs(diffMin) < 1) return 'agora';
  if (Math.abs(diffMin) < 60) return `${Math.abs(diffMin)} min ${diffMin >= 0 ? 'atrás' : 'à frente'}`;
  const diffHours = Math.round(diffMin / 60);
  if (Math.abs(diffHours) < 24) return `${Math.abs(diffHours)} h ${diffHours >= 0 ? 'atrás' : 'à frente'}`;
  return formatTs(ts);
}

function normalizeDashboardText(text) {
  if (text === null || text === undefined) return '';
  let normalized = String(text);
  const looksBroken = /[ÃÂ�]|CÃ|aÃ|nÃ|Ãƒ|Ã¢|�/.test(normalized);
  if (!looksBroken) return normalized;

  for (let i = 0; i < 2; i++) {
    try {
      const repaired = decodeURIComponent(escape(normalized));
      if (!repaired || repaired === normalized) break;
      normalized = repaired;
    } catch {
      break;
    }
  }

  return normalized.replace(/\uFFFD/g, '').trim();
}

function escapeHtml(text) {
  return normalizeDashboardText(text || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function shortId(text) {
  const s = String(text || '');
  if (s.length <= 18) return s;
  return `${s.slice(0, 6)}...${s.slice(-6)}`;
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

function parseApiKeysTextarea(id, fallbackMaskedSingle = '') {
  const values = String(document.getElementById(id)?.value || '')
    .split(/\r?\n/)
    .map(v => v.trim())
    .filter(Boolean);

  if (fallbackMaskedSingle && !values.includes(fallbackMaskedSingle)) {
    values.unshift(fallbackMaskedSingle);
  }

  return Array.from(new Set(values));
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

function renderPillList(targetId, values, emptyText = '') {
  const target = document.getElementById(targetId);
  if (!target) return;
  const items = Array.isArray(values) ? values.filter(Boolean) : [];
  if (items.length === 0) {
    target.innerHTML = emptyText ? `<span class="muted">${escapeHtml(emptyText)}</span>` : '';
    return;
  }
  target.innerHTML = items.map(value => `<span class="pill selection-chip">${escapeHtml(String(value))}</span>`).join('');
}

function offerNormalizationTargetLabel(target) {
  switch (String(target || '').toLowerCase()) {
    case 'catalog':
      return 'Catálogo';
    case 'queue':
      return 'Fila de automação';
    default:
      return 'Preview + revisão';
  }
}

function offerNormalizationStatusMeta(status) {
  switch (String(status || '').toLowerCase()) {
    case 'normalized':
      return { label: 'Normalizado', badge: 'ok' };
    case 'review_required':
      return { label: 'Revisão obrigatória', badge: 'warn' };
    case 'sent_to_catalog':
      return { label: 'Enviado ao catálogo', badge: 'ok' };
    case 'queued_for_automation':
      return { label: 'Na fila de automação', badge: 'warn' };
    case 'failed':
      return { label: 'Falhou', badge: 'bad' };
    default:
      return { label: 'Sem execução', badge: 'muted' };
  }
}

function offerNormalizationSourceLabel(sourceType) {
  switch (String(sourceType || '').toLowerCase()) {
    case 'json':
      return 'JSON';
    case 'csv':
      return 'CSV';
    case 'tsv':
      return 'TSV';
    case 'table':
      return 'Tabela simples';
    default:
      return 'Autodetectar';
  }
}

function formatOfferNormalizationMoney(value) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return '-';
  return numeric.toLocaleString('pt-BR', { style: 'currency', currency: 'BRL' });
}

function formatOfferNormalizationDiscount(value) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return '-';
  return `${numeric.toLocaleString('pt-BR', { maximumFractionDigits: 2 })}%`;
}

function setOfferNormalizationActionStatus(message = '', type = 'muted') {
  const el = document.getElementById('offerNormalizeActionStatus');
  if (!el) return;
  el.textContent = message;
  el.className = `status ${type}`;
}

function escapeOfferNormalizationCell(value, fallback = '-') {
  const text = value === null || value === undefined || value === '' ? fallback : String(value);
  return escapeHtml(text);
}

function renderOfferNormalizationIssues(issues) {
  const container = document.getElementById('offerNormalizeIssuesList');
  if (!container) return;

  const items = Array.isArray(issues) ? issues : [];
  if (!items.length) {
    container.innerHTML = '<div class="overview-list-empty">Nenhuma issue carregada.</div>';
    return;
  }

  container.innerHTML = items.map(issue => {
    const level = String(issue?.level || 'warn').toLowerCase();
    const badgeClass = level === 'error' ? 'bad' : level === 'info' ? 'muted' : 'warn';
    const row = issue?.rowNumber ? `Linha ${issue.rowNumber}` : 'Geral';
    const field = issue?.field ? ` • ${escapeHtml(issue.field)}` : '';
    return `
      <div class="overview-list-item">
        <div>
          <strong>${escapeHtml(issue?.message || 'Issue sem descrição')}</strong>
          <small class="muted">${escapeHtml(row)}${field}</small>
        </div>
        <span class="badge ${badgeClass}">${escapeHtml(level)}</span>
      </div>
    `;
  }).join('');
}

function renderOfferNormalizationPreview(offers) {
  const body = document.getElementById('offerNormalizePreviewBody');
  if (!body) return;

  const items = Array.isArray(offers) ? offers : [];
  if (!items.length) {
    body.innerHTML = '<tr><td colspan="8" class="muted">Nenhuma oferta normalizada nesta sessão.</td></tr>';
    return;
  }

  body.innerHTML = items.map(item => {
    const issues = [];
    if (!item?.productName) issues.push('Sem nome');
    if (!item?.productUrl) issues.push('Sem URL');
    if (item?.promoPrice === null || item?.promoPrice === undefined) issues.push('Sem preço promo');
    const issueBadges = issues.length
      ? issues.map(issue => `<span class="badge warn">${escapeHtml(issue)}</span>`).join(' ')
      : '<span class="badge ok">Pronta</span>';
    const safeUrl = item?.productUrl && /^https?:\/\//i.test(item.productUrl)
      ? `<a href="${escapeHtml(item.productUrl)}" target="_blank" rel="noopener noreferrer">Abrir</a>`
      : '<span class="muted">Sem URL</span>';

    return `
      <tr>
        <td><strong>${escapeOfferNormalizationCell(item?.productName, 'Sem nome')}</strong></td>
        <td><small class="muted">${safeUrl}</small></td>
        <td>${formatOfferNormalizationMoney(item?.originalPrice)}</td>
        <td>${formatOfferNormalizationMoney(item?.promoPrice)}</td>
        <td>${formatOfferNormalizationDiscount(item?.discountPercent)}</td>
        <td>${escapeOfferNormalizationCell(item?.storeName)}</td>
        <td>${escapeOfferNormalizationCell(item?.category)}</td>
        <td>${item?.commissionRaw ? escapeHtml(String(item.commissionRaw)) : issueBadges}</td>
      </tr>
    `;
  }).join('');
}

function renderOfferNormalizationRun(run) {
  const statusMeta = offerNormalizationStatusMeta(run?.status);
  const targetLabel = offerNormalizationTargetLabel(run?.selectedTarget);
  const sourceLabel = offerNormalizationSourceLabel(run?.sourceType);
  const offersCount = Array.isArray(run?.normalizedOffers) ? run.normalizedOffers.length : 0;
  const issuesCount = Array.isArray(run?.validationIssues) ? run.validationIssues.length : 0;
  const assistedSummary = run?.assistedDelivery?.summary ? ` ${run.assistedDelivery.summary}` : '';

  setSafeText('offerNormalizeRunId', run?.id ? shortId(run.id) : 'Nenhum');
  setSafeText('offerNormalizeStatusText', statusMeta.label);
  setSafeText('offerNormalizeOffersCount', String(offersCount));
  setSafeText('offerNormalizeSourceType', run ? sourceLabel : 'Sem origem processada');
  setSafeText('offerNormalizeIssuesCount', String(issuesCount));
  setSafeText('offerNormalizeCurrentTarget', targetLabel);
  setSafeText('offerNormalizeNextStep', run?.nextStepHint || 'Revise a entrada e normalize.');
  setSafeText('offerNormalizeSummaryTitle', run ? `Execução ${shortId(run.id)} • ${formatTs(run.createdAtUtc)}` : 'Nenhuma execução carregada.');
  setSafeText('offerNormalizeSummary', run ? `${run.summary || ''}${assistedSummary}`.trim() || 'Normalize uma entrada para gerar preview, issues e histórico.' : 'Normalize uma entrada para gerar preview, issues e histórico.');

  const badge = document.getElementById('offerNormalizeStatusBadge');
  if (badge) {
    badge.textContent = statusMeta.label;
    badge.className = `badge ${statusMeta.badge}`;
  }

  const targetSelect = document.getElementById('offerNormalizeTarget');
  if (targetSelect && run?.selectedTarget) {
    targetSelect.value = run.selectedTarget;
  }

  const notesInput = document.getElementById('offerNormalizeNotes');
  if (notesInput && run?.notes !== undefined && run?.notes !== null) {
    notesInput.value = run.notes;
  }

  renderOfferNormalizationPreview(run?.normalizedOffers || []);
  renderOfferNormalizationIssues(run?.validationIssues || []);
}

function renderOfferNormalizationHistory(runs) {
  const body = document.getElementById('offerNormalizeHistoryBody');
  if (!body) return;

  const items = Array.isArray(runs) ? runs : [];
  if (!items.length) {
    body.innerHTML = '<tr><td colspan="7" class="muted">Nenhuma execução carregada.</td></tr>';
    return;
  }

  body.innerHTML = items.map(run => {
    const statusMeta = offerNormalizationStatusMeta(run?.status);
    const offersCount = Array.isArray(run?.normalizedOffers) ? run.normalizedOffers.length : 0;
    const issuesCount = Array.isArray(run?.validationIssues) ? run.validationIssues.length : 0;
    const summary = run?.summary || `${offersCount} oferta(s) / ${issuesCount} issue(s)`;
    return `
      <tr>
        <td>${escapeHtml(formatTs(run?.createdAtUtc))}</td>
        <td>${escapeHtml(offerNormalizationSourceLabel(run?.sourceType))}</td>
        <td>${escapeHtml(summary)}</td>
        <td>${escapeHtml(offerNormalizationTargetLabel(run?.selectedTarget))}</td>
        <td><span class="badge ${statusMeta.badge}">${escapeHtml(statusMeta.label)}</span></td>
        <td>${escapeHtml(run?.operator || '-')}</td>
        <td>
          <div class="section-actions">
            <button class="secondary" onclick="loadOfferNormalizationRun('${escapeHtml(run?.id || '')}')">Abrir</button>
            <button class="secondary" onclick="routeOfferNormalizationRun('review', '${escapeHtml(run?.id || '')}')">Revisão</button>
          </div>
        </td>
      </tr>
    `;
  }).join('');
}

async function loadOfferNormalizationRuns() {
  const status = document.getElementById('offerNormalizeHistoryStatus')?.value || '';
  const target = document.getElementById('offerNormalizeHistoryTarget')?.value || '';
  const body = document.getElementById('offerNormalizeHistoryBody');

  if (body) {
    body.innerHTML = '<tr><td colspan="7" class="muted">Carregando execuções...</td></tr>';
  }

  try {
    const params = new URLSearchParams();
    if (status) params.set('status', status);
    if (target) params.set('target', target);
    params.set('limit', '20');
    const response = await api(`/api/admin/offers/normalization-runs?${params.toString()}`);
    renderOfferNormalizationHistory(response?.items || response?.runs || []);
  } catch (e) {
    if (body) {
      body.innerHTML = `<tr><td colspan="7" class="muted">Falha ao carregar histórico: ${escapeHtml(e?.data?.error || e?.message || 'erro desconhecido')}</td></tr>`;
    }
  }
}

async function loadOfferNormalizationRun(id) {
  if (!id) return;
  try {
    const response = await api(`/api/admin/offers/normalization-runs/${encodeURIComponent(id)}`);
    const run = response?.run || response || null;
    currentOfferNormalizationRunId = run?.id || null;
    renderOfferNormalizationRun(run);
  } catch (e) {
    showToast(e?.data?.error || e?.message || 'Falha ao carregar execução.', 'error');
  }
}

async function normalizeOffersInput() {
  const rawInput = document.getElementById('offerNormalizeInput')?.value || '';
  const inputType = document.getElementById('offerNormalizeInputType')?.value || 'autodetect';
  const selectedTarget = document.getElementById('offerNormalizeTarget')?.value || 'review';
  const notes = document.getElementById('offerNormalizeNotes')?.value || '';

  if (!rawInput.trim()) {
    setOfferNormalizationActionStatus('Cole algum conteúdo antes de normalizar.', 'warn');
    showToast('Cole JSON, CSV ou tabela antes de normalizar.', 'error');
    return;
  }

  setOfferNormalizationActionStatus('Normalizando ofertas...', 'muted');
  try {
    const response = await api('/api/admin/offers/normalize', 'POST', {
      rawInput,
      inputType,
      selectedTarget,
      notes
    });

    currentOfferNormalizationRunId = response?.runId || null;
    setOfferNormalizationActionStatus(`Execução ${shortId(response?.runId || '')} criada com sucesso.`, 'ok');
    showToast(`Normalização concluída: ${response?.offers?.length || 0} oferta(s).`, 'success');
    if (currentOfferNormalizationRunId) {
      await loadOfferNormalizationRun(currentOfferNormalizationRunId);
    }
    await loadOfferNormalizationRuns();
  } catch (e) {
    const message = e?.data?.error || e?.message || 'Falha ao normalizar ofertas.';
    setOfferNormalizationActionStatus(message, 'bad');
    showToast(message, 'error');
  }
}

async function routeOfferNormalizationRun(targetOverride, runIdOverride = null) {
  const runId = runIdOverride || currentOfferNormalizationRunId;
  if (!runId) {
    showToast('Abra ou normalize uma execução antes de encaminhar.', 'error');
    return;
  }

  const selectedTarget = targetOverride || document.getElementById('offerNormalizeTarget')?.value || 'review';
  const notes = document.getElementById('offerNormalizeNotes')?.value || '';
  setOfferNormalizationActionStatus(`Atualizando destino para ${offerNormalizationTargetLabel(selectedTarget)}...`, 'muted');

  try {
    const response = await api(`/api/admin/offers/normalization-runs/${encodeURIComponent(runId)}/route`, 'POST', {
      selectedTarget,
      notes
    });

    const run = response?.run || response || null;
    currentOfferNormalizationRunId = run?.id || runId;
    renderOfferNormalizationRun(run);
    await loadOfferNormalizationRuns();
    setOfferNormalizationActionStatus(`Execução encaminhada para ${offerNormalizationTargetLabel(selectedTarget)}.`, 'ok');
    showToast(`Execução enviada para ${offerNormalizationTargetLabel(selectedTarget)}.`, 'success');
  } catch (e) {
    const message = e?.data?.error || e?.message || 'Falha ao atualizar destino da execução.';
    setOfferNormalizationActionStatus(message, 'bad');
    showToast(message, 'error');
  }
}

function clearOfferNormalizationComposer() {
  currentOfferNormalizationRunId = null;
  setSafeVal('offerNormalizeInput', '');
  setSafeVal('offerNormalizeNotes', '');
  setSafeVal('offerNormalizeInputType', 'autodetect');
  setSafeVal('offerNormalizeTarget', 'review');
  setOfferNormalizationActionStatus('', 'muted');
  renderOfferNormalizationRun(null);
}

function loadTheme() {
  const saved = localStorage.getItem('theme') || 'light';
  document.body.setAttribute('data-theme', saved);
}

function toggleTheme() {
  const current = document.body.getAttribute('data-theme') || 'light';
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

function getOperationalTone(value) {
  if (value === true) return 'ok';
  if (value === false) return 'bad';
  return 'warn';
}

function setOperationalSummary(prefix, summary, detail, tone) {
  const summaryEl = document.getElementById(`${prefix}Summary`);
  const detailEl = document.getElementById(`${prefix}Detail`);
  if (summaryEl) summaryEl.textContent = summary;
  if (detailEl) detailEl.textContent = detail;
  const card = summaryEl?.closest('.status-board-item');
  if (card) {
    card.dataset.tone = tone;
    card.style.borderColor = tone === 'ok'
      ? 'rgba(16, 185, 129, 0.22)'
      : tone === 'bad'
        ? 'rgba(239, 68, 68, 0.24)'
        : 'rgba(245, 158, 11, 0.24)';
  }
}

function renderOperationalList(containerId, items, renderer, emptyText) {
  const container = document.getElementById(containerId);
  if (!container) return;
  if (!Array.isArray(items) || items.length === 0) {
    container.innerHTML = `<div class="overview-list-empty">${escapeHtml(emptyText)}</div>`;
    return;
  }
  container.innerHTML = items.map(renderer).join('');
}

function setOverviewRibbon(id, label, ok, detailText) {
  const tone = ok === true ? 'ok' : ok === false ? 'bad' : 'warn';
  setChipStatus(id, detailText ? `${label}: ${detailText}` : label, tone);
}

function stopOperationalOverviewAutoRefresh() {
  if (!opsOverviewTimer) return;
  clearInterval(opsOverviewTimer);
  opsOverviewTimer = null;
}

function startOperationalOverviewAutoRefresh() {
  if (opsOverviewTimer) return;
  opsOverviewTimer = setInterval(() => {
    if (localStorage.getItem('activeTab') === 'overview') {
      loadOperationalOverview(true);
    }
  }, 30000);
}

function renderOperationalOverview(snapshot) {
  const readiness = snapshot?.readiness || {};
  const checks = readiness.checks || {};
  const alerts = Array.isArray(snapshot?.alerts) ? snapshot.alerts : [];
  const workers = Array.isArray(checks.workers) ? checks.workers : [];
  const outboxes = Array.isArray(checks.outboxes) ? checks.outboxes : [];
  const issues = Array.isArray(readiness.issues) ? readiness.issues : [];
  const volumes = snapshot?.volumes || {};
  const recentMediaFailures = Array.isArray(snapshot?.recentMediaFailures) ? snapshot.recentMediaFailures : [];
  const healthyWorkers = workers.filter(x => x.healthy).length;
  const backlogTotal = outboxes.reduce((sum, item) => sum + Number(item.pendingCount || 0), 0);
  const readinessTone = readiness.ready ? 'ok' : alerts.length > 0 ? 'bad' : 'warn';
  const readinessBadge = document.getElementById('overviewReadinessBadge');

  if (readinessBadge) {
    readinessBadge.textContent = readiness.ready ? 'Saudável' : alerts.length > 0 ? 'Atenção' : 'Monitorando';
    readinessBadge.className = `badge ${readinessTone}`;
  }

  setSafeText('overviewReadinessTitle', readiness.ready
    ? 'Fluxo principal pronto para operar'
    : 'Existem sinais de degradação que pedem atenção imediata');
  setSafeText(
    'overviewReadinessSubtitle',
    readiness.ready
      ? 'RabbitMQ, Evolution, userbot e workers críticos responderam sem alertas ativos.'
      : (issues[0] || 'O snapshot indicou pendências operacionais. Use os cartões abaixo para identificar o gargalo.')
  );
  setSafeText('overviewAlertsCount', String(alerts.length));
  setSafeText('overviewWorkersHealthy', `${healthyWorkers}/${workers.length}`);
  setSafeText('overviewBacklogTotal', String(backlogTotal));
  setSafeText('overviewUpdatedAt', formatRelativeTime(snapshot?.readiness?.ts || snapshot?.ts));
  setSafeText('statStatus', readiness.ready ? 'Saudável' : 'Atenção');

  const settings = window.__settingsCache || {};
  const telegramConnected = !!settings.integrations?.telegram?.connected;
  const whatsAppConnected = !!(settings.integrations?.whatsApp?.connected || settings.integrations?.whatsapp?.connected);

  setOverviewRibbon('overviewRibbonSystem', 'Sistema', readiness.ready, readiness.ready ? 'estável' : 'atenção');
  setOverviewRibbon('overviewRibbonTelegram', 'Telegram', telegramConnected && !!checks.telegramUserbotReady, telegramConnected ? 'ativo' : 'pendente');
  setOverviewRibbon('overviewRibbonWhatsApp', 'WhatsApp', whatsAppConnected && !!checks.evolutionReady, whatsAppConnected ? 'ativo' : 'pendente');
  setOverviewRibbon('overviewRibbonRabbit', 'RabbitMQ', checks.rabbitMqReachable, checks.rabbitMqReachable ? 'ok' : 'falha');
  setOverviewRibbon('overviewRibbonEvolution', 'Evolution', checks.evolutionReady, checks.evolutionReady ? 'ok' : 'falha');

  setOperationalSummary('overviewSystem', readiness.ready ? 'Saudável' : 'Degradado', readiness.ready ? 'Sem incidentes críticos ativos.' : (issues[0] || 'Existem verificações em atenção.'), readinessTone);
  setOperationalSummary('overviewTelegram', telegramConnected ? 'Conectado' : 'Pendente', checks.telegramUserbotReady ? 'Userbot pronto para escuta.' : 'Userbot ainda não está pronto.', telegramConnected && checks.telegramUserbotReady ? 'ok' : 'warn');
  setOperationalSummary('overviewWhatsApp', whatsAppConnected ? 'Conectado' : 'Pendente', checks.evolutionReady ? 'Instância pronta para envio.' : 'Evolution ainda não validou a instância.', whatsAppConnected && checks.evolutionReady ? 'ok' : 'warn');
  setOperationalSummary('overviewRabbit', checks.rabbitMqReachable ? 'Disponível' : 'Indisponível', checks.rabbitMqReachable ? 'Fila acessível para replay e publish.' : 'Readiness não conseguiu abrir conexão.', getOperationalTone(checks.rabbitMqReachable));
  setOperationalSummary('overviewEvolution', checks.evolutionReady ? 'Disponível' : 'Indisponível', checks.evolutionReady ? 'Instância autenticada e acessível.' : 'WhatsApp ou Evolution não responderam como esperado.', getOperationalTone(checks.evolutionReady));

  renderOperationalList(
    'overviewAlertsList',
    alerts,
    (alert) => `
      <div class="overview-list-item">
        <div>
          <strong>${escapeHtml(alert.message || alert.code || 'Alerta')}</strong>
          <div class="muted">${escapeHtml(alert.code || 'sem código')}</div>
        </div>
        <span class="badge ${String(alert.severity || '').toLowerCase() === 'critical' ? 'bad' : 'warn'}">${escapeHtml(alert.severity || 'warn')}</span>
      </div>
    `,
    'Nenhum alerta crítico ativo.'
  );

  renderOperationalList(
    'overviewWorkersList',
    workers,
    (worker) => `
      <div class="overview-list-item">
        <div>
          <strong>${escapeHtml(worker.workerName || 'worker')}</strong>
          <div class="muted">${escapeHtml(worker.message || 'sem mensagem')}</div>
          <div class="muted">Último sucesso: ${escapeHtml(formatTs(worker.lastSuccessUtc))}</div>
        </div>
        <span class="badge ${worker.healthy ? 'ok' : 'bad'}">${worker.healthy ? 'ok' : 'falha'}</span>
      </div>
    `,
    'Nenhum worker monitorado.'
  );

  renderOperationalList(
    'overviewOutboxesList',
    outboxes,
    (outbox) => `
      <div class="overview-list-item">
        <div>
          <strong>${escapeHtml(outbox.name || 'outbox')}</strong>
          <div class="muted">Pendências em fila local para replay.</div>
        </div>
        <span class="badge ${Number(outbox.pendingCount || 0) > 0 ? 'warn' : 'ok'}">${Number(outbox.pendingCount || 0)}</span>
      </div>
    `,
    'Nenhuma outbox monitorada.'
  );

  setSafeText('overviewVolumeConversions', String(volumes.conversions24h || 0));
  setSafeText('overviewVolumeConversionsOk', String(volumes.successfulConversions24h || 0));
  setSafeText('overviewVolumeWhatsApp', String(volumes.whatsAppOutbound24h || 0));
  setSafeText('overviewVolumeTelegram', String(volumes.telegramOutbound24h || 0));
  setSafeText('overviewVolumeMediaFailures', String(volumes.mediaFailures24h || 0));

  const latestMediaFailure = recentMediaFailures[0];
  setSafeText(
    'overviewMediaFailureDetail',
    latestMediaFailure
      ? `Última falha: ${latestMediaFailure.reason || latestMediaFailure.detail || 'sem detalhe'} em ${formatTs(latestMediaFailure.timestamp || latestMediaFailure.createdAtUtc)}.`
      : 'Sem falhas recentes de mídia.'
  );

  setSafeText(
    'overviewQuickSummary',
    readiness.ready
      ? 'Ambiente estável. Use os atalhos para navegar nas rotinas administrativas sem perder o contexto da saúde operacional.'
      : 'Existe pelo menos um componente em atenção. Priorize alertas, workers e backlog antes de atuar nas áreas secundárias.'
  );
}

async function loadOperationalOverview(force = false) {
  if (!force && !document.getElementById('section-overview')) return;
  try {
    const snapshot = await api('/api/admin/ops/status');
    window.__opsStatusCache = snapshot;
    renderOperationalOverview(snapshot);
  } catch (error) {
    console.error('Erro ao carregar snapshot operacional', error);
    const badge = document.getElementById('overviewReadinessBadge');
    if (badge) {
      badge.textContent = 'Erro';
      badge.className = 'badge bad';
    }
    setSafeText('overviewReadinessTitle', 'Falha ao carregar a visão operacional');
    setSafeText('overviewReadinessSubtitle', error?.data?.error || error?.message || 'Não foi possível consultar /api/admin/ops/status.');
    setSafeText('overviewUpdatedAt', 'falhou');
    setOverviewRibbon('overviewRibbonSystem', 'Sistema', false, 'erro');
  }
}

function renderSettings(s) {
  if (!s) return;
  window.__settingsCache = s;
  
  try {
    setEnvironmentBadge(s.runtimeEnvironment);
    const now = Date.now();
    const lockUntil = window.__telegramStatusLockUntil || 0;
    const isLocked = now < lockUntil;
    
    // Integrations
    const tg = s.integrations?.telegram || {};
    const tgConnected = !!tg.connected;
    const telegramStatusText = tgConnected ? `Conectado (${tg.identifier || 'sem id'})` : 'Não conectado';
    const telegramStatusState = tgConnected ? 'ok' : 'warn';
    
    if (!isLocked) {
      setSafeText('telegramStatus', telegramStatusText);
      setSafeClass('telegramStatus', 'status ' + telegramStatusState);
    }
    
      const telegramDetailText = isLocked ? (window.__telegramStatusLockedText || telegramStatusText) : telegramStatusText;
      const telegramDetailState = isLocked ? (window.__telegramStatusLockedState || telegramStatusState) : telegramStatusState;
      setSafeText('telegramStatusDetail', telegramDetailText);
      setSafeClass('telegramStatusDetail', 'status ' + telegramDetailState);
      setSafeText('connectionSummaryTelegramBot', tgConnected ? 'Online' : 'Offline');
      setSafeText('connectionSummaryTelegramBotDetail', telegramDetailText);
      setSafeText('opsSummaryTelegramBot', tgConnected ? 'Online' : 'Offline');

      const wa = s.integrations?.whatsApp || s.integrations?.whatsapp || {};
      const waConnected = !!wa.connected;
      setSafeText('whatsappStatus', waConnected ? `Conectado (${wa.identifier || 'sem id'})` : 'Não conectado');
      setSafeClass('whatsappStatus', 'status ' + (waConnected ? 'ok' : 'warn'));
      if (waConnected) hideWhatsAppQr();
      setSafeText('connectionSummaryWhatsApp', waConnected ? 'Online' : 'Offline');
      setSafeText('connectionSummaryWhatsAppDetail', waConnected ? `Instância ativa: ${wa.identifier || 'sem id'}` : 'A instância principal ainda não respondeu.');
      setSafeText('opsSummaryWhatsApp', waConnected ? 'Online' : 'Offline');

      const ml = s.integrations?.mercadoLivre || {};
      const mlConnected = !!ml.connected;
      setSafeText('mercadoLivreStatus', mlConnected ? `Conectado (${ml.identifier || 'sem id'})` : 'Não validado');
      setSafeClass('mercadoLivreStatus', 'status ' + (mlConnected ? 'ok' : 'warn'));
      setSafeText('connectionSummaryMercadoLivre', mlConnected ? 'Validado' : 'Pendente');
      setSafeText('connectionSummaryMercadoLivreDetail', mlConnected ? `Conta ${ml.identifier || 'sem id'} validada.` : 'Faça um teste de OAuth para confirmar o fluxo afiliado.');

    setChipStatus('chipTelegramBot', tgConnected ? 'Telegram Bot: Conectado' : 'Telegram Bot: Offline', tgConnected ? 'ok' : 'warn');
    setChipStatus('chipWhatsApp', waConnected ? 'WhatsApp: Conectado' : 'WhatsApp: Offline', waConnected ? 'ok' : 'warn');
    setChipStatus('chipMercadoLivre', mlConnected ? 'Mercado Livre: Conectado' : 'Mercado Livre: Nao validado', mlConnected ? 'ok' : 'warn');
    setChipStatus('chipUserbot', 'Telegram Userbot: Conectando...', 'warn');
    
    setHealthBadge('healthTelegramBot', tgConnected ? 'Telegram Bot OK' : 'Telegram Bot Offline', tgConnected ? 'ok' : 'bad');
    setHealthBadge('healthWhatsApp', waConnected ? 'WhatsApp OK' : 'WhatsApp Offline', waConnected ? 'ok' : 'bad');

    // Auto Replies
    setSafeVal('rules', (s.autoReplies || []).map(r => `${r.trigger} => ${r.responseTemplate}`).join('\n'));
    setSafeChecked('autoRepliesEnabled', s.autoRepliesSettings?.enabled ?? true);

    // Link Automation
    const la = s.linkAutomation || {};
    setSafeChecked('autoConvert', !!la.autoConvertIncomingLinks);
    setSafeChecked('autoSend', !!la.autoSendToDestinationChannel);
    setSafeVal('destinationChannel', la.destinationChannel || '');

    // Telegram Forwarding
    const tf = s.telegramForwarding || {};
    setSafeChecked('userbotEnabled', !!tf.enabled);
    setSafeVal('userbotDestinationId', tf.destinationChatId || '');
    setSafeChecked('userbotAppendShein', !!tf.appendSheinCode);
    setSafeChecked('userbotPreferLinkPreviewNoMedia', tf.preferLinkPreviewWhenNoMedia ?? true);
    setSafeVal('userbotFooter', tf.footerText || '');

    // WhatsApp Forwarding
    const wf = s.whatsAppForwarding || {};
    setSafeChecked('waForwardEnabled', !!wf.enabled);
    setSafeChecked('waFromMeOnly', wf.processFromMeOnly ?? true);
    setSafeChecked('waSendMedia', wf.sendMediaEnabled ?? true);
    setSafeChecked('waPreferLinkPreviewNoMedia', wf.preferLinkPreviewWhenNoMedia ?? true);
    setSafeVal('waFooter', wf.footerText || '');
    setSafeChecked('waAppendShein', wf.appendSheinCode ?? true);
    setSafeVal('waInstanceName', wf.instanceName || '');
    setSafeText('waForwardStatus', wf.enabled ? 'Repasse ativo' : 'Repasse inativo');
    setSafeClass('waForwardStatus', `badge ${wf.enabled ? 'ok' : 'warn'}`);

    // Link Responder
    const responder = s.linkResponder || {};
    setSafeChecked('responderEnabled', !!responder.enabled);
    setSafeChecked('responderWhatsApp', responder.allowWhatsApp ?? true);
    setSafeChecked('responderTelegramBot', !!responder.allowTelegramBot);
    setSafeChecked('responderTelegramUserbot', !!responder.allowTelegramUserbot);
    setSafeChecked('responderWaPrivate', responder.whatsAppAllowPrivate ?? true);
    setSafeChecked('responderWaGroups', !!responder.whatsAppAllowGroups);
    setSafeChecked('responderTgPrivate', responder.telegramAllowPrivate ?? true);
    setSafeChecked('responderTgGroups', !!responder.telegramAllowGroups);
    setSafeVal('responderWaIds', (responder.whatsAppChatIds || []).join('\n'));
    setSafeVal('responderTgIds', (responder.telegramChatIds || []).join('\n'));
    setSafeVal('responderTemplate', responder.replyTemplate || '');
    setSafeVal('responderFailTemplate', responder.replyOnFailure || '');
    setSafeChecked('responderAppendShein', responder.appendSheinCode ?? true);
    setSafeChecked('responderTracking', responder.trackingEnabled ?? true);
    setSafeChecked('responderWelcomeEnabled', responder.welcomeEnabled ?? true);
    setSafeVal('responderWelcomeMessage', responder.welcomeMessage || '');
    setSafeVal('responderFooter', responder.footerText || '');

    // ML Compliance
    const mlCompliance = s.mercadoLivreCompliance || {};
    setSafeChecked('mlCompEnabled', !!mlCompliance.enabled);
    setSafeChecked('mlCompBlockAuto', mlCompliance.blockAutoFlows ?? true);
    setSafeChecked('mlCompRequireApproval', mlCompliance.requireManualApproval ?? true);
    setSafeChecked('mlCompWhitelistEnabled', !!mlCompliance.enforceChannelWhitelist);
    setSafeChecked('mlCompBlockUnknown', mlCompliance.blockWhenChannelUnknown ?? true);
    setSafeVal('mlCompAllowedChannels', (mlCompliance.allowedChannels || []).join('\n'));

    // Instagram Posts
    const insta = s.instagramPosts || {};
    setSafeChecked('instaEnabled', insta.enabled ?? true);
    setSafeChecked('instaAllowWhatsApp', insta.allowWhatsApp ?? true);
    setSafeChecked('instaAllowTelegramBot', !!insta.allowTelegramBot);
    setSafeChecked('instaAllowTelegramUserbot', !!insta.allowTelegramUserbot);
    setSafeChecked('instaWaPrivate', insta.whatsAppAllowPrivate ?? true);
    setSafeChecked('instaWaGroups', insta.whatsAppAllowGroups ?? false);
    setSafeVal('instaWaIds', (insta.whatsAppChatIds || []).join('\n'));
    setSafeChecked('instaTgPrivate', insta.telegramAllowPrivate ?? true);
    setSafeChecked('instaTgGroups', insta.telegramAllowGroups ?? true);
    setSafeVal('instaTgIds', (insta.telegramChatIds || []).join('\n'));
    
    if (document.getElementById('instaContextMode')) {
      let mode = 'Off';
      if (typeof insta.offerContextMode === 'number') {
        mode = insta.offerContextMode === 1 ? 'Suggestion' : insta.offerContextMode === 2 ? 'ExtraPost' : 'Off';
      } else if (typeof insta.offerContextMode === 'string') {
        mode = insta.offerContextMode;
      } else if (insta.useOfferContext) {
        mode = 'ExtraPost';
      }
      setSafeVal('instaContextMode', mode);
    }
    setSafeVal('instaTriggers', (insta.triggers || []).join('\n'));
    setSafeVal('instaFooter', insta.footerText || '');
    setSafeChecked('instaUseAi', !!insta.useAi);
    setSafeVal('instaPrompt', insta.promptTemplate || '');
    setSafeVal('instaPromptPreset', insta.promptPreset || 'premium');
    setSafeVal('instaVariations', insta.variationsCount ?? 2);
    setSafeUltraPrompt(insta);

    // AI Providers
    const openai = s.openAI || {};
    setSafeVal('openaiApiKey', openai.apiKey ? '********' : '');
    setSafeVal('openaiApiKeys', Array.isArray(openai.apiKeys) ? openai.apiKeys.join('\n') : '');
    setSafeVal('openaiModel', openai.model || 'gpt-4o-mini');
    setSafeVal('openaiTemp', openai.temperature ?? 0.7);
    setSafeVal('openaiMaxTokens', openai.maxOutputTokens ?? 700);

    const gemini = s.gemini || {};
    const gemKeys = Array.isArray(gemini.apiKeys) ? gemini.apiKeys : (gemini.apiKey ? ['********'] : ['']);
    renderGeminiApiKeyRows(gemKeys);
    setSafeVal('geminiModel', gemini.model || 'gemini-2.5-flash');
    setSafeVal('geminiMaxTokens', gemini.maxOutputTokens ?? 1200);

    const deepseek = s.deepSeek || {};
    setSafeVal('deepseekApiKey', deepseek.apiKey ? '********' : '');
    setSafeVal('deepseekApiKeys', Array.isArray(deepseek.apiKeys) ? deepseek.apiKeys.join('\n') : '');
    setSafeVal('deepseekModel', deepseek.model || 'deepseek-chat');
    setSafeVal('deepseekTemp', deepseek.temperature ?? 0.7);
    setSafeVal('deepseekMaxTokens', deepseek.maxOutputTokens ?? 1200);

    const nemotron = s.nemotron || {};
    setSafeVal('nemotronApiKey', nemotron.apiKey ? '********' : '');
    setSafeVal('nemotronApiKeys', Array.isArray(nemotron.apiKeys) ? nemotron.apiKeys.join('\n') : '');
    setSafeVal('nemotronModel', nemotron.model || 'nvidia/nemotron-3-super-120b-a12b');
    setSafeVal('nemotronTemp', nemotron.temperature ?? 1.0);
    setSafeVal('nemotronTopP', nemotron.topP ?? 0.95);
    setSafeVal('nemotronMaxTokens', nemotron.maxOutputTokens ?? 4096);
    setSafeVal('nemotronReasoningBudget', nemotron.reasoningBudget ?? 4096);
    setSafeChecked('nemotronEnableThinking', nemotron.enableThinking ?? true);
    setSafeVal('nemotronMonthlyLimit', nemotron.monthlyCallLimit ?? 0);
    setSafeVal('nemotronCostPerCall', nemotron.estimatedCostPerCallUsd ?? 0);

    const qwen = s.qwen || {};
    setSafeVal('qwenApiKey', qwen.apiKey ? '********' : '');
    setSafeVal('qwenApiKeys', Array.isArray(qwen.apiKeys) ? qwen.apiKeys.join('\n') : '');
    setSafeVal('qwenModel', qwen.model || 'qwen3.5-plus');
    setSafeVal('qwenVisionModel', qwen.visionModel || 'qwen3-vl-plus');
    setSafeVal('qwenTemp', qwen.temperature ?? 0.7);
    setSafeVal('qwenMaxTokens', qwen.maxOutputTokens ?? 4096);
    setSafeVal('qwenBaseUrl', qwen.baseUrl || 'https://dashscope-intl.aliyuncs.com/compatible-mode/v1');
    setSafeChecked('qwenEnableThinking', qwen.enableThinking ?? true);
    setSafeVal('qwenMonthlyLimit', qwen.monthlyCallLimit ?? 0);
    setSafeVal('qwenCostPerCall', qwen.estimatedCostPerCallUsd ?? 0);

    const vila = s.vilaNvidia || {};
    setSafeVal('vilaApiKey', vila.apiKey ? '********' : '');
    setSafeVal('vilaApiKeys', Array.isArray(vila.apiKeys) ? vila.apiKeys.join('\n') : '');
    setSafeVal('vilaModel', vila.model || 'nvidia/vila');
    setSafeVal('vilaTemp', vila.temperature ?? 0.2);
    setSafeVal('vilaTopP', vila.topP ?? 0.7);
    setSafeVal('vilaMaxTokens', vila.maxOutputTokens ?? 4096);
    setSafeVal('vilaBaseUrl', vila.baseUrl || 'https://integrate.api.nvidia.com/v1');
    setSafeChecked('vilaEnableThinking', vila.enableThinking ?? true);
    setSafeVal('vilaMonthlyLimit', vila.monthlyCallLimit ?? 0);
    setSafeVal('vilaCostPerCall', vila.estimatedCostPerCallUsd ?? 0);

    // Instagram Publish & Story
    const pub = s.instagramPublish || {};
    setSafeVal('igPubToken', pub.accessToken || '');
    setSafeVal('igPubUserId', pub.userId || '');
    setSafeVal('igPubBaseUrl', pub.baseUrl || '');
    setSafeVal('igPubVerifyToken', pub.verifyToken || '');
    setSafeChecked('igPubAutoPilotEnabled', !!pub.autoPilotEnabled);
    setSafeVal('igPubAutoPilotWhatsAppInstance', pub.autoPilotWhatsAppInstance || '');

    const story = s.instagramStory || {};
    setSafeVal('igStoryToken', story.accessToken || '');
    setSafeVal('igStoryUserId', story.userId || '');
    setSafeVal('igStoryApprovalWhatsAppInstance', story.approvalWhatsAppInstance || '');
    setSafeVal('igStoryApprovalWhatsAppGroupId', story.approvalWhatsAppGroupId || '');
    setSafeChecked('igStoryEnabled', !!story.enabled);

    // WA Monitoring
    const monitoredIds = s.monitoredGroupIds || [];
    renderMonitorGroups(null, monitoredIds);

    // Final UI
    setSafeText('debug', JSON.stringify(s, null, 2));
    setSafeText('statStatus', 'Online');
    refreshBioLinksPreview();
  } catch (err) {
    console.warn('Erro ao renderizar configuracoes, ignorando crash:', err);
  }
}

function setSafeUltraPrompt(insta) {
  setSafeChecked('instaUltraPrompt', !!insta.useUltraPrompt);
  setSafeChecked('instaShortName', !!insta.useShortProductName);
  setSafeChecked('instaBenefits', !!insta.useBenefitBullets);
  setSafeChecked('instaImageDownload', !!insta.useImageDownload);
  
  const captionTemplates = Array.isArray(insta.captionTemplates) && insta.captionTemplates.length > 0
    ? insta.captionTemplates
    : getDefaultInstaCaptionTemplates();
  
  setSafeVal('instaCaptionTemplate1', captionTemplates[0] || '');
  setSafeVal('instaCaptionTemplate2', captionTemplates[1] || '');
  setSafeVal('instaCaptionTemplate3', captionTemplates[2] || '');
}

async function loadSettings() {
  const s = await api('/api/settings');
  renderSettings(s);
  window.__settingsCache = s;
  await Promise.all([
    loadWaInstances(),
    loadUserbotChats(),
    loadWhatsAppGroups(s),
    hydrateAgentUiState(),
    loadConversionLogs(),
    loadMediaFailures(),
    loadOperationalOverview()
  ]);
  restoreAgentUiState();
  renderTelegramToWhatsAppRoute();
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
  const renderLinkList = (urls) => {
    if (!urls || urls.length === 0) return '-';
    return urls.map((u) => {
      const href = String(u || '').trim();
      if (!href) return '';
      const safe = escapeHtml(href);
      return `<a href="${safe}" target="_blank" rel="noopener noreferrer">${safe}</a>`;
    }).filter(Boolean).join('<br>');
  };

  if (!items || items.length === 0) {
    tbody.innerHTML = '<tr><td colspan="7" class="muted">Sem pend?ncias.</td></tr>';
    if (count) count.textContent = '0 item(s)';
    return;
  }

  if (count) count.textContent = `${items.length} item(ns)`;
  tbody.innerHTML = items.map(item => {
    const status = String(item.status || '').toLowerCase();
    const badgeClass = status === 'pending' ? 'warn' : (status === 'approved' ? 'ok' : 'bad');
    const originalUrls = (item.extractedUrls || []);
    const convertedPreviewUrls = (item.previewConvertedUrls || []);
    const originalLinksHtml = renderLinkList(originalUrls);
    const convertedLinksHtml = renderLinkList(convertedPreviewUrls);
    const originalImageUrl = String(item.originalImageUrl || '').trim();
    const originalImageHtml = originalImageUrl
      ? `<div style="margin-top:6px;">
          <small><strong>Imagem original:</strong><br><a href="${escapeHtml(originalImageUrl)}" target="_blank" rel="noopener noreferrer">abrir imagem</a></small>
        </div>`
      : '';
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
        <td>
          <div><small><strong>Original:</strong><br>${originalLinksHtml}</small></div>
          <div style="margin-top:6px;"><small><strong>Convertido (pr?via):</strong><br>${convertedLinksHtml}</small></div>
          ${originalImageHtml}
          ${status === 'pending' ? `<div style="margin-top:6px;">
            <small><strong>Link corrigido:</strong></small>
            <input id="mlOverride_${item.id}" placeholder="https://..." style="width:100%;margin-top:4px;" />
          </div>` : ''}
        </td>
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
  const note = prompt('Observa??o de aprova??o (opcional):', '') || '';
  const overrideUrl = (document.getElementById(`mlOverride_${id}`)?.value || '').trim();
  if (!overrideUrl) {
    alert('Informe o link corrigido antes de aprovar.');
    return;
  }
  if (!/^https?:\/\//i.test(overrideUrl)) {
    alert('Link corrigido inv?lido. Use URL completa com http(s).');
    return;
  }
  const sendNow = confirm('Enviar o texto aprovado para o(s) destino(s) agora?');
  try {
    const result = await api(`/api/mercadolivre/pending/${id}/approve`, 'POST', { note, sendNow, overrideUrl: overrideUrl || null });
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
    alert(e?.data?.error || e?.message || 'Erro ao aprovar pend?ncia.');
  }
}
async function rejectMercadoLivrePending(id) {
  if (currentRole !== 'admin') return;
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
  existing.telegramForwarding.preferLinkPreviewWhenNoMedia = document.getElementById('userbotPreferLinkPreviewNoMedia')?.checked ?? true;
  existing.telegramForwarding.footerText = document.getElementById('userbotFooter').value || '';
  existing.whatsAppForwarding = existing.whatsAppForwarding || {};
  existing.whatsAppForwarding.enabled = document.getElementById('waForwardEnabled').checked;
  existing.whatsAppForwarding.processFromMeOnly = document.getElementById('waFromMeOnly').checked;
  existing.whatsAppForwarding.footerText = document.getElementById('waFooter').value || '';
  existing.whatsAppForwarding.appendSheinCode = document.getElementById('waAppendShein').checked;
  existing.whatsAppForwarding.preferLinkPreviewWhenNoMedia = document.getElementById('waPreferLinkPreviewNoMedia')?.checked ?? true;
  const waSendMedia = document.getElementById('waSendMedia');
  if (waSendMedia) existing.whatsAppForwarding.sendMediaEnabled = waSendMedia.checked;

  const selected = Array.from(document.querySelectorAll("input[data-userbot-chat=\"1\"]:checked"))
    .map(el => Number(el.value));
  const manual = parseManualIds();
  const merged = Array.from(new Set([...selected, ...manual]));
  existing.telegramForwarding.sourceChatIds = merged;

  const status = document.getElementById('saveStatus');
  try {
    await api('/api/settings', 'PUT', existing);
    if (status) {
      status.textContent = 'Configurações salvas.';
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

  try {
    await api('/api/settings', 'PUT', existing);
    if (status) {
      status.textContent = 'Rota salva.';
      status.className = 'status ok';
    }
    await loadSettings();
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
  existing.linkResponder.welcomeEnabled = document.getElementById('responderWelcomeEnabled')?.checked ?? true;
  existing.linkResponder.welcomeMessage = document.getElementById('responderWelcomeMessage')?.value || '';
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
  existing.instagramPosts.aiProvider = document.getElementById('instaAiProvider')?.value || 'nemotron';
  existing.instagramPosts.triggers = parseLines('instaTriggers');
  existing.instagramPosts.footerText = document.getElementById('instaFooter')?.value || '';
  existing.instagramPosts.promptTemplate = document.getElementById('instaPrompt')?.value || '';
  const defaultCaptionTemplates = getDefaultInstaCaptionTemplates();
  existing.instagramPosts.captionTemplates = [
    (document.getElementById('instaCaptionTemplate1')?.value || defaultCaptionTemplates[0]).trim(),
    (document.getElementById('instaCaptionTemplate2')?.value || defaultCaptionTemplates[1]).trim(),
    (document.getElementById('instaCaptionTemplate3')?.value || defaultCaptionTemplates[2]).trim()
  ];

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

async function saveAiLabSettings() {
  if (currentRole !== 'admin') return;
  const status = document.getElementById('aiLabStatus');
  if (status) {
    status.textContent = 'Salvando...';
    status.className = 'status warn';
  }

  try {
    const existing = await api('/api/settings');
    existing.openAI = existing.openAI || {};
    existing.openAI.apiKey = document.getElementById('openaiApiKey')?.value || '';
    existing.openAI.apiKeys = parseApiKeysTextarea('openaiApiKeys', existing.openAI.apiKey === '********' ? '********' : '');
    existing.openAI.model = document.getElementById('openaiModel')?.value || 'gpt-4o-mini';
    existing.openAI.temperature = parseFloat(document.getElementById('openaiTemp')?.value || '0.7');
    existing.openAI.maxOutputTokens = parseInt(document.getElementById('openaiMaxTokens')?.value || '700', 10);

    existing.gemini = existing.gemini || {};
    const geminiKeys = collectGeminiApiKeysFromUi();
    existing.gemini.apiKey = geminiKeys[0] || '';
    existing.gemini.apiKeys = geminiKeys;
    existing.gemini.model = document.getElementById('geminiModel')?.value || 'gemini-2.5-flash';
    existing.gemini.maxOutputTokens = parseInt(document.getElementById('geminiMaxTokens')?.value || '1200', 10);

    existing.deepSeek = existing.deepSeek || {};
    existing.deepSeek.apiKey = document.getElementById('deepseekApiKey')?.value || '';
    existing.deepSeek.apiKeys = parseApiKeysTextarea('deepseekApiKeys', existing.deepSeek.apiKey === '********' ? '********' : '');
    existing.deepSeek.model = document.getElementById('deepseekModel')?.value || 'deepseek-chat';
    existing.deepSeek.temperature = parseFloat(document.getElementById('deepseekTemp')?.value || '0.7');
    existing.deepSeek.maxOutputTokens = parseInt(document.getElementById('deepseekMaxTokens')?.value || '1200', 10);

    existing.nemotron = existing.nemotron || {};
    existing.nemotron.apiKey = document.getElementById('nemotronApiKey')?.value || '';
    existing.nemotron.apiKeys = parseApiKeysTextarea('nemotronApiKeys', existing.nemotron.apiKey === '********' ? '********' : '');
    existing.nemotron.model = document.getElementById('nemotronModel')?.value || 'nvidia/nemotron-3-super-120b-a12b';
    existing.nemotron.temperature = parseFloat(document.getElementById('nemotronTemp')?.value || '1');
    existing.nemotron.topP = parseFloat(document.getElementById('nemotronTopP')?.value || '0.95');
    existing.nemotron.maxOutputTokens = parseInt(document.getElementById('nemotronMaxTokens')?.value || '4096', 10);
    existing.nemotron.reasoningBudget = parseInt(document.getElementById('nemotronReasoningBudget')?.value || '4096', 10);
    existing.nemotron.enableThinking = document.getElementById('nemotronEnableThinking')?.checked ?? true;
    existing.nemotron.monthlyCallLimit = parseInt(document.getElementById('nemotronMonthlyLimit')?.value || '0', 10);
    existing.nemotron.estimatedCostPerCallUsd = parseFloat(document.getElementById('nemotronCostPerCall')?.value || '0');
    existing.qwen = existing.qwen || {};
    existing.qwen.apiKey = document.getElementById('qwenApiKey')?.value || '';
    existing.qwen.apiKeys = parseApiKeysTextarea('qwenApiKeys', existing.qwen.apiKey === '********' ? '********' : '');
    existing.qwen.model = document.getElementById('qwenModel')?.value || 'qwen3.5-plus';
    existing.qwen.visionModel = document.getElementById('qwenVisionModel')?.value || 'qwen3-vl-plus';
    existing.qwen.temperature = parseFloat(document.getElementById('qwenTemp')?.value || '0.7');
    existing.qwen.maxOutputTokens = parseInt(document.getElementById('qwenMaxTokens')?.value || '4096', 10);
    existing.qwen.baseUrl = document.getElementById('qwenBaseUrl')?.value || 'https://dashscope-intl.aliyuncs.com/compatible-mode/v1';
    existing.qwen.enableThinking = document.getElementById('qwenEnableThinking')?.checked ?? true;
    existing.qwen.monthlyCallLimit = parseInt(document.getElementById('qwenMonthlyLimit')?.value || '0', 10);
    existing.qwen.estimatedCostPerCallUsd = parseFloat(document.getElementById('qwenCostPerCall')?.value || '0');
    existing.vilaNvidia = existing.vilaNvidia || {};
    existing.vilaNvidia.apiKey = document.getElementById('vilaApiKey')?.value || '';
    existing.vilaNvidia.apiKeys = parseApiKeysTextarea('vilaApiKeys', existing.vilaNvidia.apiKey === '********' ? '********' : '');
    existing.vilaNvidia.model = document.getElementById('vilaModel')?.value || 'nvidia/vila';
    existing.vilaNvidia.temperature = parseFloat(document.getElementById('vilaTemp')?.value || '0.2');
    existing.vilaNvidia.topP = parseFloat(document.getElementById('vilaTopP')?.value || '0.7');
    existing.vilaNvidia.maxOutputTokens = parseInt(document.getElementById('vilaMaxTokens')?.value || '4096', 10);
    existing.vilaNvidia.baseUrl = document.getElementById('vilaBaseUrl')?.value || 'https://integrate.api.nvidia.com/v1';
    existing.vilaNvidia.enableThinking = document.getElementById('vilaEnableThinking')?.checked ?? true;
    existing.vilaNvidia.monthlyCallLimit = parseInt(document.getElementById('vilaMonthlyLimit')?.value || '0', 10);
    existing.vilaNvidia.estimatedCostPerCallUsd = parseFloat(document.getElementById('vilaCostPerCall')?.value || '0');

    await api('/api/settings', 'PUT', existing);
    if (status) {
      status.textContent = 'IA Lab salvo.';
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

async function runAiLabCompare() {
  const status = document.getElementById('aiLabStatus');
  const results = document.getElementById('aiLabResults');
  const providers = [
    document.getElementById('aiLabProviderOpenAi')?.checked ? 'openai' : null,
    document.getElementById('aiLabProviderGemini')?.checked ? 'gemini' : null,
    document.getElementById('aiLabProviderDeepSeek')?.checked ? 'deepseek' : null,
    document.getElementById('aiLabProviderNemotron')?.checked ? 'nemotron' : null,
    document.getElementById('aiLabProviderQwen')?.checked ? 'qwen' : null,
    document.getElementById('aiLabProviderVila')?.checked ? 'vila' : null
  ].filter(Boolean);

  if (providers.length === 0) {
    if (status) {
      status.textContent = 'Selecione ao menos uma IA.';
      status.className = 'status bad';
    }
    return;
  }

  if (results) results.innerHTML = '<div class="muted">Comparando IAs...</div>';
  if (status) {
    status.textContent = 'Executando comparacao...';
    status.className = 'status warn';
  }

  try {
    const data = await api('/api/ai-lab/compare', 'POST', {
      input: document.getElementById('aiLabInput')?.value || '',
      context: document.getElementById('aiLabContext')?.value || '',
      mode: document.getElementById('aiLabMode')?.value || 'raw',
      providers
    });

    if (results) {
      results.innerHTML = (data.results || []).map(item => `
        <section class="card">
          <h3>${escapeHtml(String(item.provider || '').toUpperCase())}</h3>
          <div class="muted">Modo: ${escapeHtml(String(item.mode || 'raw'))} | Latencia: ${escapeHtml(String(item.durationMs || 0))} ms</div>
          <pre style="white-space:pre-wrap; word-break:break-word; margin-top:12px;">${escapeHtml(item.text || 'Sem resposta.')}</pre>
        </section>
      `).join('');
    }

    if (status) {
      status.textContent = 'Comparacao concluida.';
      status.className = 'status ok';
    }
  } catch (e) {
    if (results) results.innerHTML = '';
    if (status) {
      status.textContent = `Erro: ${e?.data?.error || e.message || 'Falha ao comparar'}`;
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

function renderMercadoLivrePending(items) {
  const tbody = document.getElementById('mlPendingBody');
  const count = document.getElementById('mlPendingCount');
  if (!tbody) return;
  const renderLinkList = (urls) => {
    if (!urls || urls.length === 0) return '-';
    return urls.map((u) => {
      const href = String(u || '').trim();
      if (!href) return '';
      const safe = escapeHtml(href);
      return `<a href="${safe}" target="_blank" rel="noopener noreferrer">${safe}</a>`;
    }).filter(Boolean).join('<br>');
  };

  if (!items || items.length === 0) {
    tbody.innerHTML = '<tr><td colspan="7" class="muted">Sem pendências.</td></tr>';
    if (count) count.textContent = '0 item(s)';
    return;
  }

  if (count) count.textContent = `${items.length} item(ns)`;
  tbody.innerHTML = items.map(item => {
    const status = String(item.status || '').toLowerCase();
    const badgeClass = status === 'pending' ? 'warn' : (status === 'approved' ? 'ok' : 'bad');
    const originalUrls = (item.extractedUrls || []);
    const convertedPreviewUrls = (item.previewConvertedUrls || []);
    const originalLinksHtml = renderLinkList(originalUrls);
    const convertedLinksHtml = renderLinkList(convertedPreviewUrls);
    const originalImageUrl = String(item.originalImageUrl || '').trim();
    const originalImageHtml = originalImageUrl
      ? `<div style="margin-top:6px;">
          <small><strong>Imagem original:</strong><br><a href="${escapeHtml(originalImageUrl)}" target="_blank" rel="noopener noreferrer">abrir imagem</a></small>
        </div>`
      : '';
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
        <td>
          <div><small><strong>Original:</strong><br>${originalLinksHtml}</small></div>
          <div style="margin-top:6px;"><small><strong>Convertido (prévia):</strong><br>${convertedLinksHtml}</small></div>
          ${originalImageHtml}
          ${status === 'pending' ? `<div style="margin-top:6px;">
            <small><strong>Link corrigido:</strong></small>
            <input id="mlOverride_${item.id}" placeholder="https://..." style="width:100%;margin-top:4px;" />
          </div>` : ''}
        </td>
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
  const overrideUrl = (document.getElementById(`mlOverride_${id}`)?.value || '').trim();
  if (!overrideUrl) {
    alert('Informe o link corrigido antes de aprovar.');
    return;
  }
  if (!/^https?:\/\//i.test(overrideUrl)) {
    alert('Link corrigido inválido. Use URL completa com http(s).');
    return;
  }
  const sendNow = confirm('Enviar o texto aprovado para o(s) destino(s) agora?');
  try {
    const result = await api(`/api/mercadolivre/pending/${id}/approve`, 'POST', { note, sendNow, overrideUrl: overrideUrl || null });
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
  existing.telegramForwarding.preferLinkPreviewWhenNoMedia = document.getElementById('userbotPreferLinkPreviewNoMedia')?.checked ?? true;
  existing.telegramForwarding.footerText = document.getElementById('userbotFooter').value || '';
  existing.whatsAppForwarding = existing.whatsAppForwarding || {};
  existing.whatsAppForwarding.enabled = document.getElementById('waForwardEnabled').checked;
  existing.whatsAppForwarding.processFromMeOnly = document.getElementById('waFromMeOnly').checked;
  existing.whatsAppForwarding.footerText = document.getElementById('waFooter').value || '';
  existing.whatsAppForwarding.appendSheinCode = document.getElementById('waAppendShein').checked;
  existing.whatsAppForwarding.preferLinkPreviewWhenNoMedia = document.getElementById('waPreferLinkPreviewNoMedia')?.checked ?? true;
  const waSendMedia = document.getElementById('waSendMedia');
  if (waSendMedia) existing.whatsAppForwarding.sendMediaEnabled = waSendMedia.checked;

  const selected = Array.from(document.querySelectorAll("input[data-userbot-chat=\"1\"]:checked"))
    .map(el => Number(el.value));
  const manual = parseManualIds();
  const merged = Array.from(new Set([...selected, ...manual]));
  existing.telegramForwarding.sourceChatIds = merged;

  const status = document.getElementById('saveStatus');
  try {
    await api('/api/settings', 'PUT', existing);
    if (status) {
      status.textContent = 'Configurações salvas.';
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

  try {
    await api('/api/settings', 'PUT', existing);
    if (status) {
      status.textContent = 'Rota salva.';
      status.className = 'status ok';
    }
    await loadSettings();
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
  existing.linkResponder.welcomeEnabled = document.getElementById('responderWelcomeEnabled')?.checked ?? true;
  existing.linkResponder.welcomeMessage = document.getElementById('responderWelcomeMessage')?.value || '';
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
  existing.instagramPosts.aiProvider = document.getElementById('instaAiProvider')?.value || 'nemotron';
  existing.instagramPosts.triggers = parseLines('instaTriggers');
  existing.instagramPosts.footerText = document.getElementById('instaFooter')?.value || '';
  existing.instagramPosts.promptTemplate = document.getElementById('instaPrompt')?.value || '';
  const defaultCaptionTemplates = getDefaultInstaCaptionTemplates();
  existing.instagramPosts.captionTemplates = [
    (document.getElementById('instaCaptionTemplate1')?.value || defaultCaptionTemplates[0]).trim(),
    (document.getElementById('instaCaptionTemplate2')?.value || defaultCaptionTemplates[1]).trim(),
    (document.getElementById('instaCaptionTemplate3')?.value || defaultCaptionTemplates[2]).trim()
  ];

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

async function testInstagramPublishConnection() {
  const status = document.getElementById('igPubSaveStatus');
  if (currentRole !== 'admin') {
    if (status) {
      status.textContent = 'Apenas admins podem testar a conexão.';
      status.className = 'status bad';
    }
    return;
  }
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
      status.textContent = (e?.status === 403) ? 'Acesso negado (AdminOnly).' : (e?.data?.error || e?.message || 'Falha no teste.');
      status.className = 'status bad';
    }
  }
}

async function testInstagramStoryConnection() {
  const status = document.getElementById('igStoryStatus');
  if (currentRole !== 'admin') {
    if (status) {
      status.textContent = 'Apenas admins podem testar a conexão.';
      status.className = 'status bad';
    }
    return;
  }
  if (status) {
    status.textContent = 'Testando...';
    status.className = 'status warn';
  }
  try {
    await api('/api/instagram/story/test', 'POST', {});
    if (status) {
      status.textContent = 'Conexao OK.';
      status.className = 'status ok';
    }
  } catch (e) {
    if (status) {
      status.textContent = (e?.status === 403) ? 'Acesso negado (AdminOnly).' : (e?.data?.error || e?.message || 'Falha no teste.');
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
    const qrValue = getWhatsAppQrValue(r);
    if (qrValue) {
      showWhatsAppQr(qrValue, r.message || 'Escaneie com o WhatsApp para concluir a conexão.');
      document.getElementById('whatsappStatus').textContent = 'QR gerado. Aguardando leitura...';
      document.getElementById('whatsappStatus').className = 'status warn';
      startWhatsAppQrPolling(instanceName || '');
    } else if (r.success) {
      hideWhatsAppQr();
      stopWhatsAppQrPolling();
      document.getElementById('whatsappStatus').textContent = r.message || 'Instância já conectada.';
      document.getElementById('whatsappStatus').className = 'status ok';
    } else {
      hideWhatsAppQr();
      document.getElementById('whatsappStatus').textContent = `Erro: ${r.message || 'Falha ao gerar QR'}`;
      document.getElementById('whatsappStatus').className = 'status bad';
      startWhatsAppQrPolling(instanceName || '');
      await refreshWhatsAppQrSnapshot({ instanceName: instanceName || '', silent: true });
    }
  } catch (e) {
    hideWhatsAppQr();
    stopWhatsAppQrPolling();
    document.getElementById('whatsappStatus').textContent = `Erro: ${e.data?.error || e.message || 'Falha na requisição'}`;
    document.getElementById('whatsappStatus').className = 'status bad';
  }
  setButtonBusy('btnWhatsAppConnect', false);
  setTimeout(loadSettings, 4000);
}

async function testWhatsAppConnection() {
  setButtonBusy('btnWhatsAppTest', true, 'Testando...');
  try {
    const instanceName = document.getElementById('waInstanceName').value || null;
    const r = await api('/api/integrations/whatsapp/test', 'POST', { instanceName });
    const status = document.getElementById('whatsappStatus');
    const qrImage = document.getElementById('qrImage');
    const qrHint = document.getElementById('qrHint');
    if (qrImage) {
      qrImage.classList.add('hidden');
      qrImage.removeAttribute('src');
    }
    if (qrHint) {
      qrHint.classList.add('hidden');
    }
    if (status) {
      status.textContent = r.success
        ? (r.message || 'Instância conectada.')
        : `Falha: ${r.message || 'Instância desconectada'}`;
      status.className = 'status ' + (r.success ? 'ok' : 'bad');
    }
    if (r.success) {
      hideWhatsAppQr();
      stopWhatsAppQrPolling();
    } else {
      const snapshot = await refreshWhatsAppQrSnapshot({ instanceName: instanceName || '', silent: true });
      if (getWhatsAppQrValue(snapshot)) {
        startWhatsAppQrPolling(instanceName || '');
      } else {
        stopWhatsAppQrPolling();
      }
    }
  } catch (e) {
    const status = document.getElementById('whatsappStatus');
    if (status) {
      status.textContent = `Erro: ${e.data?.error || e.message || 'Falha na requisição'}`;
      status.className = 'status bad';
    }
  }
  setButtonBusy('btnWhatsAppTest', false);
  setTimeout(loadSettings, 3000);
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
    const qrValue = getWhatsAppQrValue(r);
    if (qrValue) {
      showWhatsAppQr(qrValue, r.message || 'Escaneie com o WhatsApp para concluir a conexão.');
      document.getElementById('whatsappStatus').textContent = r.message || 'Instância criada. QR gerado.';
      document.getElementById('whatsappStatus').className = 'status warn';
      startWhatsAppQrPolling(instanceName);
    } else if (r.success) {
      hideWhatsAppQr();
      stopWhatsAppQrPolling();
      document.getElementById('whatsappStatus').textContent = r.message || 'Instância criada com sucesso.';
      document.getElementById('whatsappStatus').className = 'status ok';
    } else {
      hideWhatsAppQr();
      document.getElementById('whatsappStatus').textContent = `Erro: ${r.message || 'Falha ao criar instância'}`;
      document.getElementById('whatsappStatus').className = 'status bad';
      startWhatsAppQrPolling(instanceName);
      await refreshWhatsAppQrSnapshot({ instanceName, silent: true });
    }
  } catch (e) {
    hideWhatsAppQr();
    stopWhatsAppQrPolling();
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
    setSafeText('connectionSummaryUserbot', 'Indisponível');
    setSafeText('connectionSummaryUserbotDetail', 'A sessão do userbot não respondeu.');
    setSafeText('opsSummaryUserbot', 'Indisponível');
    setSafeText('connectionUserbotBadge', 'Indisponível');
    setSafeClass('connectionUserbotBadge', 'badge bad');
    return;
  }

  status.textContent = payload.ready ? `Conectado (${payload.chats.length} chats)` : 'Conectando...';
  status.className = 'status ' + (payload.ready ? 'ok' : 'warn');
  setChipStatus('chipUserbot', payload.ready ? 'Telegram Userbot: Conectado' : 'Telegram Userbot: Conectando...', payload.ready ? 'ok' : 'warn');
  setHealthBadge('healthUserbot', payload.ready ? 'Userbot OK' : 'Userbot Conectando', payload.ready ? 'ok' : 'warn');
  const statUserbot = document.getElementById('statUserbot');
  if (statUserbot) statUserbot.textContent = payload.ready ? 'Online' : 'Conectando...';
  setSafeText('connectionSummaryUserbot', payload.ready ? 'Online' : 'Conectando');
  setSafeText('connectionSummaryUserbotDetail', payload.ready ? `${payload.chats.length} chats disponíveis para seleção.` : 'A sessão está em reconexão; aguarde antes de salvar mudanças.');
  setSafeText('opsSummaryUserbot', payload.ready ? 'Online' : 'Conectando');
  setSafeText('connectionUserbotBadge', payload.ready ? 'Conectado' : 'Reconectando');
  setSafeClass('connectionUserbotBadge', `badge ${payload.ready ? 'ok' : 'warn'}`);

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
  renderPillList('userbotSelectedChips', selected, 'Nenhum grupo selecionado.');
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
  existing.telegramForwarding.preferLinkPreviewWhenNoMedia = document.getElementById('userbotPreferLinkPreviewNoMedia')?.checked ?? true;
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
  renderTgWaReplayPanel();
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
    preferLinkPreviewWhenNoMedia: r?.preferLinkPreviewWhenNoMedia ?? true,
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
    preferLinkPreviewWhenNoMedia: legacy.preferLinkPreviewWhenNoMedia ?? true,
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
  route.preferLinkPreviewWhenNoMedia = document.getElementById('waPreferLinkPreviewNoMedia')?.checked ?? true;
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
  const waPreferLinkPreviewNoMedia = document.getElementById('waPreferLinkPreviewNoMedia');
  if (waPreferLinkPreviewNoMedia) waPreferLinkPreviewNoMedia.checked = route.preferLinkPreviewWhenNoMedia ?? true;
  const waFooter = document.getElementById('waFooter');
  if (waFooter) waFooter.value = route.footerText || '';
  const waInstanceName = document.getElementById('waInstanceName');
  if (waInstanceName) waInstanceName.value = route.instanceName || '';
  populateAllInstanceSelects(route.instanceName || '');
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
    preferLinkPreviewWhenNoMedia: document.getElementById('waPreferLinkPreviewNoMedia')?.checked ?? true,
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
  syncTgWaReplaySelection(route);
}

function getTgWaChatLabel(chatId) {
  const chats = window.__userbotPayload?.chats || [];
  const match = chats.find(c => String(c.id) === String(chatId));
  return match ? `${match.title} (${match.id})` : String(chatId);
}

function renderTgWaReplayPanel() {
  const route = getActiveTgWaRoute();
  const sourceSelect = document.getElementById('tgWaReplaySourceChat');
  const routeSummary = document.getElementById('tgWaReplayRouteSummary');
  const routeNameSummary = document.getElementById('tgWaRouteNameSummary');
  const sourceSummary = document.getElementById('tgWaSourceCountSummary');
  const destSummary = document.getElementById('tgWaDestCountSummary');
  const replaySummary = document.getElementById('tgWaReplaySummary');
  const allowOfficial = document.getElementById('tgWaReplayAllowOfficial');
  const chats = window.__userbotPayload?.chats || [];

  if (sourceSelect) {
    const currentValue = sourceSelect.value;
    const sourceIds = Array.from(new Set([
      ...(route?.sourceChatIds || []).map(String),
      ...chats.map(c => String(c.id))
    ]));
    sourceSelect.innerHTML = ['<option value="">Selecione um grupo do Telegram...</option>']
      .concat(sourceIds.map(id => `<option value="${id}">${getTgWaChatLabel(id)}</option>`))
      .join('');
    if (sourceIds.includes(currentValue)) {
      sourceSelect.value = currentValue;
    }
  }

  syncTgWaReplaySelection(route);

  if (routeSummary) {
    const sources = (route?.sourceChatIds || []).length;
    const destinations = (route?.destinationGroupIds || []).length;
    routeSummary.textContent = route
      ? `${route.name || 'Rota'} | ${sources} origem(ns) | ${destinations} destino(s)`
      : 'Rota nao carregada';
  }

  if (routeNameSummary) {
    routeNameSummary.textContent = route?.enabled ? (route?.name || 'Ativa') : 'Pausada';
  }

  if (sourceSummary) {
    sourceSummary.textContent = String((route?.sourceChatIds || []).length);
  }

  if (destSummary) {
    destSummary.textContent = String((route?.destinationGroupIds || []).length);
  }

  if (replaySummary) {
    replaySummary.textContent = route ? 'Disponível' : 'Indisponível';
  }

  if (allowOfficial && !allowOfficial.dataset.touched) {
    allowOfficial.checked = false;
  }
}

function syncTgWaReplaySelection(route = getActiveTgWaRoute()) {
  const sourceSelect = document.getElementById('tgWaReplaySourceChat');
  if (!sourceSelect) return;

  const routeSources = (route?.sourceChatIds || []).map(String);
  const currentValue = sourceSelect.value;
  if (routeSources.length > 0 && (!currentValue || !routeSources.includes(currentValue))) {
    sourceSelect.value = routeSources[0];
    return;
  }

  if (!currentValue && sourceSelect.options.length > 1) {
    sourceSelect.value = sourceSelect.options[1].value;
  }
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

async function runTelegramToWhatsAppReplay() {
  if (currentRole !== 'admin') return;

  const status = document.getElementById('tgWaReplayStatus');
  const resultEl = document.getElementById('tgWaReplayResult');
  const button = document.getElementById('btnTgWaReplay');
  const sourceChatId = Number(document.getElementById('tgWaReplaySourceChat')?.value || 0);
  const count = Number(document.getElementById('tgWaReplayCount')?.value || 1);
  const allowOfficialDestination = !!document.getElementById('tgWaReplayAllowOfficial')?.checked;

  if (!Number.isFinite(sourceChatId) || sourceChatId === 0) {
    if (status) {
      status.textContent = 'Selecione a origem do Telegram.';
      status.className = 'status bad';
    }
    return;
  }

  if (button) button.disabled = true;
  if (status) {
    status.textContent = 'Executando replay...';
    status.className = 'status warn';
  }
  if (resultEl) {
    resultEl.textContent = 'Buscando historico recente e reenviando para os destinos da rota ativa...';
    resultEl.className = 'muted';
  }

  try {
    const response = await api('/api/telegram/userbot/replay-to-whatsapp', 'POST', {
      sourceChatId,
      count,
      allowOfficialDestination
    });
    const sourceLabel = getTgWaChatLabel(sourceChatId);
    if (status) {
      status.textContent = response?.success ? 'Replay concluido.' : (response?.message || 'Replay finalizado com alerta.');
      status.className = response?.success ? 'status ok' : 'status warn';
    }
    if (resultEl) {
      resultEl.innerHTML = [
        `<strong>${sourceLabel}</strong>`,
        `Solicitadas: ${response?.requested ?? count}`,
        `Carregadas: ${response?.loaded ?? 0}`,
        `Enviadas: ${response?.replayed ?? 0}`,
        `Falhas: ${response?.failed ?? 0}`,
        `${response?.message || 'Execucao concluida.'}`
      ].join(' | ');
      resultEl.className = response?.success ? 'status ok' : 'status warn';
    }
    showToast(response?.message || `Replay executado para ${sourceLabel}.`, response?.success ? 'success' : 'error');
  } catch (e) {
    const message = e?.data?.message || e?.data?.error || e?.message || 'Falha ao executar replay.';
    if (status) {
      status.textContent = message;
      status.className = 'status bad';
    }
    if (resultEl) {
      resultEl.textContent = message;
      resultEl.className = 'status bad';
    }
    showToast(message, 'error');
  } finally {
    if (button) button.disabled = false;
  }
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
    renderPillList(config.selectedChipsId, baseSelected, 'Nenhum grupo selecionado.');
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
  if (destChips) renderPillList('waSelectedChips', destSelected, 'Nenhum grupo de destino selecionado.');
  if (sourceChips) renderPillList('waSourceSelectedChips', sourceSelected, 'Nenhum grupo de origem selecionado.');
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

let waFooterSaveTimer = null;
function setWhatsAppFooterSaveStatus(text, tone = 'muted') {
  const el = document.getElementById('waFooterSaveStatus');
  if (!el) return;
  el.textContent = text || '';
  el.className = `status ${tone}`;
}

function scheduleWhatsAppFooterSave() {
  if (currentRole !== 'admin') return;
  if (waFooterSaveTimer) clearTimeout(waFooterSaveTimer);
  setWhatsAppFooterSaveStatus('Alteracao pendente...', 'warn');
  waFooterSaveTimer = setTimeout(() => saveWhatsAppFooter(true), 900);
}

async function saveWhatsAppFooter(isAuto = false) {
  if (currentRole !== 'admin') {
    setWhatsAppFooterSaveStatus('Permissao insuficiente para salvar.', 'bad');
    return;
  }

  setWhatsAppFooterSaveStatus(isAuto ? 'Salvando rodape...' : 'Salvando rodape manualmente...', 'warn');

  try {
    await saveWhatsAppSelection();
    setWhatsAppFooterSaveStatus(isAuto ? 'Rodape salvo automaticamente.' : 'Rodape salvo com sucesso.', 'ok');
  } catch (e) {
    const err = e?.data?.errors ? e.data.errors.join(' | ') : (e?.data?.error || e?.message || 'Erro ao salvar.');
    setWhatsAppFooterSaveStatus(err, 'bad');
  }
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
    preferLinkPreviewWhenNoMedia: route.preferLinkPreviewWhenNoMedia ?? true,
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
  existing.whatsAppForwarding.preferLinkPreviewWhenNoMedia = firstRoute ? (firstRoute.preferLinkPreviewWhenNoMedia ?? true) : true;
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

async function loadWhatsAppGroups(settingsOverride = null) {
  try {
    const instanceName = document.getElementById('waInstanceName').value || null;
    const settingsPromise = settingsOverride
      ? Promise.resolve(settingsOverride)
      : (window.__settingsCache ? Promise.resolve(window.__settingsCache) : api('/api/settings'));
    const [groupsResult, settings] = await Promise.all([
      api('/api/admin/whatsapp/groups' + (instanceName ? ('?instanceName=' + encodeURIComponent(instanceName)) : '')),
      settingsPromise
    ]);
    const payload = Array.isArray(groupsResult) ? { groups: groupsResult } : groupsResult;
    window.__settingsCache = settings;
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
    const conversionLogSummary = document.getElementById('conversionLogSummary');
    const conversionQualitySummary = document.getElementById('conversionQualitySummary');
    const conversionActionSummary = document.getElementById('conversionActionSummary');
    if (conversionLogSummary) conversionLogSummary.textContent = String(items.length);
    if (conversionQualitySummary) conversionQualitySummary.textContent = invalid.length > 0 ? `${invalid.length} inválidos` : 'OK';
    if (conversionActionSummary) conversionActionSummary.textContent = corrected.length > 0 ? `${corrected.length} corrigidos` : 'Em dia';
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
    const mediaLogSummary = document.getElementById('mediaLogSummary');
    const mediaAlertSummary = document.getElementById('mediaAlertSummary');
    if (mediaLogSummary) mediaLogSummary.textContent = items.length > 0 ? String(items.length) : '0';
    if (mediaAlertSummary) mediaAlertSummary.textContent = items.length > 0 ? 'Falhas recentes disponíveis' : 'Sem falhas recentes';
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

async function loadAnalyticsSummary() {
  const container = document.getElementById('analyticsSummaryCards');
  const hours = document.getElementById('analyticsHours')?.value || '24';

  if (container) container.innerHTML = '<div class="muted">Carregando...</div>';
  
  try {
    const data = await api(`/api/analytics/summary?hours=${encodeURIComponent(hours)}`);
    renderAnalyticsSummary(data);
  } catch (e) {
    if (container) container.innerHTML = `<div class="bad">Erro ao carregar analytics: ${e.message || 'Erro deconhecido'}</div>`;
  }
}

function showAnalyticsSubtab(name) {
  ['overview', 'behavior', 'recent'].forEach(tabName => {
    document.getElementById(`analyticsSubtab-${tabName}`)?.classList.toggle('hidden', tabName !== name);
    document.getElementById(`analyticsTab-${tabName}`)?.classList.toggle('active', tabName === name);
  });
}

function renderAnalyticsSummary(data) {
  const container = document.getElementById('analyticsSummaryCards');
  const identity = document.getElementById('analyticsIdentityCards');
  const recentBody = document.getElementById('analyticsRecentBody');
  const src = document.getElementById('analyticsSources');
  const cmp = document.getElementById('analyticsCampaigns');
  const evt = document.getElementById('analyticsEventTypes');
  const pages = document.getElementById('analyticsPageTypes');
  const devices = document.getElementById('analyticsDevices');
  const browsers = document.getElementById('analyticsBrowsers');
  const hours = document.getElementById('analyticsHours')?.value || '24';
  const hoursLabel = Number.parseInt(hours, 10) >= 24 && Number.parseInt(hours, 10) % 24 === 0
    ? `${Number.parseInt(hours, 10) / 24} dia(s)`
    : `${hours}h`;

  const categorized = Array.isArray(data.categorized)
    ? data.categorized.reduce((acc, item) => {
        const key = item?.category || item?.Category || 'default';
        acc[key] = item?.total || item?.Total || 0;
        return acc;
      }, {})
    : (data.categorized || {});

  const categories = [
    { key: 'bio', label: 'Bio Hub', iconHtml: '&#128279;' },
    { key: 'catalog', label: 'Catalogo', iconHtml: '&#128717;&#65039;' },
    { key: 'converter', label: 'Conversor', iconHtml: '&#128260;' },
    { key: 'total', label: 'Total Geral', iconHtml: '&#128202;' }
  ];

  const identityCards = [
    { label: 'Visitantes Unicos', value: data.uniqueVisitors || 0, hint: `IDs anonimos em ${hoursLabel}` },
    { label: 'Sessoes Unicas', value: data.uniqueSessions || 0, hint: `visitas separadas por sessao em ${hoursLabel}` }
  ];

  const formatBreakdown = (items) => {
    const list = Array.isArray(items) ? items : [];
    if (list.length === 0) return 'Sem dados.';
    return list.map(x => `${x.key}: ${x.count}`).join('\n');
  };

  if (container) {
    container.innerHTML = categories.map(cat => {
      const val = (cat.key === 'total') ? data.totalClicks : (categorized[cat.key] || 0);
      return `
        <div class="card analytics-card">
          <div style="font-size:24px; margin-bottom:8px;">${cat.iconHtml}</div>
          <div class="eyebrow">${cat.label}</div>
          <div class="metric">${val}</div>
          <div class="hint">eventos em ${hoursLabel}</div>
        </div>
      `;
    }).join('');
  }

  if (identity) {
    identity.innerHTML = identityCards.map(card => `
      <div class="card analytics-card">
        <div class="eyebrow">${card.label}</div>
        <div class="metric">${card.value}</div>
        <div class="hint">${card.hint}</div>
      </div>
    `).join('');
  }

  if (src) src.textContent = formatBreakdown(data.topSources);
  if (cmp) cmp.textContent = formatBreakdown(data.topCampaigns);
  if (evt) evt.textContent = formatBreakdown(data.topEventTypes);
  if (pages) pages.textContent = formatBreakdown(data.topPageTypes);
  if (devices) devices.textContent = formatBreakdown(data.topDevices);
  if (browsers) browsers.textContent = formatBreakdown(data.topBrowsers);

  // Stats de conversão
  const conv = data.summary?.conversions || {};
  const convStats = document.getElementById('analyticsConversionStats');
  if (convStats) {
      convStats.innerHTML = `
          <div class="metric">${conv.success || 0} / ${conv.total || 0}</div>
          <div class="muted">Sucesso: ${conv.successRate || 0}% | Latência: ${conv.avgElapsedMs || 0}ms</div>
      `;
  }

  // Stats de IA
  const ai = data.summary?.instagramAi || {};
  const aiStats = document.getElementById('analyticsAiStats');
  if (aiStats) {
      aiStats.innerHTML = `
          <div class="metric">${ai.success || 0} / ${ai.total || 0}</div>
          <div class="muted">Sucesso: ${ai.successRate || 0}% | Latência: ${ai.avgLatencyMs || 0}ms</div>
      `;
  }

  if (recentBody) {
    const items = data.recentItems || [];
    if (items.length === 0) {
      recentBody.innerHTML = '<tr><td colspan="5" class="muted">Nenhum clique recente.</td></tr>';
    } else {
      recentBody.innerHTML = items.map(i => `
        <tr>
          <td>${formatTs(i.timestamp)}</td>
          <td><span class="badge muted">${escapeHtml(i.category || 'default')}</span></td>
          <td>${escapeHtml(i.eventType || '-')}</td>
          <td>${escapeHtml(i.source || '-')}</td>
          <td title="${escapeHtml(i.targetUrl)}">${escapeHtml((i.targetUrl || '').substring(0, 60))}${(i.targetUrl || '').length > 60 ? '...' : ''}</td>
        </tr>
      `).join('');
    }
  }

  // Também carrega as ofertas em alta
  loadHotDeals(hours);
}

async function loadHotDeals(hours = 24) {
    const container = document.getElementById('analyticsHotDeals');
    if (!container) return;
    
    try {
        const res = await api(`/api/analytics/hot-deals?hours=${hours}&limit=6`);
        const deals = res.deals || [];
        
        if (deals.length === 0) {
            container.innerHTML = '<div class="muted">Nenhuma oferta em alta no momento.</div>';
            return;
        }

        container.innerHTML = deals.map(d => `
            <div class="card analytics-hot-card">
                <div class="analytics-hot-media">
                    <img src="${d.imageUrl || 'img/placeholder.png'}" style="width:100%; height:100%; object-fit:cover;" onerror="this.src='img/placeholder.png'">
                </div>
                <div class="analytics-hot-title">${escapeHtml(d.productName)}</div>
                <div class="analytics-hot-meta">
                    <div class="analytics-hot-price">${d.price || 'Consultar'}</div>
                    <div class="badge ok" style="font-size: 10px;">${d.viewCount || 0} ??</div>
                </div>
                <div class="muted" style="font-size: 11px;">Loja: ${escapeHtml(d.store || 'Geral')}</div>
                <a href="${d.affiliateUrl}" target="_blank" class="secondary analytics-link">Ver Oferta</a>
            </div>
        `).join('');
    } catch (e) {
        container.innerHTML = `<div class="bad">Erro ao carregar hot deals: ${e.message}</div>`;
    }
}

loadTheme();
setEnvironmentBadge(null);
checkSession();

function bindLoginShortcuts() {
  const username = document.getElementById('username');
  const password = document.getElementById('password');
  if (username && !username.dataset.loginBound) {
    username.dataset.loginBound = '1';
    username.addEventListener('keydown', (event) => {
      if (event.key === 'Enter') {
        event.preventDefault();
        login();
      }
    });
  }
  if (password && !password.dataset.loginBound) {
    password.dataset.loginBound = '1';
    password.addEventListener('keydown', (event) => {
      if (event.key === 'Enter') {
        event.preventDefault();
        login();
      }
    });
  }
}

bindLoginShortcuts();
// --- Contextual Help & Toasts (Fase 2) ---
const sectionGuides = {
  'connections': `
    <h3>Conexões e Integrações</h3>
    <ul>
      <li><strong>Telegram:</strong> Insira o Token do Bot API para envio de imagens. O Userbot é usado para "ouvir" grupos usando seu próprio número.</li>
      <li><strong>WhatsApp:</strong> Usamos a Evolution API. Defina um nome de instância e escaneie o QRCode gerado na tela.</li>
      <li><strong>Mercado Livre:</strong> A autenticação é feita via backend. Teste a conexão para garantir que os links estão sendo encurtados com seu afiliado.</li>
    </ul>`,
  'ops': `
    <h3>Operações e Saúde</h3>
    <ul>
      <li><strong>Telegram Userbot:</strong> Repassa ofertas de canais originais do Telegram para os seus canais do Telegram.</li>
      <li><strong>WhatsApp Origem/Destino:</strong> Defina quais grupos do WhatsApp o bot deve observar (escutar), e para onde deve copiar (rotear).</li>
    </ul>`,
  'route': `
    <h3>Rota Telegram -> WhatsApp</h3>
    <ul>
      <li><strong>Propósito:</strong> Capture ofertas silenciosamente em canais VIP do Telegram, e repasse-as automaticamente convertidas para seus Grupos de Oferta do WhatsApp.</li>
    </ul>`,
  'linkresponder': `
    <h3>Resposta de Links (Auto-Responder)</h3>
    <ul>
      <li>Quando alguém te manda uma DM com um link da Amazon, Shopee, ou Mercado Livre, o bot responde automaticamente com seu link de afiliado por cima!</li>
    </ul>`,
  'mercadolivre': `
    <h3>Compliance Mercado Livre</h3>
    <ul>
      <li>Bloqueia links indesejados e previne que o algoritmo do ML suspenda sua conta de afiliado exigindo aprovações manuais ou baseadas em Whitelist.</li>
    </ul>`,
  'instagram': `
    <h3>Instagram Prompts e IA</h3>
    <ul>
      <li>Defina como o conteúdo do post será montado pelo ChatGPT ou Gemini.</li>
      <li>Templates prontos podem ser escolhidos na caixa de seleção. Lembre-se de definir a chave (sk-...) da API.</li>
    </ul>`,
  'agents': `
    <h3>Agentes de IA</h3>
    <ul>
      <li><strong>Curador de ofertas:</strong> avalia drafts, catalogo e cliques para sugerir as proximas acoes.</li>
      <li><strong>Modo seguro:</strong> nesta fase o agente so recomenda. A aplicacao das acoes continua manual e auditada.</li>
    </ul>`,
  'instagram-publish': `
    <h3>Publicação Instagram (Meta Graph)</h3>
    <ul>
      <li>O robô pode postar carrosséis automaticamente no Feed da conta comercial.</li>
      <li>Configure respostas automáticas de comentários avisando que o link foi enviado no Direct!</li>
    </ul>`,
  'instagram-story': `
    <h3>Story Automático</h3>
    <ul>
      <li><strong>AutoPilot:</strong> Pega os produtos mais clicados e posta periodicamente nos stories. É a máquina de fazer dinheiro no automático.</li>
    </ul>`,
  'bio-growth': `
    <h3>Hub de Bio (Links)</h3>
    <ul>
      <li>Uma central única de agrupamento de links. Todos os botões postados no Insta apontarão pra cá.</li>
    </ul>`,
  'autoreplies': `
    <h3>Respostas Automáticas Clássicas</h3>
    <ul>
      <li>Regras simples padrão chave => valor.</li>
    </ul>`,
  'logs': `
    <h3>Logs e Monitoramento</h3>
    <ul>
      <li>Acompanhe em tempo real quem clicou no quê, onde o bot falhou em ler mídia ou se a API caiu.</li>
    </ul>`,
  'playground': `
    <h3>Playground</h3>
    <ul>
      <li>Cole um texto cru e teste se o regex de encurtamento do backend está detectando o link afiliado.</li>
    </ul>`,
  'debug': `
    <h3>Debug JSON</h3>
    <ul>
      <li>A visão raio-X de todas as variáveis ativas no sistema neste exato milissegundo.</li>
    </ul>`,
  'analytics': `
    <h3>Analytics Dashboard</h3>
    <ul>
      <li><strong>Vis?o Geral:</strong> Veja o total de cliques capturados nas ?ltimas 24h em cada parte do sistema (Bio, Cat?logo, Conversor).</li>
      <li><strong>Origens e Campanhas:</strong> Identifique de onde vem seus cliques mais quentes para otimizar suas ofertas.</li>
      <li><strong>Logs em Tempo Real:</strong> Monitore cada clique individualmente para garantir que o rastreamento est? funcionando perfeitamente.</li>
    </ul>`
};

function openDoc(tab) {
  const modal = document.getElementById('docModal');
  const body = document.getElementById('docBody');
  const title = document.getElementById('docTitle');
  if (!modal || !body) return;

  let name = tab.toUpperCase();
  const btn = document.querySelector(`button[data-tab="${tab}"]`);
  if (btn) name = btn.textContent.replace('0', '').trim();

  title.innerHTML = 'Guia: ' + name;
  body.innerHTML = sectionGuides[tab] || '<p>Guia em construção para esta aba.</p>';
  modal.classList.add('show');
}

function closeDoc() {
  const modal = document.getElementById('docModal');
  if (modal) modal.classList.remove('show');
}

function showToast(msg, type = 'success') {
  let container = document.getElementById('toastContainer');
  if (!container) return;

  const toast = document.createElement('div');
  toast.className = 'toast ' + type;
  toast.innerHTML = msg;

  container.appendChild(toast);
  setTimeout(() => toast.classList.add('show'), 10);
  setTimeout(() => {
    toast.classList.remove('show');
    setTimeout(() => toast.remove(), 300);
  }, 3000);
}

const originalSetData = Object.getOwnPropertyDescriptor(Node.prototype, 'textContent').set;
Object.defineProperty(Node.prototype, 'textContent', {
  set: function (val) {
    if (this.id && this.id.toLowerCase().includes('status') && !this.id.includes('stat') && !this.id.includes('health') && !this.id.includes('mercadolivre') && this.id !== 'loginStatus' && this.id !== 'telegramStatus') {
      if (val && val.toString().trim() !== '') {
        const isErr = val.toString().toLowerCase().includes('erro') || val.toString().toLowerCase().includes('falha');
        showToast(val, isErr ? 'error' : 'success');
      }
    }
    originalSetData.call(this, val);
  }
});

document.addEventListener('DOMContentLoaded', () => {
  hydrateAgentUiState().then(() => restoreAgentUiState());
  ['waMessageScheduleName', 'waMessageScheduleTargetGroup', 'waMessageScheduleText', 'waMessageScheduleImageUrl'].forEach(id => {
    const el = document.getElementById(id);
    if (!el) return;
    el.addEventListener('input', renderScheduledMessagePreview);
    el.addEventListener('change', renderScheduledMessagePreview);
  });

  ['engCurrentParticipants', 'engTarget120', 'engTarget1000', 'engDailyGoal', 'engActionsWeek1', 'engActionsWeek2To4', 'engActionsScale', 'engRetentionMessages'].forEach(id => {
    const el = document.getElementById(id);
    if (!el) return;
    el.addEventListener('input', refreshEngagementPlanSummary);
    el.addEventListener('change', refreshEngagementPlanSummary);
  });

  const waFooter = document.getElementById('waFooter');
  if (waFooter) {
    waFooter.addEventListener('input', scheduleWhatsAppFooterSave);
    waFooter.addEventListener('blur', () => saveWhatsAppFooter(true));
  }

  const monitorInstanceInput = document.getElementById('waInstanceName');
  if (monitorInstanceInput) {
    monitorInstanceInput.addEventListener('change', async () => {
      try {
        await loadMonitorGroups(true);
      } catch (err) {
        console.error('Erro ao recarregar grupos por instância principal', err);
      }
    });
  }

  [
    'waCopyParticipantsInstanceName',
    'waOutreachInstanceName',
    'waScheduleCopyInstanceName',
    'legacyWaScheduleCopyInstanceName',
    'waMessageScheduleInstanceName',
    'legacyWaMessageScheduleInstanceName'
  ].forEach(id => {
    const select = document.getElementById(id);
    if (!select) return;
    select.addEventListener('change', async () => {
      try {
        if (id === 'waCopyParticipantsInstanceName') {
          resetManualCopyParticipantsState();
        }
        if (id === 'waOutreachInstanceName') {
          resetOutreachParticipantsState();
        }
        await refreshInstanceBoundGroupSelectors(true);
      } catch (err) {
        console.error('Erro ao recarregar grupos por instância selecionada', err);
      }
    });
  });

  document.querySelectorAll('section[id^="section-"]').forEach(section => {
    const firstH2 = section.querySelector('.card:first-child h2:first-of-type, div:first-child > .card:first-child h2:first-of-type');
    if (firstH2 && !firstH2.querySelector('.icon-btn')) {
      const tabId = section.id.replace('section-', '');
      const btn = document.createElement('button');
      btn.className = 'icon-btn';
      btn.innerHTML = '? Ajuda';
      btn.onclick = (e) => { e.preventDefault(); openDoc(tabId); };

      if (firstH2.style.display !== 'flex') {
        firstH2.style.display = 'flex';
        firstH2.style.alignItems = 'center';
        firstH2.style.justifyContent = 'space-between';
      }
      firstH2.appendChild(btn);
    }
  });

  window.onclick = function (event) {
    const modal = document.getElementById('docModal');
    const scheduleModal = document.getElementById('waScheduleEditModal');
    if (event.target == modal) closeDoc();
    if (event.target == scheduleModal) closeWaScheduleEditor();
  }
});





// WhatsApp Monitoring
function buildGroupOptions(groups, placeholder = 'Selecione o grupo...') {
  let options = `<option value="">${placeholder}</option>`;
  if (groups && groups.length > 0) {
    options += groups.map(g => `<option value="${g.id}">${escapeHtml(g.name || g.id)}</option>`).join('');
  }
  return options;
}

function buildWaInstanceOptions(selectedValue = '') {
  const allInstances = (waInstancesCache || []);
  const activeStates = ['open', 'connected', 'online'];
  const activeInstances = allInstances.filter(inst => {
    const stateRaw = (inst?.state || inst?.State || '').toString().toLowerCase();
    return activeStates.includes(stateRaw);
  });
  const effectiveInstances = activeInstances.length > 0 ? activeInstances : allInstances;

  let options = '<option value="">Padrão do servidor</option>';
  effectiveInstances.forEach(inst => {
    const name = inst?.name || inst?.Name;
    if (!name) return;
    const stateRaw = (inst?.state || inst?.State || '').toString().toLowerCase();
    const stateLabel = stateRaw || 'unknown';
    const marker = (stateRaw === 'open' || stateRaw === 'connected' || stateRaw === 'online') ? 'OK' : 'WARN';
    const selected = String(name) === String(selectedValue || '') ? ' selected' : '';
    options += `<option value="${escapeHtml(String(name))}"${selected}>[${marker}] ${escapeHtml(String(name))} (${escapeHtml(stateLabel)})</option>`;
  });
  return options;
}

function populateWaInstanceSelect(selectId, selectedValue = '') {
  const select = document.getElementById(selectId);
  if (!select) return;
  const previousValue = selectedValue || select.value || '';
  select.innerHTML = buildWaInstanceOptions(previousValue);
  select.value = previousValue;
}

function populateAllInstanceSelects(selectedValue = '') {
  [
    'waScheduleCopyInstanceName',
    'legacyWaScheduleCopyInstanceName',
    'waMessageScheduleInstanceName',
    'legacyWaMessageScheduleInstanceName',
    'waScheduleEditInstanceName',
    'waCopyParticipantsInstanceName',
    'waOutreachInstanceName'
  ].forEach(id => populateWaInstanceSelect(id, selectedValue));
}

async function loadWaInstances(force = false) {
  if (waInstancesCache && !force) {
    populateAllInstanceSelects();
    return waInstancesCache;
  }

  try {
    const instances = await api('/api/integrations/whatsapp/instances');
    waInstancesCache = Array.isArray(instances) ? instances : [];
  } catch (err) {
    console.error('Erro ao carregar instâncias WhatsApp', err);
    waInstancesCache = [];
  }

  populateAllInstanceSelects();
  return waInstancesCache;
}

function normalizeInstanceName(value) {
  return String(value || '').trim();
}

function normalizeWhatsAppGroupsResponse(payload) {
  const rawGroups = Array.isArray(payload)
    ? payload
    : (Array.isArray(payload?.groups) ? payload.groups : []);

  return rawGroups
    .map(g => {
      const id = String(g?.id || g?.Id || '').trim();
      if (!id) return null;
      const name = String(g?.name || g?.Name || id).trim();
      return { id, name };
    })
    .filter(Boolean);
}

function extractKnownGroupIdsFromSettings(settings) {
  if (!settings || typeof settings !== 'object') return [];

  const ids = new Set();
  const add = (value) => {
    const id = String(value || '').trim();
    if (id) ids.add(id);
  };

  (settings.monitoredGroupIds || []).forEach(add);
  (settings.whatsAppForwarding?.destinationGroupIds || []).forEach(add);
  (settings.whatsAppForwarding?.sourceChatIds || []).forEach(add);

  (settings.whatsAppForwardingRoutes || []).forEach(route => {
    (route?.destinationGroupIds || []).forEach(add);
    (route?.sourceChatIds || []).forEach(add);
  });

  (settings.whatsAppAdminAutomation?.participantCopySchedules || []).forEach(item => {
    add(item?.sourceGroupId);
    add(item?.targetGroupId);
  });

  (settings.whatsAppAdminAutomation?.scheduledGroupMessages || []).forEach(item => {
    add(item?.targetGroupId);
  });

  return Array.from(ids);
}

function mergeGroupLists(primaryGroups, fallbackIds) {
  const merged = [];
  const seen = new Set();

  (primaryGroups || []).forEach(g => {
    const id = String(g?.id || '').trim();
    if (!id || seen.has(id)) return;
    seen.add(id);
    merged.push({ id, name: String(g?.name || id).trim() || id });
  });

  (fallbackIds || []).forEach(idRaw => {
    const id = String(idRaw || '').trim();
    if (!id || seen.has(id)) return;
    seen.add(id);
    merged.push({ id, name: id });
  });

  return merged;
}

async function fetchGroupsByInstance(instanceName, forceRefresh = false) {
  const normalized = normalizeInstanceName(instanceName);
  const cacheKey = normalized || '__default__';

  if (!forceRefresh && waAdminGroupsByInstanceCache.has(cacheKey)) {
    return waAdminGroupsByInstanceCache.get(cacheKey) || [];
  }

  const query = normalized ? `?instanceName=${encodeURIComponent(normalized)}` : '';
  const groupsResponse = await api(`/api/admin/whatsapp/groups${query}`);
  const safeGroups = normalizeWhatsAppGroupsResponse(groupsResponse);
  waAdminGroupsByInstanceCache.set(cacheKey, safeGroups);
  return safeGroups;
}

function syncSourceTargetGroupSelectors(sourceId, targetId, groups, sourcePlaceholder = 'Selecione o grupo origem...', targetPlaceholder = 'Selecione o grupo destino...') {
  const sourceSelect = document.getElementById(sourceId);
  const targetSelect = document.getElementById(targetId);
  if (!sourceSelect && !targetSelect) return;

  const sourcePrev = sourceSelect?.value || '';
  const targetPrev = targetSelect?.value || '';

  if (sourceSelect) sourceSelect.innerHTML = buildGroupOptions(groups, sourcePlaceholder);
  if (targetSelect) targetSelect.innerHTML = buildGroupOptions(groups, targetPlaceholder);

  if (!groups || groups.length === 0) return;

  const sourceFallback = String(groups[0].id);
  const targetFallback = String((groups.find(g => String(g.id) !== sourceFallback) || groups[0]).id);

  if (sourceSelect) {
    sourceSelect.value = groups.some(g => String(g.id) === sourcePrev) ? sourcePrev : sourceFallback;
  }
  if (targetSelect) {
    targetSelect.value = groups.some(g => String(g.id) === targetPrev) ? targetPrev : targetFallback;
  }
}

function syncSingleGroupSelector(selectId, groups, placeholder = 'Selecione o grupo destino...') {
  const select = document.getElementById(selectId);
  if (!select) return;
  const previous = select.value || '';
  select.innerHTML = buildGroupOptions(groups, placeholder);
  if (!groups || groups.length === 0) return;
  select.value = groups.some(g => String(g.id) === previous) ? previous : String(groups[0].id);
}

function syncMultiGroupSelector(selectId, groups) {
  const select = document.getElementById(selectId);
  if (!select) return;

  const previous = new Set(Array.from(select.selectedOptions || []).map(x => String(x.value)));
  select.innerHTML = '';

  if (!groups || groups.length === 0) {
    return;
  }

  groups.forEach(group => {
    const option = document.createElement('option');
    option.value = String(group.id);
    option.textContent = group.name || group.id;
    if (previous.has(String(group.id))) {
      option.selected = true;
    }
    select.appendChild(option);
  });
}

function getSelectedOutreachSourceGroupIds() {
  const multi = document.getElementById('waOutreachSourceGroups');
  const selectedFromMulti = Array.from(multi?.selectedOptions || []).map(x => String(x.value).trim()).filter(Boolean);
  if (selectedFromMulti.length > 0) {
    return Array.from(new Set(selectedFromMulti));
  }

  const single = String(document.getElementById('waOutreachSourceGroup')?.value || '').trim();
  return single ? [single] : [];
}

function resetManualCopyParticipantsState() {
  waCurrentGroupParticipants = [];
  setSafeText('waCopySelectionCount', '0');
  setSafeText('waCopyTotalCount', '0');
  const listContainer = document.getElementById('waCopyParticipantList');
  if (listContainer) listContainer.innerHTML = '<span class="muted">Aguardando carregamento...</span>';
  const selectionArea = document.getElementById('waCopySelectionArea');
  if (selectionArea) selectionArea.classList.add('hidden');
}

function resetOutreachParticipantsState() {
  setSafeText('waOutreachSelectionCount', '0');
  setSafeText('waOutreachTotalCount', '0');
  const listContainer = document.getElementById('waOutreachParticipantList');
  if (listContainer) listContainer.innerHTML = '<span class="muted">Aguardando carregamento...</span>';
  const selectionArea = document.getElementById('waOutreachSelectionArea');
  if (selectionArea) selectionArea.classList.add('hidden');
}

function getDefaultEngagementPlan() {
  return {
    currentParticipants: 0,
    target120: 120,
    target1000: 1000,
    dailyGoal: 8,
    actionsWeek1: '- Configurar 2 disparos por dia para participantes de grupos fonte\n- Publicar convite no Instagram Stories todos os dias\n- Rodar copy gradual de participantes com limite seguro',
    actionsWeek2To4: '- Testar 3 mensagens diferentes de convite\n- Criar oferta exclusiva semanal para membros do grupo oficial\n- Medir taxa de entrada por grupo origem',
    actionsScale: '- Criar calendário fixo de campanhas (WhatsApp + IG + Telegram)\n- Automatizar convite por segmentação de grupo\n- Escalar com metas por semana até 1000 participantes',
    retentionMessages: '- Boas-vindas com regras e benefício principal\n- 1 oferta premium por dia exclusiva do grupo oficial\n- Lembrete de indicação para amigos com prova social'
  };
}

function readEngagementPlanFromForm() {
  return {
    currentParticipants: parseInt(document.getElementById('engCurrentParticipants')?.value || '0', 10) || 0,
    target120: parseInt(document.getElementById('engTarget120')?.value || '120', 10) || 120,
    target1000: parseInt(document.getElementById('engTarget1000')?.value || '1000', 10) || 1000,
    dailyGoal: parseInt(document.getElementById('engDailyGoal')?.value || '8', 10) || 8,
    actionsWeek1: document.getElementById('engActionsWeek1')?.value || '',
    actionsWeek2To4: document.getElementById('engActionsWeek2To4')?.value || '',
    actionsScale: document.getElementById('engActionsScale')?.value || '',
    retentionMessages: document.getElementById('engRetentionMessages')?.value || ''
  };
}

function writeEngagementPlanToForm(plan) {
  const effective = plan || getDefaultEngagementPlan();
  setSafeVal('engCurrentParticipants', String(effective.currentParticipants ?? 0));
  setSafeVal('engTarget120', String(effective.target120 ?? 120));
  setSafeVal('engTarget1000', String(effective.target1000 ?? 1000));
  setSafeVal('engDailyGoal', String(effective.dailyGoal ?? 8));
  setSafeVal('engActionsWeek1', effective.actionsWeek1 || '');
  setSafeVal('engActionsWeek2To4', effective.actionsWeek2To4 || '');
  setSafeVal('engActionsScale', effective.actionsScale || '');
  setSafeVal('engRetentionMessages', effective.retentionMessages || '');
}

function loadEngagementPlan() {
  let plan = getDefaultEngagementPlan();
  try {
    const raw = localStorage.getItem(WA_ENGAGEMENT_PLAN_STORAGE_KEY);
    if (raw) {
      plan = { ...plan, ...JSON.parse(raw) };
    }
  } catch (err) {
    console.warn('Falha ao carregar plano de engajamento', err);
  }

  writeEngagementPlanToForm(plan);
}

function saveEngagementPlan() {
  const status = document.getElementById('engagementPlanStatus');
  try {
    const plan = readEngagementPlanFromForm();
    localStorage.setItem(WA_ENGAGEMENT_PLAN_STORAGE_KEY, JSON.stringify(plan));
    if (status) {
      status.textContent = 'Plano salvo localmente com sucesso.';
      status.className = 'status ok';
    }
    refreshEngagementPlanSummary();
  } catch (err) {
    console.error('Erro ao salvar plano de engajamento', err);
    if (status) {
      status.textContent = 'Erro ao salvar plano.';
      status.className = 'status warn';
    }
  }
}

function resetEngagementPlan() {
  writeEngagementPlanToForm(getDefaultEngagementPlan());
  saveEngagementPlan();
}

async function copyEngagementPlanJson() {
  const status = document.getElementById('engagementPlanStatus');
  const payload = JSON.stringify(readEngagementPlanFromForm(), null, 2);
  try {
    if (navigator?.clipboard?.writeText) {
      await navigator.clipboard.writeText(payload);
      if (status) {
        status.textContent = 'JSON copiado para a área de transferência.';
        status.className = 'status ok';
      }
    } else {
      throw new Error('Clipboard indisponível');
    }
  } catch {
    if (status) {
      status.textContent = 'Não foi possível copiar automaticamente. Salve e copie manualmente dos campos.';
      status.className = 'status warn';
    }
  }
}

function refreshEngagementPlanSummary() {
  const summaryEl = document.getElementById('engagementPlanSummary');
  if (!summaryEl) return;

  const plan = readEngagementPlanFromForm();
  const remainingTo120 = Math.max(0, (plan.target120 || 0) - (plan.currentParticipants || 0));
  const remainingTo1000 = Math.max(0, (plan.target1000 || 0) - (plan.currentParticipants || 0));
  const dailyGoal = Math.max(1, plan.dailyGoal || 1);
  const daysTo120 = Math.ceil(remainingTo120 / dailyGoal);
  const daysTo1000 = Math.ceil(remainingTo1000 / dailyGoal);

  summaryEl.innerHTML = `
    <div style="display:grid; gap:6px;">
      <div><strong>Meta 120:</strong> faltam ${remainingTo120} participantes (estimativa ${daysTo120} dia(s) com meta diária ${dailyGoal}).</div>
      <div><strong>Meta 1000:</strong> faltam ${remainingTo1000} participantes (estimativa ${daysTo1000} dia(s) com meta diária ${dailyGoal}).</div>
      <div><strong>Execução:</strong> foque em 1 ação de aquisição + 1 ação de retenção por dia para manter crescimento consistente.</div>
    </div>
  `;
}

async function refreshInstanceBoundGroupSelectors(forceRefresh = false) {
  const fallbackInstance = normalizeInstanceName(document.getElementById('waInstanceName')?.value);

  const manualInstance = normalizeInstanceName(document.getElementById('waCopyParticipantsInstanceName')?.value) || fallbackInstance;
  const outreachInstance = normalizeInstanceName(document.getElementById('waOutreachInstanceName')?.value) || fallbackInstance;
  const scheduleCopyInstance = normalizeInstanceName(document.getElementById('waScheduleCopyInstanceName')?.value) || fallbackInstance;
  const legacyScheduleCopyInstance = normalizeInstanceName(document.getElementById('legacyWaScheduleCopyInstanceName')?.value) || scheduleCopyInstance;
  const messageInstance = normalizeInstanceName(document.getElementById('waMessageScheduleInstanceName')?.value) || fallbackInstance;
  const legacyMessageInstance = normalizeInstanceName(document.getElementById('legacyWaMessageScheduleInstanceName')?.value) || messageInstance;

  const [manualGroups, outreachGroups, scheduleCopyGroups, legacyScheduleCopyGroups, messageGroups, legacyMessageGroups] = await Promise.all([
    fetchGroupsByInstance(manualInstance, forceRefresh),
    fetchGroupsByInstance(outreachInstance, forceRefresh),
    fetchGroupsByInstance(scheduleCopyInstance, forceRefresh),
    fetchGroupsByInstance(legacyScheduleCopyInstance, forceRefresh),
    fetchGroupsByInstance(messageInstance, forceRefresh),
    fetchGroupsByInstance(legacyMessageInstance, forceRefresh)
  ]);

  const settings = window.__settingsCache || await api('/api/settings');
  window.__settingsCache = settings;
  const knownGroupIds = extractKnownGroupIdsFromSettings(settings);

  const safeManualGroups = mergeGroupLists(manualGroups, knownGroupIds);
  const safeOutreachGroups = mergeGroupLists(outreachGroups, knownGroupIds);
  const safeScheduleCopyGroups = mergeGroupLists(scheduleCopyGroups, knownGroupIds);
  const safeLegacyScheduleCopyGroups = mergeGroupLists(legacyScheduleCopyGroups, knownGroupIds);
  const safeMessageGroups = mergeGroupLists(messageGroups, knownGroupIds);
  const safeLegacyMessageGroups = mergeGroupLists(legacyMessageGroups, knownGroupIds);

  syncSourceTargetGroupSelectors('waCopySourceGroup', 'waCopyTargetGroup', safeManualGroups);
  syncSingleGroupSelector('waOutreachSourceGroup', safeOutreachGroups, 'Selecione o grupo origem...');
  syncMultiGroupSelector('waOutreachSourceGroups', safeOutreachGroups);
  syncSourceTargetGroupSelectors('waScheduleCopySourceGroup', 'waScheduleCopyTargetGroup', safeScheduleCopyGroups);
  syncSourceTargetGroupSelectors('legacyWaScheduleCopySourceGroup', 'legacyWaScheduleCopyTargetGroup', safeLegacyScheduleCopyGroups);
  syncSingleGroupSelector('waMessageScheduleTargetGroup', safeMessageGroups);
  syncSingleGroupSelector('legacyWaMessageScheduleTargetGroup', safeLegacyMessageGroups);

  waAdminGroupsCache = safeManualGroups;
}

async function loadMonitorGroups(forceRefresh = false) {
  const picker = document.getElementById('waMonitorGroupPicker');
  const monitorInstance = normalizeInstanceName(document.getElementById('waInstanceName')?.value);
  
  if (picker) picker.innerHTML = '<span class="muted">Carregando grupos...</span>';
  
  try {
    const groupsPromise = fetchGroupsByInstance(monitorInstance, forceRefresh);
    const settingsPromise = window.__settingsCache
      ? Promise.resolve(window.__settingsCache)
      : api('/api/settings');
    const [groups, settings] = await Promise.all([groupsPromise, settingsPromise]);
    waAdminGroupsCache = groups || [];
    window.__settingsCache = settings;
    const selectedIds = settings.monitoredGroupIds || [];
    renderMonitorGroups(groups, selectedIds);
    await refreshInstanceBoundGroupSelectors(forceRefresh);
  } catch (err) {
    console.error('Erro ao carregar grupos para monitoramento', err);
    if (picker) picker.innerHTML = '<span class="warn">Erro ao carregar grupos. Verifique a conexão com WhatsApp.</span>';
  }
}

async function loadGroupParticipantsForCopy(silent = false) {
  const srcSelect = document.getElementById('waCopySourceGroup');
  const selectionArea = document.getElementById('waCopySelectionArea');
  const listContainer = document.getElementById('waCopyParticipantList');
  const statusSpan = document.getElementById('waCopyStatus');
  const instanceName = (document.getElementById('waCopyParticipantsInstanceName')?.value || document.getElementById('waInstanceName')?.value || '').trim();
  
  const sourceGroupId = srcSelect?.value;
  const cacheKey = `${instanceName || 'default'}::${sourceGroupId || ''}`;
  if (!sourceGroupId) {
    if (!silent) alert('Selecione um grupo de origem primeiro.');
    return;
  }

  if (statusSpan) statusSpan.textContent = 'Carregando membros...';
  if (listContainer) listContainer.innerHTML = '<span class="muted">Carregando membros...</span>';
  if (selectionArea) selectionArea.classList.remove('hidden');

  try {
    if (waParticipantsCache.has(cacheKey)) {
      waCurrentGroupParticipants = waParticipantsCache.get(cacheKey) || [];
      renderParticipantList(waCurrentGroupParticipants);
      if (statusSpan) statusSpan.textContent = '';
      return;
    }

    const participantsQuery = instanceName
      ? `&instanceName=${encodeURIComponent(instanceName)}`
      : '';
    const participants = await api(`/api/admin/whatsapp/groups/participants?groupId=${encodeURIComponent(sourceGroupId)}${participantsQuery}`);
    waCurrentGroupParticipants = participants || [];
    waParticipantsCache.set(cacheKey, waCurrentGroupParticipants);
    renderParticipantList(waCurrentGroupParticipants);
    if (statusSpan) statusSpan.textContent = '';
  } catch (err) {
    console.error('Erro ao carregar participantes', err);
    if (listContainer) listContainer.innerHTML = '<span class="warn">Erro ao carregar participantes.</span>';
    if (statusSpan) statusSpan.textContent = 'Erro ao carregar membros.';
  }
}

function handleCopySourceGroupChange() {
  loadGroupParticipantsForCopy(true);
}

function renderParticipantList(participants) {
  const container = document.getElementById('waCopyParticipantList');
  const totalSpan = document.getElementById('waCopyTotalCount');
  if (!container) return;

  if (totalSpan) totalSpan.textContent = participants.length;

  if (participants.length === 0) {
    container.innerHTML = '<span class="muted">Nenhum membro encontrado.</span>';
    return;
  }

  container.innerHTML = participants.map(p => `
    <label class="participant-item">
      <input type="checkbox" class="wa-participant-checkbox" value="${p}" onchange="updateSelectionCount()">
      <span title="${p}">${shortId(p)}</span>
    </label>
  `).join('');
  
  updateSelectionCount();
}

function toggleSelectAllParticipants(checked) {
  const checkboxes = document.querySelectorAll('.wa-participant-checkbox');
  checkboxes.forEach(cb => {
    if (cb.parentElement.style.display !== 'none') {
      cb.checked = checked;
    }
  });
  updateSelectionCount();
}

function applyParticipantLimit(limit) {
  const n = parseInt(limit);
  const checkboxes = document.querySelectorAll('.wa-participant-checkbox');
  
  // First uncheck all
  checkboxes.forEach(cb => cb.checked = false);
  
  if (isNaN(n) || n <= 0) {
    updateSelectionCount();
    return;
  }

  let count = 0;
  checkboxes.forEach(cb => {
    if (count < n && cb.parentElement.style.display !== 'none') {
      cb.checked = true;
      count++;
    }
  });
  updateSelectionCount();
}

function filterParticipantsList(query) {
  const q = query.toLowerCase();
  const checkboxes = document.querySelectorAll('.wa-participant-checkbox');
  checkboxes.forEach(cb => {
    const label = cb.parentElement;
    const text = label.textContent.toLowerCase();
    if (text.includes(q)) {
      label.style.display = 'flex';
    } else {
      label.style.display = 'none';
      cb.checked = false; // Uncheck hidden ones to avoid confusion
    }
  });
  updateSelectionCount();
}

function updateSelectionCount() {
  const selected = document.querySelectorAll('.wa-participant-checkbox:checked').length;
  const countSpan = document.getElementById('waCopySelectionCount');
  if (countSpan) countSpan.textContent = selected;
}

async function copyGroupParticipants() {
  const srcSelect = document.getElementById('waCopySourceGroup');
  const tgtSelect = document.getElementById('waCopyTargetGroup');
  const statusSpan = document.getElementById('waCopyStatus');
  const btn = document.getElementById('btnStartCopy');
  
  const sourceGroupId = srcSelect?.value;
  const targetGroupId = tgtSelect?.value;
  const instanceName = (document.getElementById('waCopyParticipantsInstanceName')?.value || document.getElementById('waInstanceName')?.value || '').trim();
  
  if (!sourceGroupId || !targetGroupId) {
    if (statusSpan) {
        statusSpan.textContent = 'Selecione ambos os grupos.';
        statusSpan.className = 'status warn';
    }
    return;
  }
  
  if (sourceGroupId === targetGroupId) {
    if (statusSpan) {
        statusSpan.textContent = 'O grupo de origem e destino não podem ser iguais.';
        statusSpan.className = 'status warn';
    }
    return;
  }

  // Get selected participants
  const selectedCheckboxes = document.querySelectorAll('.wa-participant-checkbox:checked');
  const participantIds = Array.from(selectedCheckboxes).map(cb => cb.value);

  if (participantIds.length === 0) {
    if (statusSpan) {
        statusSpan.textContent = 'Selecione pelo menos 1 participante antes de iniciar a copia.';
        statusSpan.className = 'status warn';
    }
    return;
  }

  if (participantIds.length > WA_MANUAL_COPY_MAX_PARTICIPANTS) {
    if (statusSpan) {
        statusSpan.textContent = `Selecione no maximo ${WA_MANUAL_COPY_MAX_PARTICIPANTS} participantes por copia manual.`;
        statusSpan.className = 'status warn';
    }
    return;
  }

  if (!confirm(`Confirmar copia manual de ${participantIds.length} participante(s) para o grupo de destino?`)) {
    return;
  }
  
  if (statusSpan) {
      statusSpan.textContent = 'Copiando participantes... Aguarde.';
      statusSpan.className = 'status muted';
  }
  if (btn) btn.disabled = true;
  
  try {
    const res = await api('/api/admin/whatsapp/groups/copy-participants', 'POST', { 
        sourceGroupId, 
        targetGroupId,
      participantIds,
      instanceName: instanceName || null
    });
    if (statusSpan) {
        statusSpan.textContent = res.queued
          ? `Enfileirado: ${res.count || 0} participante(s). Ignorados repetidos: ${res.skipped || 0}.`
          : res.success
          ? `Sucesso! ${res.count || 0} participantes copiados. Ignorados repetidos: ${res.skipped || 0}.`
          : (res.message || 'Falha ao copiar.');
        statusSpan.className = (res.success || res.queued) ? 'status ok' : 'status warn';
    }
  } catch(err) {
      console.error('Erro ao copiar contatos', err);
      if (statusSpan) {
          statusSpan.textContent = err.message || 'Erro ao conectar com servidor.';
          statusSpan.className = 'status warn';
      }
  } finally {
      if (btn) btn.disabled = false;
  }
}

async function loadGroupParticipantsForOutreach(silent = false) {
  const selectionArea = document.getElementById('waOutreachSelectionArea');
  const listContainer = document.getElementById('waOutreachParticipantList');
  const statusSpan = document.getElementById('waOutreachStatus');
  const instanceName = (document.getElementById('waOutreachInstanceName')?.value || document.getElementById('waInstanceName')?.value || '').trim();
  const useAll = document.getElementById('waOutreachUseAllParticipants')?.checked === true;

  const sourceGroupIds = getSelectedOutreachSourceGroupIds();
  const cacheKey = `${instanceName || 'default'}::${sourceGroupIds.slice().sort().join(',')}`;
  if (sourceGroupIds.length === 0) {
    if (!silent) alert('Selecione um grupo de origem primeiro.');
    return;
  }

  if (useAll) {
    if (selectionArea) selectionArea.classList.add('hidden');
    if (statusSpan) {
      statusSpan.textContent = 'Modo grupo inteiro ativo. O backend vai carregar todos os participantes dos grupos selecionados.';
      statusSpan.className = 'status ok';
    }
    return;
  }

  if (statusSpan) {
    statusSpan.textContent = sourceGroupIds.length > 1
      ? 'Carregando participantes dos grupos selecionados...'
      : 'Carregando participantes do grupo origem...';
    statusSpan.className = 'status muted';
  }
  if (listContainer) listContainer.innerHTML = '<span class="muted">Carregando participantes...</span>';
  if (selectionArea) selectionArea.classList.remove('hidden');

  try {
    if (waParticipantsCache.has(cacheKey)) {
      renderOutreachParticipantList(waParticipantsCache.get(cacheKey) || []);
      if (statusSpan) statusSpan.textContent = '';
      return;
    }

    const participantsQuery = instanceName ? `&instanceName=${encodeURIComponent(instanceName)}` : '';
    const allResults = await Promise.all(sourceGroupIds.map(groupId =>
      api(`/api/admin/whatsapp/groups/participants?groupId=${encodeURIComponent(groupId)}${participantsQuery}`)
    ));

    const union = [];
    allResults.forEach(list => {
      (list || []).forEach(p => {
        const id = String(p || '').trim();
        if (id && !id.endsWith('@g.us')) union.push(id);
      });
    });

    const filtered = Array.from(new Set(union));
    waParticipantsCache.set(cacheKey, filtered);
    renderOutreachParticipantList(filtered);
    if (statusSpan) statusSpan.textContent = '';
  } catch (err) {
    console.error('Erro ao carregar participantes para disparo', err);
    if (listContainer) listContainer.innerHTML = '<span class="warn">Erro ao carregar participantes.</span>';
    if (statusSpan) {
      statusSpan.textContent = 'Erro ao carregar participantes.';
      statusSpan.className = 'status warn';
    }
  }
}

function handleOutreachSourceGroupChange() {
  loadGroupParticipantsForOutreach(true);
}

function renderOutreachParticipantList(participants) {
  const container = document.getElementById('waOutreachParticipantList');
  const totalSpan = document.getElementById('waOutreachTotalCount');
  if (!container) return;

  if (totalSpan) totalSpan.textContent = participants.length;

  if (participants.length === 0) {
    container.innerHTML = '<span class="muted">Nenhum participante encontrado.</span>';
    updateOutreachSelectionCount();
    return;
  }

  container.innerHTML = participants.map(p => `
    <label style="display:flex; align-items:center; gap:8px; font-size:0.9em; cursor:pointer; padding:2px; border-bottom:1px solid var(--border-subtle);">
      <input type="checkbox" class="wa-outreach-participant-checkbox" value="${p}" onchange="updateOutreachSelectionCount()">
      <span title="${p}">${shortId(p)}</span>
    </label>
  `).join('');

  updateOutreachSelectionCount();
}

function toggleSelectAllOutreachParticipants(checked) {
  const checkboxes = document.querySelectorAll('.wa-outreach-participant-checkbox');
  checkboxes.forEach(cb => {
    if (cb.parentElement.style.display !== 'none') {
      cb.checked = checked;
    }
  });
  updateOutreachSelectionCount();
}

function applyOutreachParticipantLimit(limit) {
  const n = parseInt(limit, 10);
  const checkboxes = document.querySelectorAll('.wa-outreach-participant-checkbox');
  checkboxes.forEach(cb => cb.checked = false);

  if (isNaN(n) || n <= 0) {
    updateOutreachSelectionCount();
    return;
  }

  let count = 0;
  checkboxes.forEach(cb => {
    if (count < n && cb.parentElement.style.display !== 'none') {
      cb.checked = true;
      count++;
    }
  });
  updateOutreachSelectionCount();
}

function filterOutreachParticipantsList(query) {
  const q = String(query || '').toLowerCase();
  const checkboxes = document.querySelectorAll('.wa-outreach-participant-checkbox');
  checkboxes.forEach(cb => {
    const label = cb.parentElement;
    const text = label.textContent.toLowerCase();
    if (text.includes(q)) {
      label.style.display = 'flex';
    } else {
      label.style.display = 'none';
      cb.checked = false;
    }
  });
  updateOutreachSelectionCount();
}

function updateOutreachSelectionCount() {
  const selected = document.querySelectorAll('.wa-outreach-participant-checkbox:checked').length;
  const countSpan = document.getElementById('waOutreachSelectionCount');
  if (countSpan) countSpan.textContent = selected;
}

function formatOutreachProgressTs(value) {
  if (!value) return '-';
  try {
    return new Date(value).toLocaleString('pt-BR');
  } catch {
    return String(value);
  }
}

function getOutreachProgressLevelClass(level) {
  const normalized = String(level || '').toLowerCase();
  if (normalized === 'ok') return 'ok';
  if (normalized === 'warn' || normalized === 'error') return 'warn';
  return 'muted';
}

function formatSecondsDuration(totalSeconds) {
  const seconds = Math.max(0, Math.round(Number(totalSeconds) || 0));
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;

  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

function renderOutreachProgressMetrics(items) {
  const progressEl = document.getElementById('waOutreachMetricProgress');
  const successEl = document.getElementById('waOutreachMetricSuccess');
  const failEl = document.getElementById('waOutreachMetricFail');
  const etaEl = document.getElementById('waOutreachMetricEta');
  if (!progressEl || !successEl || !failEl || !etaEl) return;

  if (!Array.isArray(items) || items.length === 0) {
    progressEl.textContent = '-';
    progressEl.className = 'muted';
    successEl.textContent = '-';
    successEl.className = 'muted';
    failEl.textContent = '-';
    failEl.className = 'muted';
    etaEl.textContent = '-';
    etaEl.className = 'muted';
    return;
  }

  const ordered = [...items]
    .filter(x => x && x.timestamp)
    .sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));

  const total = ordered.reduce((max, item) => Math.max(max, Number(item.total) || 0), 0);
  const processed = ordered.reduce((max, item) => Math.max(max, Number(item.processed) || 0), 0);

  const successStages = new Set(['participant-success', 'participant-message-sent']);
  const failStages = new Set(['participant-failed', 'participant-message-failed']);

  const successParticipants = new Set();
  const failParticipants = new Set();
  let successEvents = 0;
  let failEvents = 0;

  ordered.forEach(item => {
    const stage = String(item.stage || '').toLowerCase();
    const pid = String(item.participantId || '').trim();
    if (successStages.has(stage)) {
      successEvents++;
      if (pid) successParticipants.add(pid);
    }
    if (failStages.has(stage)) {
      failEvents++;
      if (pid) failParticipants.add(pid);
    }
  });

  const successCount = Math.max(successParticipants.size, successEvents);
  const failCount = Math.max(failParticipants.size, failEvents);
  const done = Math.max(processed, successCount + failCount);
  const denom = total > 0 ? total : Math.max(done, 1);
  const pct = Math.min(100, Math.round((Math.max(0, done) / denom) * 100));

  progressEl.textContent = `${Math.max(0, done)}/${total || '-'} (${pct}%)`;
  progressEl.className = pct >= 100 ? 'ok' : 'muted';

  const successRate = done > 0 ? Math.round((successCount / done) * 100) : 0;
  successEl.textContent = `${successCount} (${successRate}%)`;
  successEl.className = successCount > 0 ? 'ok' : 'muted';

  failEl.textContent = `${failCount}`;
  failEl.className = failCount > 0 ? 'warn' : 'ok';

  let etaText = 'Concluído';
  let etaClass = 'ok';
  if (total <= 0 || done <= 0 || done >= total) {
    if (done <= 0) {
      etaText = 'Calculando...';
      etaClass = 'muted';
    }
  } else if (ordered.length >= 2) {
    const firstTs = new Date(ordered[0].timestamp).getTime();
    const lastTs = new Date(ordered[ordered.length - 1].timestamp).getTime();
    const elapsedSeconds = Math.max(1, Math.floor((lastTs - firstTs) / 1000));
    const ratePerSec = done / elapsedSeconds;
    const remaining = Math.max(0, total - done);
    if (ratePerSec > 0) {
      etaText = formatSecondsDuration(remaining / ratePerSec);
      etaClass = 'muted';
    } else {
      etaText = 'Calculando...';
      etaClass = 'muted';
    }
  } else {
    etaText = 'Calculando...';
    etaClass = 'muted';
  }

  etaEl.textContent = etaText;
  etaEl.className = etaClass;
}

async function loadOutreachProgressLogs(silent = false) {
  const body = document.getElementById('waOutreachLogsBody');
  const summary = document.getElementById('waOutreachLogsSummary');
  const opInput = document.getElementById('waOutreachOperationId');
  const limitInput = document.getElementById('waOutreachLogsLimit');
  if (!body || !summary) return;

  const requestedOperationId = String(opInput?.value || waOutreachLastOperationId || '').trim();
  const limit = parseInt(limitInput?.value || '200', 10) || 200;
  const qs = new URLSearchParams();
  qs.set('limit', String(Math.max(1, Math.min(2000, limit))));
  if (requestedOperationId) {
    qs.set('operationId', requestedOperationId);
  }

  try {
    if (!silent) {
      summary.textContent = 'Carregando log de andamento...';
      summary.className = 'status muted';
    }

    const res = await api(`/api/admin/whatsapp/groups/blast-participants/logs?${qs.toString()}`);
    const items = Array.isArray(res.items) ? res.items : [];
    const operationFromApi = String(res.operationId || requestedOperationId || '').trim();
    if (operationFromApi) {
      waOutreachLastOperationId = operationFromApi;
      if (opInput && !opInput.value) {
        opInput.value = operationFromApi;
      }
    }

    if (items.length === 0) {
      renderOutreachProgressMetrics([]);
      body.innerHTML = '<tr><td colspan="6" class="muted">Sem eventos para os filtros atuais.</td></tr>';
      summary.textContent = operationFromApi
        ? `Sem eventos encontrados para a operação ${operationFromApi}.`
        : 'Sem eventos recentes de disparo.';
      summary.className = 'status muted';
      return;
    }

    body.innerHTML = items.map(item => {
      const levelClass = getOutreachProgressLevelClass(item.level);
      const progress = (item.processed != null && item.total != null)
        ? `${item.processed}/${item.total}`
        : '-';
      return `
        <tr>
          <td>${escapeHtml(formatOutreachProgressTs(item.timestamp))}</td>
          <td><span class="badge ${levelClass}">${escapeHtml(String(item.stage || '-'))}</span></td>
          <td>${escapeHtml(String(item.participantId || '-'))}</td>
          <td>${escapeHtml(progress)}</td>
          <td>${escapeHtml(String(item.message || '-'))}</td>
          <td>${escapeHtml(String(item.operationId || '-'))}</td>
        </tr>
      `;
    }).join('');

    renderOutreachProgressMetrics(items);

    summary.textContent = operationFromApi
      ? `Mostrando ${items.length} evento(s) da operação ${operationFromApi}.`
      : `Mostrando ${items.length} evento(s) recentes.`;
    summary.className = 'status ok';
  } catch (err) {
    console.error('Erro ao carregar log de andamento do disparo', err);
    renderOutreachProgressMetrics([]);
    if (!silent) {
      summary.textContent = err?.data?.error || err?.message || 'Erro ao carregar log de andamento.';
      summary.className = 'status warn';
    }
  }
}

async function loadOutreachScheduleList() {
  const sel = document.getElementById('waConversionScheduleId');
  if (!sel) return;
  try {
    const res = await api('/api/admin/whatsapp/groups/blast-participants/schedules');
    const schedules = Array.isArray(res.schedules) ? res.schedules : [];
    const current = sel.value;
    sel.innerHTML = '<option value="">— selecione um disparo —</option>' +
      schedules.map(s => {
        const label = `${s.name} (${s.status}) — ${s.sentParticipants ?? s.successParticipants} enviados`;
        return `<option value="${escapeHtml(s.id)}">${escapeHtml(label)} [${s.id.substring(0, 8)}]</option>`;
      }).join('');
    if (current) sel.value = current;
  } catch (err) {
    console.warn('Erro ao carregar lista de disparos', err);
  }
}

async function loadOutreachConversion() {
  const scheduleId = String(document.getElementById('waConversionScheduleId')?.value || '').trim();
  const groupId = String(document.getElementById('waConversionGroupId')?.value || '').trim();
  const summary = document.getElementById('waConversionSummary');
  const body = document.getElementById('waConversionBody');
  if (!scheduleId) {
    if (summary) { summary.textContent = 'Selecione um disparo antes de calcular.'; summary.className = 'status warn'; }
    return;
  }
  if (summary) { summary.textContent = 'Calculando...'; summary.className = 'status muted'; }
  try {
    const qs = new URLSearchParams({ scheduleId });
    if (groupId) qs.set('groupId', groupId);
    const res = await api(`/api/admin/whatsapp/groups/blast-participants/conversion?${qs.toString()}`);

    document.getElementById('waConvMetricSent').textContent = res.totalSent ?? '-';
    document.getElementById('waConvMetricJoined').textContent = res.converted ?? '-';
    document.getElementById('waConvMetricRate').textContent = res.conversionRate != null ? `${res.conversionRate}%` : '-';
    document.getElementById('waConvMetricEvents').textContent = res.totalJoinEvents ?? '-';

    const converters = Array.isArray(res.converters) ? res.converters : [];
    if (converters.length === 0) {
      body.innerHTML = '<tr><td colspan="5" class="muted">Nenhum participante confirmado como convertido ainda.</td></tr>';
    } else {
      body.innerHTML = converters.map(c => `
        <tr>
          <td>${escapeHtml(c.participantId || '-')}</td>
          <td style="font-size:11px;">${escapeHtml(c.groupId || '-')}</td>
          <td>${escapeHtml(c.groupName || '-')}</td>
          <td><span class="badge ok">${escapeHtml(c.action || '-')}</span></td>
          <td>${escapeHtml(formatOutreachProgressTs(c.joinedAt))}</td>
        </tr>
      `).join('');
    }
    summary.textContent = `Disparo "${res.scheduleName}": ${res.totalSent} enviados → ${res.converted} entradas confirmadas (${res.conversionRate}% de conversão).`;
    summary.className = 'status ok';
  } catch (err) {
    if (summary) { summary.textContent = err?.data?.error || err?.message || 'Erro ao calcular conversão.'; summary.className = 'status warn'; }
  }
}

function prefillOutreachMessageTemplate() {
  const linkInput = document.getElementById('waOutreachLinkUrl');
  const el = document.getElementById('waOutreachMessage');
  if (!el) return;
  if (linkInput && !linkInput.value) {
    linkInput.value = 'https://chat.whatsapp.com/SEU_LINK_AQUI';
  }
  el.value = 'Nosso grupo oficial e moderado, com ofertas validadas e links revisados para mais seguranca e menos ruido no seu WhatsApp.';
  setSafeVal('waOutreachWaitTimeoutSeconds', '120');
  setSafeVal('waOutreachPreLinkMessages', '3');
  setSafeVal('waOutreachWaitMode', 'response-or-timeout');
  setSafeVal('waOutreachPitchPreset', 'amigavel');
  setSafeVal('waOutreachMinIntervalMs', '1200');
  setSafeVal('waOutreachMaxIntervalMs', '2600');
  setSafeVal('waOutreachBatchSize', '25');
  setSafeVal('waOutreachBatchPauseSeconds', '90');
  setSafeChecked('waOutreachSendLinkOnTimeout', true);
  const status = document.getElementById('waOutreachStatus');
  if (status) {
    status.textContent = 'Template aplicado. Ajuste pitch e link antes de disparar.';
    status.className = 'status muted';
  }
}

function applyOutreachPitchPreset() {
  const preset = String(document.getElementById('waOutreachPitchPreset')?.value || 'amigavel');
  const pitch = WA_OUTREACH_PITCH_PRESETS[preset] || WA_OUTREACH_PITCH_PRESETS.amigavel;
  setSafeVal('waOutreachMessage', pitch);
  const status = document.getElementById('waOutreachStatus');
  if (status) {
    status.textContent = `Pitch base aplicado: ${preset}. Você pode editar o texto antes de disparar.`;
    status.className = 'status ok';
  }
}

async function sendOutreachMessages() {
  const sourceGroupIds = getSelectedOutreachSourceGroupIds();
  const sourceGroupId = sourceGroupIds[0] || '';
  const instanceName = (document.getElementById('waOutreachInstanceName')?.value || document.getElementById('waInstanceName')?.value || '').trim();
  const useAllParticipants = document.getElementById('waOutreachUseAllParticipants')?.checked === true;
  const message = (document.getElementById('waOutreachMessage')?.value || '').trim();
  const linkUrl = (document.getElementById('waOutreachLinkUrl')?.value || '').trim();
  const intervalMs = parseInt(document.getElementById('waOutreachIntervalMs')?.value || '1500', 10) || 1500;
  const minUserIntervalMs = parseInt(document.getElementById('waOutreachMinIntervalMs')?.value || '1200', 10) || 1200;
  const maxUserIntervalMs = parseInt(document.getElementById('waOutreachMaxIntervalMs')?.value || '2600', 10) || 2600;
  const batchSize = parseInt(document.getElementById('waOutreachBatchSize')?.value || '25', 10) || 25;
  const batchPauseSeconds = parseInt(document.getElementById('waOutreachBatchPauseSeconds')?.value || '90', 10) || 90;
  const preLinkMessages = parseInt(document.getElementById('waOutreachPreLinkMessages')?.value || '3', 10) || 3;
  const waitMode = (document.getElementById('waOutreachWaitMode')?.value || 'response-or-timeout').trim();
  const waitTimeoutSeconds = parseInt(document.getElementById('waOutreachWaitTimeoutSeconds')?.value || '120', 10) || 120;
  const sendLinkOnTimeout = document.getElementById('waOutreachSendLinkOnTimeout')?.checked !== false;
  const status = document.getElementById('waOutreachStatus');
  const btn = document.getElementById('btnOutreachSend');

  const selectedCheckboxes = document.querySelectorAll('.wa-outreach-participant-checkbox:checked');
  const participantIds = Array.from(selectedCheckboxes).map(cb => cb.value);

  if (!sourceGroupId || sourceGroupIds.length === 0) {
    if (status) {
      status.textContent = 'Selecione ao menos um grupo origem.';
      status.className = 'status warn';
    }
    return;
  }

  if (!linkUrl) {
    if (status) {
      status.textContent = 'Informe o link do grupo oficial.';
      status.className = 'status warn';
    }
    return;
  }

  if (!message) {
    if (status) {
      status.textContent = 'Informe o pitch de segurança para o diálogo.';
      status.className = 'status warn';
    }
    return;
  }

  if (!waitMode || (waitMode !== 'response-or-timeout' && waitMode !== 'timeout')) {
    if (status) {
      status.textContent = 'Selecione um modo de espera válido.';
      status.className = 'status warn';
    }
    return;
  }

  if (waitTimeoutSeconds < 10 || waitTimeoutSeconds > 600) {
    if (status) {
      status.textContent = 'Timeout deve ficar entre 10 e 600 segundos.';
      status.className = 'status warn';
    }
    return;
  }

  if (!useAllParticipants && participantIds.length === 0) {
    if (status) {
      status.textContent = 'Selecione pelo menos 1 participante ou ative o modo grupo inteiro.';
      status.className = 'status warn';
    }
    return;
  }

  const intendedCount = useAllParticipants ? 'todos participantes dos grupos selecionados' : `${participantIds.length} participante(s)`;
  if (!confirm(`Confirmar disparo para ${intendedCount}?`)) {
    return;
  }

  if (status) {
    status.textContent = 'Enfileirando disparo...';
    status.className = 'status muted';
  }
  if (btn) btn.disabled = true;

  try {
    const res = await api('/api/admin/whatsapp/groups/blast-participants/scheduled', 'POST', {
      sourceGroupId,
      sourceGroupIds,
      participantIds,
      useAllParticipantsFromSources: useAllParticipants,
      message,
      linkUrl,
      intervalMs,
      minUserIntervalMs,
      maxUserIntervalMs,
      batchSize,
      batchPauseSeconds,
      useAiDialogue: true,
      preLinkMessages,
      waitMode,
      waitTimeoutSeconds,
      sendLinkOnTimeout,
      securityPitch: message,
      instanceName: instanceName || null
    });

    if (status) {
      status.textContent = res.queued
        ? `Disparo enfileirado para ${res.count || participantIds.length} participante(s). Fila: ${res.queueId || 'n/d'}.`
        : (res.message || 'Disparo processado.');
      status.className = res.success ? 'status ok' : 'status warn';
    }

    waOutreachLastOperationId = String(res.operationId || '').trim() || waOutreachLastOperationId;
    const opInput = document.getElementById('waOutreachOperationId');
    if (opInput && waOutreachLastOperationId) {
      opInput.value = waOutreachLastOperationId;
    }

    await loadOutreachProgressLogs();

    await loadWhatsAppAutomation();
  } catch (err) {
    console.error('Erro ao disparar mensagens para participantes', err);
    if (status) {
      status.textContent = err?.data?.error || err?.message || 'Erro ao disparar mensagens.';
      status.className = 'status warn';
    }
  } finally {
    if (btn) btn.disabled = false;
  }
}

function formatWaAutomationStatus(item) {
  if (!item) return '<span class="muted">Sem status.</span>';

  const messages = [];
  if (item.lastResultMessage) messages.push(escapeHtml(item.lastResultMessage));
  if (item.nextRunAt) messages.push(`Próxima: ${escapeHtml(formatTs(item.nextRunAt))}`);
  if (item.lastRunAt) messages.push(`Última execução: ${escapeHtml(formatTs(item.lastRunAt))}`);
  if (item.lastSentAt) messages.push(`Último envio: ${escapeHtml(formatTs(item.lastSentAt))}`);
  if (item.completedAt) messages.push(`Concluído: ${escapeHtml(formatTs(item.completedAt))}`);
  if (item.pausedAt) messages.push(`Pausado: ${escapeHtml(formatTs(item.pausedAt))}`);
  if (item.cancelledAt) messages.push(`Cancelado: ${escapeHtml(formatTs(item.cancelledAt))}`);
  return messages.length > 0 ? messages.join(' | ') : '<span class="muted">Aguardando primeira execução.</span>';
}

function getGroupNameById(groupId) {
  if (!groupId || !Array.isArray(waAdminGroupsCache)) return shortId(groupId || '');
  const found = waAdminGroupsCache.find(g => String(g.id) === String(groupId));
  return found?.name || shortId(groupId);
}

function notifyCompletedCopySchedules(copySchedules) {
  if (!Array.isArray(copySchedules) || copySchedules.length === 0) return;

  copySchedules.forEach(item => {
    if (!item || item.enabled || !item.completedAt || item.cancelledAt) return;
    const storageKey = `waCopyScheduleCompleted:${item.id}:${item.completedAt}`;
    if (localStorage.getItem(storageKey)) return;
    localStorage.setItem(storageKey, '1');
    const groupName = getGroupNameById(item.targetGroupId);
    alert(`Agendamento concluido: ${item.name || 'Copia gradual'}\nGrupo destino: ${groupName}\nProcessados: ${Number(item.processedParticipants || 0)}\nIgnorados: ${Number(item.skippedParticipants || 0)}`);
  });
}

function getCopyScheduleBadge(item) {
  if (item?.cancelledAt) return '<span class="badge bad">Cancelado</span>';
  if (item?.completedAt) return '<span class="badge muted">Concluído</span>';
  if (item?.enabled) return '<span class="badge ok">Ativo</span>';
  return '<span class="badge warn">Pausado</span>';
}

function getMessageScheduleBadge(item) {
  if (item?.cancelledAt) return '<span class="badge bad">Cancelado</span>';
  if (item?.enabled) return '<span class="badge ok">Ativo</span>';
  return '<span class="badge warn">Pausado</span>';
}

function formatAutomationQueueItem(item) {
  if (!item) return '';
  const parts = [
    `${escapeHtml(item.label || item.kind || 'Operação')}`,
    `<span class="badge ${item.status === 'running' ? 'warn' : item.status === 'done' ? 'ok' : item.status === 'failed' ? 'bad' : 'muted'}">${escapeHtml(item.status || 'queued')}</span>`
  ];
  const detail = item.detail ? `<div class="muted" style="margin-top:4px;">${escapeHtml(item.detail)}</div>` : '';
  const times = [];
  if (item.enqueuedAt) times.push(`Fila: ${escapeHtml(formatTs(item.enqueuedAt))}`);
  if (item.startedAt) times.push(`Início: ${escapeHtml(formatTs(item.startedAt))}`);
  if (item.completedAt) times.push(`Fim: ${escapeHtml(formatTs(item.completedAt))}`);
  return `
    <div class="card" style="padding:12px; margin-bottom:10px;">
      <div class="row" style="justify-content:space-between; align-items:flex-start; gap:12px;">
        <div>
          <strong>${parts[0]}</strong>
          <div class="muted" style="margin-top:4px; font-size:0.9em;">${times.join(' | ')}</div>
          ${detail}
        </div>
        <div>${parts[1]}</div>
      </div>
    </div>
  `;
}

function renderWhatsAppAutomationQueue(queueState) {
  waAutomationQueueCache = queueState || { items: [], pendingCount: 0 };
  const queueList = document.getElementById('waAutomationQueueList');
  if (!queueList) return;

  const items = waAutomationQueueCache.items || [];
  const pendingCount = Number(waAutomationQueueCache.pendingCount || 0);
  const currentJobId = waAutomationQueueCache.currentJobId || '';

  if (items.length === 0) {
    queueList.innerHTML = '<span class="muted">Nenhuma operação enfileirada no momento.</span>';
    return;
  }

  const header = `
    <div class="badge ${pendingCount > 0 ? 'warn' : 'ok'}" style="margin-bottom:10px;">Pendentes: ${pendingCount}</div>
    ${currentJobId ? `<div class="badge warn" style="margin-bottom:10px;">Em execução: ${escapeHtml(shortId(currentJobId))}</div>` : ''}
  `;

  queueList.innerHTML = header + items.map(formatAutomationQueueItem).join('');
}

async function runCopyScheduleNow(id) {
  if (!id) return;
  if (!confirm('Executar este agendamento de cópia agora?')) return;

  try {
    const res = await api(`/api/admin/whatsapp/copy-schedules/${encodeURIComponent(id)}/run-now`, 'POST', {});
    showToast(res?.message || 'Agendamento de cópia enfileirado.', 'success');
    await loadWhatsAppAutomation();
  } catch (err) {
    console.error('Erro ao executar agendamento de cópia agora', err);
    alert(err?.data?.error || 'Erro ao executar agendamento agora.');
  }
}

async function reactivateParticipantCopySchedule(id) {
  if (!id) return;

  const schedule = (waAutomationCache?.participantCopySchedules || []).find(item => item?.id === id);
  if (!schedule) {
    alert('Agendamento não encontrado na tela. Atualize o painel e tente novamente.');
    return;
  }

  if (!confirm('Reativar este agendamento de inclusão de participantes?')) return;

  try {
    const instanceName = (schedule.instanceName || document.getElementById('waInstanceName')?.value || '').trim();
    const payload = {
      name: schedule.name || null,
      sourceGroupId: schedule.sourceGroupId,
      targetGroupId: schedule.targetGroupId,
      batchSize: Number(schedule.batchSize || 1),
      intervalMinutes: Number(schedule.intervalMinutes || 1),
      enabled: true,
      refreshQueue: false,
      instanceName: instanceName || null,
      startAt: new Date().toISOString()
    };

    const res = await api(`/api/admin/whatsapp/copy-schedules/${encodeURIComponent(id)}`, 'PUT', payload);
    showToast(res?.message || 'Agendamento reativado com sucesso.', 'success');
    await loadWhatsAppAutomation();
  } catch (err) {
    console.error('Erro ao reativar agendamento de cópia', err);
    alert(err?.data?.error || 'Erro ao reativar agendamento.');
  }
}

async function pauseParticipantCopySchedule(id) {
  if (!id) return;
  if (!confirm('Pausar este agendamento individualmente?')) return;

  try {
    const res = await api(`/api/admin/whatsapp/copy-schedules/${encodeURIComponent(id)}/pause`, 'POST', {});
    showToast(res?.message || 'Agendamento pausado.', 'success');
    await loadWhatsAppAutomation();
  } catch (err) {
    console.error('Erro ao pausar agendamento de cópia', err);
    alert(err?.data?.error || 'Erro ao pausar agendamento.');
  }
}

async function cancelParticipantCopySchedule(id) {
  if (!id) return;
  if (!confirm('Cancelar este agendamento? Esta ação zera a fila pendente e não é reversível pelo botão de reativar.')) return;

  try {
    const res = await api(`/api/admin/whatsapp/copy-schedules/${encodeURIComponent(id)}/cancel`, 'POST', {});
    showToast(res?.message || 'Agendamento cancelado.', 'success');
    await loadWhatsAppAutomation();
  } catch (err) {
    console.error('Erro ao cancelar agendamento de cópia', err);
    alert(err?.data?.error || 'Erro ao cancelar agendamento.');
  }
}

async function runMessageScheduleNow(id) {
  if (!id) return;
  if (!confirm('Enviar esta mensagem agendada agora?')) return;

  try {
    const res = await api(`/api/admin/whatsapp/message-schedules/${encodeURIComponent(id)}/run-now`, 'POST', {});
    showToast(res?.message || 'Mensagem enfileirada para envio.', 'success');
    await loadWhatsAppAutomation();
  } catch (err) {
    console.error('Erro ao enviar mensagem agendada agora', err);
    alert(err?.data?.error || 'Erro ao enviar mensagem agora.');
  }
}

async function pauseMessageSchedule(id) {
  if (!id) return;
  if (!confirm('Pausar esta mensagem agendada individualmente?')) return;

  try {
    const res = await api(`/api/admin/whatsapp/message-schedules/${encodeURIComponent(id)}/pause`, 'POST', {});
    showToast(res?.message || 'Agendamento pausado.', 'success');
    await loadWhatsAppAutomation();
  } catch (err) {
    console.error('Erro ao pausar mensagem agendada', err);
    alert(err?.data?.error || 'Erro ao pausar mensagem agendada.');
  }
}

async function cancelMessageSchedule(id) {
  if (!id) return;
  if (!confirm('Cancelar esta mensagem agendada? Esta ação é tratada como terminal.')) return;

  try {
    const res = await api(`/api/admin/whatsapp/message-schedules/${encodeURIComponent(id)}/cancel`, 'POST', {});
    showToast(res?.message || 'Agendamento cancelado.', 'success');
    await loadWhatsAppAutomation();
  } catch (err) {
    console.error('Erro ao cancelar mensagem agendada', err);
    alert(err?.data?.error || 'Erro ao cancelar mensagem agendada.');
  }
}

function toggleWaScheduleEditorFieldGroup(type) {
  const isCopy = type === 'copy';
  const copyIds = [
    'waScheduleEditCopySourceWrap',
    'waScheduleEditCopyTargetWrap',
    'waScheduleEditCopyBatchWrap',
    'waScheduleEditCopyIntervalWrap',
    'waScheduleEditCopyStartWrap',
    'waScheduleEditCopyRefreshWrap'
  ];
  const messageIds = [
    'waScheduleEditMessageTargetWrap',
    'waScheduleEditMessageIntervalWrap',
    'waScheduleEditMessageStartWrap',
    'waScheduleEditMessageImageWrap',
    'waScheduleEditMessageText'
  ];

  copyIds.forEach(id => {
    const el = document.getElementById(id);
    if (el) el.style.display = isCopy ? '' : 'none';
  });

  messageIds.forEach(id => {
    const el = document.getElementById(id);
    if (el) el.style.display = isCopy ? 'none' : '';
  });
}

function closeWaScheduleEditor() {
  const modal = document.getElementById('waScheduleEditModal');
  if (modal) modal.classList.remove('show');
  waScheduleEditState = null;
}

function editWaSchedule(type, id) {
  if (!id) return;
  const schedules = type === 'copy'
    ? (waAutomationCache?.participantCopySchedules || [])
    : (waAutomationCache?.scheduledGroupMessages || []);
  const item = schedules.find(x => String(x.id) === String(id));
  if (!item) return;
  openWaScheduleEditor(type, item);
}

function openWaScheduleEditor(type, item) {
  const modal = document.getElementById('waScheduleEditModal');
  const title = document.getElementById('waScheduleEditTitle');
  const status = document.getElementById('waScheduleEditStatus');
  if (!modal || !item) return;

  waScheduleEditState = { type, id: item.id };
  const isCopy = type === 'copy';
  if (title) title.textContent = isCopy ? 'Editar agendamento de adição' : 'Editar mensagem agendada';
  if (status) {
    status.textContent = 'Edite os campos e salve para reativar/corrigir o agendamento.';
    status.className = 'status muted';
  }

  setSafeVal('waScheduleEditId', item.id);
  setSafeVal('waScheduleEditType', type);
  setSafeVal('waScheduleEditName', normalizeDashboardText(item.name || ''));
  setSafeChecked('waScheduleEditEnabled', !!item.enabled);
  setSafeVal('waScheduleEditCopySourceGroup', item.sourceGroupId || '');
  setSafeVal('waScheduleEditCopyTargetGroup', item.targetGroupId || '');
  setSafeVal('waScheduleEditCopyBatchSize', Number(item.batchSize || 1));
  setSafeVal('waScheduleEditCopyInterval', Number(item.intervalMinutes || 1));
  setSafeVal('waScheduleEditCopyStartAt', toLocalDateTimeInputValue(item.nextRunAt || item.createdAt || new Date().toISOString()));
  setSafeChecked('waScheduleEditCopyRefreshQueue', true);
  setSafeVal('waScheduleEditInstanceName', item.instanceName || '');

  setSafeVal('waScheduleEditMessageTargetGroup', item.targetGroupId || '');
  setSafeVal('waScheduleEditMessageInterval', Number(item.intervalMinutes || 1));
  setSafeVal('waScheduleEditMessageStartAt', toLocalDateTimeInputValue(item.nextRunAt || item.createdAt || new Date().toISOString()));
  setSafeVal('waScheduleEditMessageImageUrl', item.imageUrl || '');
  setSafeVal('waScheduleEditMessageText', normalizeDashboardText(item.text || ''));

  const sourceSelect = document.getElementById('waScheduleEditCopySourceGroup');
  const targetSelect = document.getElementById('waScheduleEditCopyTargetGroup');
  const messageSelect = document.getElementById('waScheduleEditMessageTargetGroup');
  const options = buildGroupOptions(waAdminGroupsCache || [], 'Selecione o grupo...');
  if (sourceSelect) sourceSelect.innerHTML = options;
  if (targetSelect) targetSelect.innerHTML = options;
  if (messageSelect) messageSelect.innerHTML = options;
  populateWaInstanceSelect('waScheduleEditInstanceName', item.instanceName || '');
  setSafeVal('waScheduleEditCopySourceGroup', item.sourceGroupId || '');
  setSafeVal('waScheduleEditCopyTargetGroup', item.targetGroupId || '');
  setSafeVal('waScheduleEditMessageTargetGroup', item.targetGroupId || '');

  toggleWaScheduleEditorFieldGroup(type);
  modal.classList.add('show');
}

async function saveWaScheduleEditor() {
  const status = document.getElementById('waScheduleEditStatus');
  const btn = document.getElementById('btnSaveWaScheduleEdit');
  const id = document.getElementById('waScheduleEditId')?.value?.trim();
  const type = document.getElementById('waScheduleEditType')?.value?.trim();
  const name = document.getElementById('waScheduleEditName')?.value?.trim() || '';
  const enabled = !!document.getElementById('waScheduleEditEnabled')?.checked;
  const startAtCopy = document.getElementById('waScheduleEditCopyStartAt')?.value || '';
  const startAtMessage = document.getElementById('waScheduleEditMessageStartAt')?.value || '';

  if (!id || !type) {
    if (status) {
      status.textContent = 'Não foi possível identificar o agendamento.';
      status.className = 'status warn';
    }
    return;
  }

  if (btn) btn.disabled = true;
  if (status) {
    status.textContent = 'Salvando alterações...';
    status.className = 'status muted';
  }

  try {
    if (type === 'copy') {
      const sourceGroupId = document.getElementById('waScheduleEditCopySourceGroup')?.value || '';
      const targetGroupId = document.getElementById('waScheduleEditCopyTargetGroup')?.value || '';
      const batchSize = Number(document.getElementById('waScheduleEditCopyBatchSize')?.value || 0);
      const intervalMinutes = Number(document.getElementById('waScheduleEditCopyInterval')?.value || 0);
      const refreshQueue = !!document.getElementById('waScheduleEditCopyRefreshQueue')?.checked;
      const instanceName = (document.getElementById('waScheduleEditInstanceName')?.value || '').trim();

      if (!sourceGroupId || !targetGroupId) {
        throw { data: { error: 'Selecione os grupos de origem e destino.' } };
      }

      if (sourceGroupId === targetGroupId) {
        throw { data: { error: 'Grupo de origem e destino não podem ser o mesmo.' } };
      }

      const payload = {
        name,
        sourceGroupId,
        targetGroupId,
        batchSize,
        intervalMinutes,
        enabled,
        refreshQueue,
        instanceName: instanceName || null,
        startAt: startAtCopy ? new Date(startAtCopy).toISOString() : null
      };

      const res = await api(`/api/admin/whatsapp/copy-schedules/${encodeURIComponent(id)}`, 'PUT', payload);
      if (status) {
        status.textContent = res?.message || 'Agendamento atualizado com sucesso.';
        status.className = 'status ok';
      }
    } else {
      const targetGroupId = document.getElementById('waScheduleEditMessageTargetGroup')?.value || '';
      const text = document.getElementById('waScheduleEditMessageText')?.value || '';
      const intervalMinutes = Number(document.getElementById('waScheduleEditMessageInterval')?.value || 0);
      const imageUrl = document.getElementById('waScheduleEditMessageImageUrl')?.value?.trim() || '';
      const instanceName = (document.getElementById('waScheduleEditInstanceName')?.value || '').trim();

      if (!targetGroupId || !text.trim()) {
        throw { data: { error: 'Selecione o grupo e preencha a mensagem.' } };
      }

      if (imageUrl) {
        try {
          const parsed = new URL(imageUrl);
          if (!isPublicAbsoluteUrl(imageUrl) || looksLikeInternalHost(parsed.hostname)) {
            throw { data: { error: 'A imagem precisa ser uma URL pública do domínio.' } };
          }
        } catch {
          throw { data: { error: 'A imagem precisa ser uma URL pública válida.' } };
        }
      }

      const payload = {
        name,
        targetGroupId,
        text,
        intervalMinutes,
        enabled,
        imageUrl: imageUrl || null,
        instanceName: instanceName || null,
        startAt: startAtMessage ? new Date(startAtMessage).toISOString() : null
      };

      const res = await api(`/api/admin/whatsapp/message-schedules/${encodeURIComponent(id)}`, 'PUT', payload);
      if (status) {
        status.textContent = res?.message || 'Mensagem agendada atualizada com sucesso.';
        status.className = 'status ok';
      }
    }

    await loadWhatsAppAutomation();
    closeWaScheduleEditor();
  } catch (err) {
    console.error('Erro ao salvar agendamento editado', err);
    if (status) {
      status.textContent = err?.data?.error || err?.message || 'Erro ao salvar alterações.';
      status.className = 'status warn';
    }
  } finally {
    if (btn) btn.disabled = false;
  }
}

function renderWhatsAppAutomation(automation) {
  waAutomationCache = automation || { participantCopySchedules: [], scheduledGroupMessages: [] };

  const safeDailyLimit = Number(waAutomationCache.maxParticipantsAddedPerDay || 120);
  const safeCooldown = Number(waAutomationCache.minMinutesBetweenParticipantAdds || 10);
  const addedToday = Number(waAutomationCache.participantsAddedToday || 0);
  const remainingQuota = Math.max(0, safeDailyLimit - addedToday);
  const isParticipantCopyAutomationEnabled = waAutomationCache.participantCopyAutomationEnabled === true;

  setSafeVal('waSafetyDailyLimit', safeDailyLimit);
  setSafeVal('waSafetyCooldownMinutes', safeCooldown);
  setSafeText('waSafetyParticipantsAddedToday', String(addedToday));
  setSafeText('waSafetyRemainingQuota', String(remainingQuota));
  setSafeText('waParticipantCopyPauseState', isParticipantCopyAutomationEnabled ? 'Pausa desativada' : 'Pausa ativada');

  const pauseState = document.getElementById('waParticipantCopyPauseState');
  if (pauseState) pauseState.className = `badge ${isParticipantCopyAutomationEnabled ? 'ok' : 'warn'}`;

  const togglePauseBtn = document.getElementById('btnToggleWaCopyPause');
  if (togglePauseBtn) {
    togglePauseBtn.textContent = isParticipantCopyAutomationEnabled ? 'Ativar pausa' : 'Desativar pausa';
    togglePauseBtn.disabled = (currentRole !== 'admin');
  }

  const copyList = document.getElementById('waCopySchedulesList');
  const messageList = document.getElementById('waMessageSchedulesList');
  const copySchedules = waAutomationCache.participantCopySchedules || [];
  const messageSchedules = waAutomationCache.scheduledGroupMessages || [];
  notifyCompletedCopySchedules(copySchedules);

  if (copyList) {
    if (copySchedules.length === 0) {
      copyList.innerHTML = '<span class="muted">Nenhum agendamento criado.</span>';
    } else {
      copyList.innerHTML = copySchedules.map(item => `
        ${(() => {
          const requestedBatch = Number(item.batchSize || 0);
          const effectiveBatch = Math.min(requestedBatch > 0 ? requestedBatch : 1, remainingQuota);
          const quotaWarning = item.enabled && requestedBatch > 0 && remainingQuota > 0 && effectiveBatch < requestedBatch
            ? `<div class="badge warn" style="margin-top:8px;">Lote atual limitado pela quota diária: ${effectiveBatch}/${requestedBatch}</div>`
            : '';
          const quotaExhausted = item.enabled && remainingQuota <= 0
            ? `<div class="badge warn" style="margin-top:8px;">Quota diária esgotada: o próximo lote só roda na próxima janela.</div>`
            : '';
          const globalPauseWarning = !isParticipantCopyAutomationEnabled
            ? `<div class="badge warn" style="margin-top:8px;">Pausa global ativa: este agendamento não executa até a pausa ser desativada.</div>`
            : '';
          return `
          <div class="card" style="padding:12px; margin-bottom:10px;">
            <div class="row" style="justify-content:space-between; align-items:flex-start; gap:12px;">
              <div>
                <strong>${escapeHtml(item.name || 'Agendamento de cópia')}</strong><br />
                <small class="muted">${escapeHtml(getGroupNameById(item.sourceGroupId))} -> ${escapeHtml(getGroupNameById(item.targetGroupId))}</small>
            </div>
            <div class="row" style="gap:8px;">
              ${getCopyScheduleBadge(item)}
              <button class="secondary" onclick="editWaSchedule('copy', '${escapeHtml(item.id)}')">Editar</button>
              ${!item.enabled && !item.cancelledAt && !item.completedAt ? `<button class="secondary" onclick="reactivateParticipantCopySchedule('${escapeHtml(item.id)}')">Reativar</button>` : ''}
              ${item.enabled ? `<button class="secondary" onclick="pauseParticipantCopySchedule('${escapeHtml(item.id)}')">Pausar</button>` : ''}
              ${!item.cancelledAt ? `<button class="secondary" onclick="runCopyScheduleNow('${escapeHtml(item.id)}')">Executar agora</button>` : ''}
              ${!item.cancelledAt ? `<button class="secondary" onclick="cancelParticipantCopySchedule('${escapeHtml(item.id)}')">Cancelar</button>` : ''}
              <button class="secondary" onclick="deleteParticipantCopySchedule('${item.id}')">Excluir</button>
              </div>
            </div>
            <div class="muted" style="margin-top:8px;">
              Processados: ${Number(item.processedParticipants || 0)} / ${Number(item.totalParticipants || 0)} | Ignorados: ${Number(item.skippedParticipants || 0)} | Lote: ${Number(item.batchSize || 0)} | Intervalo: ${Number(item.intervalMinutes || 0)} min
            </div>
            ${globalPauseWarning}
            ${quotaWarning}
            ${quotaExhausted}
            <div class="muted" style="margin-top:6px; font-size:0.9em;">${formatWaAutomationStatus(item)}</div>
          </div>
          `;
        })()}
      `).join('');
    }
  }

  if (messageList) {
    if (messageSchedules.length === 0) {
      messageList.innerHTML = '<span class="muted">Nenhuma mensagem agendada.</span>';
    } else {
      messageList.innerHTML = messageSchedules.map(item => `
        <div class="card" style="padding:12px; margin-bottom:10px;">
          <div class="row" style="justify-content:space-between; align-items:flex-start; gap:12px;">
            <div>
              <strong>${escapeHtml(item.name || 'Mensagem agendada')}</strong><br />
              <small class="muted">${escapeHtml(getGroupNameById(item.targetGroupId))}</small>
            </div>
            <div class="row" style="gap:8px;">
              ${getMessageScheduleBadge(item)}
              <button class="secondary" onclick="editWaSchedule('message', '${escapeHtml(item.id)}')">Editar</button>
              ${item.enabled ? `<button class="secondary" onclick="pauseMessageSchedule('${escapeHtml(item.id)}')">Pausar</button>` : ''}
              ${!item.cancelledAt ? `<button class="secondary" onclick="runMessageScheduleNow('${escapeHtml(item.id)}')">Enviar agora</button>` : ''}
              ${!item.cancelledAt ? `<button class="secondary" onclick="cancelMessageSchedule('${escapeHtml(item.id)}')">Cancelar</button>` : ''}
              <button class="secondary" onclick="deleteScheduledGroupMessage('${item.id}')">Excluir</button>
            </div>
          </div>
          ${item.imageUrl ? `
            <div style="margin-top:10px;">
              <small class="muted">Imagem pública:</small><br />
              <a href="${escapeHtml(item.imageUrl)}" target="_blank" rel="noopener noreferrer">${escapeHtml(item.imageUrl)}</a>
            </div>
          ` : ''}
          <div style="margin-top:8px; white-space:pre-wrap;">${escapeHtml(item.text || '')}</div>
          <div class="muted" style="margin-top:6px;">Intervalo: ${Number(item.intervalMinutes || 0)} min</div>
          <div class="muted" style="margin-top:6px; font-size:0.9em;">${formatWaAutomationStatus(item)}</div>
        </div>
      `).join('');
    }
  }

  renderWhatsAppAutomationQueue(waAutomationQueueCache);
  renderScheduledMessagePreview();
}

async function loadWhatsAppAutomation() {
  const copyList = document.getElementById('waCopySchedulesList');
  const messageList = document.getElementById('waMessageSchedulesList');
  const queueList = document.getElementById('waAutomationQueueList');
  if (copyList) copyList.innerHTML = '<span class="muted">Carregando agendamentos...</span>';
  if (messageList) messageList.innerHTML = '<span class="muted">Carregando mensagens agendadas...</span>';
  if (queueList) queueList.innerHTML = '<span class="muted">Carregando fila...</span>';

  try {
    const [automation, queue] = await Promise.all([
      api('/api/admin/whatsapp/automation'),
      api('/api/admin/whatsapp/automation/queue')
    ]);
    renderWhatsAppAutomation(automation);
    renderWhatsAppAutomationQueue(queue);
  } catch (err) {
    console.error('Erro ao carregar automações do WhatsApp', err);
    if (copyList) copyList.innerHTML = '<span class="warn">Erro ao carregar agendamentos.</span>';
    if (messageList) messageList.innerHTML = '<span class="warn">Erro ao carregar mensagens agendadas.</span>';
    if (queueList) queueList.innerHTML = '<span class="warn">Erro ao carregar fila.</span>';
  }
}

async function saveWhatsAppAutomationSafetySettings() {
  const btn = document.getElementById('btnSaveWaSafetySettings');
  const status = document.getElementById('waSafetySettingsStatus');
  const maxParticipantsAddedPerDay = Number(document.getElementById('waSafetyDailyLimit')?.value || 0);
  const minMinutesBetweenParticipantAdds = Number(document.getElementById('waSafetyCooldownMinutes')?.value || 0);
  const participantCopyAutomationEnabled = waAutomationCache?.participantCopyAutomationEnabled === true;

  if (!Number.isFinite(maxParticipantsAddedPerDay) || maxParticipantsAddedPerDay <= 0) {
    if (status) {
      status.textContent = 'Informe um limite diário maior que zero.';
      status.className = 'status warn';
    }
    return;
  }

  if (!Number.isFinite(minMinutesBetweenParticipantAdds) || minMinutesBetweenParticipantAdds <= 0) {
    if (status) {
      status.textContent = 'Informe um cooldown mínimo maior que zero.';
      status.className = 'status warn';
    }
    return;
  }

  if (status) {
    status.textContent = 'Salvando travas...';
    status.className = 'status muted';
  }
  if (btn) btn.disabled = true;

  try {
    const res = await api('/api/admin/whatsapp/automation/safety', 'PUT', {
      maxParticipantsAddedPerDay,
      minMinutesBetweenParticipantAdds,
      participantCopyAutomationEnabled
    });

    if (status) {
      status.textContent = res?.message || 'Travas atualizadas com sucesso.';
      status.className = 'status ok';
    }

    await loadWhatsAppAutomation();
  } catch (err) {
    console.error('Erro ao salvar travas de segurança do WhatsApp', err);
    if (status) {
      status.textContent = err?.data?.error || 'Erro ao salvar travas de segurança.';
      status.className = 'status warn';
    }
  } finally {
    if (btn) btn.disabled = (currentRole !== 'admin');
  }
}

async function createParticipantCopySchedule() {
  const btn = document.getElementById('btnCreateCopySchedule');
  const status = document.getElementById('waScheduleCopyStatus');
  const sourceGroupId = document.getElementById('waScheduleCopySourceGroup')?.value;
  const targetGroupId = document.getElementById('waScheduleCopyTargetGroup')?.value;
  const name = document.getElementById('waScheduleCopyName')?.value || '';
  const batchSize = Number(document.getElementById('waScheduleCopyBatchSize')?.value || 0);
  const intervalMinutes = Number(document.getElementById('waScheduleCopyInterval')?.value || 0);
  const instanceName = (document.getElementById('waScheduleCopyInstanceName')?.value || '').trim();

  if (!sourceGroupId || !targetGroupId) {
    if (status) {
      status.textContent = 'Selecione os grupos.';
      status.className = 'status warn';
    }
    return;
  }

  if (sourceGroupId === targetGroupId) {
    if (status) {
      status.textContent = 'Origem e destino não podem ser iguais.';
      status.className = 'status warn';
    }
    return;
  }

  if (batchSize <= 0 || intervalMinutes <= 0) {
    if (status) {
      status.textContent = 'Informe lote e intervalo válidos.';
      status.className = 'status warn';
    }
    return;
  }

  const participantIds = Array.from(document.querySelectorAll('.wa-participant-checkbox:checked')).map(cb => cb.value);
  if (participantIds.length === 0) {
    if (status) {
      status.textContent = 'Nenhum participante selecionado. O agendamento vai usar todos os membros do grupo de origem.';
      status.className = 'status muted';
    }
  }

  if (status) {
    status.textContent = 'Criando agendamento...';
    status.className = 'status muted';
  }
  if (btn) btn.disabled = true;

  try {
    const res = await api('/api/admin/whatsapp/copy-schedules', 'POST', {
      name,
      sourceGroupId,
      targetGroupId,
      batchSize,
      intervalMinutes,
      participantIds,
      instanceName: instanceName || null
    });
    if (status) {
      status.textContent = res?.message || `Agendamento criado. Repetidos ignorados: ${Number(res?.skippedParticipants || 0)}.`;
      status.className = 'status ok';
    }
    await loadWhatsAppAutomation();
  } catch (err) {
    console.error('Erro ao criar agendamento de cópia', err);
    if (status) {
      status.textContent = err?.data?.error || 'Erro ao criar agendamento.';
      status.className = 'status warn';
    }
  } finally {
    if (btn) btn.disabled = false;
  }
}

async function deleteParticipantCopySchedule(id) {
  if (!id) return;
  if (!confirm('Excluir este agendamento de adição?')) return;

  try {
    await api(`/api/admin/whatsapp/copy-schedules/${encodeURIComponent(id)}`, 'DELETE');
    await loadWhatsAppAutomation();
  } catch (err) {
    console.error('Erro ao excluir agendamento de cópia', err);
    alert(err?.data?.error || 'Erro ao excluir agendamento.');
  }
}

async function toggleWhatsAppParticipantCopyPause() {
  const btn = document.getElementById('btnToggleWaCopyPause');
  const status = document.getElementById('waSafetySettingsStatus');
  const maxParticipantsAddedPerDay = Number(document.getElementById('waSafetyDailyLimit')?.value || 0);
  const minMinutesBetweenParticipantAdds = Number(document.getElementById('waSafetyCooldownMinutes')?.value || 0);
  const currentlyEnabled = waAutomationCache?.participantCopyAutomationEnabled === true;
  const nextEnabled = !currentlyEnabled;
  const confirmationMessage = nextEnabled
    ? 'Desativar a pausa global e permitir novamente a cópia de participantes?'
    : 'Ativar a pausa global e impedir qualquer nova cópia de participantes?';

  if (!confirm(confirmationMessage)) {
    return;
  }

  if (!Number.isFinite(maxParticipantsAddedPerDay) || maxParticipantsAddedPerDay <= 0 || !Number.isFinite(minMinutesBetweenParticipantAdds) || minMinutesBetweenParticipantAdds <= 0) {
    if (status) {
      status.textContent = 'Revise os valores de limite diário e cooldown antes de alterar a pausa.';
      status.className = 'status warn';
    }
    return;
  }

  if (status) {
    status.textContent = nextEnabled ? 'Desativando pausa global...' : 'Ativando pausa global...';
    status.className = 'status muted';
  }
  if (btn) btn.disabled = true;

  try {
    const res = await api('/api/admin/whatsapp/automation/safety', 'PUT', {
      maxParticipantsAddedPerDay,
      minMinutesBetweenParticipantAdds,
      participantCopyAutomationEnabled: nextEnabled
    });

    if (status) {
      status.textContent = nextEnabled
        ? (res?.message || 'Pausa global desativada com sucesso.')
        : (res?.message || 'Pausa global ativada com sucesso.');
      status.className = 'status ok';
    }

    await loadWhatsAppAutomation();
  } catch (err) {
    console.error('Erro ao alternar pausa global da cópia de participantes', err);
    if (status) {
      status.textContent = err?.data?.error || 'Erro ao alterar a pausa global.';
      status.className = 'status warn';
    }
  } finally {
    if (btn) btn.disabled = (currentRole !== 'admin');
  }
}

function getPublicRouteUrl(path) {
  try {
    return new URL(path, window.location.origin).toString();
  } catch {
    return path;
  }
}

function applyScheduledMessageTemplate(templateKey) {
  const textEl = document.getElementById('waMessageScheduleText');
  const nameEl = document.getElementById('waMessageScheduleName');
  const imageEl = document.getElementById('waMessageScheduleImageUrl');
  const conversorUrl = buildPublicUrl('/conversor');
  const bioUrl = buildPublicUrl('/bio');
  const conversorImageUrl = buildPublicUrl('/assets/messages/conversor-vip-banner.svg');
  const bioImageUrl = buildPublicUrl('/assets/messages/bio-vip-banner.svg');
  const silentImageUrl = buildPublicUrl('/assets/messages/silenciar-template.png');
  if (!conversorUrl || !bioUrl || !conversorImageUrl || !bioImageUrl || !silentImageUrl) {
    const status = document.getElementById('waMessageScheduleStatus');
    if (status) {
      status.textContent = 'Configure BioHub.PublicBaseUrl com o dominio publico antes de usar os modelos.';
      status.className = 'status warn';
    }
    return;
  }

  const templates = {
    conversor: {
      name: 'Aviso conversor',
      text: `Use nosso conversor para transformar qualquer link em link pronto para oferta:\n${conversorUrl}\n\nAbra quando precisar e compartilhe com quem quiser.`,
      imageUrl: conversorImageUrl
    },
    bio: {
      name: 'Aviso bio',
      text: `Nossa bio está atualizada com os principais atalhos e destaques:\n${bioUrl}\n\nSalve o link para acessar sempre que quiser.`,
      imageUrl: bioImageUrl
    },
    silent: {
      name: 'Aviso silenciar grupo',
      text: `Para não perder as ofertas e evitar excesso de notificações, deixe este grupo silenciado.\n\nNo WhatsApp: abra o grupo -> toque no nome -> Silenciar notificações -> Sempre.\n\nEnquanto isso, acompanhe o conversor aqui:\n${conversorUrl}`,
      imageUrl: silentImageUrl
    }
  };

  const preset = templates[templateKey];
  if (!preset) return;
  if (nameEl) nameEl.value = preset.name;
  if (textEl) textEl.value = preset.text;
  if (imageEl) imageEl.value = preset.imageUrl || '';
  renderScheduledMessagePreview();

  const status = document.getElementById('waMessageScheduleStatus');
  if (status) {
    status.textContent = `Modelo "${preset.name}" aplicado. Ajuste o texto se quiser.`;
    status.className = 'status ok';
  }
}

async function createScheduledGroupMessage() {
  const btn = document.getElementById('btnCreateMessageSchedule');
  const status = document.getElementById('waMessageScheduleStatus');
  const name = document.getElementById('waMessageScheduleName')?.value || '';
  const targetGroupId = document.getElementById('waMessageScheduleTargetGroup')?.value;
  const text = document.getElementById('waMessageScheduleText')?.value || '';
  const imageUrl = document.getElementById('waMessageScheduleImageUrl')?.value || '';
  const intervalMinutes = Number(document.getElementById('waMessageScheduleInterval')?.value || 0);
  const instanceName = (document.getElementById('waMessageScheduleInstanceName')?.value || '').trim();

  if (!targetGroupId || !text.trim()) {
    if (status) {
      status.textContent = 'Selecione o grupo e escreva a mensagem.';
      status.className = 'status warn';
    }
    return;
  }

  if (intervalMinutes <= 0) {
    if (status) {
      status.textContent = 'Informe um intervalo válido.';
      status.className = 'status warn';
    }
    return;
  }

  if (status) {
    status.textContent = 'Criando mensagem agendada...';
    status.className = 'status muted';
  }
  if (btn) btn.disabled = true;

  try {
    if (imageUrl) {
      try {
        const parsed = new URL(imageUrl);
        if (!isPublicAbsoluteUrl(imageUrl) || looksLikeInternalHost(parsed.hostname)) {
          if (status) {
            status.textContent = 'A imagem precisa ser uma URL publica do dominio.';
            status.className = 'status warn';
          }
          return;
        }
      } catch {
        if (status) {
          status.textContent = 'ImageUrl precisa ser uma URL publica valida.';
          status.className = 'status warn';
        }
        return;
      }
    }

    await api('/api/admin/whatsapp/message-schedules', 'POST', {
      name,
      targetGroupId,
      text,
      intervalMinutes,
      imageUrl,
      instanceName: instanceName || null
    });
    if (status) {
      status.textContent = 'Mensagem agendada criada.';
      status.className = 'status ok';
    }
    await loadWhatsAppAutomation();
  } catch (err) {
    console.error('Erro ao criar mensagem agendada', err);
    if (status) {
      status.textContent = err?.data?.error || 'Erro ao criar mensagem agendada.';
      status.className = 'status warn';
    }
  } finally {
    if (btn) btn.disabled = false;
  }
}

async function deleteScheduledGroupMessage(id) {
  if (!id) return;
  if (!confirm('Excluir esta mensagem agendada?')) return;

  try {
    await api(`/api/admin/whatsapp/message-schedules/${encodeURIComponent(id)}`, 'DELETE');
    await loadWhatsAppAutomation();
  } catch (err) {
    console.error('Erro ao excluir mensagem agendada', err);
    alert(err?.data?.error || 'Erro ao excluir mensagem agendada.');
  }
}

function renderMonitorGroups(groups, selectedIds) {
  const picker = document.getElementById('waMonitorGroupPicker');
  if (!picker) return;
  
  if (!groups || groups.length === 0) {
    if (picker.children.length <= 1) {
      picker.innerHTML = '<span class="muted">Nenhum grupo encontrado ou carregado. Clique em Atualizar.</span>';
    }
    return;
  }

  picker.innerHTML = groups.map(g => `
    <div class="chat-item">
      <input type="checkbox" id="chk-mon-${g.id}" value="${g.id}" ${selectedIds.includes(g.id) ? 'checked' : ''} />
      <label for="chk-mon-${g.id}" class="chat-item-label">
        <strong>${escapeHtml(g.name || 'Sem nome')}</strong><br/>
        <small class="muted">${g.id}</small>
      </label>
    </div>
  `).join('');
}

async function saveMonitorSelection() {
  const status = document.getElementById('waMonitorSaveStatus');
  if (status) status.textContent = 'Salvando...';
  
  try {
    const picker = document.getElementById('waMonitorGroupPicker');
    const selectedIds = Array.from(picker.querySelectorAll('input[type="checkbox"]:checked')).map(cb => cb.value);
    
    // Load existing settings to avoid overwriting other automation flags
    const settings = await api('/api/settings');
    settings.monitoredGroupIds = selectedIds;
    
    await api('/api/settings', 'PUT', settings);
    if (status) {
      status.textContent = 'Salvo com sucesso!';
      status.className = 'status ok';
      setTimeout(() => { status.textContent = ''; }, 3000);
    }
  } catch (err) {
    console.error('Erro ao salvar seleção de monitoramento', err);
    if (status) {
      status.textContent = 'Erro ao salvar.';
      status.className = 'status warn';
    }
  }
}

async function loadMembershipEvents(forceSync = false) {
  const tbody = document.getElementById('waMonitorEventBody');
  if (tbody) tbody.innerHTML = '<tr><td colspan="4" class="muted">Carregando eventos...</td></tr>';
  
  try {
    if (forceSync) {
      await api('/api/admin/whatsapp/membership-events/sync', 'POST', {});
    }
    const events = await api('/api/admin/whatsapp/membership-events');
    if (!tbody) return;
    
    if (!events || events.length === 0) {
      tbody.innerHTML = '<tr><td colspan="4" class="muted">Nenhum evento registrado ainda.</td></tr>';
      return;
    }
    
    tbody.innerHTML = events.map(e => `
      <tr>
        <td>${formatTs(e.timestamp)}</td>
        <td title="${escapeHtml(e.groupId)}">${escapeHtml(e.groupName || shortId(e.groupId))}</td>
        <td title="${escapeHtml(e.participantId)}">${escapeHtml(e.participantName || shortId(e.participantId))}</td>
        <td>
          <span class="badge ${e.action === 'join' ? 'ok' : 'danger'}">
            ${e.action === 'join' ? 'Entrou' : 'Saiu'}
          </span>
        </td>
      </tr>
    `).join('');
  } catch (err) {
    console.error('Erro ao carregar eventos de adesão', err);
    if (tbody) tbody.innerHTML = '<tr><td colspan="4" class="warn">Erro ao carregar eventos.</td></tr>';
  }
}

