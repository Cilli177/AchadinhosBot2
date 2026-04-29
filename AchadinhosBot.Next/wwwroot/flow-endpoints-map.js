(function (global) {
  const BASE_ROWS = [
    {
      canal: 'Telegram',
      nome: 'AE-IA 3000 - VÍDEOS VIRAIS',
      ids: ['2425105459'],
      papel: 'Origem de reels e vídeo do produto',
      destino: 'Instagram - preview e publicação'
    },
    {
      canal: 'Telegram',
      nome: 'Rota Telegram principal',
      ids: ['1871121243', '1271986083', '2775581964', '3703804341', '1569488789', '3632436217'],
      papel: 'Origem Telegram para WhatsApp',
      destino: 'Grupo oficial WhatsApp'
    },
    {
      canal: 'WhatsApp',
      nome: 'Rota Nova Oficial',
      ids: ['120363399495595930@g.us', '120363216142767996@g.us', '120363390817589999@g.us', '120363401464158461@g.us', '120363403893859078@g.us', '120363027285871635@g.us', '120363421220620042@g.us', '120363343810565726@g.us', '120363296924962892@g.us', '120363421418282703@g.us'],
      papel: 'Origem WhatsApp principal',
      destino: 'Grupo oficial WhatsApp'
    },
    {
      canal: 'WhatsApp',
      nome: 'Ponte Mercado Livre Scout',
      ids: ['120363409272515351@g.us'],
      papel: 'Ponte e triagem de ofertas do Mercado Livre',
      destino: 'Grupo oficial WhatsApp'
    },
    {
      canal: 'WhatsApp',
      nome: 'Rei das Ofertas Oficial',
      ids: ['120363405661434395@g.us'],
      papel: 'Destino final',
      destino: 'Publicacao e recebimento de ofertas'
    }
  ];

  function uniqueIds(values) {
    return Array.from(new Set(
      (Array.isArray(values) ? values : [])
        .map(value => String(value || '').trim())
        .filter(Boolean)
    ));
  }

  function getSettingsRows(settings) {
    const s = settings || {};
    const tgChats = Array.isArray(s?.InstagramPosts?.TelegramChatIds) && s.InstagramPosts.TelegramChatIds.length
      ? s.InstagramPosts.TelegramChatIds.map(id => String(id).trim()).filter(Boolean)
      : BASE_ROWS[0].ids;
    const tgRoutes = Array.isArray(s?.TelegramToWhatsAppRoutes) ? s.TelegramToWhatsAppRoutes : [];
    const waRoutes = Array.isArray(s?.WhatsAppForwardingRoutes) ? s.WhatsAppForwardingRoutes : [];
    const waForward = s?.WhatsAppForwarding || {};

    const officialDestIds = uniqueIds([
      ...(Array.isArray(waForward.DestinationGroupIds) ? waForward.DestinationGroupIds : []),
      ...tgRoutes.flatMap(route => Array.isArray(route?.DestinationGroupIds) ? route.DestinationGroupIds : []),
      ...waRoutes.flatMap(route => Array.isArray(route?.DestinationGroupIds) ? route.DestinationGroupIds : [])
    ]);

    const rows = [
      {
        canal: 'Telegram',
        nome: 'AE-IA 3000 - VÍDEOS VIRAIS',
        ids: tgChats,
        papel: 'Origem de reels e vídeo do produto',
        destino: 'Instagram - preview e publicação'
      }
    ];

    const telegramRoute = tgRoutes[0] || null;
    if (telegramRoute) {
      rows.push({
        canal: 'Telegram',
        nome: telegramRoute.Name || 'Rota Telegram principal',
        ids: Array.isArray(telegramRoute.SourceChatIds) ? telegramRoute.SourceChatIds.map(id => String(id).trim()).filter(Boolean) : [],
        papel: 'Origem Telegram para WhatsApp',
        destino: Array.isArray(telegramRoute.DestinationGroupIds) && telegramRoute.DestinationGroupIds.length
          ? telegramRoute.DestinationGroupIds.map(id => String(id).trim()).filter(Boolean).join(', ')
          : 'Grupo oficial WhatsApp'
      });
    } else {
      rows.push(BASE_ROWS[1]);
    }

    const waRoute = waRoutes.find(route => (route?.Name || '').trim() === 'Rota Nova Oficial') || waRoutes[0] || null;
    if (waRoute) {
      rows.push({
        canal: 'WhatsApp',
        nome: waRoute.Name || 'Rota Nova Oficial',
        ids: Array.isArray(waRoute.SourceChatIds) ? waRoute.SourceChatIds.map(id => String(id).trim()).filter(Boolean) : [],
        papel: 'Origem WhatsApp principal',
        destino: Array.isArray(waRoute.DestinationGroupIds) && waRoute.DestinationGroupIds.length
          ? waRoute.DestinationGroupIds.map(id => String(id).trim()).filter(Boolean).join(', ')
          : 'Grupo oficial WhatsApp'
      });
    } else {
      rows.push(BASE_ROWS[2]);
    }

    const mlRoute = waRoutes.find(route => (route?.Name || '').trim() === 'Ponte Mercado Livre Scout') || null;
    if (mlRoute) {
      rows.push({
        canal: 'WhatsApp',
        nome: mlRoute.Name || 'Ponte Mercado Livre Scout',
        ids: Array.isArray(mlRoute.SourceChatIds) ? mlRoute.SourceChatIds.map(id => String(id).trim()).filter(Boolean) : [],
        papel: 'Ponte e triagem de ofertas do Mercado Livre',
        destino: Array.isArray(mlRoute.DestinationGroupIds) && mlRoute.DestinationGroupIds.length
          ? mlRoute.DestinationGroupIds.map(id => String(id).trim()).filter(Boolean).join(', ')
          : 'Grupo oficial WhatsApp'
      });
    } else {
      rows.push(BASE_ROWS[3]);
    }

    rows.push({
      canal: 'WhatsApp',
      nome: 'Rei das Ofertas Oficial',
      ids: officialDestIds.length ? officialDestIds : BASE_ROWS[4].ids,
      papel: 'Destino final',
      destino: 'Publicacao e recebimento de ofertas'
    });

    return rows;
  }

  function filterRows(rows, query) {
    const search = String(query || '').trim().toLowerCase();
    const list = Array.isArray(rows) ? rows : [];
    if (!search) return list;
    return list.filter(row => [row.canal, row.nome, row.papel, row.destino, ...(row.ids || [])]
      .some(value => String(value || '').toLowerCase().includes(search)));
  }

  function renderTable(bodyElOrId, searchElOrId, settings) {
    const body = typeof bodyElOrId === 'string' ? document.getElementById(bodyElOrId) : bodyElOrId;
    if (!body) return;

    const searchEl = typeof searchElOrId === 'string' ? document.getElementById(searchElOrId) : searchElOrId;
    const rows = filterRows(getSettingsRows(settings), searchEl?.value || '');

    if (!rows.length) {
      body.innerHTML = '<tr><td colspan="5" class="muted">Nenhuma rota corresponde ao filtro atual.</td></tr>';
      return;
    }

    body.innerHTML = rows.map(row => `
      <tr>
        <td>${row.canal || '-'}</td>
        <td><strong>${row.nome || '-'}</strong></td>
        <td>${(row.ids || []).map(id => `<div><code>${id}</code></div>`).join('')}</td>
        <td>${row.papel || '-'}</td>
        <td>${row.destino || '-'}</td>
      </tr>
    `).join('');
  }

  global.FlowEndpointsMap = {
    baseRows: BASE_ROWS,
    getRows: getSettingsRows,
    filterRows,
    renderTable
  };
})(window);
