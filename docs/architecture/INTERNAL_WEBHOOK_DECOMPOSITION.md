# Decomposição do webhook interno Bot Conversor

## Regra de segurança

O endpoint interno permanece exclusivo do runtime `worker`. Chamadas remotas exigem assinatura ou chave de webhook; o runtime `web` responde `404` antes do roteamento. Nenhuma etapa pode alterar esse contrato.

## Ordem de extração

1. **Intake e deduplicação**: leitura do payload, eventos de membership, parsing e chave de idempotência da mensagem.
2. **Comandos e conversas**: ajuda, menu Instagram, seleção de legenda, aprovação de Reel, convite e price watch.
3. **Resposta direta**: autoresposta e conversão para o chat de origem, incluindo tracking e mídia.
4. **Encaminhamento**: seleção de rota, conversão, qualidade da oferta, imagem, proteção do grupo oficial, deduplicação outbound e registro de falhas.

## Critérios obrigatórios por extração

- Criar teste de contrato que não envie mensagem nem publique oferta.
- Preservar as janelas de idempotência e os destinos autorizados.
- Manter `DeliverySafetyPolicy`, `OfferQualityGate` e `OfficialWhatsAppGroupGuard` no caminho de encaminhamento.
- Validar build, testes focados, imagem e smoke DEV antes de qualquer promoção.

## Estado atual

A fronteira HTTP e de autorização está separada. O processamento operacional ainda está no handler legado e será movido pelos quatro fluxos acima; não será copiado integralmente para outro arquivo, pois isso aumenta o risco sem reduzir o acoplamento real.
