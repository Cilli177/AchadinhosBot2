# Roadmap de Evolução — WhatsApp/Telegram nativos + Afiliados + Segurança

## Contexto atual (sandbox)
O `AchadinhosBot.Next` já tem:
- painel web para operação;
- endpoints para configuração;
- fluxo de conversão básico;
- modo sandbox para login de mensageiros.

Isso é um bom ponto de partida para plugar integrações reais sem risco para produção.

---

## 1) WhatsApp nativo via Evolution API — recomendação

## ✅ Recomendo
Usar Evolution API como **gateway oficial do seu sistema**, com:
1. criação de instância por tenant/conta;
2. QR code lifecycle (create/connect/disconnect/reconnect);
3. webhook assinado para eventos de mensagem;
4. fila de saída (Redis) para envio desacoplado.

### Arquitetura sugerida
- `IWhatsAppGateway` (abstração)
- `EvolutionWhatsAppGateway` (implementação HTTP)
- `WhatsAppWebhookController/Endpoint`
- `MessageOrchestrator` para rotear eventos para o processador de links e automações

### Fluxo ideal
1. Usuário clica “Conectar WhatsApp” no painel.
2. Backend chama Evolution API para iniciar sessão.
3. Backend exibe QR code no painel.
4. Ao receber evento de `connected`, atualiza estado da integração.
5. Mensagens entram via webhook -> normalização -> regras -> conversão -> resposta/envio.

### Por que é bom
- separa bem responsabilidade de mensageria;
- facilita observabilidade;
- reduz acoplamento do core com detalhes de protocolo.

---

## 2) Telegram nativo — recomendação

## ✅ Recomendo
Ter **dois conectores separados**:
- `TelegramBotGateway` (Bot API): comandos, atendimento, automações de canal/grupo onde bot é permitido.
- `TelegramUserbotGateway` (WTelegram): somente se realmente precisar ler contextos onde bot não consegue.

### Regras de ouro
- não misturar bot e userbot na mesma classe/mesmo token de estado;
- usar storage separado de sessão userbot;
- ter feature flag para desligar userbot em produção quando necessário.

### Por que separar
- segurança e compliance melhores;
- troubleshooting mais fácil;
- menor risco de bloqueio por comportamento indevido.

---

## 3) Conversão de links afiliados — APIs nativas vs fallback

## ✅ Recomendo fortemente
Modelo de **provider por loja**:
- `IAffiliateProvider`
  - `CanHandle(Uri)`
  - `ConvertAsync(Uri)`

Implementações:
- `AmazonProvider`
- `MercadoLivreProvider`
- `ShopeeProvider`
- `SheinProvider`
- `FallbackProvider` (quando não há API oficial viável)

## Sobre “API nativa para conversão”

### Amazon
- Nem sempre há endpoint universal simples para encurtar/afiliar qualquer URL em tempo real.
- Melhor estratégia: canonicalizar URL + aplicar tag + validar formato.

### Mercado Livre
- Pode exigir token e regras específicas de afiliado/parceiro.
- Recomendo manter integração oficial documentada por credenciais e auditoria de erros.

### Shopee/Shein
- Quando existir endpoint oficial de afiliado, use SDK/HTTP dedicado + assinatura + retry.
- Quando não existir para certo fluxo, usar fallback com regras deterministicas.

## ❌ Não recomendo
- depender 100% de scraping HTML para obter IDs e links afiliados.

### Por quê
- altamente frágil (quebra com mudança de layout);
- risco legal/operacional;
- alta taxa de manutenção.

---

## 4) Segurança e login no seu programa

## ✅ Recomendo adicionar autenticação no painel
Hoje o painel está aberto no sandbox. Para produção:
1. login com usuário/senha + JWT/cookie;
2. RBAC (admin, operador, somente leitura);
3. trilha de auditoria (quem alterou regra, quem conectou sessão);
4. rotação de segredo e criptografia de credenciais em repouso.

### Stack sugerida para auth
- ASP.NET Core Identity + cookie auth (rápido de implementar)
- ou Keycloak/Auth0/Azure AD (se quiser SSO e governança)

## ❌ Não recomendo
- manter dashboard administrativo sem autenticação em ambiente público.

---

## 5) UI/UX — melhorias objetivas

## ✅ Recomendo
1. **Wizard de conexão** (Telegram/WhatsApp): passo-a-passo com status em tempo real.
2. **Editor de regras com validação**: evitar regra inválida (`gatilho => resposta`).
3. **Playground de simulação**: colar mensagem e ver saída antes de ativar em produção.
4. **Logs funcionais no painel**: timeline por integração e por regra acionada.
5. **Feature flags**: ligar/desligar automação por canal e por horário.
6. **Métricas visuais**: taxa de conversão, links processados, erros por provider.

---

## 6) Stack: manter ou trocar?

## Minha sugestão

### Curto prazo (pragmático)
- Manter .NET e evoluir de `HttpListener` para **ASP.NET Core Minimal API + Kestrel**.
- Frontend inicial pode continuar simples (HTML/JS), mas com API REST mais limpa.

### Médio prazo
- Frontend dedicado (React/Next.js ou Blazor) consumindo API autenticada.
- Realtime com SignalR para status de QR, conexão, fila e logs.

## ❌ Não recomendo agora
- reescrever tudo em outro stack (Node/Go/etc) imediatamente.

### Por quê
- alto custo e risco de regressão;
- seu domínio já está no ecossistema .NET;
- mais valor em modularizar e estabilizar primeiro.

---

## 7) O que mais adicionar (alto impacto)

1. **Orquestração por fila** (Redis): inbound/outbound desacoplado.
2. **Idempotência** de mensagens/webhooks (evitar processar duplicado).
3. **Rate limit** por canal/provedor.
4. **Dead-letter queue** para falhas repetidas.
5. **Observabilidade completa**:
   - OpenTelemetry;
   - logs estruturados;
   - métricas por integração/provider.
6. **Testes automatizados**:
   - unitário para parser/detector;
   - integração para providers;
   - contrato para webhooks.
7. **Multi-tenant** (se operar múltiplas contas/clientes).
8. **Scheduler de campanhas** (envio em janela de horário + A/B de copy).

---

## 8) Plano de execução recomendado (ordem)

1. Migrar servidor para ASP.NET Core + autenticação.
2. Implementar `IWhatsAppGateway` com Evolution API real.
3. Implementar `ITelegramGateway` bot + (opcional) userbot com feature flag.
4. Refatorar conversão para providers por loja com fallback controlado.
5. Adicionar fila + idempotência + retries.
6. Subir observabilidade e dashboard de métricas.

---

## 9) Decisões que eu “nego” agora (com motivo)

1. **“Vamos colocar scraping como base de conversão”** → nego.
   - Motivo: instável, caro de manter e vulnerável a quebra.

2. **“Vamos unificar bot + userbot + webhook numa classe só”** → nego.
   - Motivo: retorna ao problema de god class e reduz confiabilidade.

3. **“Painel sem login em produção”** → nego.
   - Motivo: risco crítico de segurança.

4. **“Reescrever tudo em outra linguagem agora”** → nego.
   - Motivo: baixa relação custo/benefício neste estágio.

---

## 10) Próximo passo prático no repositório

Sugiro que o próximo PR implemente:
1. ASP.NET Core Minimal API no `AchadinhosBot.Next`;
2. autenticação básica (cookie + usuário admin inicial por env var);
3. serviço real `EvolutionWhatsAppGateway` com endpoint de QR e webhook de eventos;
4. tela de conexão WhatsApp com status em tempo real.

Com isso vocês já terão base sólida para operação real com segurança.
