# Roadmap de decomposição do Program

## Objetivo

Reduzir o acoplamento de `Program.cs` sem alterar os contratos públicos, o fluxo de entrega ou a separação entre DEV e produção.

## Ordem de extração

1. **Rotas administrativas de WhatsApp**: agendamentos, automações, grupos e mídia. São rotas autenticadas, com fronteiras HTTP claras e menor risco de afetar entregas.
2. **Rotas públicas e catálogo**: conversor, bio, catálogo, mídia pública e redirecionamentos. Cada rota deverá receber teste de contrato antes da migração.
3. **Webhooks de entrada**: Evolution, Bot Conversor e Instagram. Só após os contratos e a telemetria de falha estarem explícitos.
4. **Funções de domínio restantes**: parsing de mensagens, mídia, Instagram e aprovação viral serão movidos gradualmente para serviços coesos com dependências injetadas.

## Progresso desta etapa

- Autenticação: `Program.cs` passou a apenas registrar `MapAuthEndpoints`; login, logout, sessão e CSRF permanecem no módulo próprio. Registros de depuração que revelavam metadados de credenciais foram removidos.
- Mídia pública remota: a rota `GET /media/remote` foi movida para `PublicMediaEndpoints`, com testes de contrato para rejeição de URL inválida/conteúdo não-imagem e preservação do proxy de imagem e cache.
- Webhooks externos: `POST /webhooks/evolution` e `POST /webhook/bot-conversor` foram movidos para `ExternalWebhookEndpoints`. A autorização foi centralizada em `WebhookRequestAuthorizer` e o parsing de eventos de participação em `EvolutionMembershipEventParser`, reutilizado também pelo worker interno. Os testes cobrem rejeição antes do enfileiramento, enfileiramento assíncrono, idempotência e monitoramento de membros.
- Webhook interno: a fronteira de exposição e acesso foi isolada em `InternalWebhookBoundaryExtensions`. O runtime web agora oculta a rota interna antes do roteamento; o runtime worker aceita somente loopback ou uma credencial de webhook válida. A lógica operacional de mensagens permanece no worker e será extraída gradualmente por fluxos de domínio, sem uma cópia arriscada do handler de 957 linhas.

## Pendências de segurança a decidir

- `GET /media/remote` ainda aceita qualquer URL HTTP(S), como o contrato legado. Antes de restringir hosts, endereços privados ou redirecionamentos, é preciso definir uma lista de origens permitidas para não interromper imagens de ofertas existentes. Essa mudança deve ser tratada como reforço de segurança separado, com homologação em DEV.

## Regras de cada extração

- Não alterar URL, método HTTP, autorização, payload ou código de resposta sem teste e decisão explícita.
- Não emitir ofertas, reprocessar filas ou chamar integrações externas em testes.
- Compilar, executar as suítes e reconstruir DEV isolado antes de qualquer promoção.
- Uma extração por domínio; nada de refatoração ampla misturada com mudança funcional.

## Critério de conclusão

`Program.cs` deve ficar responsável apenas por composição, configuração, middleware e registro dos módulos. Regras de domínio, parsing e I/O devem estar em serviços ou módulos de endpoint testáveis.
