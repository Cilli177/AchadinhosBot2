# DIAGNOSTICO TECNICO DA BASE

## 1. Identificacao
- Titulo: Diagnostico tecnico inicial da base AchadinhosBot
- Data: 2026-03-06
- Ambiente analisado: DEV e PROD
- Responsavel: Codex
- Versao do objeto: v00

## 2. Entendimento do cenario atual
- O sistema recebe ofertas de Telegram e WhatsApp, converte links em afiliados, enriquece os dados e redistribui a oferta.
- A operacao atual funciona, mas depende de hotfixes sucessivos, forte acoplamento no runtime principal e servicos externos instaveis.
- O maior risco de negocio hoje e enviar oferta ruim: link errado, afiliacao quebrada, sem imagem ou com dados inconsistentes.

## 3. Diagnostico tecnico
- A stack principal em .NET 8 e viavel para manter a operacao. O problema central nao e a linguagem, e a arquitetura de execucao.
- O arquivo [Program.cs](C:\AchadinhoBot2\AchadinhosBot2\AchadinhosBot.Next\Program.cs) concentra uma parte excessiva da orquestracao do sistema. Isso reduz previsibilidade, aumenta risco de regressao e dificulta teste.
- O estado operacional depende fortemente de arquivos em `/app/data` e JSON/JSONL locais. Isso simplifica bootstrap, mas aumenta risco de concorrencia, corrupcao e baixa auditabilidade em cenarios de crescimento.
- A pipeline versionada no repositorio estava incorreta e apontava para projetos inexistentes, ou seja, nao havia protecao real de CI para esta base.
- Os testes automatizados existentes cobrem utilitarios e partes pontuais, mas nao cobrem o fluxo integrado critico de ingestao, validacao, aprovacao e envio.
- Foi identificado baseline de falha em teste real: `ShopeeShortLinkPayloadTests.BuildShopeePayload_IncludesFiveSubIds_FromSource`.
- Foi identificado baseline de problema operacional local: build bloqueado por arquivo DLL em uso por outro processo, o que indica ausencia de isolamento adequado do ambiente de desenvolvimento.

## 4. Modulos criticos
- Ingestao e roteamento: Telegram Userbot, Telegram Bot e webhook Evolution.
- Conversao e afiliacao: [AffiliateLinkService.cs](C:\AchadinhoBot2\AchadinhosBot2\AchadinhosBot.Next\Application\Services\AffiliateLinkService.cs) e [MessageProcessor.cs](C:\AchadinhoBot2\AchadinhosBot2\AchadinhosBot.Next\Application\Services\MessageProcessor.cs).
- Qualidade e envio: [TelegramUserbotService.cs](C:\AchadinhoBot2\AchadinhoBot2\AchadinhosBot.Next\Infrastructure\Telegram\TelegramUserbotService.cs) e [EvolutionWhatsAppGateway.cs](C:\AchadinhoBot2\AchadinhoBot2\AchadinhosBot.Next\Infrastructure\WhatsApp\EvolutionWhatsAppGateway.cs).
- Persistencia operacional: [MercadoLivreApprovalStore.cs](C:\AchadinhoBot2\AchadinhoBot2\AchadinhosBot.Next\Infrastructure\Storage\MercadoLivreApprovalStore.cs), logs JSONL e media store.

## 5. Problema prioritario identificado
- A operacao ainda nao possui um quality gate unico e explicito para impedir publicacao de oferta ruim.
- Mercado Livre e hoje o ponto de maior instabilidade funcional por depender de resolucao externa, links encurtados e validacao sensivel a parametros.
- Mídia no WhatsApp continua sendo um risco porque a cadeia de envio mistura URL temporaria, base64 e fallback tardio.

## 6. Solucao recomendada
- Curto prazo: estabilizar a base atual, sem reescrita imediata.
- Medio prazo: extrair a orquestracao critica de `Program.cs` para modulos dedicados de pipeline de ofertas.
- Longo prazo: migrar o estado operacional para armazenamento transacional e eventos mais robustos, preservando a stack .NET.

## 7. Justificativa tecnica
- Manter .NET 8 reduz risco de migracao e preserva o conhecimento ja acumulado.
- Reescrever agora aumentaria tempo de indisponibilidade e risco de regressao enquanto o problema principal ainda e operacional.
- A melhor relacao custo/beneficio neste momento e refatoracao incremental por modulos, com governanca e pipeline reais.

## 8. Avaliacao da stack
- Recomendacao atual: manter .NET 8, Docker Compose, RabbitMQ e a base existente no curto prazo.
- Ajustes necessarios: Postgres para estado critico, Redis para idempotencia/cache, OpenTelemetry para rastreabilidade, GitHub Actions valida e deploy controlado por ambiente.
- Nova stack completa so faria sentido apos estabilizar o fluxo atual e medir o gargalo real. Hoje o problema e de desenho operacional, nao de incapacidade da stack principal.

## 9. Plano de estabilizacao imediata
- P0: bloquear qualquer oferta sem gate minimo de qualidade.
- P0: forcar fluxo Mercado Livre via auditoria manual quando nao houver validacao inequívoca.
- P0: padronizar correlation id, operation id e motivo de bloqueio em todos os logs de fluxo.
- P0: separar claramente DEV e PROD com promocao controlada.
- P1: reduzir concentracao em `Program.cs`.
- P1: criar testes integrados de ingestao -> aprovacao -> envio.
- P1: mover estado critico para persistencia transacional.

## 10. Riscos e observacoes
- Risco operacional atual alto para regressao porque ha multiplos hotfixes recentes sobre o mesmo fluxo.
- Risco medio de lock e inconsistencias por uso de arquivos locais como base de estado.
- Risco alto de baixa rastreabilidade quando falhas dependem de servicos externos.

## 11. Proximos passos sugeridos
- Formalizar quality gate unico de oferta.
- Corrigir pipeline e baseline de testes.
- Versionar/documentar objetos alterados em todas as proximas entregas.
- Planejar extracao do pipeline de ofertas para servicos dedicados.
