# Fluxo de Reels Virais: Telegram -> WhatsApp -> Instagram

## Resumo

O fluxo automatico de Reels virais foi concluido e validado em producao. O sistema busca videos no grupo Telegram `2425105459`, cria um draft de Reel, envia pacote de aprovacao para o WhatsApp e publica no Instagram somente apos aprovacao humana.

Nesta fase, a publicacao automatica sem aprovacao continua desativada.

## Configuracao ativa

- Origem Telegram: `2425105459`
- Grupo WhatsApp de aprovacao: `120363427071180581@g.us`
- Instancia WhatsApp: `ZapOfertas`
- Horarios diarios: `07:30` e `17:30` no horario de Brasilia
- Lookback de busca: `24h`
- Janela anti-repeticao: `72h`
- Publicacao automatica direta: desativada
- Acao apos aprovacao: publicar Reel no Instagram, enviar oferta no WhatsApp e sincronizar catalogo

## Criterios de selecao

Uma mensagem do grupo Telegram so entra no fluxo quando atende aos criterios:

- Tem video valido.
- Tem pelo menos um link no texto.
- Veio do chat configurado.
- Nao foi usada recentemente como draft/publicacao.
- Nao caiu nos filtros de conteudo bloqueado.

A deduplicacao considera principalmente `SourceChatId + SourceMessageId` e tambem usa o link da mensagem como sinal para evitar repeticao de Reels.

## Pacote de aprovacao no WhatsApp

O envio para aprovacao contem:

- Video que sera usado no Reel.
- Legenda do Instagram.
- Post completo de WhatsApp com imagem/foto, texto e link da oferta.
- Instrucoes de resposta.

Palavras-chave aceitas:

- `sim`: aprova e executa o ciclo.
- `nao` ou `não`: reprova e busca outro candidato.
- `ajustar`: pede ajuste do texto antes de publicar.

## Geracao de legenda com IA

Gemma4 ficou como gerador principal para as copies de Instagram. As demais IAs permanecem como fallback quando a Gemma4 nao retorna um resultado valido.

Também foi ajustado o prompt para evitar respostas com raciocinio visivel, planejamento interno ou texto explicativo fora da legenda final.

## Correcoes aplicadas

- Ajuste de caracteres quebrados no pacote de aprovacao.
- Mensagem de WhatsApp com emojis e sem exibir `De` e `Por` quando os valores forem iguais.
- Renderizacao de Reels com ffmpeg corrigida para enquadrar o video em `1080x1920` sem quebrar em videos com proporcao diferente.
- Reels vindos do Telegram passam por renderizacao antes da publicacao.
- Horarios fixos substituem a execucao apenas por intervalo.
- Painel admin permite controlar o autopilot de Reels, grupo WhatsApp e horarios.

## Validacao em producao

Teste real executado com o draft:

- Draft: `dbfa3727b73c4a249d13767eb16068fc`
- Produto: `Canto Alemao Victor com 2 Cadeiras - Viero Moveis`
- MediaId Instagram: `18071966111307655`
- Status final: `published`

Evidencias do ciclo:

- Aprovacao recebida via WhatsApp com palavra `sim`.
- Catalogo sincronizado.
- Falha inicial de ffmpeg corrigida.
- Retry de Instagram publicado com sucesso.
- Healthcheck de producao confirmado em `/health/ready`.
- Proximo disparo recalculado para `17:30` BRT apos deploy.

## Testes executados

- `dotnet test AchadinhosBot.Next.Tests\AchadinhosBot.Next.Tests.csproj --filter "TelegramViralReelsAutoPilotServiceTests" --no-restore`
  - Resultado: `6/6` passaram.

- `dotnet test AchadinhosBot.Next.Tests\AchadinhosBot.Next.Tests.csproj --filter "Gemma4CopyGenerationTests|TelegramViralReelsAutoPilotServiceTests" --no-restore`
  - Resultado: `9/9` passaram.

## Operacao

Para acompanhar o fluxo em producao:

- Verificar health: `http://127.0.0.1:5005/health/ready`
- Logs esperados:
  - `Telegram viral reels autopilot next scheduled run`
  - `viral_reel_draft_created`
  - `viral_reel_approval_sent`
  - `viral_reel_whatsapp_approved`
  - `publish`
  - `catalog_sync_after_publish`

Se uma publicacao falhar por idempotencia durante retry manual, limpar somente a chave `instagram:publish:{draftId}` e reiniciar o container antes de repetir a chamada.
