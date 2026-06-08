# Estrategia de convites WhatsApp por nicho

## Objetivo

Popular os grupos de nicho do ZapOfertas2 com convites privados, humanos e rastreaveis, usando somente contatos elegiveis dos grupos atuais.

O fluxo deve priorizar consentimento, baixa cadencia e relevancia por nicho. Nao usar mensagens enganosas, pressao falsa, disparo agressivo ou tentativa de burlar filtros anti-spam.

## Regras de seguranca

- Enviar somente para contatos que ja fazem parte de grupos da operacao ou que demonstraram interesse.
- Nao enviar para contatos que pediram para parar, sairam recentemente ou ja receberam convite nos ultimos 30 dias.
- Comecar com amostras pequenas: ate 20 pessoas por campanha.
- Usar intervalo minimo de 5 minutos por pessoa e variacao ate 10 minutos.
- Usar pausa minima de 5 minutos entre lotes.
- Manter `SendLinkOnTimeout` desligado por padrao. O link deve ser enviado preferencialmente depois de resposta positiva.
- Pausar automaticamente se houver falhas, bloqueios, muitas saidas ou respostas negativas.

## Segmentacao

1. Ler os participantes dos grupos fonte do ZapOfertas2.
2. Separar por interesse provavel:
   - beleza
   - casa
   - eletronicos
   - moda
   - mercado
   - infantil
   - geral
3. Enviar convite do nicho mais relevante para cada contato.
4. Nao convidar a mesma pessoa para varios nichos no mesmo dia.

## Conversa recomendada

Fluxo inicial sem link:

1. Saudacao curta e natural.
2. Explicacao do beneficio dos grupos de nicho.
3. Lista curta dos nichos disponiveis.
4. Pedido para a pessoa responder com o numero ou nome do nicho.

Exemplo base:

```text
Oi, tudo bem?

Estamos organizando o Rei das Ofertas em grupos por nicho para voce receber so o que realmente combina com seu interesse.

Temos grupos de Tech e eletronicos, Casa e organizacao, Beleza e cuidados, Moda e acessorios, e Fitness e saude.

Me responda com o numero ou nome do nicho que voce prefere, e eu te mando apenas o link escolhido.
```

Resposta com nicho escolhido:

```text
Perfeito. Esse e o link oficial do grupo {nicho}: {link}

Quer entrar em outro tambem? Responda outro nicho: Tech, Casa, Beleza, Moda ou Fitness. Se nao quiser, responda "nao".
```

Resposta negativa:

```text
Tranquilo, obrigado por responder. Nao vou te mandar o link.
```

Persistencia do fluxo:

- O disparo inicial nao deve carregar link quando `UseAiDialogue=true` e `SendLinkOnTimeout=false`.
- O estado da conversa fica em `D:\Achadinhos\data\whatsapp-invite-conversations.json`.
- O webhook envia somente o link do nicho escolhido pela resposta.
- O progresso do disparo e salvo apos cada contato para evitar reenvio caso o computador reinicie.

## Uso da IA Gemma4

Gemma4 pode variar o texto, mas deve obedecer a estes limites:

- Tom brasileiro, direto e educado.
- Sem fingir intimidade.
- Sem prometer desconto exclusivo inexistente.
- Sem urgencia falsa.
- Sempre pedir permissao antes do link, quando possivel.
- Quando houver menu de nichos, enviar o link somente depois da escolha explicita.
- Sempre respeitar opt-out.

Prompt operacional sugerido:

```text
Crie uma mensagem curta de WhatsApp em portugues do Brasil para convidar uma pessoa a entrar em um grupo de ofertas do nicho "{nicho}".
Contexto: a pessoa ja participa de um grupo de ofertas da operacao.
Objetivo: explicar que o novo grupo tem ofertas mais filtradas, links revisados e menos mensagens fora do interesse.
Regras: nao usar pressao, nao simular amizade intima, nao prometer desconto garantido, pedir permissao antes de enviar o link.
Retorne apenas a mensagem.
```

## Cadencia operacional

- Dia 1: testar 10 a 20 convites em um unico nicho.
- Dia 2: medir respostas positivas, negativas, bloqueios e entradas confirmadas.
- Dia 3: expandir para outro nicho se a taxa de resposta positiva estiver saudavel.

Indicadores:

- resposta positiva
- resposta negativa
- link enviado
- entrada confirmada no grupo
- bloqueio/falha
- saida apos entrada

## Configuracao aplicada no sistema

- Intervalo minimo por contato: `300000 ms` (5 minutos).
- Intervalo maximo por contato: `600000 ms` (10 minutos).
- Lote padrao: `10` contatos.
- Pausa padrao entre lotes: `300 s` (5 minutos).
- Limite recomendado no painel: `20` contatos por campanha.
- Fallback de link sem resposta: desligado por padrao.

## Procedimento no painel

1. Abrir WhatsApp Admin.
2. Selecionar instancia `zapofertas2`.
3. Selecionar grupos fonte.
4. Filtrar ou selecionar participantes elegiveis.
5. Inserir link oficial `https://chat.whatsapp.com/...` do nicho.
6. Aplicar pitch amigavel.
7. Revisar intervalo, lote e fallback.
8. Confirmar o codigo do convite.
9. Acompanhar logs e conversao.
