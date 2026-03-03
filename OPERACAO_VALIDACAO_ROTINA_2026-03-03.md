# Operacao e Validacao - Rotina (2026-03-03)

## Objetivo
Padronizar a rotina de validacao e registrar o historico real do que foi feito para estabilizar:
- Conversao de links (principalmente Mercado Livre `meli.la`/social)
- Encaminhamento Telegram -> Telegram destino -> WhatsApp
- Disponibilidade do site conversor (`/conversor`) atras do Cloudflare Tunnel

## Escopo desta rodada (resumo)
- Ajustes no `AffiliateLinkService` para robustez na expansao de links ML.
- Ajustes no fluxo do conversor web para evitar retorno de link social/curto invalido.
- Diversas intervencoes operacionais para recuperar 502 (origin offline).

## Historico tecnico do que foi implementado

### 1) Conversao Mercado Livre mais robusta
Commits:
- `523ef74` `fix(ml): robustly expand meli links and decode nested MLB ids`
- `14ab5a2` `fix(ml): prioritize CTA wid/item_id and recover invalid extracted item`
- `b16bba5` `fix(ml): fallback to affiliated social link when extracted item stays invalid`

Mudancas chave:
- Expansao em cadeia para `meli.la` antes de desistir.
- Extracao de `MLB` com decode adicional (URL/HTML) para cenarios de redirecionamento.
- Priorizacao de `wid`, `item_id` e `pdp_filters` (quando presentes no link do botao "Ir para produto").
- Recuperacao de ID alternativo quando o primeiro item detectado for invalido.
- Fallback para link afiliado social quando nao houver item valido recuperavel.

### 2) Conversor web com segunda tentativa de canonicalizacao ML
Commit local:
- `1d8938f` `fix(conversor): reprocess ML short/social resolved targets before returning final link`

Status:
- Commit criado localmente.
- `push` falhou por indisponibilidade de rede para GitHub no momento da execucao.

Mudanca chave:
- No endpoint `/api/conversor`, quando URL convertida (ou seu destino resolvido) ainda eh ML social/short,
  o sistema tenta reconverter usando a URL final resolvida antes de devolver resultado ao usuario.

## Problemas operacionais identificados

### A) 502 no dominio publico
Sintoma:
- Cloudflare "Working", Host "Error 502".

Causa observada em log:
- `cloudflared` conectado, mas sem origin ouvindo em `127.0.0.1:5000`.
- Erro no tunnel: `Unable to reach the origin service ... connectex: No connection could be made`.

### B) Servicos Windows nao persistidos
Tentativa de criar servicos:
- `AchadinhosApp`
- `AchadinhosTunnel`

Resultado:
- `OpenSCManager FALHA 5 (Acesso negado)` no contexto do agente.
- Em alguns momentos os processos foram iniciados manualmente e subiram, mas sem persistencia real.

### C) Instabilidade do processo da aplicacao
Sinais em logs:
- `TelegramUserbotService` com `SocketException 10013` recorrente.
- Em alguns ciclos a API respondia `/health=200` e depois caia (origin voltava a recusar conexao).

## Estado atual conhecido
- Cloudflare Tunnel chega a ficar conectado.
- O gargalo recorrente eh o processo do app nao ficar estavel/persistente na `5000`.
- Enquanto nao houver servico Windows corretamente criado e validado, risco de nova queda permanece.

## Rotina operacional padrao (obrigatoria)

### 1) Pre-check (antes de teste/deploy)
Executar:
```powershell
git rev-parse --short HEAD
dotnet build .\AchadinhosBot.Next\AchadinhosBot.Next.csproj -c Release -v minimal
```

### 2) Health local e publico
Executar:
```powershell
Invoke-WebRequest http://127.0.0.1:5000/health
Invoke-WebRequest https://achadinhos.reidasofertas.ia.br/health
```

Regra:
- So iniciar teste funcional se ambos retornarem `200`.

### 3) Teste funcional minimo (conversor)
1. Abrir: `https://achadinhos.reidasofertas.ia.br/conversor`
2. Converter ao menos:
   - 1 link `meli.la`
   - 1 link ML social
3. Validar:
   - Metadados coerentes (titulo/preco/imagem)
   - Link final abre pagina valida do produto (sem "pagina nao existe")

### 4) Teste funcional minimo (pipeline)
1. Enviar oferta no grupo laboratorio.
2. Confirmar replicacao no Telegram destino.
3. Confirmar envio para WhatsApp destino.
4. Verificar logs de bloqueio para links invalidos.

### 5) Auditoria de logs apos teste
Buscar no log do dia:
```powershell
rg -n "Mercado Livre convertido|Produto nao identificado|bloqueou encaminhamento|/api/conversor responded|Unable to reach the origin service" .\AchadinhosBot.Next\logs\achadinhos-*.log -S
```

## Rotina de incidente 502 (playbook rapido)
1. Verificar tunnel e app:
```powershell
Get-Process dotnet,cloudflared -ErrorAction SilentlyContinue
Invoke-WebRequest http://127.0.0.1:5000/health
```
2. Se `5000` offline:
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\run-app.ps1
```
3. Se tunnel offline:
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\start-cloudflare-tunnel.ps1
```
4. Revalidar:
```powershell
Invoke-WebRequest https://achadinhos.reidasofertas.ia.br/health
```

## Padrao de registro (toda alteracao)
Para cada execucao relevante, registrar:
- Data/hora
- URL de teste
- Resultado do conversor
- Resultado Telegram destino
- Resultado WhatsApp destino
- Erros observados
- Commit/hash em execucao
- Acao corretiva aplicada

## Proximos passos recomendados
1. Concluir `push` do commit `1d8938f` quando a rede para GitHub normalizar.
2. Criar servicos Windows com conta/admin e validar `StartType=Auto`.
3. Configurar recovery de servico (`sc failure ... restart`) para app e tunnel.
4. Isolar falhas do `TelegramUserbotService` para nunca derrubar disponibilidade do conversor.
