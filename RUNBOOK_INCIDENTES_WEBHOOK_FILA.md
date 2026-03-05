# Runbook de Incidentes - Webhook e Fila

Data: 2026-03-04  
Escopo: `DEV` e `PROD`  
Objetivo: reduzir tempo de detecção/recuperação em falhas de webhook e fila.

## 1) Sinais de incidente
- Webhook com `401` recorrente (`/webhook/bot-conversor`).
- Falha de publish na fila (RabbitMQ indisponível).
- Aumento de erro de conversão/encaminhamento automático.
- Queda de entrega em WhatsApp/Telegram com tráfego de entrada ativo.

## 2) Triage rápido (5 minutos)
1. Confirmar saúde da API:
   - `GET /health` local e público.
2. Verificar logs recentes:
   - procurar `responded 401`, `Connection Failed: rabbitmq`, `Publish`, `fallback-internal`.
3. Identificar ambiente afetado:
   - `DEV`, `PROD` ou ambos.
4. Classificar severidade:
   - `SEV1`: perda total de webhook/entrega.
   - `SEV2`: degradação parcial com fallback ativo.

## 3) Playbook - Webhook 401
1. Confirmar endpoint e origem:
   - `POST /webhook/bot-conversor`.
2. Validar segredos/chaves:
   - app (`x-api-key` / webhook secret)
   - provider (Evolution) com mesmo valor.
3. Repetir chamada de teste autenticada em `DEV`.
4. Critério de recuperação:
   - `0` ocorrências de `401` em janela observada.
5. Se não recuperar:
   - manter tráfego em fallback/manual e escalar.

## 4) Playbook - Fila indisponível
1. Verificar status do RabbitMQ/container/hostname.
2. Confirmar conectividade da API para o host da fila.
3. Validar se fallback interno de webhook está acionando.
4. Mitigação:
   - restaurar RabbitMQ e revalidar publish.
   - manter processamento em fallback até estabilizar.
5. Critério de recuperação:
   - publish normalizado + erro de conexão zerado/estável.

## 5) Validação pós-correção
1. Health API: `200`.
2. Teste funcional mínimo:
   - 1 evento webhook válido.
   - 1 fluxo de conversão + encaminhamento.
3. Confirmar logs sem erro crítico novo.
4. Monitorar por 30-60 min.

## 6) Registro obrigatório do incidente
- Data/hora início e fim.
- Ambiente afetado.
- Sintoma observado.
- Causa raiz (ou hipótese principal).
- Ações aplicadas.
- Evidências (logs/health/testes).
- Impacto estimado.
- Responsável técnico.
- Pendências preventivas.

## 7) Regras operacionais
- Toda correção primeiro em `DEV`.
- `PROD` somente após aprovação e backup.
- Deploy de produção via:
  - `scripts/deploy-prod.ps1`
- Atualizar documentação a cada push relacionado ao incidente.
