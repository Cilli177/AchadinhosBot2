# Evolution API no DEV sem impactar PROD

## Objetivo
Conectar o ambiente DEV ao Evolution API sem interferir no ambiente de produção.

## Estratégia segura
1. Usar a **mesma Evolution API** com **instâncias diferentes**.
2. Produção permanece em `ZapOfertas`.
3. DEV usa `ZapOfertasDev`.

## Configuração obrigatória no DEV
- `EVOLUTION__BASEURL=http://host.docker.internal:8082`
- `EVOLUTION__APIKEY=<SUA_CHAVE_EVOLUTION>`
- `EVOLUTION__INSTANCENAME=ZapOfertasDev`

## Fluxo de conexão recomendado
1. Abrir o dashboard do DEV.
2. Ir no card de WhatsApp (Evolution).
3. Gerar QR da instância `ZapOfertasDev`.
4. Parear o número destinado aos testes.
5. Validar se o status ficou conectado somente no DEV.

## Regras para não afetar produção
1. **Nunca** usar a mesma instância (`ZapOfertas`) no DEV.
2. Manter bloqueio de envio ao grupo oficial no DEV:
   - `120363405661434395@g.us`
3. Testar apenas em grupo laboratório.
4. Não alterar variáveis de produção durante ajustes do DEV.

## Riscos se não isolar instância
- Mensagens de teste podem sair em fluxos de produção.
- Colisão de sessão/conexão da mesma instância.
- Perda de rastreabilidade entre DEV e PROD.

## Checklist rápido
- [ ] DEV está com `EVOLUTION__INSTANCENAME=ZapOfertasDev`
- [ ] PROD está com `EVOLUTION__INSTANCENAME=ZapOfertas`
- [ ] Grupo oficial bloqueado no DEV
- [ ] QR conectado na instância DEV
- [ ] Teste realizado apenas em grupo laboratório

## Observação
Se usar o mesmo número para DEV e PROD, ainda existe risco operacional.  
O cenário ideal é usar número/instância dedicados para DEV.
