# Runbook de promoção e recuperação

## Pré-requisitos

- A suíte principal e a de integração devem estar verdes no worktree de release.
- O stack DEV isolado deve passar o smoke sem chamadas de entrega.
- O destino de backup deve estar em disco físico diferente do volume que contém os dados de produção, ou em armazenamento remoto versionado.
- Nunca copie `.env`, tokens ou credenciais para o repositório, logs de terminal ou artefatos de release.

## Pendência obrigatória antes da primeira promoção desta arquitetura

- Provisionar um certificado ou mecanismo de proteção de chaves aprovado para produção e configurar `DataProtection:KeysPath` em volume persistente absoluto. Sem isso, as chaves persistem, mas não têm criptografia em repouso adequada para produção.
- Validar o mecanismo no ambiente candidato com reinício controlado antes de qualquer promoção. Não gerar, copiar ou registrar certificados em artefatos do repositório.

## Backup antes da promoção

1. Escolha um destino versionado fora do volume de dados de produção.
2. Execute `scripts/backup-operational-data.ps1 -Source <dados-producao> -Destination <destino-externo> -Label achadinhos-prod`.
3. Só prossiga quando o comando retornar `Backup verified`; ele compara caminho, tamanho e SHA-256 de cada arquivo e grava `backup-manifest.json` no novo diretório de backup.
4. Registre apenas o identificador do backup, a data e a revisão em canal operacional seguro. Nunca registre conteúdo, chaves ou tokens.
5. Confirme espaço livre no volume de produção e no destino de backup.

## Promoção controlada

1. Registre a revisão exata e a imagem candidata.
2. Faça o deploy sem recriar filas, volumes ou credenciais.
3. Verifique `/health/live` e `/health/ready` localmente no contêiner.
4. Confirme conectividade do RabbitMQ e contadores de outbox antes de liberar tráfego.
5. Observe logs e filas por 15 minutos. Não reenvie mensagens históricas nem reprocesse DLQs durante a promoção.

## Rollback

1. Pare apenas o serviço de aplicação que apresentou regressão; não apague volumes.
2. Suba a imagem anterior conhecida como saudável.
3. Execute health, readiness, RabbitMQ e os contadores de outbox.
4. Se os dados de log precisarem retornar, use a recuperação administrativa por `snapshotId`; ela cria um snapshot pré-restauração.
5. Se houver dano fora do escopo dos snapshots, restaure exclusivamente a partir do backup externo validado.

## Teste de restauração no DEV

1. Nunca teste uma restauração diretamente no volume de produção.
2. Copie o diretório de backup validado para um diretório descartável no DEV e confira o `backup-manifest.json`.
3. Inicie o stack DEV isolado usando esse diretório apenas após guardar o estado local atual.
4. Verifique health, readiness, os contadores de outbox e uma consulta administrativa representativa.
5. Registre o resultado e descarte somente o diretório de teste; o backup original deve permanecer imutável.

## Recuperação de logs

1. Acesse o painel como administrador e abra **Recuperação** nos logs de conversão.
2. Confira data, quantidade de arquivos, bytes e estado do snapshot.
3. Selecione o `snapshotId` correto, confirme `RESTORE_SNAPSHOT` e registre o resultado.
4. Verifique as entradas restauradas e a auditoria. Não repita a operação sem investigar o snapshot pré-restauração retornado.

## Critérios para abortar

- Health ou readiness falhar.
- Contadores de outbox crescerem inesperadamente.
- Espaço de snapshot atingir a cota ou o alerta de 80%.
- Falha de auditoria, retenção ou recuperação.
