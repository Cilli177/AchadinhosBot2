# DEV isolado (`achadinhos-dev-e`)

Este overlay cria uma pilha DEV paralela e descartável a partir deste worktree. Ele não usa `env_file`, binds de runtime, tunnels, Evolution, filas, volumes, redes ou destinos de produção.

Os recursos de Docker exclusivos são:

- Rede: `achadinhos-dev-e_network` (interna).
- Volumes: `achadinhos-dev-e_app_data`, `achadinhos-dev-e_app_media` e `achadinhos-dev-e_rabbitmq_data`.
- Containers: sufixo `-dev-e`.
- Portas host, vinculadas somente a `127.0.0.1`: app `18081`, scraper `13002`, AMQP `5674` e RabbitMQ Management `15674`.

Enquanto a DEV legada usa 8081/8083, 3002, 5673 e 15673, estas portas permitem qualificar a nova pilha em paralelo. Produção continua em 5005, 5672 e 15672 e não faz parte deste procedimento.

## Pré-validação sem iniciar containers

Execute no worktree reconstruído:

```powershell
docker compose -f docker-compose.dev.isolated.yml config -q
docker compose -f docker-compose.dev.isolated.yml config --services
docker ps --format '{{.Names}}\t{{.Ports}}\t{{.Label "com.docker.compose.project"}}'
```

O primeiro comando deve terminar com código zero. O segundo deve listar somente `rabbitmq`, `mercadolivre-affiliate-scraper` e `achadinhos-next`. Antes de iniciar, confirme que nenhuma das portas exclusivas está publicada e que não existe recurso Docker com prefixo `achadinhos-dev-e_` proveniente de execução anterior não aprovada.

## Inicialização autorizada posterior

Não execute este passo durante revisão ou investigação. Após autorização operacional explícita, a pilha pode ser criada exclusivamente por:

```powershell
docker compose -f docker-compose.dev.isolated.yml up -d --build
```

Não use `docker compose up` com os compose files legados, nem com `docker-compose.prod.yml`. Não conecte esta pilha às redes `achadinhos-prod_default`, `achadinhos-dev_default` ou `achadinhos-evolution_default`.

## Gates de aprovação

1. **Proveniência:** `docker inspect` dos três containers precisa mostrar projeto `achadinhos-dev-e`, rede `achadinhos-dev-e_network` e somente os volumes `achadinhos-dev-e_*`.
2. **Saúde:** RabbitMQ, scraper e app precisam ficar `healthy`; `GET http://127.0.0.1:18081/health/ready` e `GET http://127.0.0.1:13002/health` precisam retornar 200.
3. **Fila limpa:** no broker da nova pilha, filas de trabalho e de erro começam vazias. Não importar dados, não anexar volumes legados e não executar replay, requeue ou consumo de DLQ.
4. **Isolamento de entrega:** sem tunnel, sem Evolution e sem credenciais de Telegram/WhatsApp; as políticas de bloqueio de destinos oficiais permanecem ativas.
5. **Sem produção:** não pode haver mount em `E:\Achadinhos\runtime`, referência a porta de produção, nem tráfego para container ou rede de produção.

## Smoke seguro, sem destino oficial

Depois de os containers ficarem saudáveis, execute o smoke automatizado:

```powershell
.\scripts\smoke-dev-isolated.ps1
```

O script verifica por `docker inspect` a proveniência, rede e health dos três containers. Em seguida, chama por `docker exec` somente liveness/readiness locais da app e do scraper, ping do RabbitMQ e contadores de fila. Ele não chama endpoints de envio, não publica nem consome mensagens, não fornece destino, não abre tunnel e não altera qualquer fila. Falha em qualquer gate bloqueia a Fase 1.2 e requer diagnóstico somente de leitura antes de nova tentativa.

## Transição

A DEV legada pode permanecer online durante a qualificação pelo endpoint 18081. Após aprovação, o encaminhamento de operadores para a DEV nova deve usar um hostname/tunnel DEV novo e separado, em mudança autorizada posterior. A retirada dos containers legados em C: é uma operação distinta e nunca deve ocorrer junto com a qualificação da nova DEV.
