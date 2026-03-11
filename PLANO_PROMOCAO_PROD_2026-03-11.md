# Plano De Promocao Para Producao

Data: 2026-03-11
Branch de origem: `feature/vip-catalog-conversor-ui`

## Commits Recomendados

Aplicar nesta ordem:

1. `f44f24d`
   - restore dynamic bio hub
   - decouple catalog enrichment

2. `3c01614`
   - harden admin publishing
   - analytics and categorized click tracking
   - reel readiness and retry

3. `01b162c`
   - persist `/app/wwwroot/media/admin`

4. `98ab229`
   - sanitize tracked environment templates

5. `67e3aa9`
   - align tests with current services
   - add deploy checklist

## Promocao

Opcoes:

- via merge controlado da branch, se o alvo estiver limpo
- via cherry-pick destes commits para a branch de deploy

Comandos sugeridos para promocao por cherry-pick:

```powershell
git checkout main
git pull origin main
git checkout -b release/prod-2026-03-11
git cherry-pick f44f24d 3c01614 01b162c 98ab229 67e3aa9
```

Se a operacao de producao exigir deploy direto em `main`:

```powershell
git checkout main
git pull origin main
git cherry-pick f44f24d 3c01614 01b162c 98ab229 67e3aa9
```

## Validacao Por Etapa

### Apos `f44f24d`

Validar:

- `bio.*` resolve para o fluxo dinamico de `/bio`
- `/links` nao serve landing estatica quebrada
- catalogo continua carregando normalmente

Checagens:

- abrir `https://bio.reidasofertas.ia.br`
- abrir `https://achadinhos.reidasofertas.ia.br/links`
- abrir `https://achadinhos.reidasofertas.ia.br/catalogo`

### Apos `3c01614`

Validar:

- admin exibe status de draft melhorado
- publish de reel nao falha por publicar cedo demais
- analytics responde
- click tracking categoriza entradas

Checagens:

- `/api/analytics/summary`
- `/api/analytics/hot-deals`
- fluxo de draft agendado
- fluxo de publish manual controlado

### Apos `01b162c`

Validar:

- pasta de midia do admin persiste apos restart
- draft agendado nao perde video/imagem depois de reinicio do container

Checagens:

- subir midia
- reiniciar container
- confirmar persistencia do arquivo

### Apos `98ab229`

Validar:

- nenhuma credencial real ficou versionada
- `appsettings.json` permanece baseline seguro
- `docker-compose.dev.override.yml` usa env vars/placeholders
- script de cloudflare continua funcional com parametros

Checagens:

- revisar diff final
- revisar compose com envs reais no ambiente, nao no git

### Apos `67e3aa9`

Validar:

- `dotnet build AchadinhosBot.Next\AchadinhosBot.Next.csproj --no-restore`
- `dotnet test AchadinhosBot.Next.Tests\AchadinhosBot.Next.Tests.csproj --no-restore`

Esperado:

- build com `0 warnings / 0 errors`
- testes com `37 passed / 5 skipped`

## Checklist Final Antes Do Deploy

1. Confirmar `git status` limpo.
2. Confirmar segredos apenas via `.env`, secret store ou variavel de ambiente.
3. Validar `https://achadinhos.reidasofertas.ia.br/health`.
4. Validar login no admin.
5. Validar um draft sem catalogo.
6. Validar um draft com catalogo.
7. Validar analytics.
8. Validar Bio Hub.

## Rollback Simples

Se o deploy for por branch de release:

```powershell
git checkout main
git reset --hard origin/main
```

Se o deploy for por cherry-pick em `main`, preferir revert explicito:

```powershell
git revert 67e3aa9
git revert 98ab229
git revert 01b162c
git revert 3c01614
git revert f44f24d
```

Observacao:

- em rollback real, reverter do mais recente para o mais antigo
- nao usar `reset --hard` em branch compartilhada ja publicada
