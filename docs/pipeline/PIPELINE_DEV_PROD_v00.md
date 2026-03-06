# PIPELINE DEV E PROD

## 1. Identificacao
- Nome do objeto: Pipeline DEV e PROD
- Tipo do objeto: documento de arquitetura operacional
- Caminho/localizacao: `docs/pipeline/PIPELINE_DEV_PROD_v00.md`
- Responsavel: Codex
- Data: 2026-03-06
- Versao atual: v00

## 2. Objetivo
- Definir a promocao segura entre DEV e PROD.
- Impedir liberacao sem validacao tecnica real.

## 3. Estrategia recomendada
- Manter uma unica base de codigo em .NET 8.
- Usar GitHub Actions para CI.
- Usar DEV como ambiente obrigatorio de validacao funcional e tecnica.
- Promover para PROD apenas artefato validado em DEV.

## 4. Fluxo proposto
1. Desenvolvimento em branch de trabalho.
2. Pull request para `develop`.
3. CI valida restore, build, testes e publicacao de artefato.
4. Deploy controlado em DEV.
5. Homologacao funcional com checklist.
6. Aprovacao tecnica registrada em documentacao da entrega.
7. Promocao para `main`.
8. Deploy controlado em PROD com versao rastreavel e rollback documentado.

## 5. O que foi escolhido agora
- Foi corrigida a pipeline do repositorio para executar a solucao real:
- restore da solucao;
- build em Release;
- testes dos projetos reais;
- publish do app principal;
- upload de artefato e resultados de teste.

## 6. Beneficios da abordagem
- A base deixa de ter um workflow decorativo e passa a ter validacao de verdade.
- O publish gera artefato rastreavel para DEV.
- O fluxo separa claramente validacao tecnica de promocao produtiva.

## 7. Limitacoes atuais
- Ainda nao ha deploy automatizado por ambiente no repositrio.
- Ainda nao existe validacao automatica de smoke test contra DEV.
- Ainda nao existe gate de aprovacao manual por environment do GitHub.

## 8. Proxima evolucao recomendada
- `ci-dev.yml`: validacao de PR e push para `develop`.
- `promote-prod.yml`: workflow manual, protegido por approval, consumindo artefato publicado.
- smoke tests de `/health`, rotas criticas e cenarios de mensagem.
- versionamento da release com tag.

## 9. Ferramentas recomendadas
- GitHub Actions
- Docker Compose para DEV local
- Artifact upload do GitHub
- environments protegidos (`dev`, `prod`)
- smoke tests via PowerShell ou curl

## 10. Historico de versoes
- v00: definicao da pipeline alvo e baseline de CI real para a base atual.
