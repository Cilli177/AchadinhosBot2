# DOCUMENTACAO DO OBJETO

## 1. Identificacao
- Nome do objeto: Workflow de build do repositorio
- Tipo do objeto: workflow GitHub Actions
- Caminho/localizacao: `.github/workflows/build.yml`
- Responsavel: Codex
- Data: 2026-03-06
- Versao atual: v01

## 2. Finalidade
- Validar a solucao real do projeto em CI.
- Gerar artefato de publicacao e resultados de teste.

## 3. Entradas e saidas
- Entradas: eventos `push`, `pull_request` e `workflow_dispatch`.
- Saidas: status de CI, artefato `achadinhos-next-publish` e arquivos `.trx`.

## 4. Dependencias
- Dependencias internas: `AchadinhosBot2.sln`, projetos de teste e app principal.
- Dependencias externas: GitHub Actions, .NET 8 SDK.
- Servicos/APIs relacionados: GitHub Actions Artifact.

## 5. Regras de negocio
- Toda alteracao em `main` e `develop` deve passar por restore, build, test e publish.
- O workflow deve refletir a base real, nao exemplos externos.

## 6. Alteracao realizada
- Tipo da alteracao: correcao
- Motivo: o workflow anterior apontava para projetos inexistentes e nao validava esta base.
- Descricao tecnica da alteracao: substituicao do job antigo por restore/build/test/publish da solucao real.
- Impacto esperado: CI utilizavel para DEV.

## 7. Historico de versoes
- v00: workflow original invalido para esta base.
- v01: workflow corrigido para a solucao e testes reais.

## 8. Riscos e observacoes
- Riscos conhecidos: a CI ainda pode falhar enquanto a baseline de testes nao estiver verde.
- Observacoes tecnicas: esta entrega implementa apenas o baseline de CI, nao o deploy automatizado.
- Pendencias futuras: criar promocao protegida para PROD.
