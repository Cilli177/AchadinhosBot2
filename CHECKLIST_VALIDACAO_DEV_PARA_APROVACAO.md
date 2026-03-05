# Checklist de Validacao DEV para Aprovacao

Data base: 2026-03-04
Escopo: melhorias antes de promover para PROD.

## 1) Pre-check tecnico
- [ ] `git rev-parse --short HEAD` registrado
- [ ] Build `Release` sem erro
- [ ] Container DEV atualizado com a ultima imagem
- [ ] `GET /health` em DEV retorna `200`

## 2) Validacao funcional minima
- [ ] Conversao de link curto Mercado Livre valida (`success=true`)
- [ ] Link social ML sem produto confiavel bloqueia (`success=false`)
- [ ] Nao ha geracao de URL quebrada (`pagina nao existe`) nos testes
- [ ] Fluxo principal afetado pela mudanca segue operacional

## 3) Evidencias obrigatorias
- [ ] Log de execucao DEV com data/hora
- [ ] Entradas e saidas dos testes documentadas
- [ ] Arquivos alterados e objetivo da mudanca documentados
- [ ] Risco conhecido e plano de rollback descritos

## 4) Gate para aprovar subida
- [ ] Responsavel revisou resultado DEV
- [ ] Sem regressao funcional critica
- [ ] Aprovacao explicita para backup + deploy PROD

## 5) Producao (somente apos aprovacao)
- [ ] Executar backup/deploy via `scripts/deploy-prod.ps1`
- [ ] Registrar nome do volume de backup
- [ ] Monitorar 30-60 min pos deploy
- [ ] Atualizar release note da rodada
