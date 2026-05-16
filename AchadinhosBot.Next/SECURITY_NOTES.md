# Security Notes

- Segredos operacionais nao devem permanecer em `appsettings.json`.
- Credenciais do RabbitMQ devem vir de variaveis de ambiente por ambiente.
- `X-Correlation-ID` e `audit.log` devem ser usados para rastrear acoes sensiveis.
- O endpoint de debug de chave administrativa foi removido.
