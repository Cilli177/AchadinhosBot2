# 🔧 Configuração de Integrações - Telegram e WhatsApp

## Status Atual
✅ **Autenticação**: Funcionando  
❌ **Telegram**: Não configurado (Token vazio)  
❌ **WhatsApp/Evolution**: Chave da API vazia  

## 📋 O que você precisa fazer

### 1. Telegram Bot Token

**Passo 1**: Abra o Telegram e encontre `@BotFather`  
**Passo 2**: Envie `/newbot` e siga as instruções  
**Passo 3**: Você receberá um token similar a: `123456789:ABCDEfghIjklmnoPQRstuvwxyz`  

**Passo 4**: Atualize o `.env`:
```dotenv
TELEGRAM_BOT_TOKEN=seu_token_aqui
```

### 2. WhatsApp - Evolution API

**Requisitos**:
- Uma instância do Evolution API rodando (Docker ou local)
- A URL e chave de acesso

**Passo 1**: Se não tiver Evolution instalado, use Docker:
```bash
docker run -d \
  -p 8080:8080 \
  -e API_KEY=sua_chave_super_secreta \
  --name evolution-api \
  matrikserver/evolution-api:latest
```

**Passo 2**: Atualize o `.env`:
```dotenv
EVOLUTION_BASE_URL=http://localhost:8080
EVOLUTION_API_KEY=sua_chave_super_secreta
EVOLUTION_INSTANCE_NAME=achadinhos-next
```

### 3. Reiniciar a Aplicação

Após atualizar o `.env`, reinicie:

```bash
# Se rodando localmente
dotnet run --project AchadinhosBot.Next/AchadinhosBot.Next.csproj

# Se usando Docker Compose
docker-compose restart
```

### 4. Testar no Dashboard

1. Acesse http://127.0.0.1:8081/dashboard.html
2. Autentique com suas credenciais
3. Clique em **"Validar conexão Telegram"** - deve aparecer o username do bot
4. Clique em **"Conectar e gerar QR"** - deve exibir o código QR para escanear

---

## 🐛 Se tiver erros:

- **Erro: "BotToken não configurado"** → Telegram não tem token
- **Erro: "Falha getMe"** → Token do Telegram é inválido
- **Erro: "Evolution não responde"** → Verificar se está rodando em 8080
- **Erro: "Falha ao criar/validar instância"** → ApiKey da Evolution incorreta

## 📝 Verificar configurações atuais

Execute no terminal:
```bash
grep -E "TELEGRAM_BOT_TOKEN|EVOLUTION" .env
```

Deve mostrar algo como:
```
TELEGRAM_BOT_TOKEN=seu_token_aqui
EVOLUTION_BASE_URL=http://localhost:8080
EVOLUTION_API_KEY=sua_chave_super_secreta
```

---

**Próximos passos**: Configure essas variáveis e click "Validar conexão" no dashboard para confirmar! 🚀
