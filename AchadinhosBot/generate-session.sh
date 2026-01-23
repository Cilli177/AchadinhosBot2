#!/bin/bash

# Script para gerar a sessão Base64 automaticamente

if [ ! -f "WTelegram.session" ]; then
    echo "❌ Arquivo WTelegram.session não encontrado!"
    echo "Execute 'dotnet run' primeiro para fazer login."
    exit 1
fi

echo "📦 Codificando sessão em Base64..."
base64 -w 0 WTelegram.session > WTelegram.session.b64

SESSION_SIZE=$(wc -c < WTelegram.session.b64)
echo "✅ Sessão codificada com sucesso!"
echo "📊 Tamanho: $SESSION_SIZE caracteres"

echo ""
echo "📋 Opção 1: Leia o arquivo"
echo "cat WTelegram.session.b64"

echo ""
echo "📋 Opção 2: Copie com um clique"
echo "xclip -selection clipboard < WTelegram.session.b64"

echo ""
echo "🚀 No Railway, crie uma variável de ambiente chamada 'TELEGRAM_SESSION_BASE64'"
echo "E cole o conteúdo do arquivo WTelegram.session.b64"
