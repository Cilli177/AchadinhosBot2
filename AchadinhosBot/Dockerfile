# Estágio 1: Construir
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build-env
WORKDIR /app
COPY . ./
RUN dotnet restore
RUN dotnet publish -c Release -o out

# Estágio 2: Rodar com Poderes Totais
FROM mcr.microsoft.com/dotnet/runtime:8.0
WORKDIR /app
COPY --from=build-env /app/out .

# 👇 PREPARAÇÃO PARA SESSÃO EM PRODUÇÃO 👇
# Copia o arquivo de sessão Base64 se existir
RUN if [ -f "WTelegram.session.b64" ]; then cp WTelegram.session.b64 /app/; fi

USER root
RUN mkdir -p /tmp && chmod 777 /tmp

# Comando para iniciar
ENTRYPOINT ["dotnet", "AchadinhosBot.dll"]