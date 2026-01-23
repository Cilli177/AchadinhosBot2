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
COPY WTelegram.session ./

# 👇 A MUDANÇA NUCLEAR 👇
# Transforma o robô em Super Usuário (Root) para não ter bloqueio
USER root
RUN chmod 777 WTelegram.session

# Comando para iniciar
ENTRYPOINT ["dotnet", "AchadinhosBot.dll"]