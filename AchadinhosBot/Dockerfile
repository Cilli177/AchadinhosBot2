# Estágio 1: Construir o Robô
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build-env
WORKDIR /app

# Copia tudo e compila
COPY . ./
RUN dotnet restore
RUN dotnet publish -c Release -o out

# Estágio 2: Rodar o Robô (Leve)
FROM mcr.microsoft.com/dotnet/runtime:8.0
WORKDIR /app

# Pega o robô pronto do estágio anterior
COPY --from=build-env /app/out .

# 👇 A MÁGICA: Traz o login e dá permissão TOTAL para leitura e escrita
COPY WTelegram.session ./
RUN chmod 666 WTelegram.session

# Cria a pasta de dados (só por garantia)
RUN mkdir -p /app/data

# Comando para iniciar
ENTRYPOINT ["dotnet", "AchadinhosBot.dll"]