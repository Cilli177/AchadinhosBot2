# Usa a imagem oficial do .NET para criar o robô
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build-env
WORKDIR /app

# Copia tudo e compila
COPY . ./
RUN dotnet restore
RUN dotnet publish -c Release -o out

# Cria a imagem final leve para rodar na nuvem
FROM mcr.microsoft.com/dotnet/runtime:8.0
WORKDIR /app
COPY --from=build-env /app/out .

# Cria a pasta onde o login vai ficar salvo
RUN mkdir -p /app/data
COPY WTelegram.session ./

# Comando para iniciar
ENTRYPOINT ["dotnet", "AchadinhosBot.dll"]