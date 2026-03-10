# Build
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY . .
RUN dotnet restore AchadinhosBot.Next/AchadinhosBot.Next.csproj
RUN dotnet publish AchadinhosBot.Next/AchadinhosBot.Next.csproj -c Release -o /app/publish /p:UseAppHost=false

# Runtime
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS final
WORKDIR /app
COPY --from=build /app/publish .

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ffmpeg \
    && rm -rf /var/lib/apt/lists/*

ENV ASPNETCORE_URLS=http://0.0.0.0:8081
EXPOSE 8081

ENTRYPOINT ["dotnet", "AchadinhosBot.Next.dll"]
