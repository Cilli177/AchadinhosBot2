# Code Review Arquitetural — Hub de Automação de Afiliados (.NET 8/9)

## Escopo analisado
Este review cobre o `Program.cs` atual e aponta riscos imediatos, melhorias estruturais e um exemplo de refatoração com DI/Options/Hosted Services.

---

## 1) Critical Issues (pode quebrar em produção agora)

1. **Segredos hardcoded no código-fonte**
   - `API_ACCESS_KEY`, `api_id`, `api_hash`, `BOT_TOKEN`, `SHOPEE_API_SECRET`, `SHEIN_CODE`, IDs de chat e tags de afiliação estão no `Program.cs`.
   - Risco: vazamento de credenciais, abuso da API e comprometimento da conta Telegram.

2. **`catch { }` vazios escondendo falhas críticas**
   - Há múltiplos pontos de swallow de exceção (API Web, bot polling, envio Telegram, token refresh etc.).
   - Risco: o serviço parece “rodando”, mas com funcionalidades quebradas sem observabilidade.

3. **`HttpListener` exposto em `http://*:{port}/` + autenticação simples por header**
   - Escuta em qualquer interface, sem TLS, sem rate limit, sem validação robusta de método/path/payload.
   - Risco: ataques de força bruta no `x-api-key`, replay e scraping de endpoint.

4. **Medição de tempo incorreta em `ProcessarMensagemUniversal`**
   - `Stopwatch` é iniciado antes do loop e `Stop()` é chamado dentro do loop.
   - O tempo pode ficar inconsistente para múltiplos links da mesma mensagem.

5. **Regex criado dentro do hot-path**
   - `new Regex(@"https?://[^\s]+")` em toda mensagem.
   - Risco: custo extra de CPU e GC sob alto volume de mensagens.

6. **Detecção de loja por `string.Contains` sem normalização de host**
   - Pode haver falso positivo (domínios maliciosos contendo texto “amazon.com” no caminho/query).
   - Risco: classificação errada e aplicação indevida de tag afiliada.

7. **Substituição de URL por `textoFinal.Replace(match.Value, urlCurta)`**
   - Substitui ocorrências idênticas em toda a mensagem, não somente o match atual.
   - Risco: troca indevida quando há links repetidos/parciais.

8. **Acoplamento extremo entre responsabilidades**
   - Um único arquivo concentra servidor web, bot polling, userbot, regras de negócio, persistência transitória e logging.
   - Risco: manutenção lenta, regressões frequentes e baixa testabilidade.

---

## 2) Improvements (qualidade de longo prazo)

### Arquitetura (SOLID + separação de responsabilidades)

**Estrutura sugerida**

```text
AchadinhosBot/
  src/
    Bootstrap/
      Program.cs
      ServiceCollectionExtensions.cs
    Configuration/
      TelegramOptions.cs
      AffiliateOptions.cs
      WebhookOptions.cs
    Application/
      Services/
        MessageProcessingService.cs
        AffiliateLinkService.cs
      Abstractions/
        IAffiliateLinkService.cs
        IMessageProcessor.cs
        IUrlExpander.cs
        IShortenerService.cs
    Infrastructure/
      Telegram/
        TelegramBotPollingService.cs
        TelegramUserbotService.cs
      Web/
        WebhookServerService.cs
      Http/
        UrlExpander.cs
        TinyUrlShortenerService.cs
      Logging/
        TelegramLogSink.cs
    Domain/
      Models/
        ConversionResult.cs
        LinkStore.cs
      Enums/
        StoreType.cs
```

### DI simples e robusta

- Use `Host.CreateApplicationBuilder(args)`.
- Configure `Options` com `appsettings.json` + environment variables.
- Use `IHttpClientFactory` com clientes nomeados.
- Execute API Web, bot e userbot como `BackgroundService`.

### Segurança e configuração

- Remova segredos do código e padronize via:
  - `appsettings.json` (valores não sensíveis)
  - `appsettings.Production.json`
  - Variáveis de ambiente para **segredos** (`TELEGRAM__BOT_TOKEN`, `SHOPEE__API_SECRET` etc.)
- Se possível, substitua `HttpListener` por ASP.NET Core Minimal API + Kestrel:
  - HTTPS obrigatório
  - `UseRateLimiter`
  - validação de header com hash/HMAC
  - `UseForwardedHeaders` (Railway/proxy)

### Erros e logs estruturados

- Substituir `Console.WriteLine` por `ILogger<T>`.
- Nunca usar `catch { }`; logar no mínimo `LogError(ex, "...")`.
- Incluir correlação por request/message-id no escopo de log.

### Concorrência e performance

- `Task.Run` no `Main` é desnecessário com `HostedService`.
- `HttpClient` atual está único (bom), mas migre para `IHttpClientFactory` para:
  - políticas de timeout/retry por cliente
  - rotação de handler controlada
- Regex: usar `[GeneratedRegex]` ou `RegexOptions.Compiled` estático.
- Evitar cadeia de awaits sequencial para múltiplos links quando possível (com limite de paralelismo).

### Robustez da lógica de links

- Parse com `Uri.TryCreate` e compare por `uri.Host` normalizado.
- Lista allowlist por host exato/sufixo válido (ex.: `.amazon.com.br`, `.amazon.com`).
- Canonicalização de URL antes de aplicar tag.
- Substituição de links por índice (`Regex.Replace` com MatchEvaluator), não por `string.Replace` global.

---

## 3) Exemplo de implementação refatorada

### 3.1 Program.cs (bootstrap com DI)

```csharp
using AchadinhosBot.Configuration;
using AchadinhosBot.Infrastructure.Telegram;
using AchadinhosBot.Infrastructure.Web;
using AchadinhosBot.Application.Abstractions;
using AchadinhosBot.Application.Services;

var builder = Host.CreateApplicationBuilder(args);

builder.Services
    .AddOptions<TelegramOptions>().Bind(builder.Configuration.GetSection("Telegram")).ValidateDataAnnotations().ValidateOnStart();
builder.Services
    .AddOptions<AffiliateOptions>().Bind(builder.Configuration.GetSection("Affiliate")).ValidateDataAnnotations().ValidateOnStart();
builder.Services
    .AddOptions<WebhookOptions>().Bind(builder.Configuration.GetSection("Webhook")).ValidateDataAnnotations().ValidateOnStart();

builder.Services.AddHttpClient("default", c =>
{
    c.Timeout = TimeSpan.FromMinutes(2);
    c.DefaultRequestHeaders.UserAgent.ParseAdd("AchadinhosBot/1.0");
});

builder.Services.AddSingleton<IAffiliateLinkService, AffiliateLinkService>();
builder.Services.AddSingleton<IMessageProcessor, MessageProcessingService>();

builder.Services.AddHostedService<WebhookServerService>();
builder.Services.AddHostedService<TelegramBotPollingService>();
builder.Services.AddHostedService<TelegramUserbotService>();

var app = builder.Build();
await app.RunAsync();
```

### 3.2 Opções tipadas

```csharp
using System.ComponentModel.DataAnnotations;

namespace AchadinhosBot.Configuration;

public sealed class TelegramOptions
{
    [Required] public int ApiId { get; init; }
    [Required] public string ApiHash { get; init; } = string.Empty;
    [Required] public string BotToken { get; init; } = string.Empty;
    [Required] public long DestinationChatId { get; init; }
    public long LogsChatId { get; init; }
}
```

### 3.3 Regex otimizada com GeneratedRegex

```csharp
using System.Text.RegularExpressions;

internal static partial class LinkRegex
{
    [GeneratedRegex(@"https?://[^\s]+", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    public static partial Regex Url();
}
```

### 3.4 Detecção robusta de loja

```csharp
public enum StoreType { Unknown, Amazon, MercadoLivre, Shopee, Shein }

public static class StoreDetector
{
    private static readonly string[] AmazonHosts = ["amazon.com.br", "amazon.com", "amzn.to", "a.co"];

    public static StoreType Detect(string rawUrl)
    {
        if (!Uri.TryCreate(rawUrl, UriKind.Absolute, out var uri)) return StoreType.Unknown;

        var host = uri.Host.ToLowerInvariant();

        if (AmazonHosts.Any(h => host == h || host.EndsWith('.' + h))) return StoreType.Amazon;
        if (host.Contains("mercadolivre.com") || host.Contains("mercadolibre.com")) return StoreType.MercadoLivre;
        if (host.Contains("shopee.com.br") || host == "shp.ee") return StoreType.Shopee;
        if (host.Contains("shein.com")) return StoreType.Shein;

        return StoreType.Unknown;
    }
}
```

### 3.5 Webhook com validação mínima

```csharp
if (!HttpMethods.IsPost(context.Request.Method))
{
    context.Response.StatusCode = StatusCodes.Status405MethodNotAllowed;
    return;
}

if (!context.Request.Headers.TryGetValue("x-api-key", out var key) ||
    !CryptographicOperations.FixedTimeEquals(
        Encoding.UTF8.GetBytes(key.ToString()),
        Encoding.UTF8.GetBytes(_options.ApiKey)))
{
    context.Response.StatusCode = StatusCodes.Status403Forbidden;
    return;
}
```

---

## 4) Plano incremental de migração (sem “big bang”)

1. Extrair `ProcessarMensagemUniversal` para `MessageProcessingService` + interface.
2. Extrair funções de afiliado (`Amazon`, `ML`, `Shopee`, `Shein`) para `AffiliateLinkService`.
3. Introduzir `HostBuilder`, `Options` e `ILogger` mantendo comportamento atual.
4. Migrar API de `HttpListener` para Minimal API.
5. Adicionar testes unitários para detecção de host e parsing de links.

---

## 5) Checklist objetivo para seu cenário atual

- [ ] Remover todos os segredos hardcoded.
- [ ] Eliminar `catch { }` vazios.
- [ ] Introduzir logs estruturados com níveis (`Information`, `Warning`, `Error`).
- [ ] Regex otimizada e reaproveitável.
- [ ] Detecção de loja por host canônico (`Uri`).
- [ ] API Web com POST + autenticação forte + rate limit.
- [ ] Separação em serviços com DI e Hosted Services.

