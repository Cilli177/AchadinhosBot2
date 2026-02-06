using System;
using System.IO;
using System.Threading.Tasks;
using System.Linq;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Net.Http;
using System.Net;
using System.Text.Json;
using System.Text.Encodings.Web; 
using System.Security.Cryptography;
using System.Text;
using WTelegram;
using TL;

class Program
{
    // --- TELEGRAM USER (ESPIÃO) ---
    static WTelegram.Client? Client;
    static WTelegram.UpdateManager? Manager;
    static int api_id = 31119088;
    static string api_hash = "62988e712c3f839bb1a5ea094d33d047";
    static long ID_DESTINO = 3632436217; 
    static InputPeer? PeerDestino;
    static string NomeDestino = "Desconhecido";

    // --- TELEGRAM BOT (ATENDENTE) ---
    static string BOT_TOKEN = "8572207460:AAHxc5QP9BZgXeLI1uqhmaPhzK7M-YQY5Tk";
    static long BotOffset = 0; 

    // --- CONFIGURAÇÕES DE LINKS ---
    static string AMAZON_TAG = "reidasofer022-20";
    static string ML_MATT_TOOL = "98187057";
    static string ML_MATT_WORD = "land177";
    static string SHOPEE_APP_ID = "18328430896"; 
    static string SHOPEE_API_SECRET = "J2K62RUC2ABIXXOFBH4GX62C5AADNHWV"; 
    static string SHOPEE_ENDPOINT = "https://open-api.affiliate.shopee.com.br/graphql"; 
    static string SHEIN_ID = "affiliate_koc_6149117215"; 
    static string SHEIN_CODE = "M7EU2";

    // --- HTTP CLIENT GLOBAL ---
    static readonly CookieContainer Cookies = new CookieContainer();
    static readonly HttpClientHandler Handler = new HttpClientHandler 
    { 
        AllowAutoRedirect = true, 
        CookieContainer = Cookies,
        UseCookies = true
    };
    static readonly HttpClient HttpClient = new HttpClient(Handler);

    // 📡 FONTES (Userbot Espião)
    static List<long> IDs_FONTES = new List<long>()
    {
        2775581964, 1871121243, 1569488789, 5258197181, -1003703804341, 3703804341
    };

    static async Task Main(string[] args)
    {
        Console.Clear();
        WTelegram.Helpers.Log = (lvl, str) => { };

        HttpClient.Timeout = TimeSpan.FromSeconds(30);
        HttpClient.DefaultRequestHeaders.UserAgent.ParseAdd("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36");
        HttpClient.DefaultRequestHeaders.Accept.ParseAdd("text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8");

        Console.WriteLine($"🚀 INICIANDO SISTEMA SUPREMO (API + BOT + USERBOT)...");

        // 1. INICIA A API WEB (PARA N8N/WHATSAPP)
        _ = Task.Run(IniciarServidorWeb);
        Console.WriteLine($"🌍 API WEB INICIADA EM BACKGROUND!");

        // 2. INICIA O BOT TELEGRAM (EM PARALELO)
        _ = Task.Run(BotPollingLoop);
        Console.WriteLine($"🤖 BOT TELEGRAM INICIADO EM BACKGROUND!");

        // 3. INICIA O USERBOT (ESPIÃO)
        await IniciarUserbotEspiao();
    }

    // ==================================================================================
    // 🌍 LÓGICA DA API WEB (PARA O N8N)
    // ==================================================================================
    static async Task IniciarServidorWeb()
    {
        try 
        {
            // O Railway define a porta na variável de ambiente PORT. Se não tiver, usa 8080.
            string port = Environment.GetEnvironmentVariable("PORT") ?? "8080";
            var listener = new HttpListener();
            // Escuta em todos os IPs na porta definida
            listener.Prefixes.Add($"http://*:{port}/"); 
            listener.Start();
            Console.WriteLine($"🌍 SERVIDOR HTTP OUVINDO NA PORTA {port}");

            while (true)
            {
                try
                {
                    var context = await listener.GetContextAsync();
                    _ = Task.Run(() => ProcessarRequestWeb(context)); // Processa sem travar o loop
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"⚠️ Erro no Listener HTTP: {ex.Message}");
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ FALHA CRÍTICA AO INICIAR SERVIDOR WEB: {ex.Message}");
            Console.WriteLine("   Dica: Se rodar local, execute como Admin ou use porta 8080.");
        }
    }

    static async Task ProcessarRequestWeb(HttpListenerContext context)
    {
        try
        {
            var request = context.Request;
            var response = context.Response;

            // Endpoint: /converter?text=LINK
            if (request.Url.AbsolutePath == "/converter")
            {
                string text = request.QueryString["text"];
                string responseString = "";

                if (string.IsNullOrEmpty(text))
                {
                    responseString = JsonSerializer.Serialize(new { error = "Envie o parametro 'text' com o link." });
                    response.StatusCode = 400;
                }
                else
                {
                    Console.WriteLine($"🌍 API RECEBEU: {text}");
                    string? linkConvertido = await ProcessarMensagemUniversal(text);

                    if (linkConvertido != null)
                    {
                        // Formata bonitinho igual no Telegram
                        if (linkConvertido.Contains("shein.com") && !linkConvertido.Contains(SHEIN_CODE))
                            linkConvertido += $"\n\n💎 Código Shein: {SHEIN_CODE}";

                        responseString = JsonSerializer.Serialize(new { success = true, original = text, converted = linkConvertido });
                        response.StatusCode = 200;
                    }
                    else
                    {
                        responseString = JsonSerializer.Serialize(new { success = false, message = "Nenhum link suportado encontrado." });
                        response.StatusCode = 200; // Retorna 200 mas com success false
                    }
                }

                byte[] buffer = Encoding.UTF8.GetBytes(responseString);
                response.ContentType = "application/json";
                response.ContentLength64 = buffer.Length;
                await response.OutputStream.WriteAsync(buffer, 0, buffer.Length);
                response.Close();
            }
            else
            {
                // Health Check (Útil pro Railway saber que está vivo)
                byte[] buffer = Encoding.UTF8.GetBytes("Robo Online 🤖");
                response.StatusCode = 200;
                await response.OutputStream.WriteAsync(buffer, 0, buffer.Length);
                response.Close();
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ Erro processando request WEB: {ex.Message}");
            context.Response.StatusCode = 500;
            context.Response.Close();
        }
    }

    // ==================================================================================
    // 🤖 LÓGICA DO BOT TELEGRAM (ATENDENTE)
    // ==================================================================================
    private static async Task BotPollingLoop()
    {
        while (true)
        {
            try
            {
                string url = $"https://api.telegram.org/bot{BOT_TOKEN}/getUpdates?offset={BotOffset + 1}&timeout=30";
                var response = await HttpClient.GetAsync(url);
                
                if (response.IsSuccessStatusCode)
                {
                    string json = await response.Content.ReadAsStringAsync();
                    using (JsonDocument doc = JsonDocument.Parse(json))
                    {
                        var root = doc.RootElement;
                        if (root.GetProperty("ok").GetBoolean())
                        {
                            var results = root.GetProperty("result");
                            foreach (var update in results.EnumerateArray())
                            {
                                long updateId = update.GetProperty("update_id").GetInt64();
                                BotOffset = updateId;

                                if (update.TryGetProperty("message", out var message))
                                {
                                    await ProcessarMensagemBot(message);
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"⚠️ ERRO NO BOT LOOP: {ex.Message}");
                await Task.Delay(5000); 
            }
        }
    }

    private static async Task ProcessarMensagemBot(JsonElement message)
    {
        try
        {
            if (!message.TryGetProperty("chat", out var chat)) return;
            long chatId = chat.GetProperty("id").GetInt64();
            
            if (!message.TryGetProperty("text", out var textElement)) return;
            string textoUsuario = textElement.GetString() ?? "";

            Console.WriteLine($"🤖 BOT RECEBEU DE {chatId}: {textoUsuario}");

            if (textoUsuario.StartsWith("/start") || textoUsuario.StartsWith("/ajuda"))
            {
                await EnviarRespostaBot(chatId, "👋 Olá! Eu sou o Conversor do Rei das Ofertas.\n\n🔗 **Envie qualquer link** e eu devolvo o link de afiliado!", 0);
                return;
            }

            string? linkConvertido = await ProcessarMensagemUniversal(textoUsuario);

            if (linkConvertido != null)
            {
                if (linkConvertido.Contains("shein.com") && !linkConvertido.Contains(SHEIN_CODE))
                    linkConvertido += $"\n\n💎 Código de busca: `{SHEIN_CODE}`";

                string respostaFinal = $"✅ **Link Convertido:**\n\n{linkConvertido}";
                long messageId = message.GetProperty("message_id").GetInt64();
                await EnviarRespostaBot(chatId, respostaFinal, messageId);
            }
            else
            {
                string chatType = chat.GetProperty("type").GetString() ?? "private";
                if (chatType == "private")
                {
                    await EnviarRespostaBot(chatId, "❌ Não encontrei nenhum link suportado.", 0);
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ ERRO PROCESSANDO MSG BOT: {ex.Message}");
        }
    }

    private static async Task EnviarRespostaBot(long chatId, string texto, long replyToMessageId)
    {
        var payload = new
        {
            chat_id = chatId,
            text = texto,
            parse_mode = "Markdown",
            disable_web_page_preview = false,
            reply_to_message_id = replyToMessageId > 0 ? (long?)replyToMessageId : null
        };

        string json = JsonSerializer.Serialize(payload);
        var content = new StringContent(json, Encoding.UTF8, "application/json");
        await HttpClient.PostAsync($"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage", content);
    }

    // ==================================================================================
    // 🕵️ LÓGICA DO USERBOT (ESPIÃO DE CANAIS)
    // ==================================================================================
    private static async Task IniciarUserbotEspiao()
    {
        bool isProduction = Environment.GetEnvironmentVariable("RAILWAY_ENVIRONMENT") != null;
        string sessionFile = isProduction ? "/tmp/WTelegram.session" : "WTelegram.session";
        
        if (isProduction && File.Exists("WTelegram.session.b64"))
        {
            try { File.WriteAllBytes(sessionFile, Convert.FromBase64String(File.ReadAllText("WTelegram.session.b64"))); }
            catch { }
        }

        Console.WriteLine("🔐 Autenticando ML (Opcional)...");
        bool mlAtivo = await AtualizarTokenMercadoLivre();
        if (mlAtivo) Console.WriteLine("✅ ML Conectado!");

        string? Config(string what)
        {
            if (what == "session_pathname") return sessionFile;
            if (what == "api_id") return api_id.ToString();
            if (what == "api_hash") return api_hash;
            if (what == "phone_number") return Environment.GetEnvironmentVariable("TELEGRAM_PHONE") ?? Console.ReadLine();
            if (what == "verification_code") return Environment.GetEnvironmentVariable("TELEGRAM_VERIFICATION_CODE") ?? Console.ReadLine();
            if (what == "password") return Environment.GetEnvironmentVariable("TELEGRAM_PASSWORD") ?? Console.ReadLine();
            return null;
        }

        try
        {
            Client = new WTelegram.Client(Config);
            await using (Client)
            {
                Manager = Client.WithUpdateManager(OnUserbotUpdate);
                var user = await Client.LoginUserIfNeeded();
                Console.WriteLine($"✅ USERBOT: Logado como {user.username ?? user.first_name} (ID: {user.id})");

                var dialogs = await Client.Messages_GetAllDialogs();
                dialogs.CollectUsersChats(Manager.Users, Manager.Chats);

                var chatDestino = dialogs.chats.Values.FirstOrDefault(c => c.ID == ID_DESTINO);
                if (chatDestino == null)
                {
                    long idInvertido = ID_DESTINO > 0 ? (ID_DESTINO * -1) - 1000000000000 : (ID_DESTINO + 1000000000000) * -1;
                    chatDestino = dialogs.chats.Values.FirstOrDefault(c => c.ID == idInvertido || c.ID == (ID_DESTINO * -1));
                }

                if (chatDestino != null)
                {
                    PeerDestino = chatDestino.ToInputPeer();
                    NomeDestino = chatDestino.Title;
                    Console.WriteLine($"🎯 DESTINO VIP CONFIRMADO: {NomeDestino}");
                    ID_DESTINO = chatDestino.ID; 
                }

                Console.WriteLine("👀 USERBOT MONITORANDO OFERTAS...");
                await Task.Delay(-1);
            }
        }
        catch (Exception ex) { Console.WriteLine($"❌ ERRO USERBOT: {ex.Message}"); }
    }

    private static async Task OnUserbotUpdate(Update update)
    {
        if (PeerDestino == null || Client == null) return;

        switch (update)
        {
            case UpdateNewMessage unm when unm.message is Message msg:
                long idOrigem = msg.peer_id.ID;
                bool ehFonteValida = IDs_FONTES.Contains(idOrigem) || 
                                     IDs_FONTES.Contains((idOrigem * -1) - 1000000000000) || 
                                     IDs_FONTES.Contains(idOrigem * -1);

                if (ehFonteValida && !string.IsNullOrEmpty(msg.message))
                {
                    bool ehLaboratorio = (idOrigem == 5258197181 || idOrigem == 3703804341 || idOrigem == -1003703804341);
                    if (msg.message.Length < 5 && !ehLaboratorio) return;

                    Console.WriteLine($"\n⚡ [USERBOT] OFERTA DETECTADA (Fonte: {idOrigem})");
                    string? novoTexto = await ProcessarMensagemUniversal(msg.message);

                    if (novoTexto == null) return;

                    if (novoTexto.Contains("shein.com") && !novoTexto.Contains(SHEIN_CODE))
                        novoTexto += $"\n\n💎 Digite na busca: **{SHEIN_CODE}**";

                    novoTexto += "\n\n🔥 Vi no: @ReiDasOfertasVIP";

                    try
                    {
                        if (msg.media is MessageMediaPhoto mmPhoto && mmPhoto.photo is Photo photo)
                        {
                            var inputMedia = new InputMediaPhoto
                            {
                                id = new InputPhoto { id = photo.id, access_hash = photo.access_hash, file_reference = photo.file_reference }
                            };
                            await Client.Messages_SendMedia(PeerDestino, inputMedia, novoTexto, WTelegram.Helpers.RandomLong());
                            Console.WriteLine("   ✅ [USERBOT] ENVIADO PRO VIP!");
                        }
                        else
                        {
                            await Client.SendMessageAsync(PeerDestino, novoTexto);
                            Console.WriteLine("   ✅ [USERBOT] ENVIADO PRO VIP!");
                        }
                    }
                    catch (Exception ex) { Console.WriteLine($"   ❌ FALHA NO ENVIO VIP: {ex.Message}"); }
                }
                break;
        }
    }

    // ==================================================================================
    // 🧠 CÉREBRO COMPARTILHADO (PROCESSADOR DE LINKS)
    // ==================================================================================
    private static async Task<string?> ProcessarMensagemUniversal(string textoOriginal)
    {
        var regexLink = new Regex(@"https?://[^\s]+");
        var matches = regexLink.Matches(textoOriginal);
        string textoFinal = textoOriginal;
        bool linkValidoEncontrado = false;

        foreach (Match match in matches)
        {
            string urlOriginal = match.Value;
            if (urlOriginal.Contains("tidd.ly") || urlOriginal.Contains("natura.com") || urlOriginal.Contains("magazineluiza")) continue;

            string urlExpandida = urlOriginal;
            if (IsShortLink(urlOriginal)) urlExpandida = await ExpandirUrl(urlOriginal, 0);

            string urlComTag = urlExpandida;
            bool ehAmazon = urlExpandida.Contains("amazon.com") || urlExpandida.Contains("amzn.to");
            bool ehMercadoLivre = urlExpandida.Contains("mercadolivre.com") || urlExpandida.Contains("mercadolibre.com");
            bool ehShopee = urlExpandida.Contains("shopee.com.br") || urlExpandida.Contains("shp.ee");
            bool ehShein = urlExpandida.Contains("shein.com");

            if (ehAmazon) { urlComTag = AplicarTagAmazon(urlExpandida); linkValidoEncontrado = true; }
            else if (ehMercadoLivre) {
                string? linkConstruido = await GerarLinkMercadoLivre(urlExpandida);
                if (linkConstruido != null) { urlComTag = linkConstruido; linkValidoEncontrado = true; }
            }
            else if (ehShopee) {
                string? linkShopee = await GerarLinkShopee(urlExpandida);
                if (linkShopee != null) { urlComTag = linkShopee; linkValidoEncontrado = true; }
            }
            else if (ehShein) {
                urlComTag = AplicarTagShein(urlExpandida); linkValidoEncontrado = true;
            }
            else continue;

            string urlCurta = await EncurtarTinyUrl(urlComTag);
            if (urlOriginal != urlCurta) textoFinal = textoFinal.Replace(urlOriginal, urlCurta);
        }

        return linkValidoEncontrado ? textoFinal : null;
    }

    // ... (MÉTODOS AUXILIARES DEVEM FICAR AQUI: GerarLinkShopee, AplicarTagShein, etc.
    // ... (Copie os mesmos métodos que já estavam funcionando na versão anterior)
    
    // MÉTODOS MANTIDOS (Para economizar espaço, certifique-se de que eles estão aqui no arquivo final):
    // AplicarTagShein, GerarLinkShopee, GerarLinkMercadoLivre, ExtrairIdMlb, AtualizarTokenMercadoLivre, EncurtarTinyUrl, IsShortLink, ExpandirUrl, AplicarTagAmazon.
    // Se precisar que eu reenvie o arquivo COM esses métodos explicítos, me avise, mas é só manter o que já tinha.

    private static string AplicarTagShein(string url)
    {
        try 
        {
            int indexInterrogacao = url.IndexOf('?');
            string urlLimpa = indexInterrogacao > 0 ? url.Substring(0, indexInterrogacao) : url;
            return urlLimpa + "?url_from=" + SHEIN_ID;
        }
        catch { return url; }
    }

    private static async Task<string?> GerarLinkShopee(string urlOriginal)
    {
        try
        {
            string urlJson = JsonSerializer.Serialize(urlOriginal);
            string queryGraphQL = $@"mutation {{ generateShortLink(input: {{ originUrl: {urlJson} }}) {{ shortLink }} }}";
            var payload = new { query = queryGraphQL };
            var jsonOptions = new JsonSerializerOptions { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping };
            string jsonContent = JsonSerializer.Serialize(payload, jsonOptions);
            long timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            string factor = SHOPEE_APP_ID + timestamp + jsonContent + SHOPEE_API_SECRET;
            string signature;
            using (var sha256 = SHA256.Create()) {
                byte[] bytes = Encoding.UTF8.GetBytes(factor);
                byte[] hash = sha256.ComputeHash(bytes);
                signature = BitConverter.ToString(hash).Replace("-", "").ToLower();
            }
            var request = new HttpRequestMessage(HttpMethod.Post, SHOPEE_ENDPOINT);
            request.Content = new StringContent(jsonContent, Encoding.UTF8, "application/json");
            request.Headers.Add("Authorization", $"SHA256 Credential={SHOPEE_APP_ID}, Timestamp={timestamp}, Signature={signature}");
            var response = await HttpClient.SendAsync(request);
            string responseString = await response.Content.ReadAsStringAsync();
            if (!response.IsSuccessStatusCode) return null;
            var match = Regex.Match(responseString, "\"shortLink\":\"(.*?)\"");
            if (match.Success) return match.Groups[1].Value;
            return null;
        }
        catch { return null; }
    }

    private static async Task<string?> GerarLinkMercadoLivre(string urlProduto)
    {
        string? itemId = ExtrairIdMlb(urlProduto);
        if (itemId == null) {
            try {
                var html = await HttpClient.GetStringAsync(urlProduto);
                var matchMeta = Regex.Match(html, @"mercadolibre://items/(MLB-?\d+)", RegexOptions.IgnoreCase);
                if (matchMeta.Success) itemId = matchMeta.Groups[1].Value;
                if (itemId == null) { var matchJson = Regex.Match(html, @"""id""\s*:\s*""(MLB-?\d+)""", RegexOptions.IgnoreCase); if (matchJson.Success) itemId = matchJson.Groups[1].Value; }
                if (itemId == null && urlProduto.Contains("social")) { var matchSocial = Regex.Match(html, @"(MLB-?\d{7,})"); if (matchSocial.Success) itemId = matchSocial.Groups[1].Value; }
            } catch { }
        }
        if (itemId == null) return null;
        string idLimpo = itemId.Replace("-", "").ToUpper().Replace("MLB", "");
        return $"https://produto.mercadolivre.com.br/MLB-{idLimpo}?matt_tool={ML_MATT_TOOL}&matt_word={ML_MATT_WORD}";
    }

    private static string? ExtrairIdMlb(string texto) { var regex = new Regex(@"(MLB-?\d+)", RegexOptions.IgnoreCase); var match = regex.Match(texto); return match.Success ? match.Groups[1].Value : null; }
    private static async Task<bool> AtualizarTokenMercadoLivre() { try { string appId = Environment.GetEnvironmentVariable("ML_APP_ID"); string secret = Environment.GetEnvironmentVariable("ML_CLIENT_SECRET"); string refreshToken = Environment.GetEnvironmentVariable("ML_REFRESH_TOKEN"); if (string.IsNullOrEmpty(refreshToken)) return false; return true; } catch { return false; } }
    private static async Task<string> EncurtarTinyUrl(string urlLonga) { try { var response = await HttpClient.GetStringAsync($"https://tinyurl.com/api-create.php?url={urlLonga}"); return response; } catch { return urlLonga; } }
    private static bool IsShortLink(string url) { return url.Contains("amzn.to") || url.Contains("bit.ly") || url.Contains("t.co") || url.Contains("compre.link") || url.Contains("oferta.one") || url.Contains("shope.ee") || url.Contains("a.co") || url.Contains("tinyurl") || url.Contains("mercadolivre.com/sec") || url.Contains("mercadolivre.com.br/social") || url.Contains("lista.mercadolivre.com.br") || url.Contains("produto.mercadolivre.com.br") || url.Contains("divulgador.link") || url.Contains("onelink.shein.com"); }
    private static async Task<string> ExpandirUrl(string url, int depth) { if (depth > 6) return url; try { var response = await HttpClient.GetAsync(url); if ((int)response.StatusCode >= 300 && (int)response.StatusCode <= 399) { var location = response.Headers.Location; if (location != null) { string nextUrl = location.IsAbsoluteUri ? location.ToString() : new Uri(new Uri(url), location).ToString(); return await ExpandirUrl(nextUrl, depth + 1); } } return response.RequestMessage?.RequestUri?.ToString() ?? url; } catch { return url; } }
    private static string AplicarTagAmazon(string url) { try { string limpa = Regex.Replace(url, @"[?&]tag=[^&]+", ""); string separador = limpa.Contains("?") ? "&" : "?"; return limpa + separador + "tag=" + AMAZON_TAG; } catch { return url; } }
}