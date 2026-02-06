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
using System.Diagnostics; // ⏱️ Necessário para o cronômetro
using WTelegram;
using TL;

class Program
{
    // 🔐 SEGURANÇA
    static string API_ACCESS_KEY = "reidasofertas-secret-key-2026"; 

    // 📊 ID DO CANAL DE LOGS (JÁ PREENCHIDO)
    static long ID_LOGS = -1003807256386; 

    // --- TELEGRAM ---
    static WTelegram.Client? Client;
    static WTelegram.UpdateManager? Manager;
    static int api_id = 31119088;
    static string api_hash = "62988e712c3f839bb1a5ea094d33d047";
    static long ID_DESTINO = 3632436217; 
    static InputPeer? PeerDestino;
    static InputPeer? PeerLogs; 
    static string NomeDestino = "Desconhecido";
    static string BOT_TOKEN = "8572207460:AAHxc5QP9BZgXeLI1uqhmaPhzK7M-YQY5Tk";
    static long BotOffset = 0; 

    // --- CONFIGURAÇÕES ---
    static string AMAZON_TAG = "reidasofer022-20";
    static string ML_MATT_TOOL = "98187057";
    static string ML_MATT_WORD = "land177";
    static string SHOPEE_APP_ID = "18328430896"; 
    static string SHOPEE_API_SECRET = "J2K62RUC2ABIXXOFBH4GX62C5AADNHWV"; 
    static string SHOPEE_ENDPOINT = "https://open-api.affiliate.shopee.com.br/graphql"; 
    static string SHEIN_ID = "affiliate_koc_6149117215"; 
    static string SHEIN_CODE = "M7EU2";

    static readonly CookieContainer Cookies = new CookieContainer();
    static readonly HttpClientHandler Handler = new HttpClientHandler 
    { 
        AllowAutoRedirect = true, 
        CookieContainer = Cookies,
        UseCookies = true
    };
    static readonly HttpClient HttpClient = new HttpClient(Handler);

    static List<long> IDs_FONTES = new List<long>()
    {
        2775581964, 1871121243, 1569488789, 5258197181, -1003703804341, 3703804341
    };

    static async Task Main(string[] args)
    {
        Console.Clear();
        WTelegram.Helpers.Log = (lvl, str) => { };
        HttpClient.Timeout = TimeSpan.FromMinutes(2);
        HttpClient.DefaultRequestHeaders.UserAgent.ParseAdd("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36");
        HttpClient.DefaultRequestHeaders.Accept.ParseAdd("text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8");

        Console.WriteLine($"🚀 INICIANDO SISTEMA COM ANALYTICS 2.0 📊...");

        _ = Task.Run(IniciarServidorWeb);
        Console.WriteLine($"🌍 API WEB INICIADA!");

        _ = Task.Run(BotPollingLoop);
        Console.WriteLine($"🤖 BOT TELEGRAM INICIADO!");

        await IniciarUserbotEspiao();
    }

    // ==================================================================================
    // 🌍 API WEB
    // ==================================================================================
    static async Task IniciarServidorWeb()
    {
        try 
        {
            string port = Environment.GetEnvironmentVariable("PORT") ?? "8080";
            var listener = new HttpListener();
            listener.Prefixes.Add($"http://*:{port}/"); 
            listener.Start();
            
            while (true)
            {
                try { var context = await listener.GetContextAsync(); _ = Task.Run(() => ProcessarRequestWeb(context)); }
                catch { }
            }
        }
        catch (Exception ex) { Console.WriteLine($"❌ FALHA API WEB: {ex.Message}"); }
    }

    static async Task ProcessarRequestWeb(HttpListenerContext context)
    {
        try
        {
            var request = context.Request;
            var response = context.Response;

            string? clientKey = request.Headers["x-api-key"];
            if (string.IsNullOrEmpty(clientKey) || clientKey != API_ACCESS_KEY)
            {
                response.StatusCode = 403;
                response.Close();
                return;
            }

            if (request.Url.AbsolutePath == "/converter")
            {
                string text = request.QueryString["text"];
                string responseString = "";

                if (!string.IsNullOrEmpty(text))
                {
                    string? linkConvertido = await ProcessarMensagemUniversal(text, "WhatsApp/API");

                    if (linkConvertido != null)
                    {
                        if (linkConvertido.Contains("shein.com") && !linkConvertido.Contains(SHEIN_CODE))
                            linkConvertido += $"\n\n💎 Código Shein: {SHEIN_CODE}";

                        responseString = JsonSerializer.Serialize(new { success = true, converted = linkConvertido });
                    }
                    else
                    {
                        responseString = JsonSerializer.Serialize(new { success = false });
                    }
                }
                
                byte[] buffer = Encoding.UTF8.GetBytes(responseString);
                response.ContentType = "application/json";
                await response.OutputStream.WriteAsync(buffer, 0, buffer.Length);
                response.Close();
            }
            else
            {
                response.StatusCode = 200;
                response.Close();
            }
        }
        catch { context.Response.Close(); }
    }

    // ==================================================================================
    // 🤖 BOT TELEGRAM
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
                    using (JsonDocument doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync()))
                    {
                        if (doc.RootElement.GetProperty("ok").GetBoolean())
                        {
                            foreach (var update in doc.RootElement.GetProperty("result").EnumerateArray())
                            {
                                BotOffset = update.GetProperty("update_id").GetInt64();
                                if (update.TryGetProperty("message", out var message)) await ProcessarMensagemBot(message);
                            }
                        }
                    }
                }
            }
            catch { await Task.Delay(5000); }
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

            if (textoUsuario.StartsWith("/start")) 
            {
                await EnviarRespostaBot(chatId, "👋 Mande o link!", 0);
                return;
            }

            string? linkConvertido = await ProcessarMensagemUniversal(textoUsuario, "Bot Telegram");

            if (linkConvertido != null)
            {
                if (linkConvertido.Contains("shein.com") && !linkConvertido.Contains(SHEIN_CODE))
                    linkConvertido += $"\n\n💎 Código: `{SHEIN_CODE}`";

                await EnviarRespostaBot(chatId, $"✅ **Link Convertido:**\n\n{linkConvertido}", message.GetProperty("message_id").GetInt64());
            }
            else if (chat.GetProperty("type").GetString() == "private")
            {
                await EnviarRespostaBot(chatId, "❌ Link não suportado.", 0);
            }
        }
        catch { }
    }

    private static async Task EnviarRespostaBot(long chatId, string texto, long replyToMessageId)
    {
        var payload = new { chat_id = chatId, text = texto, parse_mode = "Markdown", reply_to_message_id = replyToMessageId > 0 ? (long?)replyToMessageId : null };
        var content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");
        await HttpClient.PostAsync($"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage", content);
    }

    // ==================================================================================
    // 🕵️ USERBOT
    // ==================================================================================
    private static async Task IniciarUserbotEspiao()
    {
        bool isProduction = Environment.GetEnvironmentVariable("RAILWAY_ENVIRONMENT") != null;
        string sessionFile = isProduction ? "/tmp/WTelegram.session" : "WTelegram.session";
        if (isProduction && File.Exists("WTelegram.session.b64")) try { File.WriteAllBytes(sessionFile, Convert.FromBase64String(File.ReadAllText("WTelegram.session.b64"))); } catch { }

        await AtualizarTokenMercadoLivre();

        try
        {
            Client = new WTelegram.Client(what => what == "session_pathname" ? sessionFile : 
                                                  what == "api_id" ? api_id.ToString() : 
                                                  what == "api_hash" ? api_hash : 
                                                  Environment.GetEnvironmentVariable(what.ToUpper())); // Fallback para ENV
            await using (Client)
            {
                Manager = Client.WithUpdateManager(OnUserbotUpdate);
                await Client.LoginUserIfNeeded();
                
                var dialogs = await Client.Messages_GetAllDialogs();
                dialogs.CollectUsersChats(Manager.Users, Manager.Chats);

                var chatDestino = dialogs.chats.Values.FirstOrDefault(c => c.ID == ID_DESTINO);
                if (chatDestino != null) { PeerDestino = chatDestino.ToInputPeer(); ID_DESTINO = chatDestino.ID; }
                else
                {
                   // Fallback para encontrar destino por ID negativo
                   long idInvertido = ID_DESTINO > 0 ? (ID_DESTINO * -1) - 1000000000000 : (ID_DESTINO + 1000000000000) * -1;
                   chatDestino = dialogs.chats.Values.FirstOrDefault(c => c.ID == idInvertido || c.ID == (ID_DESTINO * -1));
                   if (chatDestino != null) { PeerDestino = chatDestino.ToInputPeer(); ID_DESTINO = chatDestino.ID; }
                }

                // 📊 CONFIGURA CANAL DE LOGS
                if (ID_LOGS != 0)
                {
                    var chatLogs = dialogs.chats.Values.FirstOrDefault(c => c.ID == ID_LOGS);
                    if (chatLogs == null)
                    {
                        long idInvertido = ID_LOGS > 0 ? (ID_LOGS * -1) - 1000000000000 : (ID_LOGS + 1000000000000) * -1;
                        chatLogs = dialogs.chats.Values.FirstOrDefault(c => c.ID == idInvertido || c.ID == (ID_LOGS * -1));
                    }
                    if (chatLogs != null) 
                    {
                        PeerLogs = chatLogs.ToInputPeer(); 
                        Console.WriteLine($"📊 LOGS ATIVOS: {chatLogs.Title}");
                    }
                    else
                    {
                        Console.WriteLine($"❌ CANAL DE LOGS {ID_LOGS} NÃO ENCONTRADO NA LISTA DE CHATS!");
                    }
                }

                Console.WriteLine("👀 MONITORANDO...");
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
                bool ehFonteValida = IDs_FONTES.Contains(idOrigem) || IDs_FONTES.Contains((idOrigem * -1) - 1000000000000) || IDs_FONTES.Contains(idOrigem * -1);

                if (ehFonteValida && !string.IsNullOrEmpty(msg.message))
                {
                    if (msg.message.Length < 5 && idOrigem != 3703804341) return;

                    string? novoTexto = await ProcessarMensagemUniversal(msg.message, "Espião (Auto)");

                    if (novoTexto == null) return;

                    if (novoTexto.Contains("shein.com") && !novoTexto.Contains(SHEIN_CODE))
                        novoTexto += $"\n\n💎 Digite na busca: **{SHEIN_CODE}**";
                    novoTexto += "\n\n🔥 Vi no: @ReiDasOfertasVIP";

                    try
                    {
                        if (msg.media is MessageMediaPhoto mmPhoto && mmPhoto.photo is Photo photo)
                        {
                            var inputMedia = new InputMediaPhoto { id = new InputPhoto { id = photo.id, access_hash = photo.access_hash, file_reference = photo.file_reference } };
                            await Client.Messages_SendMedia(PeerDestino, inputMedia, novoTexto, WTelegram.Helpers.RandomLong());
                        }
                        else
                        {
                            await Client.SendMessageAsync(PeerDestino, novoTexto);
                        }
                    }
                    catch { }
                }
                break;
        }
    }

    // ==================================================================================
    // 🧠 CÉREBRO + LOGS ANALYTICS 2.0
    // ==================================================================================
    private static async Task<string?> ProcessarMensagemUniversal(string textoOriginal, string origem)
    {
        var sw = Stopwatch.StartNew(); // ⏱️ INICIA O CRONÔMETRO

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
            string lojaDetectada = "Desconhecida";
            string icone = "❓";

            if (urlExpandida.Contains("amazon.com") || urlExpandida.Contains("amzn.to"))
            {
                urlComTag = AplicarTagAmazon(urlExpandida);
                lojaDetectada = "Amazon";
                icone = "🍌";
                linkValidoEncontrado = true;
            }
            else if (urlExpandida.Contains("mercadolivre.com") || urlExpandida.Contains("mercadolibre.com"))
            {
                string? link = await GerarLinkMercadoLivre(urlExpandida);
                if (link != null) { urlComTag = link; lojaDetectada = "Mercado Livre"; icone = "🤝"; linkValidoEncontrado = true; }
            }
            else if (urlExpandida.Contains("shopee.com.br") || urlExpandida.Contains("shp.ee"))
            {
                string? link = await GerarLinkShopee(urlExpandida);
                if (link != null) { urlComTag = link; lojaDetectada = "Shopee"; icone = "🟠"; linkValidoEncontrado = true; }
            }
            else if (urlExpandida.Contains("shein.com"))
            {
                urlComTag = AplicarTagShein(urlExpandida);
                lojaDetectada = "Shein";
                icone = "👗";
                linkValidoEncontrado = true;
            }
            else continue;

            string urlCurta = await EncurtarTinyUrl(urlComTag);
            if (urlOriginal != urlCurta) textoFinal = textoFinal.Replace(urlOriginal, urlCurta);

            sw.Stop(); // ⏱️ PARA O CRONÔMETRO

            if (linkValidoEncontrado)
            {
                _ = LogarConversao(origem, lojaDetectada, icone, urlOriginal, urlCurta, sw.ElapsedMilliseconds);
            }
        }

        return linkValidoEncontrado ? textoFinal : null;
    }

    // 📊 LOG ANALYTICS 2.0
    private static async Task LogarConversao(string origem, string loja, string icone, string original, string final, long ms)
    {
        try 
        {
            if (Client != null && PeerLogs != null)
            {
                string logMsg = $"{icone} **{loja.ToUpper()}** (⏱️ {ms}ms)\n\n" +
                                $"🌍 **Origem:** {origem}\n" +
                                $"📥 **Entrada:** `{original}`\n" +
                                $"📤 **Saída:** `{final}`\n" +
                                $"✅ **Status:** Afiliado Confirmado";
                
                await Client.SendMessageAsync(PeerLogs, logMsg);
            }
            else
            {
                Console.WriteLine($"[LOG LOCAL] {loja} ({ms}ms)");
            }
        }
        catch (Exception ex) { Console.WriteLine($"Erro Log: {ex.Message}"); }
    }

    // MÉTODOS AUXILIARES
    private static string AplicarTagShein(string url) { try { int i = url.IndexOf('?'); string u = i > 0 ? url.Substring(0, i) : url; return u + "?url_from=" + SHEIN_ID; } catch { return url; } }
    private static async Task<string?> GerarLinkShopee(string url) { try { string json = JsonSerializer.Serialize(new { query = $@"mutation {{ generateShortLink(input: {{ originUrl: {JsonSerializer.Serialize(url)} }}) {{ shortLink }} }}" }); string ts = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(); string sig; using (var sha = SHA256.Create()) sig = BitConverter.ToString(sha.ComputeHash(Encoding.UTF8.GetBytes(SHOPEE_APP_ID + ts + json + SHOPEE_API_SECRET))).Replace("-", "").ToLower(); var req = new HttpRequestMessage(HttpMethod.Post, SHOPEE_ENDPOINT) { Content = new StringContent(json, Encoding.UTF8, "application/json") }; req.Headers.Add("Authorization", $"SHA256 Credential={SHOPEE_APP_ID}, Timestamp={ts}, Signature={sig}"); var res = await HttpClient.SendAsync(req); var m = Regex.Match(await res.Content.ReadAsStringAsync(), "\"shortLink\":\"(.*?)\""); return m.Success ? m.Groups[1].Value : null; } catch { return null; } }
    private static async Task<string?> GerarLinkMercadoLivre(string url) { string? id = ExtrairIdMlb(url); if(id == null) { try { var h = await HttpClient.GetStringAsync(url); var m = Regex.Match(h, @"mercadolibre://items/(MLB-?\d+)"); if(m.Success) id = m.Groups[1].Value; if(id==null && url.Contains("social")) { m = Regex.Match(h, @"(MLB-?\d{7,})"); if(m.Success) id=m.Groups[1].Value; } } catch {} } if(id==null) return null; return $"https://produto.mercadolivre.com.br/MLB-{id.Replace("-","").ToUpper().Replace("MLB","")}?matt_tool={ML_MATT_TOOL}&matt_word={ML_MATT_WORD}"; }
    private static string? ExtrairIdMlb(string t) { var m = Regex.Match(t, @"(MLB-?\d+)", RegexOptions.IgnoreCase); return m.Success ? m.Groups[1].Value : null; }
    private static async Task<bool> AtualizarTokenMercadoLivre() { try { string r = Environment.GetEnvironmentVariable("ML_REFRESH_TOKEN"); if(string.IsNullOrEmpty(r)) return false; var c = new FormUrlEncodedContent(new[] { new KeyValuePair<string,string>("grant_type","refresh_token"), new KeyValuePair<string,string>("client_id", Environment.GetEnvironmentVariable("ML_APP_ID")), new KeyValuePair<string,string>("client_secret", Environment.GetEnvironmentVariable("ML_CLIENT_SECRET")), new KeyValuePair<string,string>("refresh_token", r) }); return (await HttpClient.PostAsync("https://api.mercadolibre.com/oauth/token", c)).IsSuccessStatusCode; } catch { return false; } }
    private static async Task<string> EncurtarTinyUrl(string u) { try { return await HttpClient.GetStringAsync($"https://tinyurl.com/api-create.php?url={u}"); } catch { return u; } }
    private static bool IsShortLink(string u) { return u.Contains("amzn.to") || u.Contains("bit.ly") || u.Contains("t.co") || u.Contains("compre.link") || u.Contains("oferta.one") || u.Contains("shope.ee") || u.Contains("a.co") || u.Contains("tinyurl") || u.Contains("mercadolivre.com") || u.Contains("shein.com") || u.Contains("divulgador.link"); }
    private static async Task<string> ExpandirUrl(string u, int d) { if(d>6) return u; try { var r = await HttpClient.GetAsync(u); if((int)r.StatusCode>=300 && (int)r.StatusCode<=399 && r.Headers.Location!=null) return await ExpandirUrl(r.Headers.Location.IsAbsoluteUri ? r.Headers.Location.ToString() : new Uri(new Uri(u), r.Headers.Location).ToString(), d+1); return r.RequestMessage?.RequestUri?.ToString() ?? u; } catch { return u; } }
    private static string AplicarTagAmazon(string u) { try { string l = Regex.Replace(u, @"[?&]tag=[^&]+", ""); return l + (l.Contains("?")?"&":"?") + "tag=" + AMAZON_TAG; } catch { return u; } }
}