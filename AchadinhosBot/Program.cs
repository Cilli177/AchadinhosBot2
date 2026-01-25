using System;
using System.IO;
using System.Threading.Tasks;
using System.Linq;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Net.Http;
using System.Net;
using System.Text.Json;
using WTelegram;
using TL;

class Program
{
    static WTelegram.Client? Client;
    static WTelegram.UpdateManager? Manager;
    
    static readonly CookieContainer Cookies = new CookieContainer();
    static readonly HttpClientHandler Handler = new HttpClientHandler 
    { 
        AllowAutoRedirect = false, 
        CookieContainer = Cookies,
        UseCookies = true
    };
    static readonly HttpClient HttpClient = new HttpClient(Handler);

    // ⚙️ SEUS DADOS
    static int api_id = 31119088;
    static string api_hash = "62988e712c3f839bb1a5ea094d33d047";
    static long ID_DESTINO = 3632436217; 
    static InputPeer? PeerDestino;

    // 🍌 AMAZON
    static string AMAZON_TAG = "reidasofer022-20";

    // 🤝 MERCADO LIVRE
    static string ML_MATT_TOOL = "98187057";
    static string ML_MATT_WORD = "land177";
    static string? ML_ACCESS_TOKEN = null;

    // 📡 FONTES
    static List<long> IDs_FONTES = new List<long>()
    {
        2775581964, // Herói da Promo
        1871121243, // táBaratasso
        1569488789, // Ofertas Gamer
        5258197181  // 🧪 Laboratório
    };

    static async Task Main(string[] args)
    {
        Console.Clear();
        WTelegram.Helpers.Log = (lvl, str) => { };

        // Headers Otimizados
        HttpClient.Timeout = TimeSpan.FromSeconds(30);
        HttpClient.DefaultRequestHeaders.UserAgent.ParseAdd("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36");
        HttpClient.DefaultRequestHeaders.Accept.ParseAdd("text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8");

        Console.WriteLine("🚀 INICIANDO ROBÔ (Modo Rápido - Sem IA)...");

        // --- LOGIN TELEGRAM ---
        bool isProduction = Environment.GetEnvironmentVariable("RAILWAY_ENVIRONMENT") != null;
        string sessionFile = isProduction ? "/tmp/WTelegram.session" : "WTelegram.session";
        
        if (isProduction && File.Exists("WTelegram.session.b64"))
        {
            try 
            {
                File.WriteAllBytes(sessionFile, Convert.FromBase64String(File.ReadAllText("WTelegram.session.b64")));
                Console.WriteLine($"📦 Sessão Telegram restaurada!");
            }
            catch (Exception ex) { Console.WriteLine($"❌ Erro sessão: {ex.Message}"); }
        }

        // --- LOGIN ML (Mantido para futuro uso, mas não bloqueia o robô) ---
        Console.WriteLine("🔐 Autenticando ML...");
        bool mlAtivo = await AtualizarTokenMercadoLivre();
        if (mlAtivo) Console.WriteLine("✅ ML Conectado (Token Ativo)!");
        else Console.WriteLine("⚠️ ML Token Off (Seguindo com Link Manual).");

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
                Manager = Client.WithUpdateManager(OnUpdate);
                var user = await Client.LoginUserIfNeeded();
                Console.WriteLine($"✅ TELEGRAM: Logado como {user.username ?? user.first_name}");

                Console.WriteLine("⏳ Mapeando canais...");
                var dialogs = await Client.Messages_GetAllDialogs();
                dialogs.CollectUsersChats(Manager.Users, Manager.Chats);

                var chatDestino = dialogs.chats.Values.FirstOrDefault(c => c.ID == ID_DESTINO);
                if (chatDestino != null)
                {
                    PeerDestino = chatDestino.ToInputPeer();
                    Console.WriteLine($"📢 DESTINO: {chatDestino.Title}");
                }
                else { Console.WriteLine($"❌ ERRO: Canal destino {ID_DESTINO} não encontrado!"); }

                Console.WriteLine("---------------------------------------------------");
                Console.WriteLine("👀 MONITORANDO OFERTAS...");
                
                await Task.Delay(-1);
            }
        }
        catch (Exception ex) { Console.WriteLine($"❌ ERRO MAIN: {ex.Message}"); }
    }

    private static async Task OnUpdate(Update update)
    {
        if (PeerDestino == null || Client == null) return;

        switch (update)
        {
            case UpdateNewMessage unm when unm.message is Message msg:
                if (msg.peer_id != null && IDs_FONTES.Contains(msg.peer_id.ID) && !string.IsNullOrEmpty(msg.message))
                {
                    // No laboratório aceita msg curta
                    if (msg.message.Length < 5 && msg.peer_id.ID != 5258197181) return;

                    Console.WriteLine($"\n⚡ OFERTA DETECTADA (Fonte: {msg.peer_id.ID})");

                    string? novoTexto = await ProcessarMensagemUniversal(msg.message);

                    if (novoTexto == null)
                    {
                        Console.WriteLine("🗑️ IGNORADO: Sem links válidos.");
                        return; 
                    }

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
                            Console.WriteLine("✅ FOTO + LINK ENVIADOS!");
                        }
                        else
                        {
                            await Client.SendMessageAsync(PeerDestino, novoTexto);
                            Console.WriteLine("✅ TEXTO + LINK ENVIADOS!");
                        }
                    }
                    catch (Exception ex) { Console.WriteLine($"❌ FALHA ENVIO: {ex.Message}"); }
                }
                break;
        }
    }

    private static async Task<string?> ProcessarMensagemUniversal(string textoOriginal)
    {
        var regexLink = new Regex(@"https?://[^\s]+");
        var matches = regexLink.Matches(textoOriginal);
        string textoFinal = textoOriginal;
        bool linkValidoEncontrado = false;

        Console.WriteLine($"   🔎 Analisando {matches.Count} links...");

        foreach (Match match in matches)
        {
            string urlOriginal = match.Value;
            
            if (urlOriginal.Contains("tidd.ly") || urlOriginal.Contains("natura.com") || urlOriginal.Contains("magazineluiza"))
            {
                continue;
            }

            string urlExpandida = urlOriginal;
            if (IsShortLink(urlOriginal))
            {
                Console.Write($"   ↳ Expandindo... ");
                urlExpandida = await ExpandirUrl(urlOriginal, 0);
                if (urlExpandida != urlOriginal) Console.WriteLine("OK! ✅"); else Console.WriteLine("Mantido.");
            }

            string urlComTag = urlExpandida;
            bool ehAmazon = urlExpandida.Contains("amazon.com") || urlExpandida.Contains("amzn.to");
            bool ehMercadoLivre = urlExpandida.Contains("mercadolivre.com") || urlExpandida.Contains("mercadolibre.com");

            if (ehAmazon)
            {
                urlComTag = AplicarTagAmazon(urlExpandida);
                Console.WriteLine($"   🍌 AMAZON: Tag aplicada.");
                linkValidoEncontrado = true;
            }
            else if (ehMercadoLivre)
            {
                Console.WriteLine($"   🤝 MERCADO LIVRE: Processando...");
                string? linkConstruido = await GerarLinkMercadoLivre(urlExpandida);
                
                if (linkConstruido != null)
                {
                    urlComTag = linkConstruido;
                    Console.WriteLine($"   🤝 Link Manual Gerado: {urlComTag}");
                    linkValidoEncontrado = true;
                }
                else
                {
                    Console.WriteLine("      ❌ ERRO: ID não encontrado.");
                    continue; 
                }
            }
            else
            {
                continue;
            }

            Console.Write($"   ✂️ Encurtando... ");
            string urlCurta = await EncurtarTinyUrl(urlComTag);
            Console.WriteLine($"Feito! ({urlCurta})");
            
            if (urlOriginal != urlCurta)
                textoFinal = textoFinal.Replace(urlOriginal, urlCurta);
        }

        return linkValidoEncontrado ? textoFinal : null;
    }

    private static async Task<string?> GerarLinkMercadoLivre(string urlProduto)
    {
        string? itemId = ExtrairIdMlb(urlProduto);

        if (itemId == null)
        {
            Console.WriteLine("      ⚠️ ID não na URL. Escaneando HTML...");
            try 
            {
                var html = await HttpClient.GetStringAsync(urlProduto);
                var matchMeta = Regex.Match(html, @"mercadolibre://items/(MLB-?\d+)", RegexOptions.IgnoreCase);
                if (matchMeta.Success) itemId = matchMeta.Groups[1].Value;
                if (itemId == null) {
                    var matchJson = Regex.Match(html, @"""id""\s*:\s*""(MLB-?\d+)""", RegexOptions.IgnoreCase);
                    if (matchJson.Success) itemId = matchJson.Groups[1].Value;
                }
                if (itemId == null) {
                    var matchCanonical = Regex.Match(html, @"mercadolivre\.com\.br/.*?/(MLB-?\d+)", RegexOptions.IgnoreCase);
                    if (matchCanonical.Success) itemId = matchCanonical.Groups[1].Value;
                }
            }
            catch (Exception ex) { Console.WriteLine($"      ❌ Erro HTML: {ex.Message}"); }
        }

        if (itemId == null) return null;

        string idLimpo = itemId.Replace("-", "").ToUpper().Replace("MLB", "");
        Console.WriteLine($"      💎 ID ENCONTRADO: MLB{idLimpo}");

        // Construtor Manual (Infalível)
        return $"https://produto.mercadolivre.com.br/MLB-{idLimpo}?matt_tool={ML_MATT_TOOL}&matt_word={ML_MATT_WORD}";
    }

    private static string? ExtrairIdMlb(string texto)
    {
        var regex = new Regex(@"(MLB-?\d+)", RegexOptions.IgnoreCase);
        var match = regex.Match(texto);
        return match.Success ? match.Groups[1].Value : null;
    }

    private static async Task<bool> AtualizarTokenMercadoLivre()
    {
        try
        {
            string appId = Environment.GetEnvironmentVariable("ML_APP_ID");
            string secret = Environment.GetEnvironmentVariable("ML_CLIENT_SECRET");
            string refreshToken = Environment.GetEnvironmentVariable("ML_REFRESH_TOKEN");
            if (string.IsNullOrEmpty(refreshToken)) return false;

            var content = new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("grant_type", "refresh_token"),
                new KeyValuePair<string, string>("client_id", appId),
                new KeyValuePair<string, string>("client_secret", secret),
                new KeyValuePair<string, string>("refresh_token", refreshToken)
            });
            var response = await HttpClient.PostAsync("https://api.mercadolibre.com/oauth/token", content);
            return response.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    private static async Task<string> EncurtarTinyUrl(string urlLonga)
    {
        try
        {
            var response = await HttpClient.GetStringAsync($"https://tinyurl.com/api-create.php?url={urlLonga}");
            return response;
        }
        catch { return urlLonga; }
    }

    private static bool IsShortLink(string url)
    {
        return url.Contains("amzn.to") || url.Contains("bit.ly") || url.Contains("t.co") || 
               url.Contains("compre.link") || url.Contains("oferta.one") || url.Contains("shope.ee") ||
               url.Contains("a.co") || url.Contains("tinyurl") || url.Contains("mercadolivre.com/sec") ||
               url.Contains("mercadolivre.com.br/social") || url.Contains("lista.mercadolivre.com.br") ||
               url.Contains("produto.mercadolivre.com.br");
    }

    private static async Task<string> ExpandirUrl(string url, int depth)
    {
        if (depth > 6) return url;
        try
        {
            var response = await HttpClient.GetAsync(url);
            if ((int)response.StatusCode >= 300 && (int)response.StatusCode <= 399) 
            {
                var location = response.Headers.Location;
                if (location != null) 
                {
                    string nextUrl = location.IsAbsoluteUri ? location.ToString() : new Uri(new Uri(url), location).ToString();
                    return await ExpandirUrl(nextUrl, depth + 1);
                }
            }
            if (response.IsSuccessStatusCode)
            {
                string html = await response.Content.ReadAsStringAsync();
                var metaMatch = Regex.Match(html, @"content=['""]\d+;\s*url=['""]?([^'"" >]+)", RegexOptions.IgnoreCase);
                if (metaMatch.Success)
                {
                    string nextUrl = metaMatch.Groups[1].Value;
                    if (!nextUrl.StartsWith("http")) nextUrl = new Uri(new Uri(url), nextUrl).ToString();
                    return await ExpandirUrl(nextUrl, depth + 1);
                }
                var jsMatch = Regex.Match(html, @"window\.location(?:\.href)?\s*=\s*['""]([^'""]+)['""]", RegexOptions.IgnoreCase);
                if (jsMatch.Success)
                {
                     string nextUrl = jsMatch.Groups[1].Value;
                     if (!nextUrl.StartsWith("http")) nextUrl = new Uri(new Uri(url), nextUrl).ToString();
                     return await ExpandirUrl(nextUrl, depth + 1);
                }
            }
            return response.RequestMessage?.RequestUri?.ToString() ?? url;
        }
        catch { return url; }
    }

    private static string AplicarTagAmazon(string url)
    {
        try 
        {
            string limpa = Regex.Replace(url, @"[?&]tag=[^&]+", "");
            string separador = limpa.Contains("?") ? "&" : "?";
            return limpa + separador + "tag=" + AMAZON_TAG;
        }
        catch { return url; }
    }
}