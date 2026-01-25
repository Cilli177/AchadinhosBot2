using System;
using System.IO;
using System.Threading.Tasks;
using System.Linq;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Net.Http;
using System.Net;
using System.Text; // Necessário para JSON da OpenAI
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

    // 🍌 AMAZON & ML
    static string AMAZON_TAG = "reidasofer022-20";
    static string ML_MATT_TOOL = "98187057";
    static string ML_MATT_WORD = "land177";
    static string? ML_ACCESS_TOKEN = null;

    // 🧠 OPENAI (IA)
    static string? OPENAI_KEY = Environment.GetEnvironmentVariable("OPENAI_API_KEY");

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

        // Headers
        HttpClient.Timeout = TimeSpan.FromSeconds(30);
        HttpClient.DefaultRequestHeaders.UserAgent.ParseAdd("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36");
        HttpClient.DefaultRequestHeaders.Accept.ParseAdd("text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8");

        Console.WriteLine("🚀 INICIANDO ROBÔ (Modo IA: Copywriter Ativo)...");

        if (string.IsNullOrEmpty(OPENAI_KEY))
            Console.WriteLine("⚠️ AVISO: Chave OPENAI_API_KEY não encontrada. A IA não será usada.");
        else
            Console.WriteLine("🧠 IA: OpenAI Conectada e Pronta!");

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

        // --- LOGIN ML ---
        Console.WriteLine("🔐 Autenticando ML...");
        bool mlAtivo = await AtualizarTokenMercadoLivre();
        if (mlAtivo) Console.WriteLine("✅ ML Conectado (Token Ativo)!");
        else Console.WriteLine("⚠️ ML Token Off (Modo Manual Ativo).");

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
                    if (msg.message.Length < 5 && msg.peer_id.ID != 5258197181) return;

                    Console.WriteLine($"\n⚡ OFERTA DETECTADA (Fonte: {msg.peer_id.ID})");

                    // 1. Processa Links (Gera o link de afiliado)
                    var resultadoLinks = await ProcessarLinks(msg.message);

                    if (resultadoLinks.LinkAfiliado == null)
                    {
                        Console.WriteLine("🗑️ IGNORADO: Sem links válidos.");
                        return; 
                    }

                    // 2. Gera o Texto com IA (Copywriting)
                    Console.WriteLine("   🧠 IA: Gerando texto persuasivo...");
                    string textoFinal = await GerarCopyComIA(msg.message, resultadoLinks.LinkAfiliado);

                    // Adiciona rodapé
                    textoFinal += "\n\n🔥 Vi no: @ReiDasOfertasVIP";

                    try
                    {
                        if (msg.media is MessageMediaPhoto mmPhoto && mmPhoto.photo is Photo photo)
                        {
                            var inputMedia = new InputMediaPhoto
                            {
                                id = new InputPhoto { id = photo.id, access_hash = photo.access_hash, file_reference = photo.file_reference }
                            };
                            await Client.Messages_SendMedia(PeerDestino, inputMedia, textoFinal, WTelegram.Helpers.RandomLong());
                            Console.WriteLine("✅ FOTO + LINK + IA ENVIADOS!");
                        }
                        else
                        {
                            await Client.SendMessageAsync(PeerDestino, textoFinal);
                            Console.WriteLine("✅ TEXTO + LINK + IA ENVIADOS!");
                        }
                    }
                    catch (Exception ex) { Console.WriteLine($"❌ FALHA ENVIO: {ex.Message}"); }
                }
                break;
        }
    }

    // --- ESTRUTURA PARA RETORNAR LINK PROCESSADO ---
    class ResultadoLink { public string? LinkAfiliado; }

    private static async Task<ResultadoLink> ProcessarLinks(string textoOriginal)
    {
        var regexLink = new Regex(@"https?://[^\s]+");
        var matches = regexLink.Matches(textoOriginal);
        var resultado = new ResultadoLink();

        Console.WriteLine($"   🔎 Analisando {matches.Count} links...");

        foreach (Match match in matches)
        {
            string urlOriginal = match.Value;
            
            if (urlOriginal.Contains("tidd.ly") || urlOriginal.Contains("natura.com") || urlOriginal.Contains("magazineluiza"))
                continue;

            string urlExpandida = urlOriginal;
            if (IsShortLink(urlOriginal))
            {
                urlExpandida = await ExpandirUrl(urlOriginal, 0);
            }

            string urlComTag = urlExpandida;
            bool ehAmazon = urlExpandida.Contains("amazon.com") || urlExpandida.Contains("amzn.to");
            bool ehMercadoLivre = urlExpandida.Contains("mercadolivre.com") || urlExpandida.Contains("mercadolibre.com");

            if (ehAmazon)
            {
                urlComTag = AplicarTagAmazon(urlExpandida);
                resultado.LinkAfiliado = await EncurtarTinyUrl(urlComTag);
                return resultado; // Retorna o primeiro link válido encontrado
            }
            else if (ehMercadoLivre)
            {
                string? linkConstruido = await GerarLinkMercadoLivre(urlExpandida);
                if (linkConstruido != null)
                {
                    resultado.LinkAfiliado = await EncurtarTinyUrl(linkConstruido);
                    return resultado; // Retorna o primeiro link válido encontrado
                }
            }
        }
        return resultado;
    }

    // --- 🧠 FUNÇÃO DE INTELIGÊNCIA ARTIFICIAL ---
    private static async Task<string> GerarCopyComIA(string textoOriginal, string linkAfiliado)
    {
        if (string.IsNullOrEmpty(OPENAI_KEY)) 
        {
            // Se não tiver chave, devolve o texto original com o link novo substituindo o velho
            return "🔥 OFERTA ENCONTRADA:\n" + linkAfiliado;
        }

        try
        {
            // Prompt para o ChatGPT
            var prompt = $@"
            Atue como um especialista em Copywriting para promoções no Telegram.
            Seu objetivo é reescrever a oferta abaixo para torná-la irresistível.
            
            Regras:
            1. Use gatilhos de urgência (ex: 'Corre', 'Preço de Erro', 'Histórico').
            2. Seja breve e direto (máximo 3 linhas de texto).
            3. Use emojis chamativos (🚨, 🔥, 😱, 📉).
            4. NÃO coloque o link no texto, eu vou colocar depois.
            5. Responda APENAS com o texto novo.

            Texto original da oferta:
            {textoOriginal}";

            var payload = new
            {
                model = "gpt-3.5-turbo", // Modelo rápido e barato
                messages = new[]
                {
                    new { role = "user", content = prompt }
                },
                temperature = 0.7
            };

            var jsonPayload = JsonSerializer.Serialize(payload);
            var content = new StringContent(jsonPayload, Encoding.UTF8, "application/json");

            using (var request = new HttpRequestMessage(HttpMethod.Post, "https://api.openai.com/v1/chat/completions"))
            {
                request.Headers.Add("Authorization", $"Bearer {OPENAI_KEY}");
                request.Content = content;

                var response = await HttpClient.SendAsync(request);
                if (response.IsSuccessStatusCode)
                {
                    var responseString = await response.Content.ReadAsStringAsync();
                    using (JsonDocument doc = JsonDocument.Parse(responseString))
                    {
                        string textoGerado = doc.RootElement
                            .GetProperty("choices")[0]
                            .GetProperty("message")
                            .GetProperty("content")
                            .GetString() ?? "";

                        // Retorna o texto da IA + o Link
                        return $"{textoGerado.Trim()}\n\n👇 COMPRE AQUI:\n{linkAfiliado}";
                    }
                }
                else
                {
                    Console.WriteLine($"   ❌ Erro IA: {response.StatusCode}");
                    // Fallback: texto simples se der erro
                    return $"🚨 OFERTA DETECTADA!\n\nConfira essa oportunidade:\n{linkAfiliado}";
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"   ❌ Exceção IA: {ex.Message}");
            return $"🚨 OFERTA DETECTADA!\n\nConfira essa oportunidade:\n{linkAfiliado}";
        }
    }

    // --- FUNÇÕES DE LINKS (Amazon, ML, Encurtador) ---
    // (Mantidas idênticas à versão estável anterior)

    private static async Task<string?> GerarLinkMercadoLivre(string urlProduto)
    {
        string? itemId = ExtrairIdMlb(urlProduto);
        if (itemId == null)
        {
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
            catch { }
        }

        if (itemId == null) return null;
        string idLimpo = itemId.Replace("-", "").ToUpper().Replace("MLB", "");
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
        // Mantido apenas para evitar erros de compilação/futuro uso, 
        // mas o link manual não depende disso.
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