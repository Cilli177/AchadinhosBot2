using System;
using System.IO;
using System.Threading.Tasks;
using System.Linq;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Net.Http;
using System.Net;
using System.Text;
using System.Text.Json; // Importante para ler o Token do ML
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

    // ⚙️ SEUS DADOS TELEGRAM
    static int api_id = 31119088;
    static string api_hash = "62988e712c3f839bb1a5ea094d33d047";
    static long ID_DESTINO = 3632436217; 
    static InputPeer? PeerDestino;

    // 🍌 AMAZON
    static string AMAZON_TAG = "reidasofer022-20";

    // 🤝 MERCADO LIVRE (Variáveis e Configs)
    static string ML_MATT_TOOL = "98187057";
    static string ML_MATT_WORD = "land177";
    static string? ML_ACCESS_TOKEN = null; // Guardará a chave temporária

    // 📡 FONTES
    static List<long> IDs_FONTES = new List<long>()
    {
        2775581964, // Herói da Promo
        1871121243, // táBaratasso
        1569488789  // Ofertas Gamer
    };

    static async Task Main(string[] args)
    {
        Console.Clear();
        WTelegram.Helpers.Log = (lvl, str) => { };

        // Configuração do Navegador
        HttpClient.Timeout = TimeSpan.FromSeconds(20);
        HttpClient.DefaultRequestHeaders.UserAgent.ParseAdd("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36");
        HttpClient.DefaultRequestHeaders.Accept.ParseAdd("text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8");

        Console.WriteLine("🚀 INICIANDO ROBÔ (Versão API Oficial Mercado Livre)...");

        // --- 1. LOGIN TELEGRAM ---
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

        // --- 2. PREPARAÇÃO MERCADO LIVRE ---
        Console.WriteLine("🔐 Testando Autenticação ML...");
        bool mlAtivo = await AtualizarTokenMercadoLivre();
        if (mlAtivo) Console.WriteLine("✅ ML Conectado com Sucesso!");
        else Console.WriteLine("⚠️ ML Falhou (Verifique as variáveis no Railway).");

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
                Console.WriteLine($"🍌 AMAZON TAG: {AMAZON_TAG}");
                Console.WriteLine($"🤝 ML SOCIAL: {ML_MATT_WORD}");
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
                    if (msg.message.Length < 10) return;

                    Console.WriteLine($"\n⚡ OFERTA DETECTADA (Fonte: {msg.peer_id.ID})");

                    // Processa links (Amazon ou ML)
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
            string urlExpandida = urlOriginal;

            // 1. Expandir Link (Descobrir destino real)
            if (IsShortLink(urlOriginal))
            {
                Console.Write($"   ↳ Expandindo {urlOriginal.Substring(0, 15)}... ");
                urlExpandida = await ExpandirUrl(urlOriginal, 0);
                if (urlExpandida != urlOriginal) Console.WriteLine("Sucesso! ✅");
                else Console.WriteLine("Mantido ⚠️");
            }

            string urlComTag = urlExpandida;
            bool ehAmazon = urlExpandida.Contains("amazon.com") || urlExpandida.Contains("amzn.to");
            bool ehMercadoLivre = urlExpandida.Contains("mercadolivre.com") || urlExpandida.Contains("mercadolibre.com");

            if (ehAmazon)
            {
                // --- LÓGICA AMAZON ---
                urlComTag = AplicarTagAmazon(urlExpandida);
                Console.WriteLine($"   🍌 AMAZON: Tag aplicada.");
                linkValidoEncontrado = true;
            }
            else if (ehMercadoLivre)
            {
                // --- LÓGICA MERCADO LIVRE (API/SOCIAL) ---
                Console.WriteLine($"   🤝 MERCADO LIVRE: Processando...");
                string? linkSocial = await GerarLinkMercadoLivre(urlExpandida);
                
                if (linkSocial != null)
                {
                    urlComTag = linkSocial;
                    Console.WriteLine($"   🤝 Link Social gerado: {urlComTag}");
                    linkValidoEncontrado = true;
                }
                else
                {
                    Console.WriteLine($"   ❌ Falha ao gerar link ML (Produto não identificado).");
                    continue; // Pula encurtamento
                }
            }
            else
            {
                Console.WriteLine($"   ❌ Ignorado: {new Uri(urlExpandida).Host}");
                continue;
            }

            // 3. Encurtar (TinyURL)
            Console.Write($"   ✂️ Encurtando... ");
            string urlCurta = await EncurtarTinyUrl(urlComTag);
            Console.WriteLine($"Feito! ({urlCurta})");
            
            if (urlOriginal != urlCurta)
                textoFinal = textoFinal.Replace(urlOriginal, urlCurta);
        }

        return linkValidoEncontrado ? textoFinal : null;
    }

    // --- 🤝 FUNÇÕES MERCADO LIVRE (API OAUTH) ---

    // Gera o link oficial do seu perfil social apontando para o produto
    private static async Task<string?> GerarLinkMercadoLivre(string urlProduto)
    {
        // 1. Tenta extrair o ID do produto (Ex: MLB12345678)
        // Padrão: /p/MLB123... ou /MLB-123...
        var regexMLB = new Regex(@"(MLB-?\d+)"); 
        var match = regexMLB.Match(urlProduto);

        if (!match.Success) return null;

        // Remove o hífen se tiver (MLB-123 -> MLB123)
        string itemId = match.Groups[1].Value.Replace("-", "");

        // 2. (Opcional) Validar se o item existe via API para não postar erro
        // Mas para ser rápido, vamos montar o link direto que é garantido funcionar se o item existir.
        
        // 3. Constrói o Link Social Deep Link
        // Esse formato manda o usuário pro seu perfil, mas abre o produto direto
        // É o formato mais seguro contra bloqueios.
        string linkSocial = $"https://www.mercadolivre.com.br/social/{ML_MATT_WORD}?matt_tool={ML_MATT_TOOL}&matt_product_id={itemId}";

        return linkSocial;
    }

    // Gerencia o Token de Acesso (Renova a cada 6h automaticamente)
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
            if (!response.IsSuccessStatusCode) 
            {
                Console.WriteLine($"Erro Auth ML: {response.StatusCode} - {await response.Content.ReadAsStringAsync()}");
                return false;
            }

            var json = await response.Content.ReadAsStringAsync();
            using (JsonDocument doc = JsonDocument.Parse(json))
            {
                ML_ACCESS_TOKEN = doc.RootElement.GetProperty("access_token").GetString();
                // Opcional: Poderíamos salvar o novo refresh_token se ele mudasse, 
                // mas geralmente o ML aceita o antigo por um tempo.
            }
            return true;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Exceção Auth ML: {ex.Message}");
            return false;
        }
    }

    // --- 🍌 FUNÇÕES AUXILIARES E AMAZON ---

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
               url.Contains("a.co") || url.Contains("tinyurl") || url.Contains("mercadolivre.com/sec");
    }

    private static async Task<string> ExpandirUrl(string url, int depth)
    {
        if (depth > 5) return url;

        try
        {
            var response = await HttpClient.GetAsync(url);
            
            if (response.StatusCode == HttpStatusCode.Moved || 
                response.StatusCode == HttpStatusCode.Found ||
                response.StatusCode == HttpStatusCode.Redirect ||
                response.StatusCode == HttpStatusCode.TemporaryRedirect) 
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