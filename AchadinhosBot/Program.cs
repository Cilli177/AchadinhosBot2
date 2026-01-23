using System;
using System.IO;
using System.Threading.Tasks;
using System.Linq;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Net.Http;
using System.Net;
using WTelegram;
using TL;

class Program
{
    static WTelegram.Client? Client;
    static WTelegram.UpdateManager? Manager;
    
    // HttpClient configurado para seguir redirecionamentos manualmente
    static readonly HttpClient HttpClient = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false });

    // ⚙️ SEUS DADOS
    static int api_id = 31119088;
    static string api_hash = "62988e712c3f839bb1a5ea094d33d047";
    static string AMAZON_TAG = "reidasofer022-20";
    static long ID_DESTINO = 3632436217; 
    static InputPeer? PeerDestino;

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

        // --- CONFIGURAÇÃO DO NAVEGADOR ---
        HttpClient.Timeout = TimeSpan.FromSeconds(8);
        HttpClient.DefaultRequestHeaders.UserAgent.ParseAdd("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36");

        Console.WriteLine("🚀 INICIANDO ROBÔ (Modo Exclusivo Amazon)...");

        // --- LÓGICA DE LOGIN ---
        bool isProduction = Environment.GetEnvironmentVariable("RAILWAY_ENVIRONMENT") != null;
        string sessionFile = isProduction ? "/tmp/WTelegram.session" : "WTelegram.session";
        
        if (isProduction && File.Exists("WTelegram.session.b64"))
        {
            try 
            {
                var b64 = File.ReadAllText("WTelegram.session.b64");
                File.WriteAllBytes(sessionFile, Convert.FromBase64String(b64));
                Console.WriteLine($"📦 Sessão restaurada!");
            }
            catch (Exception ex) { Console.WriteLine($"❌ Erro sessão: {ex.Message}"); }
        }

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
                Console.WriteLine($"✅ SUCESSO! Logado como: {user.username ?? user.first_name}");

                // --- MAPEAR CANAIS ---
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
                Console.WriteLine($"💰 TAG AMAZON: {AMAZON_TAG}");
                Console.WriteLine("🛡️ FILTRO ATIVO: Apenas Amazon será postado!");
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

                    // --- PASSO 1: PROCESSAR E FILTRAR ---
                    // Se retornar null, é porque não é Amazon
                    string? novoTexto = await ProcessarMensagemAmazonOnly(msg.message);

                    if (novoTexto == null)
                    {
                        Console.WriteLine("🗑️ IGNORADO: Não é oferta Amazon.");
                        return; // ⛔ PARA TUDO AQUI
                    }

                    novoTexto += "\n\n🔥 Vi no: @ReiDasOfertasVIP";

                    // --- PASSO 2: ENVIAR ---
                    try
                    {
                        if (msg.media is MessageMediaPhoto mmPhoto && mmPhoto.photo is Photo photo)
                        {
                            var inputMedia = new InputMediaPhoto
                            {
                                id = new InputPhoto { id = photo.id, access_hash = photo.access_hash, file_reference = photo.file_reference }
                            };
                            await Client.Messages_SendMedia(PeerDestino, inputMedia, novoTexto, WTelegram.Helpers.RandomLong());
                            Console.WriteLine("✅ FOTO AMAZON ENVIADA!");
                        }
                        else
                        {
                            await Client.SendMessageAsync(PeerDestino, novoTexto);
                            Console.WriteLine("✅ TEXTO AMAZON ENVIADO!");
                        }
                    }
                    catch (Exception ex) { Console.WriteLine($"❌ FALHA ENVIO: {ex.Message}"); }
                }
                break;
        }
    }

    // Retorna NULL se não achar link da Amazon
    private static async Task<string?> ProcessarMensagemAmazonOnly(string textoOriginal)
    {
        var regexLink = new Regex(@"https?://[^\s]+");
        var matches = regexLink.Matches(textoOriginal);
        string textoFinal = textoOriginal;
        bool encontrouAmazon = false;

        Console.WriteLine($"   🔎 Analisando {matches.Count} links...");

        foreach (Match match in matches)
        {
            string urlOriginal = match.Value;
            string urlExpandida = urlOriginal;

            // 1. EXPANDIR SE FOR CURTO
            if (IsShortLink(urlOriginal))
            {
                Console.Write($"   ↳ Expandindo {urlOriginal.Substring(0, 15)}... ");
                urlExpandida = await ExpandirUrl(urlOriginal);
                Console.WriteLine(urlExpandida == urlOriginal ? "Falhou/Igual ⚠️" : "Sucesso! ✅");
            }

            // 2. VERIFICAR SE É AMAZON
            if (urlExpandida.Contains("amazon.com") || urlExpandida.Contains("amzn.to"))
            {
                string urlComTag = AplicarTagAmazon(urlExpandida);
                Console.WriteLine("   💰 É AMAZON! Tag aplicada.");
                
                if (urlOriginal != urlComTag)
                    textoFinal = textoFinal.Replace(urlOriginal, urlComTag);
                
                encontrouAmazon = true;
            }
            else
            {
                Console.WriteLine($"   ❌ Link de fora ({new Uri(urlExpandida).Host}) ignorado.");
            }
        }

        // Se NÃO tiver nenhum link Amazon na mensagem inteira, retorna NULL
        return encontrouAmazon ? textoFinal : null;
    }

    private static bool IsShortLink(string url)
    {
        return url.Contains("amzn.to") || url.Contains("bit.ly") || url.Contains("t.co") || 
               url.Contains("compre.link") || url.Contains("oferta.one") || url.Contains("shope.ee") ||
               url.Contains("a.co");
    }

    private static async Task<string> ExpandirUrl(string url)
    {
        try
        {
            var response = await HttpClient.GetAsync(url);
            if (response.StatusCode == HttpStatusCode.Moved || 
                response.StatusCode == HttpStatusCode.Found ||
                response.StatusCode == HttpStatusCode.Redirect ||
                response.StatusCode == HttpStatusCode.TemporaryRedirect) 
            {
                var location = response.Headers.Location;
                if (location != null) return await ExpandirUrl(location.ToString());
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