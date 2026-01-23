using System;
using System.IO;
using System.Threading.Tasks;
using System.Linq;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Net.Http;
using WTelegram;
using TL;

class Program
{
    static WTelegram.Client Client;
    static WTelegram.UpdateManager Manager;
    static readonly HttpClient HttpClient = new HttpClient();

    // ⚙️ SEUS DADOS
    static int api_id = 31119088;
    static string api_hash = "62988e712c3f839bb1a5ea094d33d047";
    static string AMAZON_TAG = "reidasofer022-20";
    static long ID_DESTINO = 3632436217; // Rei das Ofertas VIP
    static InputPeer PeerDestino;

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

        // --- CONFIGURAÇÃO DO NAVEGADOR (DISFARCE) ---
        // Timeout de 5 segundos para não travar o robô
        HttpClient.Timeout = TimeSpan.FromSeconds(5);
        // Finge ser um navegador Chrome para não tomar bloqueio da Amazon
        HttpClient.DefaultRequestHeaders.UserAgent.ParseAdd("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36");

        Console.WriteLine("🚀 INICIANDO ROBÔ (Versão Anti-Travamento)...");

        // --- LÓGICA DE LOGIN (BASE64/RAILWAY) ---
        bool isProduction = Environment.GetEnvironmentVariable("RAILWAY_ENVIRONMENT") != null;
        string sessionFile = isProduction ? "/tmp/WTelegram.session" : "WTelegram.session";
        
        if (isProduction)
        {
            Console.WriteLine($"🔧 Ambiente: PRODUÇÃO (Railway)");
            Console.WriteLine("🔍 Procurando arquivo de sessão...");
            
            // Tenta recuperar do arquivo .b64 que subimos via Git
            if (File.Exists("WTelegram.session.b64"))
            {
                Console.WriteLine("✅ Arquivo WTelegram.session.b64 encontrado!");
                try 
                {
                    var b64 = File.ReadAllText("WTelegram.session.b64");
                    File.WriteAllBytes(sessionFile, Convert.FromBase64String(b64));
                    Console.WriteLine($"📦 Sessão restaurada em {sessionFile}!");
                }
                catch (Exception ex) { Console.WriteLine($"❌ Erro ao restaurar sessão: {ex.Message}"); }
            }
        }
        else
        {
             Console.WriteLine($"🔧 Ambiente: LOCAL (Dev)");
        }

        string Config(string what)
        {
            if (what == "session_pathname") return sessionFile;
            if (what == "api_id") return api_id.ToString();
            if (what == "api_hash") return api_hash;
            
            // Login automático via variáveis (Railway) ou Console (Local)
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

                // Busca o canal destino e garante que temos acesso
                var chatDestino = dialogs.chats.Values.FirstOrDefault(c => c.ID == ID_DESTINO);
                if (chatDestino != null)
                {
                    PeerDestino = chatDestino.ToInputPeer();
                    Console.WriteLine($"📢 DESTINO CONFIRMADO: {chatDestino.Title} (ID: {chatDestino.ID})");
                }
                else
                {
                    Console.WriteLine($"❌ ERRO CRÍTICO: Não encontrei o canal destino ID {ID_DESTINO}. O robô é admin lá?");
                }

                Console.WriteLine("---------------------------------------------------");
                Console.WriteLine($"💰 TAG AMAZON: {AMAZON_TAG}");
                Console.WriteLine("👀 MONITORANDO OFERTAS...");
                
                await Task.Delay(-1);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ ERRO FATAL NO MAIN: {ex.Message}");
        }
    }

    private static async Task OnUpdate(Update update)
    {
        if (PeerDestino == null) return;

        switch (update)
        {
            case UpdateNewMessage unm when unm.message is Message msg:
                // Filtra apenas mensagens dos canais fonte que tenham texto
                if (msg.peer_id != null && IDs_FONTES.Contains(msg.peer_id.ID) && !string.IsNullOrEmpty(msg.message))
                {
                    // Ignora mensagens muito curtas ("bom dia", "oi")
                    if (msg.message.Length < 10) return;

                    Console.WriteLine($"\n⚡ OFERTA DETECTADA (Fonte: {msg.peer_id.ID})");

                    // --- PASSO 1: PROCESSAR LINK ---
                    string novoTexto = await ProcessarMensagem(msg.message);
                    
                    // Adiciona assinatura
                    novoTexto += "\n\n🔥 Vi no: @ReiDasOfertasVIP";

                    // --- PASSO 2: ENVIAR ---
                    try
                    {
                        Console.WriteLine("📤 Tentando enviar para o canal...");
                        
                        if (msg.media is MessageMediaPhoto mmPhoto && mmPhoto.photo is Photo photo)
                        {
                            // Reutiliza a foto que já está nos servidores do Telegram (mais rápido)
                            var inputMedia = new InputMediaPhoto
                            {
                                id = new InputPhoto
                                {
                                    id = photo.id,
                                    access_hash = photo.access_hash,
                                    file_reference = photo.file_reference
                                }
                            };
                            await Client.Messages_SendMedia(PeerDestino, inputMedia, novoTexto);
                            Console.WriteLine("✅ FOTO + TEXTO ENVIADOS!");
                        }
                        else
                        {
                            await Client.SendMessageAsync(PeerDestino, novoTexto);
                            Console.WriteLine("✅ APENAS TEXTO ENVIADO!");
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"❌ FALHA NO ENVIO: {ex.Message}");
                    }
                }
                break;
        }
    }

    private static async Task<string> ProcessarMensagem(string textoOriginal)
    {
        var regexLink = new Regex(@"https?://[^\s]+");
        var matches = regexLink.Matches(textoOriginal);
        string textoFinal = textoOriginal;

        Console.WriteLine($"   🔎 Analisando {matches.Count} links...");

        foreach (Match match in matches)
        {
            string urlOriginal = match.Value;
            string urlProcessada = urlOriginal;

            // Só tenta expandir se for link curto
            if (urlOriginal.Contains("amzn.to") || urlOriginal.Contains("bit.ly") || urlOriginal.Contains("t.co"))
            {
                Console.Write($"   ↳ Expandindo {urlOriginal}... ");
                try
                {
                    // Tenta acessar o link com timeout de 5 segundos
                    var response = await HttpClient.GetAsync(urlOriginal);
                    urlProcessada = response.RequestMessage.RequestUri.ToString();
                    Console.WriteLine("OK! ✅");
                }
                catch
                {
                    Console.WriteLine("TIMEOUT/ERRO (Mantendo original) ⚠️");
                }
            }

            // Se for Amazon, troca a tag
            if (urlProcessada.Contains("amazon.com.br") || urlProcessada.Contains("amazon.com"))
            {
                if (urlProcessada.Contains("tag="))
                    urlProcessada = Regex.Replace(urlProcessada, @"tag=[^&]+", $"tag={AMAZON_TAG}");
                else
                    urlProcessada += (urlProcessada.Contains("?") ? "&" : "?") + $"tag={AMAZON_TAG}";
                
                Console.WriteLine("   💰 Tag aplicada!");
            }

            if (urlOriginal != urlProcessada)
                textoFinal = textoFinal.Replace(urlOriginal, urlProcessada);
        }
        return textoFinal;
    }
}