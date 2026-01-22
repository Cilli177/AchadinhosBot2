using System;
using System.IO; // Necessário para mexer com arquivos
using System.Threading.Tasks;
using System.Linq;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Net.Http; // Necessário para expandir links
using WTelegram;
using TL;

class Program
{
    static WTelegram.Client Client;
    static WTelegram.UpdateManager Manager;
    
    // Navegador para expandir links
    static readonly HttpClient HttpClient = new HttpClient(); 

    // ⚙️ SEUS DADOS
    static int api_id = 31119088;
    static string api_hash = "62988e712c3f839bb1a5ea094d33d047";
    
    // 💲 SEU CÓDIGO
    static string AMAZON_TAG = "reidasofer022-20"; 
    
    // 🎯 DESTINO
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
        // 👇 CÓDIGO MÁGICO CORRIGIDO (Protegido contra erros locais) 👇
        string pastaNuvem = "/app/data";
        string arquivoDestino = Path.Combine(pastaNuvem, "WTelegram.session");

        // Só tenta copiar se a pasta da nuvem EXISTIR (ou seja, se estiver na Railway)
        if (Directory.Exists(pastaNuvem) && !File.Exists(arquivoDestino) && File.Exists("WTelegram.session"))
        {
            Console.WriteLine("🚚 Movendo login para a pasta segura da nuvem...");
            File.Copy("WTelegram.session", arquivoDestino);
        }
        // 👆 FIM DO CÓDIGO MÁGICO 👆

        Console.Clear();
        WTelegram.Helpers.Log = (lvl, str) => { }; 

        // Configuração do HttpClient para seguir redirecionamentos
        HttpClient.Timeout = TimeSpan.FromSeconds(10);

        Console.WriteLine("🚀 INICIANDO MÁQUINA DE VENDAS (Versão Expansor de Links)...");

        string Config(string what)
        {
            // 👇 A MÁGICA: Usa a pasta certa dependendo de onde está (PC ou Nuvem)
            if (what == "session_pathname") 
                return Directory.Exists("/app/data") ? "/app/data/WTelegram.session" : "WTelegram.session";
            
            if (what == "api_id") return api_id.ToString();
            if (what == "api_hash") return api_hash;
            if (what == "phone_number") { Console.Write("📱 Celular: "); return Console.ReadLine() ?? ""; }
            if (what == "verification_code") { Console.Write("🔑 Código: "); return Console.ReadLine() ?? ""; }
            if (what == "password") { Console.Write("🔒 Senha 2FA: "); return Console.ReadLine() ?? ""; }
            return null;
        }

        try
        {
            Client = new WTelegram.Client(Config);
            await using (Client)
            {
                Manager = Client.WithUpdateManager(OnUpdate);
                var user = await Client.LoginUserIfNeeded();
                Console.WriteLine($"✅ Logado como: {user.username ?? user.first_name}");

                Console.WriteLine("⏳ Mapeando canais...");
                var dialogs = await Client.Messages_GetAllDialogs();
                dialogs.CollectUsersChats(Manager.Users, Manager.Chats);

                var chatDestino = dialogs.chats.Values.FirstOrDefault(c => c.ID == ID_DESTINO);
                if (chatDestino != null)
                {
                    PeerDestino = chatDestino.ToInputPeer(); 
                    Console.WriteLine($"📢 PUBLICANDO EM: {chatDestino.Title}");
                }
                else
                {
                    Console.WriteLine($"❌ ERRO: Canal destino não encontrado.");
                    return;
                }

                Console.WriteLine("\n👀 MONITORANDO:");
                foreach (var id in IDs_FONTES)
                {
                    var chat = dialogs.chats.Values.FirstOrDefault(c => c.ID == id);
                    if (chat != null) Console.WriteLine($"   ✅ {chat.Title}");
                }

                Console.WriteLine("---------------------------------------------------");
                Console.WriteLine($"💰 TAG AMAZON: {AMAZON_TAG}");
                Console.WriteLine("Aguardando ofertas... (O robô vai expandir os links automaticamente)");
                
                await Task.Delay(-1);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ ERRO GERAL: {ex.Message}");
        }
    }

    private static async Task OnUpdate(Update update)
    {
        if (PeerDestino == null) return;

        switch (update)
        {
            case UpdateNewMessage unm when unm.message is Message msg:
                if (msg.peer_id != null && IDs_FONTES.Contains(msg.peer_id.ID) && !string.IsNullOrEmpty(msg.message))
                {
                    if (msg.message.Length < 10) return; 

                    Console.BackgroundColor = ConsoleColor.DarkBlue;
                    Console.WriteLine($"🔍 OFERTA DETECTADA! Analisando links...");
                    Console.ResetColor();

                    // --- PASSO 1: PROCESSAR O TEXTO E EXPANDIR LINKS ---
                    string novoTexto = await ProcessarMensagem(msg.message);
                    
                    // Adiciona assinatura
                    novoTexto += "\n\n🔥 Vi no: @ReiDasOfertasVIP";

                    try 
                    {
                        if (msg.media is MessageMediaPhoto mmPhoto && mmPhoto.photo is Photo photo)
                        {
                            var inputMedia = new InputMediaPhoto 
                            { 
                                id = new InputPhoto 
                                { 
                                    id = photo.id, 
                                    access_hash = photo.access_hash, 
                                    file_reference = photo.file_reference 
                                }
                            };
                            await Client.Messages_SendMedia(PeerDestino, inputMedia, novoTexto, WTelegram.Helpers.RandomLong());
                            Console.WriteLine("✅ POSTADO (Links Ajustados!)");
                        }
                        else
                        {
                            await Client.SendMessageAsync(PeerDestino, novoTexto);
                            Console.WriteLine("✅ TEXTO POSTADO (Links Ajustados!)");
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"❌ Erro envio: {ex.Message}");
                    }
                }
                break;
        }
    }

    // 🛠️ FUNÇÃO QUE ABRE O COFRE DOS LINKS
    private static async Task<string> ProcessarMensagem(string textoOriginal)
    {
        // Encontra todos os links (http/https) no texto
        var regexLink = new Regex(@"https?://[^\s]+");
        var matches = regexLink.Matches(textoOriginal);
        
        string textoFinal = textoOriginal;

        foreach (Match match in matches)
        {
            string urlOriginal = match.Value;
            string urlProcessada = urlOriginal;

            // Se for link encurtado (amzn.to, bit.ly, etc), TENTA EXPANDIR
            if (urlOriginal.Contains("amzn.to") || urlOriginal.Contains("bit.ly") || urlOriginal.Contains("t.co"))
            {
                Console.Write($"   ↳ Expandindo {urlOriginal}... ");
                try
                {
                    var response = await HttpClient.GetAsync(urlOriginal);
                    // Pega o link final depois do redirecionamento
                    urlProcessada = response.RequestMessage.RequestUri.ToString();
                    Console.WriteLine("OK!");
                }
                catch 
                {
                    Console.WriteLine("Falha (Manteve original)");
                }
            }

            // Se o link final for da Amazon, TROCA A TAG
            if (urlProcessada.Contains("amazon.com"))
            {
                // Se já tem tag, substitui
                if (urlProcessada.Contains("tag="))
                {
                    urlProcessada = Regex.Replace(urlProcessada, @"tag=[^&]+", $"tag={AMAZON_TAG}");
                }
                // Se não tem tag, adiciona
                else
                {
                    if (urlProcessada.Contains("?"))
                        urlProcessada += $"&tag={AMAZON_TAG}";
                    else
                        urlProcessada += $"?tag={AMAZON_TAG}";
                }
            }

            // Substitui no texto apenas se o link mudou
            if (urlOriginal != urlProcessada)
            {
                textoFinal = textoFinal.Replace(urlOriginal, urlProcessada);
            }
        }

        return textoFinal;
    }
}