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
        // 👇 CÓDIGO MÁGICO COM PROTEÇÃO TOTAL (TRY-CATCH) 👇
        try 
        {
            string pastaNuvem = "/app/data";
            string arquivoDestino = Path.Combine(pastaNuvem, "WTelegram.session");

            // Tenta copiar. Se der erro (porque a pasta não existe no PC), ele cai no catch e não trava.
            if (File.Exists("WTelegram.session") && Directory.Exists(pastaNuvem) && !File.Exists(arquivoDestino))
            {
                Console.WriteLine("🚚 Movendo login para a pasta segura...");
                File.Copy("WTelegram.session", arquivoDestino);
            }
        }
        catch 
        {
            // Se der erro, ignora silenciosamente e segue a vida (evita o crash no PC)
        }
        // 👆 FIM DO CÓDIGO MÁGICO 👆

        Console.Clear();
        WTelegram.Helpers.Log = (lvl, str) => { }; 
        HttpClient.Timeout = TimeSpan.FromSeconds(10);
        Console.WriteLine("🚀 INICIANDO MÁQUINA DE VENDAS...");

        string Config(string what)
        {
            if (what == "session_pathname") 
            {
                // Prioridade: Pasta Segura > Arquivo Local
                if (File.Exists("/app/data/WTelegram.session")) return "/app/data/WTelegram.session";
                return "WTelegram.session";
            }
            
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
                Console.WriteLine("Aguardando ofertas...");
                
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

                    string novoTexto = await ProcessarMensagem(msg.message);
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
                            Console.WriteLine("✅ POSTADO");
                        }
                        else
                        {
                            await Client.SendMessageAsync(PeerDestino, novoTexto);
                            Console.WriteLine("✅ TEXTO POSTADO");
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

    private static async Task<string> ProcessarMensagem(string textoOriginal)
    {
        var regexLink = new Regex(@"https?://[^\s]+");
        var matches = regexLink.Matches(textoOriginal);
        string textoFinal = textoOriginal;

        foreach (Match match in matches)
        {
            string urlOriginal = match.Value;
            string urlProcessada = urlOriginal;

            if (urlOriginal.Contains("amzn.to") || urlOriginal.Contains("bit.ly") || urlOriginal.Contains("t.co"))
            {
                Console.Write($"   ↳ Expandindo {urlOriginal}... ");
                try
                {
                    var response = await HttpClient.GetAsync(urlOriginal);
                    urlProcessada = response.RequestMessage.RequestUri.ToString();
                    Console.WriteLine("OK!");
                }
                catch { Console.WriteLine("Falha"); }
            }

            if (urlProcessada.Contains("amazon.com"))
            {
                if (urlProcessada.Contains("tag="))
                    urlProcessada = Regex.Replace(urlProcessada, @"tag=[^&]+", $"tag={AMAZON_TAG}");
                else
                    urlProcessada += (urlProcessada.Contains("?") ? "&" : "?") + $"tag={AMAZON_TAG}";
            }

            if (urlOriginal != urlProcessada)
                textoFinal = textoFinal.Replace(urlOriginal, urlProcessada);
        }
        return textoFinal;
    }
}