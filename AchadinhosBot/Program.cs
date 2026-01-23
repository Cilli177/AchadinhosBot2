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
    static long ID_DESTINO = 3632436217; 

    static List<long> IDs_FONTES = new List<long>() { 2775581964, 1871121243, 1569488789 };

    static async Task Main(string[] args)
    {
        Console.Clear();
        WTelegram.Helpers.Log = (lvl, str) => { }; 
        HttpClient.Timeout = TimeSpan.FromSeconds(10);

        Console.WriteLine("🚀 INICIANDO ROBÔ (Modo Direto)...");

        // 👇 DIAGNÓSTICO DE ARQUIVO 👇
        if (File.Exists("WTelegram.session"))
        {
            var info = new FileInfo("WTelegram.session");
            Console.WriteLine($"✅ ARQUIVO DE SESSÃO ENCONTRADO! Tamanho: {info.Length} bytes");
        }
        else
        {
            Console.WriteLine("⚠️ AVISO: Arquivo WTelegram.session não encontrado na pasta raiz.");
        }
        // 👆 FIM DO DIAGNÓSTICO 👆

        string Config(string what)
        {
            // Simples e Direto: Usa o arquivo na pasta atual
            if (what == "session_pathname") return "WTelegram.session";
            
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
                Console.WriteLine($"✅ SUCESSO! Logado como: {user.username ?? user.first_name}");
                Console.WriteLine("---------------------------------------------------");
                Console.WriteLine($"💰 TAG AMAZON: {AMAZON_TAG}");
                Console.WriteLine("👀 MONITORANDO OFERTAS...");
                
                await Task.Delay(-1);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ ERRO FATAL: {ex.Message}");
        }
    }

    private static async Task OnUpdate(Update update)
    {
        // Lógica de monitoramento (Mantive compacta para caber aqui, funciona igual)
        if (update is UpdateNewMessage unm && unm.message is Message msg && IDs_FONTES.Contains(msg.peer_id?.ID ?? 0) && !string.IsNullOrEmpty(msg.message))
        {
             Console.WriteLine($"🔍 OFERTA DETECTADA!");
             // (Aqui viria o restante da lógica de envio que você já tem)
        }
    }
}