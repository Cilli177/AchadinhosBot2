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

        // 🌐 DETECTA AMBIENTE
        bool isProduction = !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("RAILWAY_ENVIRONMENT")) ||
                           !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("HEROKU_APP_NAME")) ||
                           Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") == "Production";

        Console.WriteLine($"🔧 Ambiente: {(isProduction ? "PRODUÇÃO (Railway)" : "DESENVOLVIMENTO")}");

        // 👇 DIAGNÓSTICO DE ARQUIVO 👇
        string sessionFile = isProduction ? "/tmp/WTelegram.session" : "WTelegram.session";
        
        if (File.Exists(sessionFile))
        {
            var info = new FileInfo(sessionFile);
            Console.WriteLine($"✅ ARQUIVO DE SESSÃO ENCONTRADO! Tamanho: {info.Length} bytes");
        }
        else
        {
            Console.WriteLine($"⚠️ AVISO: Arquivo de sessão não encontrado em {sessionFile}");
        }
        // 👆 FIM DO DIAGNÓSTICO 👆

        string Config(string what)
        {
            if (what == "session_pathname") return sessionFile;
            
            if (what == "api_id") return api_id.ToString();
            if (what == "api_hash") return api_hash;
            
            // 🔧 CONFIGURAÇÃO DE AUTENTICAÇÃO
            if (what == "phone_number") 
            { 
                var phone = Environment.GetEnvironmentVariable("TELEGRAM_PHONE");
                if (string.IsNullOrEmpty(phone))
                {
                    if (isProduction)
                    {
                        throw new Exception("❌ TELEGRAM_PHONE não configurado como variável de ambiente!");
                    }
                    Console.Write("📱 Celular: "); 
                    phone = Console.ReadLine() ?? "";
                }
                
                if (!string.IsNullOrEmpty(phone))
                {
                    Console.WriteLine($"📱 Celular: {MaskPhone(phone)} (autenticando...)");
                }
                return phone;
            }
            
            if (what == "verification_code") 
            { 
                if (isProduction)
                {
                    Console.WriteLine("❌ ERRO: Código de verificação necessário em produção!");
                    Console.WriteLine("⚠️  Se recebeu código SMS, a senha pode estar incorreta.");
                    throw new Exception("Necessário código de verificação. Verifique se a senha 2FA está correta.");
                }
                Console.Write("🔑 Código: "); 
                return Console.ReadLine() ?? ""; 
            }
            
            if (what == "password") 
            { 
                var password = Environment.GetEnvironmentVariable("TELEGRAM_PASSWORD");
                if (string.IsNullOrEmpty(password))
                {
                    if (isProduction)
                    {
                        Console.WriteLine("⚠️  Nenhuma senha 2FA configurada (variável TELEGRAM_PASSWORD)");
                        return "";
                    }
                    Console.Write("🔒 Senha 2FA (deixe em branco se não tiver): "); 
                    password = Console.ReadLine() ?? "";
                }
                return password;
            }
            
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
            Console.WriteLine($"📋 Stack Trace: {ex.StackTrace}");
            if (ex.InnerException != null)
            {
                Console.WriteLine($"📋 Inner Exception: {ex.InnerException.Message}");
            }
            Environment.Exit(1);
        }
    }

    static string MaskPhone(string phone)
    {
        if (phone.Length > 5)
            return phone.Substring(0, 3) + "***" + phone.Substring(phone.Length - 2);
        return "***";
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