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

        // 👇 PREPARAÇÃO DA SESSÃO 👇
        string sessionFile = isProduction ? "/tmp/WTelegram.session" : "WTelegram.session";
        
        // Se em produção, tenta restaurar a sessão do Base64 (variável de ambiente ou arquivo)
        if (isProduction)
        {
            var sessionBase64 = Environment.GetEnvironmentVariable("TELEGRAM_SESSION_BASE64");
            
            // Se não tem variável, tenta arquivo
            if (string.IsNullOrEmpty(sessionBase64) && File.Exists("WTelegram.session.b64"))
            {
                sessionBase64 = File.ReadAllText("WTelegram.session.b64").Trim();
            }
            
            if (!string.IsNullOrEmpty(sessionBase64))
            {
                try
                {
                    Console.WriteLine("📦 Restaurando sessão do Base64...");
                    var sessionBytes = Convert.FromBase64String(sessionBase64);
                    File.WriteAllBytes(sessionFile, sessionBytes);
                    Console.WriteLine($"✅ Sessão restaurada com sucesso! ({sessionBytes.Length} bytes)");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"⚠️  Erro ao restaurar sessão: {ex.Message}");
                }
            }
        }
        
        // Verifica se a sessão existe
        if (File.Exists(sessionFile))
        {
            var info = new FileInfo(sessionFile);
            Console.WriteLine($"📦 Arquivo de sessão encontrado: {info.Length} bytes");
            
            // Sessão muito pequena (<5KB) provavelmente está corrompida
            if (info.Length < 5000 && isProduction)
            {
                Console.WriteLine("⚠️  Sessão parece corrompida. Deletando para novo login...");
                try { File.Delete(sessionFile); }
                catch { Console.WriteLine("⚠️  Não foi possível deletar sessão corrompida"); }
            }
        }
        else
        {
            Console.WriteLine($"📝 Nenhuma sessão encontrada. Será feito novo login.");
        }
        // 👆 FIM DA PREPARAÇÃO 👆

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
                    Console.WriteLine($"📱 Usando telefone: {MaskPhone(phone)}");
                }
                return phone;
            }
            
            if (what == "verification_code") 
            { 
                var code = Environment.GetEnvironmentVariable("TELEGRAM_VERIFICATION_CODE");
                if (string.IsNullOrEmpty(code))
                {
                    if (isProduction)
                    {
                        Console.WriteLine("⚠️  Código de verificação necessário!");
                        Console.WriteLine("📲 Você recebeu um SMS ou mensagem no Telegram com o código.");
                        Console.WriteLine("🔧 Se já logou antes, certifique-se que TELEGRAM_SESSION_BASE64 está configurado.");
                        throw new Exception("Código de verificação não configurado (TELEGRAM_VERIFICATION_CODE)");
                    }
                    Console.Write("🔑 Código de verificação: "); 
                    code = Console.ReadLine() ?? "";
                }
                
                Console.WriteLine($"✅ Usando código de verificação");
                return code;
            }
            
            if (what == "password") 
            { 
                var password = Environment.GetEnvironmentVariable("TELEGRAM_PASSWORD");
                if (string.IsNullOrEmpty(password))
                {
                    if (isProduction)
                    {
                        return "";
                    }
                    Console.Write("🔒 Senha 2FA (deixe em branco se não tiver): "); 
                    password = Console.ReadLine() ?? "";
                }
                
                if (!string.IsNullOrEmpty(password))
                {
                    Console.WriteLine("✅ Usando senha 2FA");
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
                
                // Se em desenvolvimento, salva a sessão em Base64 para copiar
                if (!isProduction)
                {
                    var sessionBytes = File.ReadAllBytes(sessionFile);
                    var sessionBase64 = Convert.ToBase64String(sessionBytes);
                    Console.WriteLine("\n📋 SESSÃO GERADA (copie para TELEGRAM_SESSION_BASE64 no Railway):");
                    Console.WriteLine(sessionBase64);
                }
                
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