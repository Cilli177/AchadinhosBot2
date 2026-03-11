using System;
class Program {
    static void Main() {
        string mlbId = "MLB-18932157";
        var numericPart = mlbId.ToUpperInvariant().Replace("MLB", "").Replace("-", "");
        if (numericPart.Length <= 8) {
            Console.WriteLine($"https://www.mercadolivre.com.br/p/MLB{numericPart}");
        } else {
            Console.WriteLine($"https://produto.mercadolivre.com.br/MLB-{numericPart}");
        }
    }
}
