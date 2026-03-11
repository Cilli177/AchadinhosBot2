import codecs
import re

program_path = r'c:\AchadinhoBot2\AchadinhosBot2\AchadinhosBot.Next\Program.cs'
program = codecs.open(program_path, 'r', 'utf-8').read()

old_block_start = "static string BuildCatalogPageHtml(IReadOnlyList<CatalogOfferItem> items, string? query, string currentUrl)"
old_block_end = "static string BuildCatalogItemPageHtml(CatalogOfferItem item, string catalogUrl)"

if old_block_start in program and old_block_end in program:
    start_idx = program.find(old_block_start)
    end_idx = program.find(old_block_end)
    old_method = program[start_idx:end_idx]
    
    new_method = """static string BuildCatalogPageHtml(IReadOnlyList<CatalogOfferItem> items, string? query, string currentUrl)
{
    var q = query?.Trim() ?? string.Empty;
    var qEncoded = System.Net.WebUtility.HtmlEncode(q);
    var currentUrlEncoded = System.Net.WebUtility.HtmlEncode(currentUrl);
    var sb = new StringBuilder();

    var headerHtml = $$$\"\"\"
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Catálogo VIP de Ofertas</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Montserrat:wght@400;700;800&family=Inter:wght@300;400;600&display=swap" rel="stylesheet">
    <script>
        tailwind.config = {
            theme: {
                extend: {
                    colors: {
                        primary: '#0f172a',
                        accent: '#c4a468',
                        accentHover: '#b39359',
                        vipRed: '#e11d48',
                        surface: '#1e293b'
                    },
                    fontFamily: {
                        display: ['Montserrat', 'sans-serif'],
                        body: ['Inter', 'sans-serif'],
                    }
                }
            }
        }
    </script>
    <style>
        body { font-family: 'Inter', sans-serif; background-color: #0f172a; color: #f8fafc; }
        h1, h2, h3 { font-family: 'Montserrat', sans-serif; }
        .glass-header { background: rgba(15, 23, 42, 0.9); backdrop-filter: blur(8px); border-bottom: 1px solid rgba(196, 164, 104, 0.2); }
        .vip-card { background: linear-gradient(145deg, #1e293b, #0f172a); border: 1px solid rgba(196, 164, 104, 0.15); transition: transform 0.3s ease, box-shadow 0.3s ease; }
        .vip-card:hover { transform: translateY(-5px); box-shadow: 0 10px 25px rgba(196, 164, 104, 0.15); border-color: rgba(196, 164, 104, 0.4); }
        .image-wrapper { background: #fff; display: flex; align-items: center; justify-content: center; overflow: hidden; height: 240px; border-bottom: 1px solid rgba(196, 164, 104, 0.1); }
    </style>
</head>
<body class="min-h-screen pb-12">
    <!-- Header -->
    <header class="sticky top-0 z-50 glass-header">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-5 flex flex-col md:flex-row gap-4 justify-between items-center">
            <div class="flex items-center gap-3">
                <div class="w-10 h-10 bg-accent rounded-full flex items-center justify-center shadow-[0_0_15px_rgba(196,164,104,0.4)]">
                    <span class="text-primary font-black text-sm tracking-tighter">VIP</span>
                </div>
                <h1 class="text-xl md:text-2xl font-extrabold uppercase tracking-widest text-white">Catálogo <span class="text-accent">Exclusivo</span></h1>
            </div>
            
            <form method="get" action="/catalogo" class="w-full md:w-auto flex flex-1 max-w-md">
                <input type="text" name="q" value="{{{qEncoded}}}" placeholder="Buscar produto ou marca..." class="w-full bg-surface/50 border border-accent/30 rounded-l-xl px-4 py-2 text-white placeholder-slate-400 focus:outline-none focus:border-accent focus:ring-1 focus:ring-accent transition-colors">
                <button type="submit" class="bg-accent hover:bg-accentHover text-primary font-bold px-6 py-2 rounded-r-xl transition-colors">
                    Buscar
                </button>
            </form>
        </div>
    </header>

    <main class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
\"\"\";

    sb.AppendLine(headerHtml);

    if (items.Count == 0)
    {
        sb.AppendLine($$\"\"\"
        <div class="mt-12 text-center p-12 vip-card rounded-2xl max-w-2xl mx-auto">
            <div class="text-accent mb-4"><svg class="w-16 h-16 mx-auto opacity-50" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"></path></svg></div>
            <h2 class="text-2xl font-bold text-white mb-2">Nenhum achadinho encontrado.</h2>
            <p class="text-slate-400">Tente buscar por outro termo ou volte mais tarde para novas ofertas.</p>
        </div>
\"\"\");
    }
    else
    {
        sb.AppendLine("        <div class=\"grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6\">");
        
        foreach (var item in items)
        {
            var title = System.Net.WebUtility.HtmlEncode(item.ProductName);
            var titleShort = title.Length > 60 ? title.Substring(0, 57) + "..." : title;
            var store = System.Net.WebUtility.HtmlEncode(item.Store);
            var detailLink = $"/item/{item.ItemNumber}";
            var image = string.IsNullOrWhiteSpace(item.ImageUrl) ? "https://via.placeholder.com/400" : System.Net.WebUtility.HtmlEncode(item.ImageUrl);
            
            var fullPrice = item.PriceText ?? "Indisponível";
            var price_val = fullPrice.Replace("R$ ", "").Replace("R$", "").Trim();
            
            var published = item.PublishedAt.ToString("dd/MM/yyyy");

            var cardHtml = $$$\"\"\"
            <article class="vip-card rounded-2xl overflow-hidden flex flex-col h-full group">
                <a href="{{{detailLink}}}" class="block relative image-wrapper">
                    <!-- Date badge inside image -->
                    <div class="absolute top-3 left-3 bg-primary/90 text-accent text-[10px] font-bold uppercase tracking-wider px-2 py-1 rounded backdrop-blur-sm border border-accent/20 z-10">
                        {{{published}}}
                    </div>
                    <!-- View overlay -->
                    <div class="absolute inset-0 bg-primary/40 opacity-0 group-hover:opacity-100 transition-opacity z-10 flex items-center justify-center backdrop-blur-[2px]">
                        <span class="bg-accent text-primary font-bold px-4 py-2 rounded-full transform translate-y-4 group-hover:translate-y-0 transition-transform">Ver Detalhes</span>
                    </div>
                    <img src="{{{image}}}" alt="{{{title}}}" loading="lazy" class="w-full h-full object-contain p-4 mix-blend-multiply group-hover:scale-110 transition-transform duration-500" />
                </a>
                
                <div class="p-5 flex flex-col flex-1">
                    <div class="text-[10px] font-bold uppercase tracking-widest text-slate-400 mb-2 flex items-center justify-between">
                        <span>{{{store}}}</span>
                        <span class="text-accent">#{{{item.ItemNumber}}}</span>
                    </div>
                    
                    <h3 class="text-white font-semibold flex-1 leading-snug mb-4">
                        <a href="{{{detailLink}}}" class="hover:text-accent transition-colors" title="{{{title}}}">{{{titleShort}}}</a>
                    </h3>
                    
                    <div class="mt-auto pt-4 border-t border-white/5 flex items-center justify-between">
                        <div class="flex flex-col">
                            <span class="text-xs text-slate-500">Preço VIP</span>
                            <div class="flex items-baseline gap-1">
                                <span class="text-white text-sm">R$</span>
                                <span class="text-accent text-2xl font-bold tracking-tight">{{{price_val}}}</span>
                            </div>
                        </div>
                    </div>
                </div>
            </article>
\"\"\";
            sb.AppendLine(cardHtml);
        }
        
        sb.AppendLine("        </div>"); // End grid
    }

    sb.AppendLine($$\"\"\"
    </main>
    <footer class="mt-12 py-8 border-t border-white/10 text-center">
        <p class="text-slate-500 text-sm">Design VIP Exclusivo • Seu link: <span class="text-slate-400">{{{currentUrlEncoded}}}</span></p>
    </footer>
</body>
</html>
\"\"\");

    return sb.ToString();
}

"""

    program = program.replace(old_method, new_method)
    codecs.open(program_path, 'w', 'utf-8').write(program)
    print("Patched completely!")
else:
    print("Could not find blocks")
