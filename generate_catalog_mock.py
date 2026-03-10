import urllib.parse

html = """
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
    <style>
        body { font-family: 'Inter', sans-serif; background-color: #0f172a; color: #f8fafc; }
        h1, h2, h3 { font-family: 'Montserrat', sans-serif; }
        .glass-header { background: rgba(15, 23, 42, 0.9); backdrop-filter: blur(8px); border-bottom: 1px solid rgba(196, 164, 104, 0.2); }
        .vip-card { background: linear-gradient(145deg, #1e293b, #0f172a); border: 1px solid rgba(196, 164, 104, 0.15); transition: transform 0.3s ease, box-shadow 0.3s ease; }
        .vip-card:hover { transform: translateY(-5px); box-shadow: 0 10px 25px rgba(196, 164, 104, 0.15); border-color: rgba(196, 164, 104, 0.4); }
        .image-wrapper { background: #fff; display: flex; align-items: center; justify-content: center; overflow: hidden; height: 240px; border-bottom: 1px solid rgba(196, 164, 104, 0.1); }
    </style>
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
                    }
                }
            }
        }
    </script>
</head>
<body class="min-h-screen pb-12">
    <header class="sticky top-0 z-50 glass-header">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-5 flex flex-col md:flex-row gap-4 justify-between items-center">
            <div class="flex items-center gap-3">
                <div class="w-10 h-10 bg-accent rounded-full flex items-center justify-center shadow-[0_0_15px_rgba(196,164,104,0.4)]">
                    <span class="text-primary font-black text-sm tracking-tighter">VIP</span>
                </div>
                <h1 class="text-xl md:text-2xl font-extrabold uppercase tracking-widest text-white">Catálogo <span class="text-accent">Exclusivo</span></h1>
            </div>
            
            <form method="get" action="/catalogo" class="w-full md:w-auto flex flex-1 max-w-md">
                <input type="text" name="q" value="" placeholder="Buscar produto ou marca..." class="w-full bg-surface/50 border border-accent/30 rounded-l-xl px-4 py-2 text-white placeholder-slate-400 focus:outline-none focus:border-accent focus:ring-1 focus:ring-accent transition-colors">
                <button type="submit" class="bg-accent hover:bg-accentHover text-primary font-bold px-6 py-2 rounded-r-xl transition-colors">
                    Buscar
                </button>
            </form>
        </div>
    </header>

    <main class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
"""

items = [
    {"num": 1, "title": "Smartphone Apple iPhone 15 Pro Max (256 GB) - Titânio Natural", "price": "7.000,00", "image": "https://m.media-amazon.com/images/I/81M5wqH37LL._AC_SX679_.jpg", "store": "Amazon", "date": "09/03/2026"},
    {"num": 2, "title": "Console PlayStation 5 Slim com Leitor de Disco", "price": "3.899,00", "image": "https://m.media-amazon.com/images/I/51AAL91x24L._AC_SX679_.jpg", "store": "Amazon", "date": "08/03/2026"},
    {"num": 3, "title": "Fone de Ouvido Sem Fio AirPods Pro (2ª Geração)", "price": "1.999,00", "image": "https://m.media-amazon.com/images/I/61SUj2aFiwL._AC_SX679_.jpg", "store": "Amazon", "date": "07/03/2026"},
    {"num": 4, "title": "Samsung Smart TV 55 polegadas QLED 4K Q60D 2024", "price": "2.849,00", "image": "https://m.media-amazon.com/images/I/81lS25XOSmL._AC_SX679_.jpg", "store": "Mercado Livre", "date": "06/03/2026"}
]

for item in items:
    title_short = item["title"][:57] + "..." if len(item["title"]) > 60 else item["title"]
    card = f"""
            <article class="vip-card rounded-2xl overflow-hidden flex flex-col h-full group">
                <a href="https://achadinhos.tv.br/item/{item['num']}" class="block relative image-wrapper">
                    <div class="absolute top-3 left-3 bg-primary/90 text-accent text-[10px] font-bold uppercase tracking-wider px-2 py-1 rounded backdrop-blur-sm border border-accent/20 z-10">
                        {item['date']}
                    </div>
                    <div class="absolute inset-0 bg-primary/40 opacity-0 group-hover:opacity-100 transition-opacity z-10 flex items-center justify-center backdrop-blur-[2px]">
                        <span class="bg-accent text-primary font-bold px-4 py-2 rounded-full transform translate-y-4 group-hover:translate-y-0 transition-transform">Ver Detalhes</span>
                    </div>
                    <img src="{item['image']}" alt="{item['title']}" loading="lazy" class="w-full h-full object-contain p-4 mix-blend-multiply group-hover:scale-110 transition-transform duration-500" />
                </a>
                
                <div class="p-5 flex flex-col flex-1">
                    <div class="text-[10px] font-bold uppercase tracking-widest text-slate-400 mb-2 flex items-center justify-between">
                        <span>{item['store']}</span>
                        <span class="text-accent">#{item['num']}</span>
                    </div>
                    
                    <h3 class="text-white font-semibold flex-1 leading-snug mb-4">
                        <a href="https://achadinhos.tv.br/item/{item['num']}" class="hover:text-accent transition-colors" title="{item['title']}">{title_short}</a>
                    </h3>
                    
                    <div class="mt-auto pt-4 border-t border-white/5 flex items-center justify-between">
                        <div class="flex flex-col">
                            <span class="text-xs text-slate-500">Preço VIP</span>
                            <div class="flex items-baseline gap-1">
                                <span class="text-white text-sm">R$</span>
                                <span class="text-accent text-2xl font-bold tracking-tight">{item['price']}</span>
                            </div>
                        </div>
                    </div>
                </div>
            </article>
    """
    html += card

html += """
        </div>
    </main>
    <footer class="mt-12 py-8 border-t border-white/10 text-center">
        <p class="text-slate-500 text-sm">Design VIP Exclusivo • Seu link: <span class="text-slate-400">https://achadinhos.tv.br/catalogo</span></p>
    </footer>
</body>
</html>
"""

out_path = r'C:\Users\overl\.gemini\antigravity\brain\00daeec3-5cbb-4f29-b74f-b5a8e5c459a7\vip_catalog_index_preview.html'
with open(out_path, 'w', encoding='utf-8') as f:
    f.write(html)
print(f"Mock generated at {out_path}")
