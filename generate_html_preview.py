import codecs

html = codecs.open(r'templates\Ofertas VIP-saved.html', 'r', 'utf-8').read()

# Base replacements
html = html.replace('Oferta VIP (NOME DO ITEM OPAL)', 'Smartphone Apple iPhone 15 Pro Max (256 GB) - Titânio Natural')
html = html.replace('12x de R$ 100 OPAL', 'R$ 7.000,00')
html = html.replace('Em até 10x sem juros (OPAL)', 'Em até 10x sem juros')
html = html.replace('amazon.com.br/OPAL', 'https://achadinhos.tv.br/item/teste-vip')

# The img is originally wrapped in nothing. Give it the new <a> tag format.
original_img = '<img src="URL_DA_IMAGEM_AQUI" alt="Oferta VIP (NOME DO ITEM OPAL)" class="w-full h-auto max-w-md object-contain drop-shadow-[0_20px_50px_rgba(0,0,0,0.5)] transform transition-transform duration-500 hover:scale-105" />'
new_img = '<a href="https://achadinhos.tv.br/item/teste-vip" target="_blank" rel="noopener noreferrer"><img src="https://m.media-amazon.com/images/I/81M5wqH37LL._AC_SX679_.jpg" alt="Smartphone Apple iPhone 15 Pro Max" class="w-full h-auto max-w-md object-contain drop-shadow-[0_20px_50px_rgba(0,0,0,0.5)] transform transition-transform duration-500 hover:scale-105" /></a>'
html = html.replace(original_img, new_img)

# The badge container replacement
original_badge = '<div class="inline-block px-4 py-1.5 rounded-full bg-accent/10 border border-accent/30 text-accent font-bold text-sm tracking-wider uppercase mb-4">\n                        Desconto Imperdível\n                    </div>'
new_badge = """<div class="flex items-center justify-center lg:justify-start gap-3 mb-4">
                        <div class="inline-block px-4 py-1.5 rounded-full bg-accent/10 border border-accent/30 text-accent font-bold text-sm tracking-wider uppercase">
                            Desconto Imperdível
                        </div>
                        <div class="inline-block px-4 py-1.5 rounded-full bg-slate-800 text-slate-300 font-medium text-xs tracking-wide">
                            Postado em 09/03/2026 15:35
                        </div>
                    </div>"""
html = html.replace(original_badge, new_badge)

out_path = r'C:\Users\overl\.gemini\antigravity\brain\00daeec3-5cbb-4f29-b74f-b5a8e5c459a7\vip_catalog_preview.html'
codecs.open(out_path, 'w', 'utf-8').write(html)
print('HTML Generated at ' + out_path)
