import codecs

html = codecs.open('templates/Ofertas VIP-saved.html', 'r', 'utf-8').read()

# Replace specific data with placeholders for $$""" interpolation
# Use {{var}} for interpolation since we will use $$"""
html = html.replace('Oferta VIP Exclusiva - New Balance 413V3', 'Oferta VIP Exclusiva - {{title}}')
html = html.replace('https://opal.google/board/blobs/c6e2535c-feb6-4997-ac9e-f8006d82277c', '{{image}}')
html = html.replace("alt='Tênis New Balance 413V3'", "alt='{{title}}'")
html = html.replace('Tênis New Balance 413V3', '{{title}}')
html = html.replace('NOVO BALANÇO', 'DETALHES DO PRODUTO')

html = html.replace('https://produto.mercadolivre.com.br/MLB-4161795293?matt_tool=98187057&matt_word=land177', '{{offerUrl}}')
html = html.replace('212,00', '{{price_val}}')
html = html.replace('R$ 399,00', '{{previous_price}}')
html = html.replace('OFERTAMELI', '{{coupon}}')
html = html.replace('Economia de R$ 187,00', '{{savings_text}}')

# Remove the specific description paragraphs and replace with generic
import re
html = re.sub(r'<p>\s*O Tênis New Balance 413V3 é projetado.*?casual urbano.\s*</p>', '<p>{{description}}</p>', html, flags=re.DOTALL)
html = re.sub(r'<p>\s*Com tecnologia de amortecimento avançada.*?a marca representa.\s*</p>', '<p>Aproveite esta oferta exclusiva do catálogo!</p>', html, flags=re.DOTALL)

# Handle the coupon blocks conditionally.
# Since we use $$""", we can do logic outside and inject HTML blocks.
# Block 1 (Instruction)
block1 = """<div class="mt-8 p-6 bg-slate-50 rounded-2xl border-l-4 border-accent">
                        <p class="text-sm font-bold text-slate-500 uppercase mb-2">Instrução de Compra:</p>
                        <p class="text-primary font-semibold">Aplique o cupom <span class="bg-accent/20 text-accent px-2 py-0.5 rounded">{{coupon}}</span> no checkout para garantir este valor exclusivo.</p>
                    </div>"""

# Block 2 (Coupon Active Badge)
block2 = """<div class="mt-8 pt-8 border-t border-white/10">
                    <div class="bg-white/5 rounded-xl p-4 text-center">
                        <p class="text-white/60 text-xs uppercase tracking-widest mb-1">CUPOM ATIVO</p>
                        <p class="text-accent font-mono font-bold text-xl tracking-wider">{{coupon}}</p>
                    </div>
                </div>"""

# Remove hardcoded blocks from HTML to place placeholders
html = html.replace(block1, '{{couponBlock1}}')
html = html.replace(block2, '{{couponBlock2}}')

csharp_code = f"""static string BuildCatalogItemPageHtml(CatalogOfferItem item, string catalogUrl)
{{
    var title = System.Net.WebUtility.HtmlEncode(item.ProductName);
    var store = System.Net.WebUtility.HtmlEncode(item.Store);
    var keyword = System.Net.WebUtility.HtmlEncode(item.Keyword);
    var fullPrice = System.Net.WebUtility.HtmlEncode(item.PriceText ?? "Preco indisponivel");
    var price_val = fullPrice.Replace("R$ ", "").Replace("R$", "").Trim();
    var offerUrl = System.Net.WebUtility.HtmlEncode(item.OfferUrl);
    var image = System.Net.WebUtility.HtmlEncode(item.ImageUrl ?? "https://via.placeholder.com/800");
    var catalog = System.Net.WebUtility.HtmlEncode(catalogUrl);
    var description = "Adquira este item incrivel na " + store + ". Verifique as condicoes no site oficial.";
    var previous_price = "---";
    var savings_text = "Desconto aplicado";
    
    // As we lack specific coupon parsing right now in CatalogOfferItem, we leave it empty.
    var coupon = ""; 
    var couponBlock1 = string.IsNullOrWhiteSpace(coupon) ? "" : $$"\"\"\"
<div class=\\"mt-8 p-6 bg-slate-50 rounded-2xl border-l-4 border-accent\\">
    <p class=\\"text-sm font-bold text-slate-500 uppercase mb-2\\">Instrução de Compra:</p>
    <p class=\\"text-primary font-semibold\\">Aplique o cupom <span class=\\"bg-accent/20 text-accent px-2 py-0.5 rounded\\">{{{{coupon}}}}</span> no checkout para garantir este valor exclusivo.</p>
</div>
\"\"\"";

    var couponBlock2 = string.IsNullOrWhiteSpace(coupon) ? "" : $$"\"\"\"
<div class=\\"mt-8 pt-8 border-t border-white/10\\">
    <div class=\\"bg-white/5 rounded-xl p-4 text-center\\">
        <p class=\\"text-white/60 text-xs uppercase tracking-widest mb-1\\">CUPOM ATIVO</p>
        <p class=\\"text-accent font-mono font-bold text-xl tracking-wider\\">{{{{coupon}}}}</p>
    </div>
</div>
\"\"\"";

    return $$"\"\"\"
{html}
\"\"\";
}}"""

codecs.open('tmp_csharp.txt', 'w', 'utf-8').write(csharp_code)
