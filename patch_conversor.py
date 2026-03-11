import codecs

conversor_path = r'c:\AchadinhoBot2\AchadinhosBot2\AchadinhosBot.Next\wwwroot\conversor.html'
old_html = codecs.open(conversor_path, 'r', 'utf-8').read()

new_html = """<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VIP Converter - Rei das Ofertas</title>
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
                        surface: '#1e293b'
                    },
                    fontFamily: {
                        display: ['Montserrat', 'sans-serif'],
                        body: ['Inter', 'sans-serif'],
                    },
                    animation: {
                        'float': 'float 20s infinite ease-in-out alternate',
                    },
                    keyframes: {
                        float: {
                            '0%': { transform: 'translate(0, 0) scale(1)' },
                            '100%': { transform: 'translate(50px, 50px) scale(1.1)' }
                        }
                    }
                }
            }
        }
    </script>
    <style>
        body { font-family: 'Inter', sans-serif; }
        h1, h2, h3 { font-family: 'Montserrat', sans-serif; }
        
        .spinner {
            display: none;
            width: 20px;
            height: 20px;
            border: 3px solid rgba(255, 255, 255, 0.3);
            border-radius: 50%;
            border-top-color: white;
            animation: spin 1s ease-in-out infinite;
        }

        @keyframes spin {
            to { transform: rotate(360deg); }
        }

        .result-container {
            display: none;
            animation: slideUp 0.5s cubic-bezier(0.16, 1, 0.3, 1) forwards;
        }

        @keyframes slideUp {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .toast {
            position: fixed;
            bottom: 2rem;
            left: 50%;
            transform: translateX(-50%) translateY(100px);
            background: #f8fafc;
            color: #0f172a;
            padding: 1rem 2rem;
            border-radius: 999px;
            font-weight: 600;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.3);
            transition: transform 0.4s cubic-bezier(0.16, 1, 0.3, 1);
            z-index: 1000;
        }

        .toast.show {
            transform: translateX(-50%) translateY(0);
        }
        
        /* Make sure old DOM elements JS manipulates correctly toggle display */
        #errorAlert { display: none; }
        #discountBadge { display: none; }
        #deliveryInfo { display: none; }
    </style>
</head>
<body class="bg-primary text-slate-100 min-h-screen flex flex-col items-center justify-center p-4 md:p-8 relative overflow-x-hidden">

    <!-- Orbs -->
    <div class="absolute w-[400px] h-[400px] bg-accent/10 rounded-full blur-[80px] -top-24 -left-24 animate-float -z-10"></div>
    <div class="absolute w-[500px] h-[500px] bg-sky-500/10 rounded-full blur-[80px] -bottom-48 -right-24 animate-float -z-10" style="animation-delay: -5s"></div>

    <main class="w-full max-w-3xl bg-surface/40 backdrop-blur-xl border border-white/10 rounded-[24px] p-6 md:p-12 shadow-2xl">
        
        <div class="text-center mb-10">
            <div class="w-12 h-12 bg-accent rounded-full flex items-center justify-center mx-auto shadow-[0_0_15px_rgba(196,164,104,0.4)] mb-4">
                <span class="text-primary font-black text-sm tracking-tighter">VIP</span>
            </div>
            <h1 class="text-3xl md:text-5xl font-extrabold text-transparent bg-clip-text bg-gradient-to-r from-accent to-yellow-300 mb-3">Conversor Mágico</h1>
            <p class="text-slate-400 text-lg">Transforme links comuns em <span class="text-accent font-semibold">Ofertas Exclusivas</span> rastreáveis.</p>
        </div>

        <form id="convertForm" class="flex flex-col gap-4">
            <input type="url" id="urlInput" 
                   class="w-full bg-primary/60 border border-white/10 rounded-2xl px-6 py-4 text-white text-lg placeholder-slate-500 focus:outline-none focus:border-accent focus:ring-2 focus:ring-accent/20 transition-all"
                   placeholder="Cole o link da Amazon, Shopee, Mercado Livre..." required autocomplete="off">
            
            <button type="submit" id="submitBtn" 
                    class="w-full bg-accent hover:bg-accentHover text-primary font-bold text-lg px-6 py-4 rounded-2xl transition-all shadow-lg hover:shadow-accent/20 flex items-center justify-center gap-2 disabled:opacity-70 disabled:cursor-not-allowed">
                <span class="btn-text">Gerar Link VIP Exclusivo</span>
                <div class="spinner" id="spinner"></div>
            </button>
        </form>

        <div id="errorAlert" class="mt-6 bg-red-500/10 border border-red-500/20 text-red-400 p-4 rounded-xl font-medium"></div>

        <div id="resultArea" class="result-container mt-10">
            <div class="bg-[#151f32] border border-white/10 rounded-[20px] overflow-hidden flex flex-col md:flex-row group shadow-xl">
                
                <!-- Image Side -->
                <div class="w-full md:w-2/5 md:min-w-[300px] h-64 md:h-auto bg-white relative flex items-center justify-center p-6 border-b md:border-b-0 md:border-r border-white/10">
                    <span id="discountBadge" class="absolute top-4 right-4 bg-red-600 text-white px-3 py-1 rounded-full font-bold text-sm shadow-lg tracking-wider"></span>
                    <img id="productImage" src="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='100' height='100' viewBox='0 0 24 24' fill='none' stroke='%2394a3b8' stroke-width='1' stroke-linecap='round' stroke-linejoin='round'%3E%3Crect x='3' y='3' width='18' height='18' rx='2' ry='2'%3E%3C/rect%3E%3Ccircle cx='8.5' cy='8.5' r='1.5'%3E%3C/circle%3E%3Cpolyline points='21 15 16 10 5 21'%3E%3C/polyline%3E%3C/svg%3E" alt="Produto" class="max-w-full max-h-full object-contain group-hover:scale-105 transition-transform duration-500">
                </div>

                <!-- Info Side -->
                <div class="w-full md:w-3/5 p-6 md:p-8 flex flex-col justify-between">
                    
                    <div class="mb-6">
                        <span id="storeBadge" class="inline-block px-3 py-1 bg-surface border border-white/10 rounded-lg text-xs font-bold uppercase tracking-widest text-slate-300 mb-3">Loja</span>
                        <h2 id="productTitle" class="text-xl md:text-2xl font-semibold text-white leading-snug">Carregando detalhes do produto...</h2>
                    </div>

                    <div class="mt-auto space-y-5">
                        <div class="flex items-baseline gap-3 flex-wrap">
                            <span id="productPrice" class="text-3xl md:text-4xl font-extrabold text-accent">---</span>
                            <span id="productOldPrice" class="text-lg text-slate-500 line-through font-medium" style="display: none;"></span>
                        </div>

                        <div id="deliveryInfo" class="inline-flex items-center gap-2 text-sm font-medium text-green-400 bg-green-400/10 border border-green-400/20 px-3 py-1.5 rounded-lg">
                            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 8h14M5 8a2 2 0 110-4h14a2 2 0 110 4M5 8v10a2 2 0 002 2h10a2 2 0 002-2V8m-9 4h4"></path></svg>
                            <span id="deliveryText"></span>
                        </div>

                        <!-- Action Buttons -->
                        <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 pt-4 border-t border-white/10">
                            
                            <button id="copyBtn" class="flex items-center justify-center gap-2 bg-slate-700 hover:bg-slate-600 text-white font-semibold py-3 px-2 rounded-xl transition-colors" onclick="copyResult()">
                                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
                                <span class="text-sm">Copiar</span>
                            </button>
                            
                            <button id="openBtn" class="flex items-center justify-center gap-2 bg-green-600 hover:bg-green-500 text-white font-semibold py-3 px-2 rounded-xl transition-colors shadow-lg shadow-green-600/20" onclick="openLink()">
                                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"></path><polyline points="15 3 21 3 21 9"></polyline><line x1="10" y1="14" x2="21" y2="3"></line></svg>
                                <span class="text-sm">Abrir</span>
                            </button>
                            
                            <button id="whatsappBtn" class="flex items-center justify-center gap-2 bg-transparent hover:bg-white/5 border border-white/20 text-white font-semibold py-3 px-2 rounded-xl transition-colors" onclick="shareWhatsApp()">
                                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2"><path d="M21 11.5a8.38 8.38 0 0 1-.9 3.8 8.5 8.5 0 0 1-7.6 4.7 8.38 8.38 0 0 1-3.8-.9L3 21l1.9-5.7a8.38 8.38 0 0 1-.9-3.8 8.5 8.5 0 0 1 4.7-7.6 8.38 8.38 0 0 1 3.8-.9h.5a8.48 8.48 0 0 1 8 8v.5z"></path></svg>
                                <span class="text-sm border-b border-transparent">Zap</span>
                            </button>
                            
                            <button id="reportBtn" class="flex items-center justify-center gap-2 bg-transparent hover:bg-red-500/10 border border-red-500/30 text-red-400 font-semibold py-3 px-2 rounded-xl transition-colors" onclick="reportLink()">
                                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>
                                <span class="text-sm">Report</span>
                            </button>
                            
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </main>

    <div id="toast" class="toast">Link copiado com sucesso! 🎉</div>

    <!-- Inject original JavaScript Logic EXACTLY as it was to guarantee no regressions -->
"""

# Extract the original JavaScript Block
script_start = old_html.find("<script>")
script_end = old_html.find("</script>") + len("</script>")

js_block = old_html[script_start:script_end]

new_html += js_block + "\n</body>\n</html>"

codecs.open(conversor_path, 'w', 'utf-8').write(new_html)
print('conversor.html VIP UI patched!')
