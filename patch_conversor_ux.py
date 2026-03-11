import codecs
import re

file_path = r'c:\AchadinhoBot2\AchadinhosBot2\AchadinhosBot.Next\wwwroot\conversor.html'
with codecs.open(file_path, 'r', 'utf-8') as f:
    content = f.read()

# 1. CSS Adds (Tilt)
tilt_style = """
        .tilt-card {
            transition: transform 0.1s ease, box-shadow 0.1s ease;
            transform-style: preserve-3d;
            will-change: transform;
        }
"""
if ".tilt-card" not in content:
    content = content.replace("</style>", tilt_style + "</style>")

# 2. Add Skeleton Loader and Recent History HTML
skeleton_and_history_html = """
        <!-- Skeleton Loader -->
        <div id="skeletonLoader" class="hidden mt-10">
            <div class="bg-[#151f32] border border-white/5 rounded-[20px] overflow-hidden flex flex-col md:flex-row shadow-xl animate-pulse">
                <div class="w-full md:w-2/5 md:min-w-[300px] h-64 md:h-auto bg-white/5 relative flex items-center justify-center border-b md:border-b-0 md:border-r border-white/5">
                    <div class="w-20 h-20 bg-white/10 rounded-full"></div>
                </div>
                <div class="w-full md:w-3/5 p-6 md:p-8 flex flex-col justify-between space-y-4">
                    <div class="space-y-3">
                        <div class="h-6 bg-white/10 rounded-lg w-1/4"></div>
                        <div class="h-8 bg-white/10 rounded-lg w-3/4"></div>
                        <div class="h-8 bg-white/10 rounded-lg w-1/2"></div>
                    </div>
                    <div class="mt-8 space-y-4">
                        <div class="h-12 bg-white/10 rounded-lg w-1/3"></div>
                        <div class="grid grid-cols-2 md:grid-cols-4 gap-3">
                            <div class="h-12 bg-white/10 rounded-xl"></div>
                            <div class="h-12 bg-white/10 rounded-xl"></div>
                            <div class="h-12 bg-white/10 rounded-xl"></div>
                            <div class="h-12 bg-white/10 rounded-xl"></div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <div id="resultArea" class="result-container mt-10">
"""

content = content.replace('<div id="resultArea" class="result-container mt-10">', skeleton_and_history_html)

history_html = """
        <!-- Recent History -->
        <div id="historySection" class="hidden mt-12 w-full max-w-3xl mx-auto">
            <div class="flex items-center gap-2 mb-4">
                <svg class="w-5 h-5 text-accent" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
                <h3 class="text-white font-semibold text-lg">Convertidos Recentemente</h3>
            </div>
            <div id="historyGrid" class="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-4">
                <!-- History Items Injected via JS -->
            </div>
        </div>
    </main>
"""
content = content.replace('</main>', history_html)

# Add tilt class to the result card
content = content.replace('class="bg-[#151f32] border border-white/10 rounded-[20px] overflow-hidden flex flex-col md:flex-row group shadow-xl"', 'id="vipResultCard" class="bg-[#151f32] border border-white/10 rounded-[20px] overflow-hidden flex flex-col md:flex-row group shadow-xl tilt-card perspective-1000"')

# 3. Rewrite JS Logic to include Skeleton, Local Storage, and Tilt
js_start = content.find("<script>")
js_end = content.find("</script>", js_start) + len("</script>")

new_js = """<script>
        let currentConvertedUrl = '';
        let currentShareText = '';

        // Tilt Effect
        const applyTilt = (element) => {
            element.addEventListener('mousemove', (e) => {
                const rect = element.getBoundingClientRect();
                const x = e.clientX - rect.left;
                const y = e.clientY - rect.top;
                
                const centerX = rect.width / 2;
                const centerY = rect.height / 2;
                
                const rotateX = ((y - centerY) / centerY) * -5;
                const rotateY = ((x - centerX) / centerX) * 5;
                
                element.style.transform = `perspective(1000px) rotateX(${rotateX}deg) rotateY(${rotateY}deg) scale3d(1.02, 1.02, 1.02)`;
            });
            
            element.addEventListener('mouseleave', () => {
                element.style.transform = `perspective(1000px) rotateX(0deg) rotateY(0deg) scale3d(1, 1, 1)`;
            });
        };

        // History Management
        const loadHistory = () => {
            try {
                return JSON.parse(localStorage.getItem('vip_converter_history')) || [];
            } catch { return []; }
        };

        const saveToHistory = (data) => {
            let history = loadHistory();
            // Remove duplicates
            history = history.filter(h => h.trackedUrl !== data.trackedUrl && h.convertedUrl !== data.convertedUrl);
            
            history.unshift({
                title: data.title || 'Oferta',
                price: data.price || '',
                store: data.store || 'Loja',
                imageUrl: data.imageUrl,
                trackedUrl: data.trackedUrl || data.convertedUrl,
                timestamp: new Date().getTime()
            });
            
            // Keep only last 3
            history = history.slice(0, 3);
            localStorage.setItem('vip_converter_history', JSON.stringify(history));
            renderHistory();
        };

        const renderHistory = () => {
            const history = loadHistory();
            const section = document.getElementById('historySection');
            const grid = document.getElementById('historyGrid');
            
            if (history.length === 0) {
                section.classList.add('hidden');
                return;
            }
            
            section.classList.remove('hidden');
            grid.innerHTML = history.map(item => `
                <a href="${item.trackedUrl}" target="_blank" class="bg-surface/50 hover:bg-surface border border-white/5 hover:border-accent/30 rounded-xl p-3 flex gap-3 items-center transition-all group tilt-card">
                    <div class="w-12 h-12 bg-white rounded-lg flex-shrink-0 flex items-center justify-center p-1 overflow-hidden">
                        <img src="${item.imageUrl || ''}" class="max-w-full max-h-full object-contain mix-blend-multiply group-hover:scale-110 transition-transform">
                    </div>
                    <div class="flex-1 min-w-0">
                        <p class="text-white text-xs font-semibold truncate" title="${item.title}">${item.title}</p>
                        <p class="text-accent font-bold text-xs mt-1">${item.price}</p>
                    </div>
                </a>
            `).join('');

            // Apply tilt to history cards
            document.querySelectorAll('#historyGrid .tilt-card').forEach(applyTilt);
        };

        document.addEventListener('DOMContentLoaded', () => {
            renderHistory();
            const mainCard = document.getElementById('vipResultCard');
            if (mainCard) applyTilt(mainCard);
        });

        document.getElementById('convertForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const urlInput = document.getElementById('urlInput').value.trim();
            if (!urlInput) return;

            const btn = document.getElementById('submitBtn');
            const btnText = btn.querySelector('.btn-text');
            const spinner = document.getElementById('spinner');
            const resultArea = document.getElementById('resultArea');
            const skeletonLoader = document.getElementById('skeletonLoader');
            const errorAlert = document.getElementById('errorAlert');

            // Setup loading state (Skeleton)
            errorAlert.style.display = 'none';
            resultArea.style.display = 'none';
            skeletonLoader.classList.remove('hidden');
            
            btn.disabled = true;
            btnText.style.display = 'none';
            spinner.style.display = 'block';

            try {
                const response = await fetch('/api/conversor', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ url: urlInput })
                });

                const text = await response.text();
                let data;
                try {
                    data = JSON.parse(text);
                } catch {
                    throw new Error(`Erro de resposta do servidor.`);
                }

                if (!response.ok || !data.success) {
                    throw new Error(data.error || data.validationError || 'Falha na conversão.');
                }

                // Update UI
                currentConvertedUrl = data.trackedUrl || data.convertedUrl;

                document.getElementById('productImage').src = data.imageUrl || "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='100' height='100' viewBox='0 0 24 24' fill='none' stroke='%2394a3b8' stroke-width='1' stroke-linecap='round' stroke-linejoin='round'%3E%3Crect x='3' y='3' width='18' height='18' rx='2' ry='2'%3E%3C/rect%3E%3Ccircle cx='8.5' cy='8.5' r='1.5'%3E%3C/circle%3E%3Cpolyline points='21 15 16 10 5 21'%3E%3C/polyline%3E%3C/svg%3E";
                document.getElementById('storeBadge').textContent = data.store || 'Loja';
                document.getElementById('productTitle').textContent = data.title || 'Oferta Imperdível';
                document.getElementById('productPrice').textContent = data.price || 'Preço indisponível';

                const oldPriceEl = document.getElementById('productOldPrice');
                if (data.previousPrice && data.previousPrice !== data.price) {
                    oldPriceEl.textContent = data.previousPrice;
                    oldPriceEl.style.display = 'inline';
                } else {
                    oldPriceEl.style.display = 'none';
                }

                const discountBadge = document.getElementById('discountBadge');
                if (data.discountPercent > 0) {
                    discountBadge.textContent = `${data.discountPercent}% OFF`;
                    discountBadge.style.display = 'block';
                } else {
                    discountBadge.style.display = 'none';
                }

                const deliveryEl = document.getElementById('deliveryInfo');
                const deliveryText = document.getElementById('deliveryText');
                if (data.estimatedDelivery) {
                    deliveryText.textContent = data.estimatedDelivery;
                    deliveryEl.style.display = 'flex';
                } else {
                    deliveryEl.style.display = 'none';
                }

                const couponText = data.hasCoupon && data.couponCode ? `\\n\\n🎟️ Cupom: ${data.couponCode}` : '';
                const discountText = data.discountPercent > 0 ? ` 🏷️ -${data.discountPercent}%` : '';
                const deliveryShareText = data.estimatedDelivery ? `\\n${data.estimatedDelivery === 'Entrega grátis' ? '🚚 Entrega grátis!' : `🚚 ${data.estimatedDelivery}`}` : '';
                currentShareText = `*${data.title || 'Nova Oferta'}*${discountText}\\n⚡ Por apenas: *${data.price || ''}*${couponText}${deliveryShareText}\\n\\n🛒 Compre aqui: ${currentConvertedUrl}`;

                // Swap Skeleton to Real Result
                skeletonLoader.classList.add('hidden');
                resultArea.style.display = 'block';
                errorAlert.style.display = 'none';
                
                // Save and update history
                saveToHistory(data);

            } catch (error) {
                errorAlert.textContent = error.message;
                errorAlert.style.display = 'block';
                skeletonLoader.classList.add('hidden');
            } finally {
                btn.disabled = false;
                btnText.style.display = 'block';
                spinner.style.display = 'none';
            }
        });

        function copyResult() {
            if (!currentConvertedUrl) return;
            navigator.clipboard.writeText(currentConvertedUrl).then(() => showToast('Link copiado com sucesso! 🔗')).catch(() => showToast('Erro ao copiar.'));
        }

        function openLink() {
            if (!currentConvertedUrl) return;
            window.open(currentConvertedUrl, '_blank', 'noopener,noreferrer');
        }

        function shareWhatsApp() {
            if (!currentShareText) return;
            const waUrl = `https://wa.me/?text=${encodeURIComponent(currentShareText)}`;
            window.open(waUrl, '_blank');
        }

        function reportLink() {
            const originalUrl = document.getElementById('urlInput').value.trim();
            const reportPhone = '5513996877283';
            const message = `Olá, meu link deu problema, consegue verificar o que houve?\\n\\n🔗 Link original: ${originalUrl}\\n🔗 Link convertido: ${currentConvertedUrl}`;
            const waUrl = `https://wa.me/${reportPhone}?text=${encodeURIComponent(message)}`;
            window.open(waUrl, '_blank');
        }

        function showToast(message) {
            const toast = document.getElementById('toast');
            toast.textContent = message;
            toast.classList.add('show');
            setTimeout(() => toast.classList.remove('show'), 3000);
        }
    </script>
"""

content = content[:js_start] + new_js + content[js_end:]

with codecs.open(file_path, 'w', 'utf-8') as f:
    f.write(content)
print("done patching ux features")
