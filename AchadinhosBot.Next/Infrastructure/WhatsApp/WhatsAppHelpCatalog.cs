namespace AchadinhosBot.Next.Infrastructure.WhatsApp;

public static class WhatsAppHelpCatalog
{
    public static string ForScope(string scope) => scope switch
    {
        "instagram" => InstagramHelp(),
        "cta" => CtaHelp(),
        "links" => LinksHelp(),
        "ads" => AdsHelp(),
        "quick" => QuickHelp(),
        _ => GeneralHelp()
    };

    public static string InstagramHelp() => Lines(
        "GUIA /ig - Instagram via WhatsApp", "", "FLUXO PADRAO:",
        "1) /ig criar <produto ou link> cta=BIKE", "2) /ig imagem ultimo <url> (se faltar imagem)", "3) /ig leg 1 ultimo  (ou /leg 1)", "4) /ig formatar ultimo", "5) /ig revisar ultimo", "6) /ig confirmar ultimo", "",
        "FLUXO RAPIDO:", "- /ig rapido <produto ou link> cta=BIKE img=https://... tipo=feed|story", "", "COMANDOS (com descricao):",
        "- /ig criar ... : cria rascunho com legenda, CTA e imagens detectadas.", "- /ig rapido ... : cria + tenta publicar automaticamente.", "- /ig imagem <id|ultimo> <url1,url2> : adiciona imagens no rascunho.", "- /ig imagens <id|ultimo> [1|1,2|2-4] : lista/seleciona quais imagens usar.", "- /ig tipo <id|ultimo> feed|story|reel|carrossel : define formato.", "- /ig cta <id|ultimo> PALAVRA1,PALAVRA2 : define palavra-chave do CTA.", "- /ig leg <numero> <id|ultimo> : escolhe uma das legendas geradas.", "- /ig legenda <id|ultimo> <texto> : sobrescreve a legenda manualmente.", "- /ig formatar <id|ultimo> : corrige espacos e quebras de linha.", "- /ig template <id|ultimo> <1|2|3> : aplica template de legenda.", "- /ig templates : lista templates disponiveis.", "- /ig revisar <id|ultimo> : mostra resumo do rascunho.", "- /ig confirmar <id|ultimo> : publica no Instagram.", "- /ig revisar <1|2|3> : atalho por ordem do rascunho mais recente.", "- /ig reset [tudo] : limpa estado do chat; com 'tudo' apaga os drafts.", "- /ig anunciar ... : cria anuncio (Meta Ads) do post publicado.", "- /ig menu : abre menu numerico rapido (1..8).", "", "ATALHOS:", "- /ig ajuda", "- /help ig", "- /bio", "", "OBS:", "- 'ultimo' sempre aponta para o rascunho mais recente.", "- Link clicavel no Instagram: Bio (/bio), DM ou anuncio.");

    public static string GeneralHelp() => Lines("HELP - Menu Principal", "", "Categorias:", "1) Instagram (criacao/publicacao de post)", "2) CTA e respostas (comentario/DM)", "3) Links e bio (links clicaveis)", "4) Anuncios (boost com CTA)", "5) Atalhos rapidos (fluxo curto)", "", "Como usar:", "- /help <numero>  (ex.: /help 1)", "- Depois de /help, responda apenas 1, 2, 3, 4 ou 5", "- /help ig  (atalho para Instagram)", "- /help cta | /help links | /help ads | /help rapido", "", "Comandos base:", "- /help  |  \\help  |  /ajuda", "- /bio");
    public static string CtaHelp() => Lines("HELP 2 - CTA e Respostas", "", "Objetivo:", "- Capturar palavra-chave (ex.: BIKE) e entregar link.", "", "Comandos uteis:", "- /ig cta ultimo BIKE", "- /ig revisar ultimo", "- /ig confirmar ultimo", "", "Boas praticas:", "- Use palavra curta, sem acento e sem espaco.", "- Garanta que o link esteja no draft.", "- Prefira DM/Bio para link clicavel.", "", "Voltar ao menu: /help");
    public static string LinksHelp() => Lines("HELP 3 - Links e Bio", "", "Instagram nao permite link clicavel em comentario.", "Use estas opcoes:", "- /bio  (pagina com links clicaveis)", "- DM automatica com o link", "- anuncio com CTA (saiba mais/comprar)", "", "Fluxo recomendado:", "1) Definir CTA no post", "2) Publicar", "3) Entregar link por DM ou /bio", "", "Voltar ao menu: /help");
    public static string AdsHelp() => Lines("HELP 4 - Anuncios (Boost)", "", "Comando:", "- /ig anunciar <id|ultimo> conta=<ad_account_id> cta=SHOP_NOW url=<link>", "", "Requisitos:", "- Post ja publicado (/ig confirmar).", "- Token com permissoes de anuncios.", "- Conta de anuncios valida.", "", "Observacao:", "- Se a API retornar erro de capability (#3), o app nao tem permissao para esse endpoint.", "", "Voltar ao menu: /help");
    public static string QuickHelp() => Lines("HELP 5 - Atalhos Rapidos", "", "Criar + publicar:", "- /ig rapido <produto ou link> cta=BIKE img=https://... tipo=feed", "", "Menu por numero:", "- /ig menu", "- Responda 1..8 para a acao desejada", "", "Fluxo com mais controle:", "- /ig criar ...", "- /ig revisar ultimo", "- /ig confirmar ultimo", "", "Voltar ao menu: /help");
    public static string InstagramMenu() => Lines("MENU /ig (responda so com o numero):", "1) Revisar ultimo rascunho", "2) Confirmar/publicar ultimo", "3) Formatar legenda do ultimo", "4) Aplicar template 1 no ultimo", "5) Aplicar template 2 no ultimo", "6) Aplicar template 3 no ultimo", "7) Listar templates", "8) Ver ajuda do Instagram", "", "Validade: 15 minutos para este chat.");

    private static string Lines(params string[] lines) => string.Join('\n', lines);
}
