using System.Collections.Concurrent;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Configuration;
using AchadinhosBot.Next.Domain.Settings;
using AchadinhosBot.Next.Infrastructure.Media;
using AchadinhosBot.Next.Infrastructure.Storage;
using AchadinhosBot.Next.Infrastructure.Instagram;
using Microsoft.Extensions.Options;
using System.Text;
using System.Text.RegularExpressions;
using TL;
using WTelegram;
using System.Linq;

namespace AchadinhosBot.Next.Infrastructure.Telegram;

public sealed class TelegramUserbotService : BackgroundService, ITelegramUserbotService
{
    private readonly TelegramOptions _options;
    private readonly AffiliateOptions _affiliateOptions;
    private readonly ISettingsStore _settingsStore;
    private readonly IMessageProcessor _messageProcessor;
    private readonly IWhatsAppGateway _whatsAppGateway;
    private readonly IMediaFailureLogStore _mediaFailureLogStore;
    private readonly IMediaStore _mediaStore;
    private readonly WebhookOptions _webhookOptions;
    private readonly ILinkTrackingStore _linkTrackingStore;
    private readonly IConversionLogStore _conversionLogStore;
    private readonly IInstagramPostComposer _instagramComposer;
    private readonly InstagramConversationStore _instagramStore;
    private readonly ILogger<TelegramUserbotService> _logger;
    private Client? _client;
    private UpdateManager? _manager;
    private IReadOnlyList<TelegramUserbotChat> _cachedChats = Array.Empty<TelegramUserbotChat>();
    private readonly ConcurrentDictionary<long, InputPeer> _inputPeers = new();
    private readonly SemaphoreSlim _refreshLock = new(1, 1);
    private long? _selfUserId;
    private volatile bool _ready;

    public bool IsReady => _ready;

    public TelegramUserbotService(
        IOptions<TelegramOptions> options,
        IOptions<AffiliateOptions> affiliateOptions,
        IOptions<WebhookOptions> webhookOptions,
        ISettingsStore settingsStore,
        IMessageProcessor messageProcessor,
        IWhatsAppGateway whatsAppGateway,
        ILinkTrackingStore linkTrackingStore,
        IConversionLogStore conversionLogStore,
        IInstagramPostComposer instagramComposer,
        InstagramConversationStore instagramStore,
        IMediaStore mediaStore,
        IMediaFailureLogStore mediaFailureLogStore,
        ILogger<TelegramUserbotService> logger)
    {
        _options = options.Value;
        _affiliateOptions = affiliateOptions.Value;
        _webhookOptions = webhookOptions.Value;
        _settingsStore = settingsStore;
        _messageProcessor = messageProcessor;
        _whatsAppGateway = whatsAppGateway;
        _linkTrackingStore = linkTrackingStore;
        _conversionLogStore = conversionLogStore;
        _instagramComposer = instagramComposer;
        _instagramStore = instagramStore;
        _mediaStore = mediaStore;
        _mediaFailureLogStore = mediaFailureLogStore;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (_options.ApiId <= 0 || string.IsNullOrWhiteSpace(_options.ApiHash))
        {
            _logger.LogWarning("TelegramUserbotService: ApiId/ApiHash nÃ£o configurados.");
            return;
        }

        var sessionPath = Environment.GetEnvironmentVariable("WTELEGRAM_SESSION");
        if (string.IsNullOrWhiteSpace(sessionPath))
        {
            sessionPath = Path.Combine(AppContext.BaseDirectory, "WTelegram.session");
        }

        var hasSession = File.Exists(sessionPath);
        if (!hasSession)
        {
            var altSession = Path.Combine(Directory.GetCurrentDirectory(), "WTelegram.session");
            if (File.Exists(altSession))
            {
                sessionPath = altSession;
                hasSession = true;
            }
        }

        var phoneEnv = Environment.GetEnvironmentVariable("TELEGRAM_PHONE");
        var phoneConfig = _options.UserbotPhone;
        if (!hasSession && string.IsNullOrWhiteSpace(phoneEnv))
        {
            _logger.LogWarning("TelegramUserbotService: defina TELEGRAM_PHONE ou forneÃ§a um session file ({SessionPath}).", sessionPath);
            return;
        }

        string? Config(string what)
        {
            return what switch
            {
                "session_pathname" => sessionPath,
                "api_id" => _options.ApiId.ToString(),
                "api_hash" => _options.ApiHash,
                "phone_number" => phoneEnv ?? phoneConfig ?? string.Empty,
                "verification_code" => Environment.GetEnvironmentVariable("TELEGRAM_VERIFICATION_CODE") ?? string.Empty,
                "password" => Environment.GetEnvironmentVariable("TELEGRAM_PASSWORD") ?? string.Empty,
                _ => null
            };
        }

        var retryCount = 0;
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                _client = new Client(Config);
                await using (_client)
                {
                    _manager = _client.WithUpdateManager(OnUserbotUpdate);
                    await _client.LoginUserIfNeeded();
                    _selfUserId = _client.User?.id;
                    _ready = true;
                    retryCount = 0;
                    _logger.LogInformation("TelegramUserbot conectado. UserId={UserId}. Session={SessionPath}", _selfUserId, sessionPath);

                    await RefreshDialogsAsync(stoppingToken);
                    await Task.Delay(Timeout.InfiniteTimeSpan, stoppingToken);
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                _logger.LogInformation("TelegramUserbotService cancelado.");
                break;
            }
            catch (Exception ex)
            {
                retryCount++;
                var isBadMsg = IsBadMsgSessionOrClockError(ex);
                var delay = GetRetryDelay(retryCount);
                _logger.LogError(ex, "Falha no TelegramUserbotService. Tentativa={Attempt}, RetryEm={DelaySeconds}s", retryCount, delay.TotalSeconds);

                if (isBadMsg)
                {
                    _logger.LogWarning(
                        "TelegramUserbot retornou BadMsg/BadServerSalt. Normalmente indica sessao inconsistente ou horario do Windows fora de sincronia. " +
                        "Verifique relogio/NTP e, se necessario, recrie o arquivo WTelegram.session.");
                }

                try
                {
                    await Task.Delay(delay, stoppingToken);
                }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
                {
                    break;
                }
            }
            finally
            {
                _ready = false;
                _manager = null;
                _client = null;
            }
        }
    }

    private static bool IsBadMsgSessionOrClockError(Exception ex)
    {
        var dump = ex.ToString();
        return dump.Contains("BadMsgNotification", StringComparison.OrdinalIgnoreCase)
               || dump.Contains("BadServerSalt", StringComparison.OrdinalIgnoreCase);
    }

    private static TimeSpan GetRetryDelay(int retryCount)
    {
        var seconds = Math.Min(60, Math.Max(5, retryCount * 5));
        return TimeSpan.FromSeconds(seconds);
    }

    public async Task<IReadOnlyList<TelegramUserbotChat>> GetDialogsAsync(CancellationToken cancellationToken)
    {
        await _refreshLock.WaitAsync(cancellationToken);
        try
        {
            return _cachedChats;
        }
        finally
        {
            _refreshLock.Release();
        }
    }

    public async Task<bool> RefreshDialogsAsync(CancellationToken cancellationToken)
    {
        if (_client is null || _manager is null)
        {
            return false;
        }

        await _refreshLock.WaitAsync(cancellationToken);
        try
        {
            var dialogs = await _client.Messages_GetAllDialogs();
            dialogs.CollectUsersChats(_manager.Users, _manager.Chats);

            var list = new List<TelegramUserbotChat>();
            foreach (var chat in dialogs.chats.Values)
            {
                switch (chat)
                {
                    case Chat g:
                        list.Add(new TelegramUserbotChat(g.ID, g.Title, "group"));
                        _inputPeers[g.ID] = g.ToInputPeer();
                        break;
                    case Channel c:
                        list.Add(new TelegramUserbotChat(c.ID, c.title, "channel"));
                        _inputPeers[c.ID] = c.ToInputPeer();
                        break;
                }
            }

            _cachedChats = list.OrderBy(x => x.Title).ToArray();
            _logger.LogInformation("TelegramUserbot: {Count} chats carregados.", _cachedChats.Count);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Falha ao carregar chats do userbot.");
            return false;
        }
        finally
        {
            _refreshLock.Release();
        }
    }

    private async Task OnUserbotUpdate(Update update)
    {
        if (_client is null || _manager is null)
        {
            return;
        }

        Message? msg = null;
        if (update is UpdateNewMessage unm && unm.message is Message m1)
        {
            msg = m1;
        }
        else if (update is UpdateNewChannelMessage ucm && ucm.message is Message m2)
        {
            msg = m2;
        }

        if (msg is null)
        {
            return;
        }

        var text = msg.message ?? string.Empty;
        if (string.IsNullOrWhiteSpace(text))
        {
            return;
        }

        var settings = await _settingsStore.GetAsync(CancellationToken.None);
        if (IsInstagramBotResponse(text))
        {
            return;
        }
        var instaSettings = settings.InstagramPosts;
        if (instaSettings.Enabled && instaSettings.AllowTelegramUserbot && IsTelegramInstagramAllowed(instaSettings, msg.peer_id))
        {
            if (instaSettings.TelegramChatIds.Count > 0 && !instaSettings.TelegramChatIds.Contains(msg.peer_id.ID))
            {
                // ignore chats not explicitly allowed
            }
            else
            {
            var instaKey = $"tgu:{msg.peer_id.ID}";
            if (_instagramStore.TryConsume(instaKey, out var convo))
            {
                var post = await _instagramComposer.BuildAsync(text, convo.Context, instaSettings, CancellationToken.None);
                var peer = ResolvePeer(msg.peer_id.ID);
                if (peer is not null && _client is not null)
                {
                    foreach (var chunk in SplitInstagramMessages(post))
                    {
                        await _client.SendMessageAsync(peer, chunk);
                    }
                }
                return;
            }

            if (IsInstagramTrigger(text, instaSettings.Triggers))
            {
                if (TryGetInstagramInlineProduct(text, instaSettings.Triggers, out var inlineProduct))
                {
                    var post = await _instagramComposer.BuildAsync(inlineProduct, null, instaSettings, CancellationToken.None);
                    var peer = ResolvePeer(msg.peer_id.ID);
                    if (peer is not null && _client is not null)
                    {
                        foreach (var chunk in SplitInstagramMessages(post))
                        {
                            await _client.SendMessageAsync(peer, chunk);
                        }
                    }
                }
                else
                {
                    _instagramStore.SetPending(instaKey, text);
                    var peer = ResolvePeer(msg.peer_id.ID);
                    if (peer is not null && _client is not null)
                    {
                        await _client.SendMessageAsync(peer, "Qual produto? Envie o nome ou o link.");
                    }
                }
                return;
            }
            }
        }

        var autoReply = GetAutoReply(settings, text);
        if (!string.IsNullOrWhiteSpace(autoReply))
        {
            var peer = ResolvePeer(msg.peer_id.ID);
            if (peer is not null && _client is not null)
            {
                var trackedReply = await ApplyTrackingAsync(autoReply, settings.LinkResponder?.TrackingEnabled ?? true, CancellationToken.None);
                await _client.SendMessageAsync(peer, trackedReply.Text);
                _ = _conversionLogStore.AppendAsync(new Domain.Logs.ConversionLogEntry
                {
                    Source = "AutoReply",
                    Store = "AutoReply",
                    Success = true,
                    OriginalUrl = text,
                    ConvertedUrl = trackedReply.Text,
                    TrackingIds = trackedReply.TrackingIds,
                    OriginChatId = msg.peer_id.ID,
                    DestinationChatId = msg.peer_id.ID
                }, CancellationToken.None);
            }
            return;
        }

        if (!text.Contains("http", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        var responder = settings.LinkResponder;
        var originId = msg.peer_id.ID;
        var originPeer = ResolvePeer(originId);

        if (responder.Enabled && responder.AllowTelegramUserbot && originPeer is not null && _client is not null)
        {
            if (IsTelegramResponderAllowed(responder, originId, msg.peer_id))
            {
                var responderResult = await _messageProcessor.ProcessAsync(
                    text,
                    "TelegramUserbotResponder",
                    CancellationToken.None,
                    originChatId: originId,
                    destinationChatId: originId);

                if (responderResult.Success && !string.IsNullOrWhiteSpace(responderResult.ConvertedText))
                {
                    var responseText = BuildResponderMessage(responder, responderResult.ConvertedText);
                    if (responder.AppendSheinCode &&
                        responseText.Contains("shein", StringComparison.OrdinalIgnoreCase) &&
                        !string.IsNullOrWhiteSpace(_affiliateOptions.SheinCode) &&
                        !responseText.Contains(_affiliateOptions.SheinCode, StringComparison.OrdinalIgnoreCase))
                    {
                        responseText += $"\n\nCodigo Shein: {_affiliateOptions.SheinCode}";
                    }

                    if (!string.IsNullOrWhiteSpace(responder.FooterText))
                    {
                        responseText += $"\n\n{responder.FooterText}";
                    }

                    var tracked = await ApplyTrackingAsync(responseText, responder.TrackingEnabled, CancellationToken.None);
                    responseText = tracked.Text;
                    await _client.SendMessageAsync(originPeer, responseText);
                    _ = _conversionLogStore.AppendAsync(new Domain.Logs.ConversionLogEntry
                    {
                        Source = "TelegramUserbotResponder",
                        Store = "Unknown",
                        Success = true,
                        OriginalUrl = text,
                        ConvertedUrl = responseText,
                        TrackingIds = tracked.TrackingIds,
                        OriginChatId = originId,
                        DestinationChatId = originId
                    }, CancellationToken.None);
                }
                else if (!IsTelegramGroupPeer(msg.peer_id) && !string.IsNullOrWhiteSpace(responder.ReplyOnFailure))
                {
                    var trackedFail = await ApplyTrackingAsync(responder.ReplyOnFailure, responder.TrackingEnabled, CancellationToken.None);
                    await _client.SendMessageAsync(originPeer, trackedFail.Text);
                }
            }
        }

        if (!settings.TelegramForwarding.Enabled)
        {
            return;
        }

        var sourceIds = settings.TelegramForwarding.SourceChatIds;
        if (sourceIds.Count == 0)
        {
            return;
        }

        if (!IsSourceMatch(originId, sourceIds))
        {
            return;
        }

        var result = await _messageProcessor.ProcessAsync(
            text,
            "TelegramUserbot",
            CancellationToken.None,
            originChatId: originId,
            destinationChatId: settings.TelegramForwarding.DestinationChatId);
        if (!result.Success || string.IsNullOrWhiteSpace(result.ConvertedText))
        {
            return;
        }

        var destinationId = settings.TelegramForwarding.DestinationChatId;
        if (destinationId == 0)
        {
            _logger.LogWarning("TelegramUserbot: DestinationChatId nÃ£o configurado.");
            return;
        }

        var destinationPeer = ResolvePeer(destinationId);
        if (destinationPeer is null)
        {
            _logger.LogWarning("TelegramUserbot: destino {DestinationId} nÃ£o encontrado nos dialogs.", destinationId);
            return;
        }

        var finalText = result.ConvertedText;
        if (settings.TelegramForwarding.AppendSheinCode &&
            ContainsShein(finalText) &&
            !string.IsNullOrWhiteSpace(_affiliateOptions.SheinCode) &&
            !finalText.Contains(_affiliateOptions.SheinCode, StringComparison.OrdinalIgnoreCase))
        {
            finalText += $"\n\nCodigo Shein: {_affiliateOptions.SheinCode}";
        }

        if (!string.IsNullOrWhiteSpace(settings.TelegramForwarding.FooterText))
        {
            finalText += $"\n\n{settings.TelegramForwarding.FooterText}";
        }

        byte[]? waImageBytes = null;
        string? waImageMime = null;
        var client = _client;
        if (client is null)
        {
            _logger.LogWarning("TelegramUserbot: cliente nÃ£o inicializado para enviar mensagem ao destino {DestinationId}.", destinationId);
            return;
        }

        try
        {
            if (msg.media is MessageMediaPhoto mmPhoto && mmPhoto.photo is Photo photo)
            {
                var inputMedia = new InputMediaPhoto
                {
                    id = new InputPhoto
                    {
                        id = photo.id,
                        access_hash = photo.access_hash,
                        file_reference = photo.file_reference
                    }
                };
                await client.Messages_SendMedia(destinationPeer, inputMedia, finalText, WTelegram.Helpers.RandomLong());
                (waImageBytes, waImageMime) = await TryDownloadPhotoAsync(photo);
            }
            else if (msg.media is MessageMediaDocument mmDoc && mmDoc.document is Document doc)
            {
                var inputMedia = new InputMediaDocument
                {
                    id = new InputDocument
                    {
                        id = doc.id,
                        access_hash = doc.access_hash,
                        file_reference = doc.file_reference
                    }
                };
                await client.Messages_SendMedia(destinationPeer, inputMedia, finalText, WTelegram.Helpers.RandomLong());
                if (!string.IsNullOrWhiteSpace(doc.mime_type) && doc.mime_type.StartsWith("image/", StringComparison.OrdinalIgnoreCase))
                {
                    (waImageBytes, waImageMime) = await TryDownloadDocumentAsync(doc);
                }
            }
            else if (msg.media is MessageMediaWebPage mmWeb && mmWeb.webpage is WebPage webPage && webPage.photo is Photo webPhoto)
            {
                await client.SendMessageAsync(destinationPeer, finalText);
                (waImageBytes, waImageMime) = await TryDownloadPhotoAsync(webPhoto);
            }
            else
            {
                await client.SendMessageAsync(destinationPeer, finalText);
                if (msg.grouped_id != 0)
                {
                    var grouped = await TryDownloadGroupedMediaAsync(msg);
                    if (grouped.bytes is not null)
                    {
                        waImageBytes = grouped.bytes;
                        waImageMime = grouped.mime;
                    }
                }
                else
                {
                    var nearby = await TryDownloadNearbyMediaAsync(msg);
                    if (nearby.bytes is not null)
                    {
                        waImageBytes = nearby.bytes;
                        waImageMime = nearby.mime;
                    }
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Falha ao enviar mensagem para destino {DestinationId}.", destinationId);
        }

        if ((msg.media is not null || msg.grouped_id != 0) && (waImageBytes is null || waImageBytes.Length == 0))
        {
            await _mediaFailureLogStore.AppendAsync(new Domain.Logs.MediaFailureEntry
            {
                OriginChatId = originId,
                Reason = msg.media is null ? "grouped_media_missing" : "media_unavailable",
                Detail = msg.media?.GetType().Name ?? $"grouped_id={msg.grouped_id}",
                Success = false
            }, CancellationToken.None);
        }
        else if ((msg.media is null && msg.grouped_id == 0) && (waImageBytes is null || waImageBytes.Length == 0))
        {
            await _mediaFailureLogStore.AppendAsync(new Domain.Logs.MediaFailureEntry
            {
                OriginChatId = originId,
                Reason = "media_missing_no_group",
                Detail = "Sem media/grupo; tentativa de buscar vizinhas falhou",
                Success = false
            }, CancellationToken.None);
        }
        else
        {
            await _mediaFailureLogStore.AppendAsync(new Domain.Logs.MediaFailureEntry
            {
                OriginChatId = originId,
                Reason = waImageBytes is null ? "no_media" : "media_ok",
                Detail = waImageBytes is null ? "Mensagem sem mídia" : "Imagem capturada",
                Success = waImageBytes is not null && waImageBytes.Length > 0
            }, CancellationToken.None);
        }

        await SendToWhatsAppIfEnabled(settings, result.ConvertedText, originId, waImageBytes, waImageMime);
    }

    private async Task SendToWhatsAppIfEnabled(AutomationSettings settings, string convertedText, long originId, byte[]? imageBytes, string? imageMime)
    {
        var route = settings.TelegramToWhatsApp;
        var wa = settings.WhatsAppForwarding;

        var enabled = route.Enabled || wa.Enabled;
        if (!enabled)
        {
            return;
        }

        var routeSources = route.SourceChatIds.Count > 0 || settings.TelegramForwarding.SourceChatIds.Count > 0
            ? route.SourceChatIds.Union(settings.TelegramForwarding.SourceChatIds).ToList()
            : settings.TelegramForwarding.SourceChatIds;
        if (route.Enabled && routeSources.Count > 0 && !IsSourceMatch(originId, routeSources))
        {
            return;
        }

        var destinations = route.Enabled
            ? route.DestinationGroupIds.Union(wa.DestinationGroupIds).ToList()
            : wa.DestinationGroupIds;
        if (destinations.Count == 0)
        {
            return;
        }

        var text = convertedText;
        if (wa.AppendSheinCode &&
            ContainsShein(text) &&
            !string.IsNullOrWhiteSpace(_affiliateOptions.SheinCode) &&
            !text.Contains(_affiliateOptions.SheinCode, StringComparison.OrdinalIgnoreCase))
        {
            text += $"\n\nCodigo Shein: {_affiliateOptions.SheinCode}";
        }

        if (!string.IsNullOrWhiteSpace(wa.FooterText))
        {
            text += $"\n\n{wa.FooterText}";
        }

        string? mediaUrl = null;
        if (imageBytes is not null && imageBytes.Length > 0)
        {
            var id = _mediaStore.Add(imageBytes, string.IsNullOrWhiteSpace(imageMime) ? "image/jpeg" : imageMime);
            var port = _webhookOptions.Port <= 0 ? 5000 : _webhookOptions.Port;
            if (!string.IsNullOrWhiteSpace(_webhookOptions.PublicBaseUrl))
            {
                mediaUrl = _webhookOptions.PublicBaseUrl.TrimEnd('/') + $"/media/{id}";
            }
            else
            {
                mediaUrl = $"http://localhost:{port}/media/{id}";
            }
        }

        var destList = destinations.Distinct().Where(d => !string.IsNullOrWhiteSpace(d)).ToArray();
        await _mediaFailureLogStore.AppendAsync(new Domain.Logs.MediaFailureEntry
        {
            OriginChatId = originId,
            DestinationChatRef = string.Join(",", destList),
            Reason = "telegram_media_capture",
            Detail = imageBytes is not null && imageBytes.Length > 0 ? "Imagem capturada" : "Sem imagem capturada",
            Success = imageBytes is not null && imageBytes.Length > 0
        }, CancellationToken.None);

        foreach (var destination in destList)
        {
            if (string.IsNullOrWhiteSpace(destination)) continue;
            WhatsAppSendResult result;
            if (wa.SendMediaEnabled && !string.IsNullOrWhiteSpace(mediaUrl))
            {
                result = await _whatsAppGateway.SendImageUrlAsync(wa.InstanceName, destination, mediaUrl, text, imageMime, "oferta.jpg", CancellationToken.None);
                if (!result.Success)
                {
                    _logger.LogWarning("Falha ao enviar WhatsApp imagem (url) (origem TG {Origin} -> {Destination}): {Message}", originId, destination, result.Message);
                    result = await _whatsAppGateway.SendImageAsync(wa.InstanceName, destination, imageBytes!, text, imageMime, CancellationToken.None);
                    if (!result.Success)
                    {
                        _logger.LogWarning("Falha ao enviar WhatsApp imagem (base64) (origem TG {Origin} -> {Destination}): {Message}", originId, destination, result.Message);
                        await _mediaFailureLogStore.AppendAsync(new Domain.Logs.MediaFailureEntry
                        {
                            OriginChatId = originId,
                            DestinationChatRef = destination,
                            Reason = "whatsapp_media_failed",
                            Detail = result.Message,
                            Success = false
                        }, CancellationToken.None);
                        result = await _whatsAppGateway.SendTextAsync(wa.InstanceName, destination, text, CancellationToken.None);
                        await _mediaFailureLogStore.AppendAsync(new Domain.Logs.MediaFailureEntry
                        {
                            OriginChatId = originId,
                            DestinationChatRef = destination,
                            Reason = "whatsapp_media_fallback_text",
                            Detail = result.Success ? "Texto enviado" : (result.Message ?? "Falha ao enviar texto"),
                            Success = result.Success
                        }, CancellationToken.None);
                    }
                    else
                    {
                        await _mediaFailureLogStore.AppendAsync(new Domain.Logs.MediaFailureEntry
                        {
                            OriginChatId = originId,
                            DestinationChatRef = destination,
                            Reason = "whatsapp_media_sent_base64",
                            Detail = "Imagem enviada (base64)",
                            Success = true
                        }, CancellationToken.None);
                    }
                }
                else
                {
                    await _mediaFailureLogStore.AppendAsync(new Domain.Logs.MediaFailureEntry
                    {
                        OriginChatId = originId,
                        DestinationChatRef = destination,
                        Reason = "whatsapp_media_sent_url",
                        Detail = "Imagem enviada (url)",
                        Success = true
                    }, CancellationToken.None);
                }
            }
            else
            {
                result = await _whatsAppGateway.SendTextAsync(wa.InstanceName, destination, text, CancellationToken.None);
                await _mediaFailureLogStore.AppendAsync(new Domain.Logs.MediaFailureEntry
                {
                    OriginChatId = originId,
                    DestinationChatRef = destination,
                    Reason = wa.SendMediaEnabled ? "media_missing_text_only" : "media_disabled_text_only",
                    Detail = result.Success ? "Texto enviado" : (result.Message ?? "Falha ao enviar texto"),
                    Success = !wa.SendMediaEnabled && result.Success
                }, CancellationToken.None);
            }
            if (!result.Success)
            {
                _logger.LogWarning("Falha ao enviar WhatsApp (origem TG {Origin} -> {Destination}): {Message}", originId, destination, result.Message);
            }
        }

        await _mediaFailureLogStore.AppendAsync(new Domain.Logs.MediaFailureEntry
        {
            OriginChatId = originId,
            DestinationChatRef = string.Join(",", destList),
            Reason = "media_route_summary",
            Detail = $"Destinos={destList.Length}",
            Success = imageBytes is not null && imageBytes.Length > 0
        }, CancellationToken.None);
    }

    private async Task<(byte[]? bytes, string? mime)> TryDownloadPhotoAsync(Photo photo)
    {
        if (_client is null) return (null, null);

        try
        {
            var bestType = GetBestPhotoSizeType(photo.sizes);
            if (string.IsNullOrWhiteSpace(bestType)) return (null, null);

            var location = new InputPhotoFileLocation
            {
                id = photo.id,
                access_hash = photo.access_hash,
                file_reference = photo.file_reference,
                thumb_size = bestType
            };

            using var ms = new MemoryStream();
            await _client.DownloadFileAsync(location, ms);
            return (ms.ToArray(), "image/jpeg");
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Falha ao baixar foto do Telegram.");
            return (null, null);
        }
    }

    private async Task<(byte[]? bytes, string? mime)> TryDownloadDocumentAsync(Document doc)
    {
        if (_client is null) return (null, null);

        try
        {
            var location = new InputDocumentFileLocation
            {
                id = doc.id,
                access_hash = doc.access_hash,
                file_reference = doc.file_reference,
                thumb_size = string.Empty
            };

            using var ms = new MemoryStream();
            await _client.DownloadFileAsync(location, ms);
            var mime = string.IsNullOrWhiteSpace(doc.mime_type) ? "image/jpeg" : doc.mime_type;
            return (ms.ToArray(), mime);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Falha ao baixar documento do Telegram.");
            return (null, null);
        }
    }

    private async Task<(byte[]? bytes, string? mime)> TryDownloadGroupedMediaAsync(Message msg)
    {
        if (_client is null) return (null, null);
        try
        {
            if (msg.grouped_id == 0) return (null, null);
            var originId = msg.peer_id.ID;
            var peer = ResolvePeer(originId);
            if (peer is null) return (null, null);

            var history = await _client.Messages_GetHistory(peer, offset_id: msg.id, limit: 20);
            if (history is null) return (null, null);

            IEnumerable<Message> historyMessages;
            if (history is Messages_Messages mm)
            {
                historyMessages = mm.messages.OfType<Message>();
            }
            else if (history is Messages_ChannelMessages cm)
            {
                historyMessages = cm.messages.OfType<Message>();
            }
            else if (history is Messages_MessagesSlice ms)
            {
                historyMessages = ms.messages.OfType<Message>();
            }
            else
            {
                historyMessages = Enumerable.Empty<Message>();
            }

            foreach (var hm in historyMessages)
            {
                if (hm.grouped_id != msg.grouped_id) continue;
                if (hm.media is MessageMediaPhoto photoMedia && photoMedia.photo is Photo p)
                {
                    return await TryDownloadPhotoAsync(p);
                }
                if (hm.media is MessageMediaDocument docMedia && docMedia.document is Document d)
                {
                    if (!string.IsNullOrWhiteSpace(d.mime_type) && d.mime_type.StartsWith("image/", StringComparison.OrdinalIgnoreCase))
                    {
                        return await TryDownloadDocumentAsync(d);
                    }
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Falha ao buscar mídia de álbum.");
        }

        return (null, null);
    }

    private async Task<(byte[]? bytes, string? mime)> TryDownloadNearbyMediaAsync(Message msg)
    {
        if (_client is null) return (null, null);
        try
        {
            var originId = msg.peer_id.ID;
            var peer = ResolvePeer(originId);
            if (peer is null) return (null, null);

            var history = await _client.Messages_GetHistory(peer, offset_id: msg.id, limit: 6);
            if (history is null) return (null, null);

            IEnumerable<Message> historyMessages;
            if (history is Messages_Messages mm)
            {
                historyMessages = mm.messages.OfType<Message>();
            }
            else if (history is Messages_ChannelMessages cm)
            {
                historyMessages = cm.messages.OfType<Message>();
            }
            else if (history is Messages_MessagesSlice ms)
            {
                historyMessages = ms.messages.OfType<Message>();
            }
            else
            {
                historyMessages = Enumerable.Empty<Message>();
            }

            var candidates = historyMessages
                .Where(m => m.id != msg.id)
                .Where(m => Math.Abs(m.id - msg.id) <= 3)
                .Where(m => m.media is MessageMediaPhoto || m.media is MessageMediaDocument)
                .ToList();

            if (candidates.Count != 1) return (null, null);
            var candidate = candidates[0];

            if (candidate.media is MessageMediaPhoto p && p.photo is Photo photo)
            {
                return await TryDownloadPhotoAsync(photo);
            }

            if (candidate.media is MessageMediaDocument d && d.document is Document doc)
            {
                if (!string.IsNullOrWhiteSpace(doc.mime_type) && doc.mime_type.StartsWith("image/", StringComparison.OrdinalIgnoreCase))
                {
                    return await TryDownloadDocumentAsync(doc);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Falha ao buscar mídia próxima.");
        }

        return (null, null);
    }

    private static string? GetBestPhotoSizeType(PhotoSizeBase[] sizes)
    {
        string? bestType = null;
        var bestArea = 0;
        foreach (var size in sizes)
        {
            switch (size)
            {
                case PhotoSize s:
                    {
                        var area = s.w * s.h;
                        if (area > bestArea)
                        {
                            bestArea = area;
                            bestType = s.type;
                        }
                        break;
                    }
                case PhotoSizeProgressive s:
                    {
                        var area = s.w * s.h;
                        if (area > bestArea)
                        {
                            bestArea = area;
                            bestType = s.type;
                        }
                        break;
                    }
                case PhotoCachedSize s:
                    {
                        var area = s.w * s.h;
                        if (area > bestArea)
                        {
                            bestArea = area;
                            bestType = s.type;
                        }
                        break;
                    }
            }
        }

        return bestType;
    }

    private InputPeer? ResolvePeer(long id)
    {
        if (_inputPeers.TryGetValue(id, out var peer))
        {
            return peer;
        }

        var inverted = (id * -1) - 1000000000000;
        if (_inputPeers.TryGetValue(inverted, out peer))
        {
            return peer;
        }

        var neg = id * -1;
        if (_inputPeers.TryGetValue(neg, out peer))
        {
            return peer;
        }

        return null;
    }

    private static bool IsSourceMatch(long originId, List<long> sourceIds)
    {
        if (sourceIds.Contains(originId)) return true;
        var inverted = (originId * -1) - 1000000000000;
        if (sourceIds.Contains(inverted)) return true;
        var neg = originId * -1;
        return sourceIds.Contains(neg);
    }

    private static bool IsTelegramResponderAllowed(LinkResponderSettings responder, long originId, Peer peer)
    {
        if (responder.TelegramChatIds.Count > 0)
        {
            return IsSourceMatch(originId, responder.TelegramChatIds);
        }

        return IsTelegramGroupPeer(peer) ? responder.TelegramAllowGroups : responder.TelegramAllowPrivate;
    }

    private static bool IsTelegramGroupPeer(Peer peer)
        => peer is PeerChat || peer is PeerChannel;

    private static string? GetAutoReply(AutomationSettings settings, string text)
    {
        if (!settings.AutoRepliesSettings.Enabled) return null;
        if (string.IsNullOrWhiteSpace(text)) return null;
        var hasLink = text.Contains("http", StringComparison.OrdinalIgnoreCase);
        if (hasLink) return null;

        foreach (var rule in settings.AutoReplies)
        {
            if (!rule.Enabled) continue;
            if (string.IsNullOrWhiteSpace(rule.Trigger)) continue;
            if (text.Contains(rule.Trigger, StringComparison.OrdinalIgnoreCase))
            {
                return rule.ResponseTemplate;
            }
        }

        return null;
    }

    private static bool IsInstagramTrigger(string text, List<string> triggers)
    {
        if (string.IsNullOrWhiteSpace(text)) return false;
        if (triggers is null || triggers.Count == 0) return false;
        foreach (var trigger in triggers)
        {
            if (string.IsNullOrWhiteSpace(trigger)) continue;
            if (text.Contains(trigger, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }
        return false;
    }

    private static bool IsInstagramBotResponse(string text)
    {
        if (string.IsNullOrWhiteSpace(text)) return false;
        return text.Contains("POST PARA INSTAGRAM", StringComparison.OrdinalIgnoreCase)
               || text.Contains("Legenda 1", StringComparison.OrdinalIgnoreCase)
               || text.Contains("Hashtags sugeridas", StringComparison.OrdinalIgnoreCase)
               || text.StartsWith("Qual produto?", StringComparison.OrdinalIgnoreCase)
               || text.Contains("Envie o nome ou o link", StringComparison.OrdinalIgnoreCase);
    }

    private static IEnumerable<string> SplitInstagramMessages(string text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            yield break;
        }

        var lines = text.Replace("\r", string.Empty).Split('\n');
        var blocks = new List<List<string>>();

        foreach (var raw in lines)
        {
            var line = raw?.TrimEnd() ?? string.Empty;
            if (IsInstagramSectionHeader(line) && blocks.Count > 0)
            {
                blocks.Add(new List<string>());
            }
            if (blocks.Count == 0)
            {
                blocks.Add(new List<string>());
            }
            blocks[^1].Add(line);
        }

        foreach (var block in blocks)
        {
            var chunk = string.Join('\n', block).Trim();
            if (!string.IsNullOrWhiteSpace(chunk))
            {
                yield return chunk;
            }
        }
    }

    private static bool IsInstagramSectionHeader(string line)
    {
        if (string.IsNullOrWhiteSpace(line)) return false;
        var t = line.Trim();
        return t.StartsWith("Legenda 1", StringComparison.OrdinalIgnoreCase)
               || t.StartsWith("Legenda 2", StringComparison.OrdinalIgnoreCase)
               || t.StartsWith("Hashtags sugeridas", StringComparison.OrdinalIgnoreCase)
               || t.StartsWith("Sugestões de imagem", StringComparison.OrdinalIgnoreCase)
               || t.StartsWith("Sugestoes de imagem", StringComparison.OrdinalIgnoreCase)
               || t.StartsWith("Post extra", StringComparison.OrdinalIgnoreCase)
               || t.StartsWith("Sugestão rápida", StringComparison.OrdinalIgnoreCase)
               || t.StartsWith("Sugestao rapida", StringComparison.OrdinalIgnoreCase);
    }

    private static bool TryGetInstagramInlineProduct(string text, List<string> triggers, out string product)
    {
        product = string.Empty;
        if (string.IsNullOrWhiteSpace(text)) return false;
        if (triggers is null || triggers.Count == 0) return false;
        var normalized = text.Trim();
        foreach (var trigger in triggers)
        {
            if (string.IsNullOrWhiteSpace(trigger)) continue;
            var idx = normalized.IndexOf(trigger, StringComparison.OrdinalIgnoreCase);
            if (idx < 0) continue;
            var remaining = normalized.Remove(idx, trigger.Length).Trim();
            remaining = remaining.Trim('-', ':', '—', '–');
            if (!string.IsNullOrWhiteSpace(remaining))
            {
                product = remaining;
                return true;
            }
        }
        return false;
    }

    private static bool IsTelegramInstagramAllowed(InstagramPostSettings settings, Peer peer)
    {
        return IsTelegramGroupPeer(peer) ? settings.TelegramAllowGroups : settings.TelegramAllowPrivate;
    }

    private static string BuildResponderMessage(LinkResponderSettings responder, string convertedText)
    {
        var template = responder.ReplyTemplate;
        if (string.IsNullOrWhiteSpace(template))
        {
            return convertedText;
        }

        var result = template;
        if (result.Contains("{link}", StringComparison.OrdinalIgnoreCase))
        {
            result = result.Replace("{link}", convertedText, StringComparison.OrdinalIgnoreCase);
        }

        if (result.Contains("{text}", StringComparison.OrdinalIgnoreCase))
        {
            result = result.Replace("{text}", convertedText, StringComparison.OrdinalIgnoreCase);
        }

        if (!result.Contains(convertedText, StringComparison.OrdinalIgnoreCase))
        {
            result = $"{result}\n{convertedText}";
        }

        return result;
    }

    private async Task<TrackingResult> ApplyTrackingAsync(string text, bool trackingEnabled, CancellationToken ct)
    {
        if (!trackingEnabled || string.IsNullOrWhiteSpace(text) || string.IsNullOrWhiteSpace(_webhookOptions.PublicBaseUrl))
        {
            return new TrackingResult(text, new List<string>());
        }

        var baseUrl = _webhookOptions.PublicBaseUrl.TrimEnd('/');
        var trackingSuffix = GetTrackingSuffix(baseUrl);
        var matches = UrlRegex.Matches(text);
        if (matches.Count == 0) return new TrackingResult(text, new List<string>());

        var sb = new StringBuilder(text.Length + 32);
        var lastIndex = 0;
        var trackingIds = new List<string>();
        foreach (Match match in matches)
        {
            sb.Append(text, lastIndex, match.Index - lastIndex);
            var url = match.Value;
            if (url.StartsWith(baseUrl, StringComparison.OrdinalIgnoreCase))
            {
                sb.Append(url);
            }
            else
            {
                var entry = await _linkTrackingStore.CreateAsync(url, ct);
                sb.Append($"{baseUrl}/r/{entry.Id}{trackingSuffix}");
                trackingIds.Add(entry.Id);
            }
            lastIndex = match.Index + match.Length;
        }
        sb.Append(text, lastIndex, text.Length - lastIndex);
        return new TrackingResult(sb.ToString(), trackingIds);
    }

    private static readonly Regex UrlRegex = new(@"https?://[^\s]+", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    private sealed record TrackingResult(string Text, List<string> TrackingIds);

    private static string GetTrackingSuffix(string baseUrl)
    {
        var lower = baseUrl.ToLowerInvariant();
        if (lower.Contains("ngrok-free") || lower.Contains("ngrok.app"))
        {
            return "?ngrok-skip-browser-warning=1";
        }
        return string.Empty;
    }

    private static bool ContainsShein(string text)
    {
        return text.Contains("shein", StringComparison.OrdinalIgnoreCase);
    }
}
