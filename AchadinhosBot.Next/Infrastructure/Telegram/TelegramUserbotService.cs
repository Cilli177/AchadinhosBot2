using System.Collections.Concurrent;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Configuration;
using AchadinhosBot.Next.Domain.Settings;
using AchadinhosBot.Next.Infrastructure.Media;
using AchadinhosBot.Next.Infrastructure.Storage;
using AchadinhosBot.Next.Infrastructure.Instagram;
using AchadinhosBot.Next.Infrastructure.Safety;
using Microsoft.Extensions.Options;
using System.Text;
using System.Text.RegularExpressions;
using TL;
using WTelegram;
using System.Linq;

namespace AchadinhosBot.Next.Infrastructure.Telegram;

public sealed class TelegramUserbotService : BackgroundService, ITelegramUserbotService
{
    private const string OfficialWhatsAppDemandGroupId = "120363405661434395@g.us";
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
    private readonly DeliverySafetyPolicy _deliverySafetyPolicy;
    private readonly ILogger<TelegramUserbotService> _logger;
    private Client? _client;
    private UpdateManager? _manager;
    private IReadOnlyList<TelegramUserbotChat> _cachedChats = Array.Empty<TelegramUserbotChat>();
    private readonly ConcurrentDictionary<long, InputPeer> _inputPeers = new();
    private readonly SemaphoreSlim _refreshLock = new(1, 1);
    private readonly object _runtimeAuthLock = new();
    private readonly object _reconnectLock = new();
    private CancellationTokenSource _reconnectSignal = new();
    private string? _runtimePhoneNumber;
    private string? _runtimeVerificationCode;
    private string? _runtimePassword;
    private long? _selfUserId;
    private volatile bool _ready;
    private volatile bool _awaitingVerificationCode;
    private volatile bool _awaitingPassword;

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
        DeliverySafetyPolicy deliverySafetyPolicy,
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
        _deliverySafetyPolicy = deliverySafetyPolicy;
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
            // Keep userbot session under /app/data so container restarts do not require a new login.
            var dataDir = Path.Combine(AppContext.BaseDirectory, "data");
            Directory.CreateDirectory(dataDir);
            sessionPath = Path.Combine(dataDir, "WTelegram.session");
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

        if (!hasSession && string.IsNullOrWhiteSpace(GetPhoneNumberForLogin()))
        {
            _logger.LogWarning("TelegramUserbotService: sem sessao valida e sem telefone configurado. Aguardando credenciais via painel.");
        }

        string? Config(string what)
        {
            return what switch
            {
                "session_pathname" => sessionPath,
                "api_id" => _options.ApiId.ToString(),
                "api_hash" => _options.ApiHash,
                "phone_number" => GetPhoneNumberForLogin(),
                "verification_code" => GetVerificationCodeForLogin(),
                "password" => GetPasswordForLogin(),
                _ => null
            };
        }

        var retryCount = 0;
        var waitCredentialsCount = 0;
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                hasSession = File.Exists(sessionPath);
                if (!hasSession)
                {
                    var altSession = Path.Combine(Directory.GetCurrentDirectory(), "WTelegram.session");
                    if (File.Exists(altSession))
                    {
                        sessionPath = altSession;
                        hasSession = true;
                    }
                }

                if (!hasSession && string.IsNullOrWhiteSpace(GetPhoneNumberForLogin()))
                {
                    waitCredentialsCount++;
                    if (waitCredentialsCount == 1 || waitCredentialsCount % 12 == 0)
                    {
                        _logger.LogWarning("TelegramUserbotService: aguardando telefone/codigo no painel para autenticar.");
                    }
                    await Task.Delay(TimeSpan.FromSeconds(5), stoppingToken);
                    continue;
                }

                if (_awaitingVerificationCode && string.IsNullOrWhiteSpace(GetCurrentRuntimeVerificationCode()))
                {
                    waitCredentialsCount++;
                    if (waitCredentialsCount == 1 || waitCredentialsCount % 12 == 0)
                    {
                        _logger.LogWarning("TelegramUserbotService: codigo de verificacao pendente. Informe no painel para concluir login.");
                    }
                    await Task.Delay(TimeSpan.FromSeconds(3), stoppingToken);
                    continue;
                }

                if (_awaitingPassword && string.IsNullOrWhiteSpace(GetCurrentRuntimePassword()))
                {
                    waitCredentialsCount++;
                    if (waitCredentialsCount == 1 || waitCredentialsCount % 12 == 0)
                    {
                        _logger.LogWarning("TelegramUserbotService: senha 2FA pendente. Informe no painel para concluir login.");
                    }
                    await Task.Delay(TimeSpan.FromSeconds(3), stoppingToken);
                    continue;
                }

                waitCredentialsCount = 0;
                _client = new Client(Config);
                await using (_client)
                {
                    _manager = _client.WithUpdateManager(OnUserbotUpdate);
                    await _client.LoginUserIfNeeded();
                    _selfUserId = _client.User?.id;
                    _ready = true;
                    _awaitingVerificationCode = false;
                    _awaitingPassword = false;
                    retryCount = 0;
                    _logger.LogInformation("TelegramUserbot conectado. UserId={UserId}. Session={SessionPath}", _selfUserId, sessionPath);

                    await RefreshDialogsAsync(stoppingToken);
                    using var linkedRun = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken, GetReconnectToken());
                    await Task.Delay(Timeout.InfiniteTimeSpan, linkedRun.Token);
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                _logger.LogInformation("TelegramUserbotService cancelado.");
                break;
            }
            catch (OperationCanceledException)
            {
                retryCount = 0;
                _logger.LogInformation("TelegramUserbotService: reconexao acionada manualmente.");
            }
            catch (Exception ex)
            {
                if (IsVerificationCodeRequired(ex))
                {
                    _awaitingVerificationCode = true;
                    _awaitingPassword = false;
                    retryCount = 0;
                    _logger.LogWarning("TelegramUserbotService: codigo de verificacao solicitado. Envie o codigo no painel para continuar.");
                    try
                    {
                        await Task.Delay(TimeSpan.FromSeconds(2), stoppingToken);
                    }
                    catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
                    {
                        break;
                    }

                    continue;
                }

                if (IsPasswordRequired(ex))
                {
                    _awaitingPassword = true;
                    retryCount = 0;
                    _logger.LogWarning("TelegramUserbotService: senha 2FA solicitada. Envie a senha no painel para continuar.");
                    try
                    {
                        await Task.Delay(TimeSpan.FromSeconds(2), stoppingToken);
                    }
                    catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
                    {
                        break;
                    }

                    continue;
                }

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

                if (IsPhoneNumberInvalid(ex))
                {
                    _logger.LogWarning(
                        "TelegramUserbot falhou com PHONE_NUMBER_INVALID. Configure TELEGRAM__USERBOTPHONE no formato internacional (ex: +5511999999999) e, se preciso, apague WTelegram.session para refazer login.");
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

    private static bool IsPhoneNumberInvalid(Exception ex)
    {
        return ex.ToString().Contains("PHONE_NUMBER_INVALID", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsVerificationCodeRequired(Exception ex)
    {
        return ex.ToString().Contains("verification_code", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsPasswordRequired(Exception ex)
    {
        var dump = ex.ToString();
        return dump.Contains("SESSION_PASSWORD_NEEDED", StringComparison.OrdinalIgnoreCase)
               || dump.Contains("PASSWORD_HASH_INVALID", StringComparison.OrdinalIgnoreCase)
               || dump.Contains("password", StringComparison.OrdinalIgnoreCase);
    }

    private static TimeSpan GetRetryDelay(int retryCount)
    {
        var seconds = Math.Min(60, Math.Max(5, retryCount * 5));
        return TimeSpan.FromSeconds(seconds);
    }

    public Task<TelegramUserbotAuthUpdateResult> UpdateRuntimeAuthAsync(TelegramUserbotAuthUpdateRequest request, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var phone = NormalizePhone(request.PhoneNumber);
        var code = NormalizeSecret(request.VerificationCode);
        var password = NormalizeSecret(request.Password);
        var updated = false;
        var phoneUpdated = request.PhoneNumber is not null;
        var codeUpdated = request.VerificationCode is not null;
        var passwordUpdated = request.Password is not null;

        lock (_runtimeAuthLock)
        {
            if (phoneUpdated)
            {
                _runtimePhoneNumber = phone;
                updated = true;
            }

            if (codeUpdated)
            {
                _runtimeVerificationCode = code;
                updated = true;
            }

            if (passwordUpdated)
            {
                _runtimePassword = password;
                updated = true;
            }
        }

        if (phoneUpdated)
        {
            _awaitingVerificationCode = false;
            _awaitingPassword = false;
        }

        if (codeUpdated && !string.IsNullOrWhiteSpace(code))
        {
            _awaitingVerificationCode = false;
        }

        if (passwordUpdated && !string.IsNullOrWhiteSpace(password))
        {
            _awaitingPassword = false;
        }

        var reconnectRequested = request.ForceReconnect || codeUpdated || passwordUpdated || (phoneUpdated && !_ready);
        if (reconnectRequested)
        {
            RequestReconnect("userbot_auth_update");
        }

        var hasPhone = !string.IsNullOrWhiteSpace(GetPhoneNumberForLogin());
        var hasCode = !string.IsNullOrWhiteSpace(GetCurrentRuntimeVerificationCode());
        var hasPassword = !string.IsNullOrWhiteSpace(GetPasswordForLogin());

        if (!updated && !reconnectRequested)
        {
            return Task.FromResult(new TelegramUserbotAuthUpdateResult(
                false,
                false,
                hasPhone,
                hasCode,
                hasPassword,
                "Nenhum dado foi informado."));
        }

        _logger.LogInformation(
            "TelegramUserbot auth atualizado via painel. phone={HasPhone} code={HasCode} password={HasPassword} reconnect={ReconnectRequested}",
            request.PhoneNumber is not null,
            request.VerificationCode is not null,
            request.Password is not null,
            reconnectRequested);

        return Task.FromResult(new TelegramUserbotAuthUpdateResult(
            true,
            reconnectRequested,
            hasPhone,
            hasCode,
            hasPassword,
            reconnectRequested
                ? "Credenciais atualizadas e reconexao solicitada."
                : "Credenciais atualizadas."));
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

    private string GetPhoneNumberForLogin()
    {
        var runtime = GetCurrentRuntimePhoneNumber();
        if (!string.IsNullOrWhiteSpace(runtime))
        {
            return runtime;
        }

        var envPhone =
            Environment.GetEnvironmentVariable("TELEGRAM_PHONE")
            ?? Environment.GetEnvironmentVariable("TELEGRAM__USERBOTPHONE")
            ?? Environment.GetEnvironmentVariable("TELEGRAM__USERBOT_PHONE");

        return NormalizePhone(envPhone) ?? NormalizePhone(_options.UserbotPhone) ?? string.Empty;
    }

    private string? GetVerificationCodeForLogin()
    {
        lock (_runtimeAuthLock)
        {
            if (!string.IsNullOrWhiteSpace(_runtimeVerificationCode))
            {
                var code = _runtimeVerificationCode!;
                _runtimeVerificationCode = null;
                return code;
            }
        }

        return NormalizeSecret(Environment.GetEnvironmentVariable("TELEGRAM_VERIFICATION_CODE"));
    }

    private string? GetPasswordForLogin()
    {
        var runtime = GetCurrentRuntimePassword();
        if (!string.IsNullOrWhiteSpace(runtime))
        {
            return runtime;
        }

        return NormalizeSecret(Environment.GetEnvironmentVariable("TELEGRAM_PASSWORD"));
    }

    private string? GetCurrentRuntimePhoneNumber()
    {
        lock (_runtimeAuthLock)
        {
            return _runtimePhoneNumber;
        }
    }

    private string? GetCurrentRuntimeVerificationCode()
    {
        lock (_runtimeAuthLock)
        {
            return _runtimeVerificationCode;
        }
    }

    private string? GetCurrentRuntimePassword()
    {
        lock (_runtimeAuthLock)
        {
            return _runtimePassword;
        }
    }

    private CancellationToken GetReconnectToken()
    {
        lock (_reconnectLock)
        {
            return _reconnectSignal.Token;
        }
    }

    private void RequestReconnect(string reason)
    {
        CancellationTokenSource previous;
        lock (_reconnectLock)
        {
            previous = _reconnectSignal;
            _reconnectSignal = new CancellationTokenSource();
        }

        try
        {
            previous.Cancel();
        }
        catch
        {
            // ignore cancellation races
        }
        finally
        {
            previous.Dispose();
        }

        _ready = false;
        try
        {
            _client?.Dispose();
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Falha ao descartar client durante reconexao manual.");
        }

        _logger.LogInformation("TelegramUserbot reconexao solicitada. reason={Reason}", reason);
    }

    private static string? NormalizePhone(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var trimmed = value.Trim().Replace(" ", string.Empty, StringComparison.Ordinal);
        return trimmed.Length == 0 ? null : trimmed;
    }

    private static string? NormalizeSecret(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var trimmed = value.Trim();
        return trimmed.Length == 0 ? null : trimmed;
    }

    public async Task<TelegramUserbotReplayResult> ReplayRecentOffersToWhatsAppAsync(long sourceChatId, int count, bool allowOfficialDestination, CancellationToken cancellationToken)
    {
        if (_client is null || _manager is null || !_ready)
        {
            return new TelegramUserbotReplayResult(
                false,
                "Telegram userbot nao esta pronto.",
                sourceChatId,
                count,
                0,
                0,
                0);
        }

        var requested = Math.Clamp(count, 1, 50);
        var peer = ResolvePeer(sourceChatId);
        if (peer is null)
        {
            await RefreshDialogsAsync(cancellationToken);
            peer = ResolvePeer(sourceChatId);
        }

        if (peer is null)
        {
            return new TelegramUserbotReplayResult(
                false,
                $"Chat {sourceChatId} nao encontrado nos dialogs do userbot.",
                sourceChatId,
                requested,
                0,
                0,
                0);
        }

        Messages_MessagesBase? history;
        try
        {
            history = await _client.Messages_GetHistory(peer, limit: Math.Clamp(requested * 8, 20, 200));
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Falha ao carregar historico do chat {SourceChatId} para replay.", sourceChatId);
            return new TelegramUserbotReplayResult(
                false,
                "Falha ao carregar historico do Telegram.",
                sourceChatId,
                requested,
                0,
                0,
                0);
        }

        if (history is null)
        {
            return new TelegramUserbotReplayResult(
                false,
                "Historico vazio para o chat informado.",
                sourceChatId,
                requested,
                0,
                0,
                0);
        }

        var candidates = ExtractHistoryMessages(history)
            .Where(m => !string.IsNullOrWhiteSpace(m.message))
            .Where(m => m.message!.Contains("http", StringComparison.OrdinalIgnoreCase))
            .OrderByDescending(m => m.date)
            .ThenByDescending(m => m.id)
            .Take(requested)
            .OrderBy(m => m.date)
            .ThenBy(m => m.id)
            .ToArray();

        if (candidates.Length == 0)
        {
            return new TelegramUserbotReplayResult(
                true,
                "Nenhuma oferta com link encontrada no historico recente.",
                sourceChatId,
                requested,
                0,
                0,
                0);
        }

        var settings = await _settingsStore.GetAsync(cancellationToken);
        var replayDestinations = ResolveReplayWhatsAppDestinations(settings, sourceChatId);
        if (!allowOfficialDestination && replayDestinations.Any(d => string.Equals(d, OfficialWhatsAppDemandGroupId, StringComparison.OrdinalIgnoreCase)))
        {
            return new TelegramUserbotReplayResult(
                false,
                $"Replay bloqueado: destino oficial {OfficialWhatsAppDemandGroupId} protegido. Use AllowOfficialDestination=true somente em recuperacao real.",
                sourceChatId,
                requested,
                candidates.Length,
                0,
                0);
        }

        var replayed = 0;
        var failed = 0;
        var telegramReplayEnabled = IsTelegramReplayEnabled(settings, sourceChatId);
        var telegramDestinationPeer = telegramReplayEnabled
            ? ResolvePeer(settings.TelegramForwarding.DestinationChatId)
            : null;
        if (telegramReplayEnabled && telegramDestinationPeer is null)
        {
            await RefreshDialogsAsync(cancellationToken);
            telegramDestinationPeer = ResolvePeer(settings.TelegramForwarding.DestinationChatId);
        }

        foreach (var msg in candidates)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                var text = BuildMessageTextForConversion(msg);
                var result = await _messageProcessor.ProcessAsync(
                    text,
                    "manual",
                    cancellationToken,
                    originChatId: sourceChatId,
                    destinationChatId: settings.TelegramForwarding.DestinationChatId);
                if (!TryGetStrictForwardText(text, result.Success, result.ConvertedLinks, result.ConvertedText, out var replayText))
                {
                    _logger.LogWarning(
                        "Replay bloqueado por conversao invalida. SourceChat={SourceChatId} MsgId={MessageId} ConvertedLinks={ConvertedLinks} Success={Success}",
                        sourceChatId,
                        msg.id,
                        result.ConvertedLinks,
                        result.Success);
                    failed++;
                    continue;
                }

                var enrichment = await _messageProcessor.EnrichTextWithProductDataAsync(replayText, text, cancellationToken);
                replayText = enrichment.EnrichedText;

                if (telegramReplayEnabled && telegramDestinationPeer is not null)
                {
                    try
                    {
                        if (IsTelegramDestinationAllowed(settings.TelegramForwarding.DestinationChatId))
                        {
                            var telegramText = BuildTelegramForwardText(settings, replayText);
                            await _client.SendMessageAsync(telegramDestinationPeer, telegramText);
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Falha ao reenviar oferta para Telegram destino. Source={SourceChatId} MsgId={MessageId}", sourceChatId, msg.id);
                    }
                }

                var (imageBytes, imageMime) = await TryExtractImageForWhatsAppAsync(msg);
                await SendToWhatsAppIfEnabled(settings, replayText, sourceChatId, imageBytes, imageMime, allowOfficialDestination);
                replayed++;
            }
            catch (Exception ex)
            {
                failed++;
                _logger.LogWarning(ex, "Falha ao reenviar mensagem do Telegram para WhatsApp. Chat={SourceChatId} MsgId={MessageId}", sourceChatId, msg.id);
            }
        }

        return new TelegramUserbotReplayResult(
            true,
            $"Replay concluido. reenviadas={replayed}, falhas={failed}.",
            sourceChatId,
            requested,
            candidates.Length,
            replayed,
            failed);
    }

    private bool IsTelegramReplayEnabled(AutomationSettings settings, long sourceChatId)
    {
        if (!settings.TelegramForwarding.Enabled)
        {
            return false;
        }

        if (settings.TelegramForwarding.DestinationChatId == 0)
        {
            return false;
        }

        var sourceIds = settings.TelegramForwarding.SourceChatIds;
        return sourceIds.Count > 0 && IsSourceMatch(sourceChatId, sourceIds);
    }

    private string BuildTelegramForwardText(AutomationSettings settings, string text)
    {
        var finalText = text;
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

        return finalText;
    }

    private static IEnumerable<Message> ExtractHistoryMessages(Messages_MessagesBase history)
    {
        return history switch
        {
            Messages_MessagesSlice ms => ms.messages.OfType<Message>(),
            Messages_ChannelMessages cm => cm.messages.OfType<Message>(),
            Messages_Messages mm => mm.messages.OfType<Message>(),
            _ => Enumerable.Empty<Message>()
        };
    }

    private async Task<(byte[]? bytes, string? mime)> TryExtractImageForWhatsAppAsync(Message msg)
    {
        if (msg.media is MessageMediaPhoto mmPhoto && mmPhoto.photo is Photo photo)
        {
            return await TryDownloadPhotoAsync(photo);
        }

        if (msg.media is MessageMediaDocument mmDoc && mmDoc.document is Document doc)
        {
            if (!string.IsNullOrWhiteSpace(doc.mime_type) &&
                doc.mime_type.StartsWith("image/", StringComparison.OrdinalIgnoreCase))
            {
                return await TryDownloadDocumentAsync(doc);
            }
        }

        if (msg.media is MessageMediaWebPage mmWeb &&
            mmWeb.webpage is WebPage webPage &&
            webPage.photo is Photo webPhoto)
        {
            return await TryDownloadPhotoAsync(webPhoto);
        }

        if (msg.grouped_id != 0)
        {
            var grouped = await TryDownloadGroupedMediaAsync(msg);
            if (grouped.bytes is not null && grouped.bytes.Length > 0)
            {
                return grouped;
            }
        }

        return await TryDownloadNearbyMediaAsync(msg);
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

        // Prevent infinite loops: ignore messages sent by the userbot itself
        if (msg.flags.HasFlag(Message.Flags.out_))
        {
            return;
        }

        var text = BuildMessageTextForConversion(msg);
        if (string.IsNullOrWhiteSpace(text))
        {
            return;
        }

        var settings = await _settingsStore.GetAsync(CancellationToken.None);
        if (IsInstagramBotResponse(text))
        {
            return;
        }

        // Prevent infinite loops between Userbot and Bot
        if (text.Contains("Link convertido", StringComparison.OrdinalIgnoreCase))
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
                if (peer is not null && _client is not null && IsTelegramDestinationAllowed(msg.peer_id.ID))
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
                    if (peer is not null && _client is not null && IsTelegramDestinationAllowed(msg.peer_id.ID))
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
                    if (peer is not null && _client is not null && IsTelegramDestinationAllowed(msg.peer_id.ID))
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
            if (peer is not null && _client is not null && IsTelegramDestinationAllowed(msg.peer_id.ID))
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
                    if (IsTelegramDestinationAllowed(originId))
                    {
                        await _client.SendMessageAsync(originPeer, responseText);
                    }
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

                    // Sprint 1: Auto-Responder Inteligente (Clean Chat)
                    // Remove a mensagem original do membro após postar a conversão bonita
                    if (IsTelegramGroupPeer(msg.peer_id))
                    {
                        try
                        {
                            await _client.DeleteMessages(originPeer, new[] { msg.id });
                        }
                        catch (Exception ex)
                        {
                            _logger.LogWarning(ex, "Falha ao apagar mensagem original do usuário via Telegram Responder. Peer={Peer} MsgId={MsgId}", originId, msg.id);
                        }
                    }
                }
                else if (!IsTelegramGroupPeer(msg.peer_id) && !string.IsNullOrWhiteSpace(responder.ReplyOnFailure))
                {
                    var trackedFail = await ApplyTrackingAsync(responder.ReplyOnFailure, responder.TrackingEnabled, CancellationToken.None);
                    if (IsTelegramDestinationAllowed(originId))
                    {
                        await _client.SendMessageAsync(originPeer, trackedFail.Text);
                    }
                }
            }
        }

        var tgForwarding = settings.TelegramForwarding ?? new TelegramForwardingSettings();
        var telegramToWhatsAppRoutes = ResolveTelegramToWhatsAppRoutes(settings);
        var hasEnabledTelegramToWhatsAppRoute = telegramToWhatsAppRoutes.Any(route => route.Enabled);
        if (!tgForwarding.Enabled && !hasEnabledTelegramToWhatsAppRoute)
        {
            return;
        }

        var tgSources = tgForwarding.SourceChatIds ?? new List<long>();
        var waSources = settings.TelegramToWhatsApp?.SourceChatIds ?? new List<long>();
        var legacyWaSources = settings.TelegramToWhatsAppRoutes?.SelectMany(r => r.SourceChatIds).ToList() ?? new List<long>();
        var allSources = tgSources.Union(waSources).Union(legacyWaSources).Distinct().ToList();

        if (allSources.Count == 0)
        {
            return;
        }

        if (!IsSourceMatch(originId, allSources))
        {
            return;
        }

        var result = await _messageProcessor.ProcessAsync(
            text,
            "TelegramUserbot",
            CancellationToken.None,
            originChatId: originId,
            destinationChatId: settings.TelegramForwarding.DestinationChatId);
        if (!TryGetStrictForwardText(text, result.Success, result.ConvertedLinks, result.ConvertedText, out var finalText))
        {
            _logger.LogWarning(
                "TelegramUserbot bloqueou encaminhamento automatico por conversao invalida ou nao afiliada. Origin={OriginChatId} MsgId={MessageId} ConvertedLinks={ConvertedLinks} Success={Success}",
                originId,
                msg.id,
                result.ConvertedLinks,
                result.Success);
            return;
        }

        var enrichment = await _messageProcessor.EnrichTextWithProductDataAsync(finalText, text, CancellationToken.None);
        finalText = enrichment.EnrichedText;

        var destinationId = tgForwarding.DestinationChatId;
        var destinationPeer = destinationId != 0 ? ResolvePeer(destinationId) : null;
        if (destinationPeer is null && destinationId != 0)
        {
            _logger.LogWarning("TelegramUserbot: destino {DestinationId} nao encontrado nos dialogs.", destinationId);
        }

        var shouldSendToTelegram = tgForwarding.Enabled
                                   && destinationPeer is not null
                                   && IsSourceMatch(originId, tgSources)
                                   && IsTelegramDestinationAllowed(destinationId);

        if (tgForwarding.AppendSheinCode &&
            ContainsShein(finalText) &&
            !string.IsNullOrWhiteSpace(_affiliateOptions.SheinCode) &&
            !finalText.Contains(_affiliateOptions.SheinCode, StringComparison.OrdinalIgnoreCase))
        {
            finalText += $"\n\nCodigo Shein: {_affiliateOptions.SheinCode}";
        }

        if (!string.IsNullOrWhiteSpace(tgForwarding.FooterText))
        {
            finalText += $"\n\n{tgForwarding.FooterText}";
        }

        byte[]? waImageBytes = null;
        string? waImageMime = null;
        var client = _client;
        if (client is null)
        {
            _logger.LogWarning("TelegramUserbot: cliente nÃ£o inicializado.");
            shouldSendToTelegram = false;
        }

        try
        {
            if (msg.media is MessageMediaPhoto mmPhoto && mmPhoto.photo is Photo photo)
            {
                if (shouldSendToTelegram)
                {
                    var inputMedia = new InputMediaPhoto { id = new InputPhoto { id = photo.id, access_hash = photo.access_hash, file_reference = photo.file_reference } };
                    await client!.Messages_SendMedia(destinationPeer, inputMedia, finalText, WTelegram.Helpers.RandomLong());
                }
                (waImageBytes, waImageMime) = await TryDownloadPhotoAsync(photo);
            }
            else if (msg.media is MessageMediaDocument mmDoc && mmDoc.document is Document doc)
            {
                if (shouldSendToTelegram)
                {
                    var inputMedia = new InputMediaDocument { id = new InputDocument { id = doc.id, access_hash = doc.access_hash, file_reference = doc.file_reference } };
                    await client!.Messages_SendMedia(destinationPeer, inputMedia, finalText, WTelegram.Helpers.RandomLong());
                }
                if (!string.IsNullOrWhiteSpace(doc.mime_type) && doc.mime_type.StartsWith("image/", StringComparison.OrdinalIgnoreCase))
                {
                    (waImageBytes, waImageMime) = await TryDownloadDocumentAsync(doc);
                }
            }
            else if (msg.media is MessageMediaWebPage mmWeb && mmWeb.webpage is WebPage webPage && webPage.photo is Photo webPhoto)
            {
                if (shouldSendToTelegram) await client!.SendMessageAsync(destinationPeer, finalText);
                (waImageBytes, waImageMime) = await TryDownloadPhotoAsync(webPhoto);
            }
            else
            {
                if (shouldSendToTelegram) await client!.SendMessageAsync(destinationPeer, finalText);
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
            _logger.LogWarning(ex, "Falha ao processar ou enviar mensagem para destinos configurados.");
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

        await SendToWhatsAppIfEnabled(settings, finalText, originId, waImageBytes, waImageMime);
    }

    private async Task SendToWhatsAppIfEnabled(AutomationSettings settings, string convertedText, long originId, byte[]? imageBytes, string? imageMime, bool allowOfficialDestination = true)
    {
        var wa = settings.WhatsAppForwarding ?? new WhatsAppForwardingSettings();
        var routes = ResolveTelegramToWhatsAppRoutes(settings);
        if (routes.Count == 0)
        {
            return;
        }

        var destinations = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var defaultSources = (settings.TelegramToWhatsApp?.SourceChatIds ?? new List<long>())
            .Union(settings.TelegramForwarding?.SourceChatIds ?? new List<long>())
            .Distinct()
            .ToList();
        foreach (var route in routes)
        {
            if (!route.Enabled) continue;
            var isTestRoute = !string.IsNullOrWhiteSpace(route.Name)
                && route.Name.Contains("teste", StringComparison.OrdinalIgnoreCase);
            var effectiveSources = route.SourceChatIds
                .Union(defaultSources)
                .Distinct()
                .ToList();
            if (effectiveSources.Count == 0) continue;
            if (!IsSourceMatch(originId, effectiveSources)) continue;

            foreach (var destination in route.DestinationGroupIds)
            {
                if (!string.IsNullOrWhiteSpace(destination))
                {
                    var normalizedDestination = destination.Trim();
                    if (isTestRoute && string.Equals(normalizedDestination, OfficialWhatsAppDemandGroupId, StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    destinations.Add(normalizedDestination);
                }
            }
        }

        if (destinations.Count == 0)
        {
            return;
        }

        if (!allowOfficialDestination)
        {
            destinations.RemoveWhere(x => string.Equals(x, OfficialWhatsAppDemandGroupId, StringComparison.OrdinalIgnoreCase));
            if (destinations.Count == 0)
            {
                _logger.LogWarning("Envio para WhatsApp ignorado: apenas grupo oficial protegido estava como destino.");
                return;
            }
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

        var destList = destinations.Where(d => !string.IsNullOrWhiteSpace(d)).ToArray();
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

    private static HashSet<string> ResolveReplayWhatsAppDestinations(AutomationSettings settings, long originId)
    {
        var destinations = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var routes = ResolveTelegramToWhatsAppRoutes(settings);
        var defaultSources = (settings.TelegramToWhatsApp?.SourceChatIds ?? new List<long>())
            .Union(settings.TelegramForwarding?.SourceChatIds ?? new List<long>())
            .Distinct()
            .ToList();

        foreach (var route in routes)
        {
            if (!route.Enabled)
            {
                continue;
            }

            var isTestRoute = !string.IsNullOrWhiteSpace(route.Name)
                && route.Name.Contains("teste", StringComparison.OrdinalIgnoreCase);

            var effectiveSources = route.SourceChatIds
                .Union(defaultSources)
                .Distinct()
                .ToList();

            if (effectiveSources.Count == 0 || !IsSourceMatch(originId, effectiveSources))
            {
                continue;
            }

            foreach (var destination in route.DestinationGroupIds)
            {
                if (!string.IsNullOrWhiteSpace(destination))
                {
                    var normalizedDestination = destination.Trim();
                    if (isTestRoute && string.Equals(normalizedDestination, OfficialWhatsAppDemandGroupId, StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    destinations.Add(normalizedDestination);
                }
            }
        }

        return destinations;
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

    private bool IsTelegramDestinationAllowed(long chatId)
    {
        if (_deliverySafetyPolicy.IsTelegramDestinationAllowed(chatId, out _))
        {
            return true;
        }

        _logger.LogWarning("Envio Telegram bloqueado por safety policy. ChatId={ChatId}", chatId);
        return false;
    }

    private static IReadOnlyList<TelegramToWhatsAppRouteSettings> ResolveTelegramToWhatsAppRoutes(AutomationSettings settings)
    {
        var explicitRoutes = (settings.TelegramToWhatsAppRoutes ?? new List<TelegramToWhatsAppRouteSettings>())
            .Where(route => route is not null)
            .Select(route => new TelegramToWhatsAppRouteSettings
            {
                Name = string.IsNullOrWhiteSpace(route.Name) ? "Rota Telegram -> WhatsApp" : route.Name.Trim(),
                Enabled = route.Enabled,
                SourceChatIds = route.SourceChatIds
                    .Distinct()
                    .ToList(),
                DestinationGroupIds = route.DestinationGroupIds
                    .Where(x => !string.IsNullOrWhiteSpace(x))
                    .Select(x => x.Trim())
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToList()
            })
            .ToList();
        if (explicitRoutes.Count > 0)
        {
            return explicitRoutes;
        }

        var legacy = settings.TelegramToWhatsApp ?? new TelegramToWhatsAppSettings();
        if (legacy.SourceChatIds.Count > 0 || legacy.DestinationGroupIds.Count > 0)
        {
            return new List<TelegramToWhatsAppRouteSettings>
            {
                new()
                {
                    Name = "Rota Telegram -> WhatsApp (legado)",
                    Enabled = legacy.Enabled,
                    SourceChatIds = legacy.SourceChatIds.Distinct().ToList(),
                    DestinationGroupIds = legacy.DestinationGroupIds
                        .Where(x => !string.IsNullOrWhiteSpace(x))
                        .Select(x => x.Trim())
                        .Distinct(StringComparer.OrdinalIgnoreCase)
                        .ToList()
                }
            };
        }

        var wa = settings.WhatsAppForwarding ?? new WhatsAppForwardingSettings();
        var tgSources = settings.TelegramForwarding?.SourceChatIds ?? new List<long>();
        if (!wa.Enabled || wa.DestinationGroupIds.Count == 0 || tgSources.Count == 0)
        {
            return Array.Empty<TelegramToWhatsAppRouteSettings>();
        }

        return new List<TelegramToWhatsAppRouteSettings>
        {
            new()
            {
                Name = "Rota Telegram -> WhatsApp (fallback)",
                Enabled = true,
                SourceChatIds = tgSources.Distinct().ToList(),
                DestinationGroupIds = wa.DestinationGroupIds
                    .Where(x => !string.IsNullOrWhiteSpace(x))
                    .Select(x => x.Trim())
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToList()
            }
        };
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

    private static string BuildMessageTextForConversion(Message msg)
    {
        var baseText = msg.message ?? string.Empty;
        var urls = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        if (msg.entities is not null)
        {
            foreach (var entity in msg.entities)
            {
                switch (entity)
                {
                    case MessageEntityTextUrl textUrl when !string.IsNullOrWhiteSpace(textUrl.url):
                        urls.Add(textUrl.url.Trim());
                        break;
                    case MessageEntityUrl urlEntity:
                        var extracted = TryExtractUrlFromEntity(baseText, urlEntity.offset, urlEntity.length);
                        if (!string.IsNullOrWhiteSpace(extracted))
                        {
                            urls.Add(extracted);
                        }
                        break;
                }
            }
        }

        if (msg.media is MessageMediaWebPage mmWeb &&
            mmWeb.webpage is WebPage webPage &&
            !string.IsNullOrWhiteSpace(webPage.url))
        {
            urls.Add(webPage.url.Trim());
        }

        if (urls.Count == 0)
        {
            return baseText;
        }

        var sb = new StringBuilder(baseText);
        foreach (var url in urls)
        {
            if (baseText.Contains(url, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (sb.Length > 0)
            {
                sb.AppendLine();
            }
            sb.Append(url);
        }

        return sb.ToString();
    }

    private static string? TryExtractUrlFromEntity(string text, int offset, int length)
    {
        if (string.IsNullOrWhiteSpace(text) || offset < 0 || length <= 0 || offset >= text.Length)
        {
            return null;
        }

        var max = Math.Min(length, text.Length - offset);
        if (max <= 0)
        {
            return null;
        }

        var candidate = text.Substring(offset, max).Trim();
        if (candidate.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
            candidate.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            return candidate;
        }

        return null;
    }

    private static bool TryGetStrictForwardText(string originalText, bool conversionSuccess, int convertedLinks, string? convertedText, out string strictText)
    {
        strictText = string.Empty;
        if (!conversionSuccess || convertedLinks <= 0 || string.IsNullOrWhiteSpace(convertedText))
        {
            return false;
        }

        var originalUrls = ExtractNormalizedUrls(originalText);
        if (originalUrls.Count == 0)
        {
            return false;
        }

        var convertedUrls = ExtractNormalizedUrls(convertedText);
        if (convertedUrls.Count == 0)
        {
            return false;
        }

        foreach (var originalUrl in originalUrls)
        {
            if (convertedUrls.Contains(originalUrl))
            {
                return false;
            }
        }

        strictText = convertedText;
        return true;
    }

    private static HashSet<string> ExtractNormalizedUrls(string text)
    {
        var urls = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrWhiteSpace(text))
        {
            return urls;
        }

        foreach (Match match in UrlRegex.Matches(text))
        {
            var normalized = NormalizeUrlForComparison(match.Value);
            if (!string.IsNullOrWhiteSpace(normalized))
            {
                urls.Add(normalized);
            }
        }

        return urls;
    }

    private static string NormalizeUrlForComparison(string rawUrl)
    {
        return rawUrl
            .Trim()
            .TrimEnd('"', '\'', '`', '.', ',', ';', ':', ')', ']', '}', '!', '?');
    }

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
               || text.Contains("Hashtags", StringComparison.OrdinalIgnoreCase)
               || text.StartsWith("Qual produto?", StringComparison.OrdinalIgnoreCase)
               || text.Contains("Envie o nome ou o link", StringComparison.OrdinalIgnoreCase)
               || text.Contains("Link convertido", StringComparison.OrdinalIgnoreCase)
               || text.Contains("Executando criacao", StringComparison.OrdinalIgnoreCase)
               || text.Contains("Autopilot story", StringComparison.OrdinalIgnoreCase)
               || text.Contains("Aprovacao", StringComparison.OrdinalIgnoreCase);
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
