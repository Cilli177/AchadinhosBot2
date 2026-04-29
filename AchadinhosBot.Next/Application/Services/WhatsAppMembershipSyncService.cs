using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Domain.Models;
using AchadinhosBot.Next.Domain.Settings;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace AchadinhosBot.Next.Application.Services;

public sealed class WhatsAppMembershipSyncService : BackgroundService
{
    private readonly IWhatsAppGateway _gateway;
    private readonly IWhatsAppGroupMembershipStore _store;
    private readonly ISettingsStore _settingsStore;
    private readonly ILogger<WhatsAppMembershipSyncService> _logger;
    private readonly TimeSpan _syncInterval = TimeSpan.FromMinutes(1);

    public WhatsAppMembershipSyncService(
        IWhatsAppGateway gateway,
        IWhatsAppGroupMembershipStore store,
        ISettingsStore settingsStore,
        ILogger<WhatsAppMembershipSyncService> logger)
    {
        _gateway = gateway;
        _store = store;
        _settingsStore = settingsStore;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("WhatsAppMembershipSyncService iniciado. Intervalo: {Interval}", _syncInterval);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await SynchronizeAllGroupsAsync(stoppingToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erro no loop principal de sincronização de membros do WhatsApp");
            }

            await Task.Delay(_syncInterval, stoppingToken);
        }
    }

    public Task SynchronizeAllGroupsNowAsync(CancellationToken ct)
        => SynchronizeAllGroupsAsync(ct);

    private async Task SynchronizeAllGroupsAsync(CancellationToken ct)
    {
        _logger.LogInformation("Iniciando sincronização de membros de grupos de WhatsApp...");

        var settings = await _settingsStore.GetAsync(ct);
        var monitoredByInstance = BuildMonitoredGroupsByInstance(settings);
        if (monitoredByInstance.Count == 0)
        {
            _logger.LogInformation("Nenhum grupo monitorado selecionado. Sync de membros ignorado.");
            return;
        }

        foreach (var kvp in monitoredByInstance)
        {
            var instanceName = string.Equals(kvp.Key, DefaultInstanceKey, StringComparison.Ordinal)
                ? null
                : kvp.Key;
            var monitoredGroupIds = kvp.Value;
            var groups = await _gateway.GetGroupsAsync(instanceName, ct);
            if (groups.Count == 0)
            {
                _logger.LogWarning("Nenhum grupo encontrado para sincronização. Instância={InstanceName}", instanceName ?? "default");
                continue;
            }

            foreach (var group in groups.Where(g => monitoredGroupIds.Contains(g.Id)))
            {
                if (ct.IsCancellationRequested) break;

                try
                {
                    await SynchronizeGroupAsync(group.Id, group.Name, instanceName, ct);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Falha ao sincronizar grupo {GroupName} ({GroupId}) da instância {InstanceName}", group.Name, group.Id, instanceName ?? "default");
                }
            }
        }

        _logger.LogInformation("Sincronização de membros finalizada.");
    }

    private async Task SynchronizeGroupAsync(string groupId, string groupName, string? instanceName, CancellationToken ct)
    {
        var currentParticipants = await _gateway.GetGroupParticipantsAsync(instanceName, groupId, ct);
        if (currentParticipants.Count == 0) return;

        var lastKnownParticipants = await _store.GetParticipantsAsync(groupId, instanceName, ct);
        
        // Se não temos estado anterior, apenas salvamos o atual e saímos
        if (lastKnownParticipants.Count == 0)
        {
            _logger.LogInformation("Primeira sincronização do grupo {GroupName}. Instância={InstanceName}. Salvando {Count} membros.", groupName, instanceName ?? "default", currentParticipants.Count);
            await _store.SetParticipantsAsync(groupId, instanceName, currentParticipants, ct);
            return;
        }

        var currentSet = new HashSet<string>(currentParticipants);
        var lastSet = new HashSet<string>(lastKnownParticipants);

        // Quem saiu? (Estava no lastSet mas não está no currentSet)
        var exits = lastKnownParticipants.Where(p => !currentSet.Contains(p)).ToList();
        
        // Quem entrou? (Está no currentSet mas não estava no lastSet)
        var joins = currentParticipants.Where(p => !lastSet.Contains(p)).ToList();

        if (exits.Count == 0 && joins.Count == 0)
        {
            // Nada mudou no saldo final, mas talvez a lista atual esteja mais limpa
            await _store.SetParticipantsAsync(groupId, instanceName, currentParticipants, ct);
            return;
        }

        _logger.LogInformation("Grupo {GroupName}: {Exits} saídas detectadas, {Joins} entradas detectadas via sync. Instância={InstanceName}", groupName, exits.Count, joins.Count, instanceName ?? "default");

        foreach (var participant in exits)
        {
            await _store.AppendAsync(new WhatsAppGroupMembershipEvent
            {
                InstanceName = instanceName,
                GroupId = groupId,
                GroupName = groupName,
                ParticipantId = participant,
                Action = "remove",
                Timestamp = DateTimeOffset.UtcNow,
                IsSyncDetection = true
            }, ct);
        }

        foreach (var participant in joins)
        {
            await _store.AppendAsync(new WhatsAppGroupMembershipEvent
            {
                InstanceName = instanceName,
                GroupId = groupId,
                GroupName = groupName,
                ParticipantId = participant,
                Action = "add",
                Timestamp = DateTimeOffset.UtcNow,
                IsSyncDetection = true
            }, ct);
        }

        // Atualiza o estado atual
        await _store.SetParticipantsAsync(groupId, instanceName, currentParticipants, ct);
    }

    private static Dictionary<string, HashSet<string>> BuildMonitoredGroupsByInstance(AutomationSettings settings)
    {
        var map = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);

        foreach (var groupId in settings.MonitoredGroupIds ?? [])
        {
            if (string.IsNullOrWhiteSpace(groupId))
                continue;

            if (!map.TryGetValue(DefaultInstanceKey, out var defaultSet))
            {
                defaultSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                map[DefaultInstanceKey] = defaultSet;
            }

            defaultSet.Add(groupId.Trim());
        }

        foreach (var monitored in settings.MonitoredWhatsAppGroups ?? [])
        {
            if (string.IsNullOrWhiteSpace(monitored.GroupId))
                continue;

            var key = string.IsNullOrWhiteSpace(monitored.InstanceName) ? DefaultInstanceKey : monitored.InstanceName.Trim();
            if (!map.TryGetValue(key, out var set))
            {
                set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                map[key] = set;
            }

            set.Add(monitored.GroupId.Trim());
        }

        return map;
    }

    private const string DefaultInstanceKey = "__default__";
}
