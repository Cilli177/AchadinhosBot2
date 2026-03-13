using AchadinhosBot.Next.Domain.Agents;

namespace AchadinhosBot.Next.Application.Abstractions;

public interface IChannelMonitorSelectionStore
{
    Task<IReadOnlyList<ChannelMonitorSelectionEntry>> ListBySourceAsync(string sourceChannel, CancellationToken cancellationToken);
    Task<IReadOnlyList<ChannelMonitorSelectionEntry>> ReplaceSelectionsAsync(
        string sourceChannel,
        IEnumerable<ChannelMonitorSelectionEntry> selections,
        CancellationToken cancellationToken);
}
