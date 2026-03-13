using AchadinhosBot.Next.Domain.Agents;

namespace AchadinhosBot.Next.Application.Abstractions;

public interface IChannelMonitorUiStateStore
{
    Task<ChannelMonitorUiState> GetAsync(CancellationToken cancellationToken);
    Task<ChannelMonitorUiState> SaveAsync(ChannelMonitorUiState state, CancellationToken cancellationToken);
}
