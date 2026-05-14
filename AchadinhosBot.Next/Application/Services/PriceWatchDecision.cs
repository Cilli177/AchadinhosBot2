namespace AchadinhosBot.Next.Application.Services;

public sealed record PriceWatchDecisionResult(bool ShouldSend, string Reason);

public static class PriceWatchDecision
{
    public static PriceWatchDecisionResult Decide(
        decimal? currentPrice,
        decimal? lastSentPrice,
        decimal? desiredPrice,
        decimal nearTargetPercent,
        DateTimeOffset? lastSentAt,
        DateTimeOffset now)
    {
        if (currentPrice is null || currentPrice <= 0)
        {
            return new(false, "preco_atual_indisponivel");
        }

        if (lastSentAt is not null && now - lastSentAt.Value < TimeSpan.FromHours(1))
        {
            return new(false, "envio_recente");
        }

        if (lastSentPrice is not null && currentPrice.Value < lastSentPrice.Value)
        {
            return new(true, "queda_real");
        }

        if (desiredPrice is not null && desiredPrice.Value > 0)
        {
            if (currentPrice.Value <= desiredPrice.Value)
            {
                return new(true, "preco_alvo");
            }

            var nearLimit = desiredPrice.Value * (1 + Math.Clamp(nearTargetPercent, 1m, 25m) / 100m);
            if (currentPrice.Value <= nearLimit)
            {
                return new(true, "perto_do_alvo");
            }
        }

        if (lastSentPrice is null)
        {
            return new(false, "baseline_registrado");
        }

        return new(false, "sem_melhoria");
    }
}
