namespace AchadinhosBot.Next.Infrastructure.Security;

public sealed class LoginAttemptStore
{
    private readonly Dictionary<string, AttemptState> _states = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _sync = new();

    public bool IsLocked(string key, DateTimeOffset now)
    {
        lock (_sync)
        {
            if (!_states.TryGetValue(key, out var state)) return false;
            if (state.LockedUntil is null) return false;
            if (state.LockedUntil <= now)
            {
                _states.Remove(key);
                return false;
            }

            return true;
        }
    }

    public void RegisterFailure(string key, DateTimeOffset now, int maxAttempts, TimeSpan lockDuration)
    {
        lock (_sync)
        {
            if (!_states.TryGetValue(key, out var state))
            {
                state = new AttemptState();
                _states[key] = state;
            }

            state.Failures++;
            if (state.Failures >= maxAttempts)
            {
                state.LockedUntil = now.Add(lockDuration);
            }
        }
    }

    public void RegisterSuccess(string key)
    {
        lock (_sync)
        {
            _states.Remove(key);
        }
    }

    private sealed class AttemptState
    {
        public int Failures { get; set; }
        public DateTimeOffset? LockedUntil { get; set; }
    }
}
