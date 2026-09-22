namespace RegulatedAi.Core.Data;

/// <summary>
/// Injected time. Expiry drives a risk band, and approval records are timestamped, so time is
/// business logic here and must be controllable from a test.
/// </summary>
public interface IClock
{
    DateTimeOffset UtcNow { get; }
}

public sealed class SystemClock : IClock
{
    public DateTimeOffset UtcNow => DateTimeOffset.UtcNow;
}
