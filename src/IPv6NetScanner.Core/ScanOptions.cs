namespace IPv6NetScanner.Core;

public sealed class ScanOptions
{
    /// <summary>How many echo requests are sent per target.</summary>
    public int Rounds { get; init; } = 3;

    /// <summary>Pause between two rounds.</summary>
    public TimeSpan Interval { get; init; } = TimeSpan.FromSeconds(1);

    /// <summary>How long to keep listening after the last request.</summary>
    public TimeSpan Linger { get; init; } = TimeSpan.FromSeconds(2);

    public IReadOnlyList<ScanTarget> Targets { get; init; } = ScanTarget.Default;
}
