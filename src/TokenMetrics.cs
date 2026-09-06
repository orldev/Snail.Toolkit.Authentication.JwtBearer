using System.Diagnostics.Metrics;

namespace Snail.Toolkit.Authentication.JwtBearer;

/// <summary>
/// Counts the tokens this application signs and the ones it turns away.
/// </summary>
/// <remarks>
/// Error details are off by default, so a refused caller is told nothing and neither was the
/// operator: a wave of 401s looked the same whether tokens were merely expiring or arriving with
/// broken signatures. The meter is taken from <see cref="IMeterFactory"/> when the host provides
/// one and created directly otherwise, so the package adds no dependency to an application that
/// collects no metrics.
/// </remarks>
public sealed class TokenMetrics : IDisposable
{
    /// <summary>
    /// The meter every instrument of this package is published under.
    /// </summary>
    public const string MeterName = "Snail.Toolkit.Authentication.JwtBearer";

    private readonly Meter _meter;
    private readonly Counter<long> _issued;
    private readonly Counter<long> _refused;

    /// <summary>
    /// Publishes the instruments, through the host's factory when there is one.
    /// </summary>
    public TokenMetrics(IMeterFactory? factory = null)
    {
        _meter = factory?.Create(MeterName) ?? new Meter(MeterName);

        _issued = _meter.CreateCounter<long>(
            "auth.tokens.issued", "{token}", "Access tokens signed by this application.");

        _refused = _meter.CreateCounter<long>(
            "auth.tokens.refused", "{token}", "Tokens this application turned away, by reason.");
    }

    /// <summary>
    /// Records a token this application has just signed.
    /// </summary>
    public void Issued(string scheme) =>
        _issued.Add(1, new KeyValuePair<string, object?>("auth.scheme", scheme));

    /// <summary>
    /// Records a token this application has turned away, and why.
    /// </summary>
    public void Refused(string scheme, TokenRefusal refusal) =>
        _refused.Add(
            1,
            new KeyValuePair<string, object?>("auth.scheme", scheme),
            new KeyValuePair<string, object?>("auth.refusal", refusal.ToString()));

    /// <inheritdoc />
    public void Dispose() => _meter.Dispose();
}
