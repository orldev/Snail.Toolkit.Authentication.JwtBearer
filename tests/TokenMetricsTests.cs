using System.Diagnostics.Metrics;

namespace Snail.Toolkit.Authentication.JwtBearer.Tests;

public class TokenMetricsTests
{
    [Fact]
    public async Task Provider_IssuingAndRefusing_IsCounted()
    {
        List<(string Instrument, string? Refusal)> recorded = [];

        using var listener = Listening(recorded);

        var tokens = new ServiceCollection()
            .AddAuthJwtBearer(Settings.Complete())
            .BuildServiceProvider()
            .GetRequiredService<ITokenProvider>();

        tokens.Create();
        await tokens.ValidateAsync("not-a-token");

        Assert.Contains(("auth.tokens.issued", null), recorded);
        Assert.Contains(("auth.tokens.refused", nameof(TokenRefusal.Malformed)), recorded);
    }

    private static MeterListener Listening(List<(string, string?)> recorded)
    {
        var listener = new MeterListener
        {
            InstrumentPublished = (instrument, active) =>
            {
                if (instrument.Meter.Name is TokenMetrics.MeterName)
                    active.EnableMeasurementEvents(instrument);
            }
        };

        listener.SetMeasurementEventCallback<long>((instrument, _, tags, _) =>
        {
            string? refusal = null;

            foreach (var tag in tags)
            {
                if (tag.Key is "auth.refusal")
                    refusal = tag.Value?.ToString();
            }

            recorded.Add((instrument.Name, refusal));
        });

        listener.Start();

        return listener;
    }
}
