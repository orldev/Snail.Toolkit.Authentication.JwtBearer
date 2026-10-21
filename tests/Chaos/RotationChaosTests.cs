using Microsoft.Extensions.Options;

namespace Snail.Toolkit.Authentication.JwtBearer.Tests.Chaos;

/// <summary>
/// The settings change while the process runs. Issuing reads them live; judging reads a snapshot taken when the
/// bearer options were built, plus the live secret. These tests look for the places where the two disagree.
/// </summary>
public class RotationChaosTests
{
    /// <summary>
    /// Breaks: the issuer (or audience) is changed in a reloadable configuration. The provider mints the next token
    /// with the new issuer, because <c>Create</c> reads the settings afresh, while the validation rules still hold
    /// the issuer captured when the bearer options were built. The same process then refuses every token it mints.
    /// </summary>
    [Fact]
    public async Task Create_IssuerChangedInConfiguration_IsStillAcceptedByTheSameProcess()
    {
        var configuration = (IConfigurationRoot)Settings.Complete();
        var tokens = Provider(configuration);
        var before = await tokens.ValidateAsync(tokens.Create());

        configuration[$"{AuthOptions.SectionName}:{nameof(AuthOptions.Issuer)}"] = "issuer.renamed";
        configuration.Reload();

        var after = await tokens.ValidateAsync(tokens.Create());

        Assert.True(before.IsValid);
        Assert.True(after.IsValid, $"refused as {after.Refusal}: {after.Fault}");
    }

    /// <summary>
    /// Breaks: the secret is rotated fifty times while thirty-two threads keep judging tokens of both secrets.
    /// The key pair is swapped as one, so a verdict is Valid or Signature and never a crash or Other.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_SecretRotatingUnderLoad_AnswersValidOrSignatureOnly()
    {
        const string other = "Q3mZ8vYp2LkR7tWn5XcB1HdJ6FgS9AeU4oIy0PqVr8TuMw3NzKb2CxLj5GhD7fEs";
        var configuration = (IConfigurationRoot)Settings.Complete();
        var tokens = Provider(configuration);
        var first = tokens.Create();
        Rotate(configuration, other);
        var second = tokens.Create();
        Rotate(configuration, Settings.Secret);
        using var stop = new CancellationTokenSource();

        var judges = Enumerable.Range(0, 32).Select(index => Task.Run(async () =>
        {
            List<TokenRefusal> seen = [];

            while (!stop.IsCancellationRequested)
            {
                var verdict = await tokens.ValidateAsync(index % 2 == 0 ? first : second);
                seen.Add(verdict.Refusal);
            }

            return seen;
        })).ToArray();

        for (var round = 0; round < 50; round++)
            Rotate(configuration, round % 2 == 0 ? other : Settings.Secret);

        await stop.CancelAsync();
        var verdicts = await Task.WhenAll(judges);

        Assert.All(verdicts.SelectMany(seen => seen), refusal => Assert.True(refusal is TokenRefusal.None or TokenRefusal.Signature, refusal.ToString()));
    }

    /// <summary>
    /// Pins: the secret is rotated to one HMAC-SHA512 cannot use. The options validator refuses it on reload, the
    /// cached settings are gone, and from then on issuing fails naming the key while judging refuses everything —
    /// the process fails closed rather than keeping the last good secret. The reload itself surfaces the fault to
    /// whoever triggered it; a file watcher swallows it.
    /// </summary>
    [Fact]
    public async Task Create_SecretRotatedToAShortOne_FailsClosedNamingTheKey()
    {
        var configuration = (IConfigurationRoot)Settings.Complete();
        var tokens = Provider(configuration);
        var good = tokens.Create();
        var warm = await tokens.ValidateAsync(good);

        var reload = Record.Exception(() => Rotate(configuration, new string('k', 32)));
        var mint = Record.Exception(() => tokens.Create());
        var verdict = await tokens.ValidateAsync(good);

        Assert.True(warm.IsValid);
        Assert.NotNull(reload);
        var fault = Assert.IsType<OptionsValidationException>(mint);
        Assert.Contains($"{AuthOptions.SectionName}:{nameof(AuthOptions.SecretKey)}", fault.Message, StringComparison.Ordinal);
        Assert.Equal(TokenRefusal.Other, verdict.Refusal);
    }

    private static void Rotate(IConfigurationRoot configuration, string secret)
    {
        configuration[$"{AuthOptions.SectionName}:{nameof(AuthOptions.SecretKey)}"] = secret;
        configuration.Reload();
    }

    private static ITokenProvider Provider(IConfiguration configuration) =>
        new ServiceCollection()
            .AddAuthJwtBearer(configuration)
            .BuildServiceProvider()
            .GetRequiredService<ITokenProvider>();
}
