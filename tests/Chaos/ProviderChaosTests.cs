using System.Collections.Concurrent;
using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Globalization;
using System.Security.Claims;
using System.Text;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Snail.Toolkit.Authentication.JwtBearer.Tests.Chaos;

/// <summary>
/// The provider on the paths the happy tests never walk: settings that were never bound, values at the edge of
/// their type, a mint that fails halfway, a cancelled caller, a token the size of a file.
/// </summary>
[Collection(GlobalCryptoCollection.Name)]
public class ProviderChaosTests
{
    /// <summary>
    /// Breaks: <c>AddTokenProvider()</c> registers no validator, so an application that forgot to configure the
    /// settings learns it from an <c>ArgumentNullException</c> thrown by <c>Encoding.GetBytes</c> deep inside the
    /// provider's constructor, instead of from a message naming <c>Issuer</c> and <c>SecretKey</c>.
    /// </summary>
    [Fact]
    public void AddTokenProvider_SettingsNeverConfigured_SaysWhatIsMissing()
    {
        var services = new ServiceCollection().AddTokenProvider().BuildServiceProvider();

        var fault = Assert.Throws<OptionsValidationException>(() => services.GetRequiredService<ITokenProvider>().Create());

        Assert.Contains(nameof(AuthOptions.SecretKey), fault.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// Breaks: with <c>AddTokenProvider()</c> a 32-character secret is accepted at registration and at resolution;
    /// the first <c>Create</c> dies inside IdentityModel with IDX10720 — the failure the package exists to move to
    /// startup.
    /// </summary>
    [Fact]
    public void AddTokenProvider_SecretTooShort_IsRefusedBeforeTheFirstToken()
    {
        var services = new ServiceCollection()
            .AddTokenProvider()
            .Configure<AuthOptions>(settings =>
            {
                settings.Issuer = Settings.Issuer;
                settings.Audience = Settings.Audience;
                settings.SecretKey = new string('k', 32);
            })
            .BuildServiceProvider();

        Assert.Throws<OptionsValidationException>(() => services.GetRequiredService<ITokenProvider>().Create());
    }

    /// <summary>
    /// Breaks: <c>auth.tokens.issued</c> is incremented before the handler signs, so a mint that fails — here the
    /// crypto behind the key is away — is counted as a token handed out. An operator reading the counter against
    /// the login log sees tokens that never existed.
    /// </summary>
    [Fact]
    public void Create_SigningFails_CountsNoIssuedToken()
    {
        const string secret = "Zk7Pq2Lm9Rt4Wx1Vb8Nc3Hd6Jf0Gs5Ae2Uy7Io4Pq1Rt8Mw3Nz6Kb9Cx2Lj5GhDf";
        const string scheme = "chaos-signer-away";
        ConcurrentQueue<(string Instrument, string? Scheme)> recorded = [];
        using var listener = Listening(recorded);
        var values = Settings.Values(scheme);
        values[$"{scheme}:{nameof(AuthOptions.SecretKey)}"] = secret;
        var tokens = new ServiceCollection()
            .AddKeyedAuthJwtBearer(Settings.Of(values), scheme)
            .BuildServiceProvider()
            .GetRequiredKeyedService<ITokenProvider>(scheme);

        CryptoProviderFactory.Default.CustomCryptoProvider = new AbsentCrypto(secret);

        try
        {
            Assert.Throws<IOException>(() => tokens.Create());
        }
        finally
        {
            CryptoProviderFactory.Default.CustomCryptoProvider = null;
        }

        Assert.DoesNotContain(("auth.tokens.issued", scheme), recorded);
    }

    /// <summary>
    /// The crypto behind one secret, gone: what a hardware module or a remote signer looks like when it is down.
    /// </summary>
    private sealed class AbsentCrypto(string secret) : ICryptoProvider
    {
        public bool IsSupportedAlgorithm(string algorithm, params object[] args) =>
            args is [SymmetricSecurityKey key, ..] && key.Key.AsSpan().SequenceEqual(Encoding.UTF8.GetBytes(secret));

        public object Create(string algorithm, params object[] args) => throw new IOException("The signer is away.");

        public void Release(object cryptoInstance)
        {
        }
    }

    /// <summary>
    /// Breaks: a lifetime of <c>int.MaxValue</c> minutes passes the validator, which only asks for a positive number,
    /// and the provider mints a token good until the year 6109. A value no one can mean is accepted in silence where
    /// every other misconfiguration is refused at startup.
    /// </summary>
    [Fact]
    public void Create_LifetimeAtIntMax_IsRefusedByTheValidator()
    {
        var values = Settings.Values();
        values[$"{AuthOptions.SectionName}:{nameof(AuthOptions.TokenLifetime)}"] = int.MaxValue.ToString(CultureInfo.InvariantCulture);
        var services = new ServiceCollection().AddAuthJwtBearer(Settings.Of(values)).BuildServiceProvider();

        Assert.Throws<OptionsValidationException>(() => services.GetRequiredService<ITokenProvider>().Create());
    }

    /// <summary>
    /// Pins: a token of one megabyte is refused as malformed by the size limit before anything is parsed, and in
    /// well under a request's budget.
    /// </summary>
    /// <remarks>
    /// A short malformed token goes first, so the limit measures the refusal and not the first compilation of the
    /// validation path: cold, under a parallel suite on a loaded machine, the first call took 303 ms.
    /// </remarks>
    [Fact]
    public async Task ValidateAsync_OneMegabyteToken_IsMalformedQuickly()
    {
        var tokens = Provider();
        var huge = new string('a', 1_048_576);
        await tokens.ValidateAsync("warm-up");
        var watch = Stopwatch.StartNew();

        var verdict = await tokens.ValidateAsync(huge);

        Assert.Equal(TokenRefusal.Malformed, verdict.Refusal);
        Assert.True(watch.ElapsedMilliseconds < 200, $"{watch.ElapsedMilliseconds} ms");
    }

    /// <summary>
    /// Pins: a caller that already gave up gets the cancellation back and no refusal is counted against the scheme.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_CancelledBeforeTheCall_ThrowsAndCountsNothing()
    {
        const string scheme = "chaos-cancelled";
        ConcurrentQueue<(string Instrument, string? Scheme)> recorded = [];
        using var listener = Listening(recorded);
        var tokens = new ServiceCollection()
            .AddKeyedAuthJwtBearer(Settings.Of(Settings.Values(scheme)), scheme)
            .BuildServiceProvider()
            .GetRequiredKeyedService<ITokenProvider>(scheme);
        var token = tokens.Create();
        using var cancelled = new CancellationTokenSource();
        await cancelled.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => tokens.ValidateAsync(token, cancelled.Token));

        Assert.DoesNotContain(("auth.tokens.refused", scheme), recorded);
    }

    /// <summary>
    /// Pins: the spare descriptor and the lending identity are per thread, not per provider, so two issuers minting
    /// from the same pool of threads must still each sign their own issuer into every token.
    /// </summary>
    [Fact]
    public async Task Create_TwoIssuersFromManyThreads_NeverSwapIssuers()
    {
        const string partners = "Partners";
        var values = Settings.Values();
        foreach (var (key, value) in Settings.Values(partners))
            values[key] = value;
        values[$"{partners}:{nameof(AuthOptions.Issuer)}"] = "issuer.partners";
        var container = new ServiceCollection()
            .AddAuthJwtBearer(Settings.Of(values))
            .AddKeyedAuthJwtBearer(Settings.Of(values), partners)
            .BuildServiceProvider();
        var standard = container.GetRequiredService<ITokenProvider>();
        var partner = container.GetRequiredKeyedService<ITokenProvider>(partners);

        var minted = await Task.WhenAll(Enumerable.Range(0, 2_000).Select(index => Task.Run(() =>
            index % 2 == 0
                ? (Issuer: Settings.Issuer, Token: standard.Create([new Claim("sub", "a")]))
                : (Issuer: "issuer.partners", Token: partner.Create([new Claim("sub", "b")])))));

        Assert.All(minted, pair => Assert.Equal(pair.Issuer, new JsonWebToken(pair.Token).Issuer));
    }

    /// <summary>
    /// Pins: a claims sequence that mints another token while it is being read — the remark on the spare descriptor
    /// promises the inner token one of its own — leaves both tokens with their own claims.
    /// </summary>
    [Fact]
    public void Create_ClaimsThatMintAnotherTokenWhileRead_KeepBothTokensApart()
    {
        var tokens = Provider();
        string inner = string.Empty;

        var outer = tokens.Create(Reentrant());

        Assert.Equal("outer", new JsonWebToken(outer).Subject);
        Assert.Equal("inner", new JsonWebToken(inner).Subject);

        IEnumerable<Claim> Reentrant()
        {
            inner = tokens.Create([new Claim("sub", "inner")]);
            yield return new Claim("sub", "outer");
        }
    }

    private static ITokenProvider Provider() =>
        new ServiceCollection()
            .AddAuthJwtBearer(Settings.Complete())
            .BuildServiceProvider()
            .GetRequiredService<ITokenProvider>();

    private static MeterListener Listening(ConcurrentQueue<(string Instrument, string? Scheme)> recorded)
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
            string? scheme = null;

            foreach (var tag in tags)
            {
                if (tag.Key is "auth.scheme")
                    scheme = tag.Value?.ToString();
            }

            recorded.Enqueue((instrument.Name, scheme));
        });
        listener.Start();

        return listener;
    }
}
