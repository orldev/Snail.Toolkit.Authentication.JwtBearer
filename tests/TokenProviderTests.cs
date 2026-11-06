using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Snail.Toolkit.Authentication.JwtBearer.Tests;

[Collection(GlobalCryptoCollection.Name)]
public class TokenProviderTests
{
    [Fact]
    public async Task Create_ThenValidate_Passes()
    {
        var tokens = Provider();

        var verdict = await tokens.ValidateAsync(tokens.Create(Claims()));

        Assert.True(verdict.IsValid);
        Assert.Null(verdict.Fault);
    }

    /// <summary>
    /// The old suite cut the token with <c>Remove(0)</c>, which empties the string instead of
    /// tampering with it, so a broken signature had never been tried.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_TamperedSignature_ReportsTheFault()
    {
        var tokens = Provider();
        var token = tokens.Create(Claims());
        var tampered = $"{token[..^1]}{(token[^1] is 'a' ? 'b' : 'a')}";

        var verdict = await tokens.ValidateAsync(tampered);

        Assert.Equal(TokenRefusal.Signature, verdict.Refusal);
        Assert.NotNull(verdict.Fault);
    }

    [Fact]
    public async Task ValidateAsync_ExpiredToken_ReportsTheFault()
    {
        var expired = Provider(DateTimeOffset.UtcNow.AddHours(-2)).Create(Claims());

        var verdict = await Provider().ValidateAsync(expired);

        Assert.Equal(TokenRefusal.Expired, verdict.Refusal);
        Assert.NotNull(verdict.Fault);
    }

    [Fact]
    public async Task ValidateAsync_Garbage_ReportsTheFault()
    {
        var verdict = await Provider().ValidateAsync("not-a-token");

        Assert.Equal(TokenRefusal.Malformed, verdict.Refusal);
        Assert.NotNull(verdict.Fault);
    }

    /// <summary>
    /// HmacSha512Signature used to put the XML-dsig URI in the header, which no validator outside
    /// Microsoft's mapping accepts.
    /// </summary>
    [Fact]
    public void Create_Always_NamesTheAlgorithmAsRfc7518Does()
    {
        var token = Provider().Create();
        var header = Encoding.UTF8.GetString(Base64UrlEncoder.DecodeBytes(token.Split('.')[0]));

        Assert.Contains($"\"alg\":\"{SecurityAlgorithms.HmacSha512}\"", header, StringComparison.Ordinal);
    }

    [Fact]
    public void Create_WithClaims_CarriesThemUnchanged()
    {
        var token = new JsonWebToken(Provider().Create(Claims()));

        Assert.Equal("User1", token.GetClaim(JwtRegisteredClaimNames.Name).Value);
        Assert.Equal(Settings.Issuer, token.Issuer);
    }

    /// <summary>
    /// Each thread reuses one token descriptor between tokens, so a token minted on one thread must never
    /// carry the claims another thread was minting at the same moment.
    /// </summary>
    [Fact]
    public async Task Create_FromManyThreads_EachTokenCarriesItsOwnClaims()
    {
        var tokens = Provider();

        var minted = await Task.WhenAll(Enumerable.Range(0, 2_000).Select(index => Task.Run(() =>
            (Subject: $"user-{index}", Token: tokens.Create([new Claim(JwtRegisteredClaimNames.Sub, $"user-{index}")])))));

        Assert.All(minted, pair => Assert.Equal(pair.Subject, new JsonWebToken(pair.Token).Subject));
    }

    [Fact]
    public void Create_DefaultLifetime_ExpiresAnHourLater()
    {
        var issuedAt = new DateTimeOffset(2026, 9, 6, 12, 0, 0, TimeSpan.Zero);

        var token = new JsonWebToken(Provider(issuedAt).Create());

        Assert.Equal(issuedAt.AddMinutes(60).UtcDateTime, token.ValidTo, TimeSpan.FromSeconds(1));
    }

    /// <summary>
    /// The token for one set of claims at one instant, byte for byte, as issued before the issuing path was
    /// tuned: a speed-up may change how a token is made, never what is signed. Repeated claim types, a null
    /// among them and a sequence that is not a collection each take a path of their own through the payload.
    /// </summary>
    [Fact]
    public void Create_SameClaimsAndClock_IssuesTheSameToken()
    {
        const string issued =
            "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9." +
            "eyJhdWQiOiJhdWRpZW5jZS50ZXN0IiwiaXNzIjoiaXNzdWVyLnRlc3QiLCJleHAiOjE3OTE4OTY0MDAsImlhdCI6MTc5MTg5MjgwMCwibmJm" +
            "IjoxNzkxODkyODAwLCJzdWIiOiJ1c2VyLTQyIiwiaHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS93cy8yMDA4LzA2L2lkZW50aXR5L2Ns" +
            "YWltcy9yb2xlIjpbIkFkbWluIiwiQXVkaXRvciJdfQ." +
            "Fn5wvSXnbGGMKiypDxZ1IOmO-38w6JBEw5dYwWhuXQzLkcapaIqhhOHvd7zcNbisrG17xB-TwIG13UMx8p5OIA";
        var tokens = Provider(new DateTimeOffset(2026, 10, 13, 12, 0, 0, TimeSpan.Zero));
        Claim?[] claims = [new(JwtRegisteredClaimNames.Sub, "user-42"), null, new(ClaimTypes.Role, "Admin"), new(ClaimTypes.Role, "Auditor")];

        var fromCollection = tokens.Create(claims!);
        var fromSequence = tokens.Create(claims.Select(claim => claim)!);

        Assert.Equal(issued, fromCollection);
        Assert.Equal(issued, fromSequence);
    }

    /// <summary>
    /// The provider used to build a second set of rules of its own, so anything the caller changed
    /// on the scheme's options held for the middleware and for nothing else.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_CallerTurnedTheLifetimeCheckOff_AcceptsAnExpiredToken()
    {
        var tokens = new ServiceCollection()
            .AddSingleton<TimeProvider>(new FrozenTime(DateTimeOffset.UtcNow.AddHours(-2)))
            .AddAuthJwtBearer(Settings.Complete(), bearer => bearer.TokenValidationParameters.ValidateLifetime = false)
            .BuildServiceProvider()
            .GetRequiredService<ITokenProvider>();

        var verdict = await tokens.ValidateAsync(tokens.Create());

        Assert.True(verdict.IsValid);
    }

    /// <summary>
    /// The signing key is read per token, not captured once: a rotated secret takes effect on the
    /// next token without a restart, and rotating back restores the first.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_SecretRotatedAndBack_FollowsEachSecret()
    {
        const string rotated = "Q3mZ8vYp2LkR7tWn5XcB1HdJ6FgS9AeU4oIy0PqVr8TuMw3NzKb2CxLj5GhD7fEs";
        var configuration = (IConfigurationRoot)Settings.Complete();
        var tokens = new ServiceCollection()
            .AddAuthJwtBearer(configuration)
            .BuildServiceProvider()
            .GetRequiredService<ITokenProvider>();
        var first = tokens.Create(Claims());
        var forged = $"{first[..first.LastIndexOf('.')]}.{new string('A', 86)}";

        var firstBefore = await tokens.ValidateAsync(first);
        var forgedBefore = await tokens.ValidateAsync(forged);

        Rotate(configuration, rotated);
        var second = tokens.Create(Claims());
        var firstAfterRotation = await tokens.ValidateAsync(first);
        var secondAfterRotation = await tokens.ValidateAsync(second);

        Rotate(configuration, Settings.Secret);
        var firstAfterReturn = await tokens.ValidateAsync(first);
        var secondAfterReturn = await tokens.ValidateAsync(second);

        Assert.True(firstBefore.IsValid);
        Assert.Equal(TokenRefusal.Signature, forgedBefore.Refusal);
        Assert.Equal(TokenRefusal.Signature, firstAfterRotation.Refusal);
        Assert.True(secondAfterRotation.IsValid);
        Assert.True(firstAfterReturn.IsValid);
        Assert.Equal(TokenRefusal.Signature, secondAfterReturn.Refusal);
    }

    private static void Rotate(IConfigurationRoot configuration, string secret)
    {
        configuration[$"{AuthOptions.SectionName}:{nameof(AuthOptions.SecretKey)}"] = secret;
        configuration.Reload();
    }

    /// <summary>
    /// The signing key keeps its signature providers in a cache of its own, but a custom crypto provider an
    /// application installs on IdentityModel's default factory, even after the key exists, still signs and
    /// checks every token. The provider answers only for this test's secret, so tests running beside it are
    /// not touched.
    /// </summary>
    [Fact]
    public async Task Create_CustomCryptoProviderInstalledLater_SignsAndChecksThroughIt()
    {
        const string secret = "Wq4Lr8Zt1Xm6Kp3Vb9Nc2Hd7Jf5Gs0Ae4Uy8Io1Pq6Rt3Mw9Nz2Kb5Cx7Lj0GhDf";
        var custom = new CountingCrypto(secret);
        var values = Settings.Values();
        values[$"{AuthOptions.SectionName}:{nameof(AuthOptions.SecretKey)}"] = secret;
        var tokens = new ServiceCollection()
            .AddAuthJwtBearer(Settings.Of(values))
            .BuildServiceProvider()
            .GetRequiredService<ITokenProvider>();
        var token = tokens.Create(Claims());

        CryptoProviderFactory.Default.CustomCryptoProvider = custom;

        try
        {
            tokens.Create(Claims());
            var verdict = await tokens.ValidateAsync(token);

            Assert.True(verdict.IsValid);
            Assert.Equal(2, custom.Created);
        }
        finally
        {
            CryptoProviderFactory.Default.CustomCryptoProvider = null;
        }
    }

    private sealed class CountingCrypto(string secret) : ICryptoProvider
    {
        private int _created;

        public int Created => _created;

        public bool IsSupportedAlgorithm(string algorithm, params object[] args) =>
            args is [SymmetricSecurityKey key, ..] && key.Key.AsSpan().SequenceEqual(Encoding.UTF8.GetBytes(secret));

        public object Create(string algorithm, params object[] args)
        {
            Interlocked.Increment(ref _created);

            return new SymmetricSignatureProvider((SecurityKey)args[0], algorithm, (bool)args[1]);
        }

        public void Release(object cryptoInstance) => (cryptoInstance as IDisposable)?.Dispose();
    }

    [Fact]
    public void Mint_SizeBelowTheMinimum_IsRefused()
    {
        var secrets = Secrets();

        Assert.Throws<ArgumentOutOfRangeException>(() => secrets.Mint(0));
        Assert.Throws<ArgumentOutOfRangeException>(() => secrets.Mint(-1));
    }

    [Fact]
    public void Mint_Default_IsUrlSafe()
    {
        var refresh = Secrets().Mint();

        Assert.DoesNotContain('+', refresh);
        Assert.DoesNotContain('/', refresh);
        Assert.DoesNotContain('=', refresh);
    }

    [Fact]
    public void Mint_Twice_DiffersEveryTime()
    {
        var secrets = Secrets();

        Assert.NotEqual(secrets.Mint(), secrets.Mint());
    }

    private static IRefreshTokens Secrets() => new RefreshTokens();

    private static ITokenProvider Provider(DateTimeOffset? now = null)
    {
        var services = new ServiceCollection();

        if (now is { } frozen)
            services.AddSingleton<TimeProvider>(new FrozenTime(frozen));

        return services
            .AddAuthJwtBearer(Settings.Complete())
            .BuildServiceProvider()
            .GetRequiredService<ITokenProvider>();
    }

    private static List<Claim> Claims() =>
    [
        new(JwtRegisteredClaimNames.Name, "User1"),
        new(JwtRegisteredClaimNames.Sub, "email@email.test"),
        new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
        new(ClaimTypes.Role, "Admin")
    ];
}
