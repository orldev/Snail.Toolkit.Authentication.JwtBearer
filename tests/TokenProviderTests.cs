using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Snail.Toolkit.Authentication.JwtBearer.Tests;

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

    [Fact]
    public void Create_DefaultLifetime_ExpiresAnHourLater()
    {
        var issuedAt = new DateTimeOffset(2026, 9, 6, 12, 0, 0, TimeSpan.Zero);

        var token = new JsonWebToken(Provider(issuedAt).Create());

        Assert.Equal(issuedAt.AddMinutes(60).UtcDateTime, token.ValidTo, TimeSpan.FromSeconds(1));
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
