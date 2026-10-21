using System.Text;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Snail.Toolkit.Authentication.JwtBearer.Tests.Chaos;

/// <summary>
/// The tokens an attacker sends: the classic JWT confusions and the edges of the clock.
/// </summary>
public class ForgeryChaosTests
{
    /// <summary>
    /// Pins: a token whose header says <c>alg: none</c> over a genuine payload is refused on the signature.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_AlgorithmNone_IsRefusedAsSignature()
    {
        var tokens = Provider();
        var payload = tokens.Create().Split('.')[1];
        var header = Base64UrlEncoder.Encode("""{"alg":"none","typ":"JWT"}""");

        var verdict = await tokens.ValidateAsync($"{header}.{payload}.");

        Assert.Equal(TokenRefusal.Signature, verdict.Refusal);
    }

    /// <summary>
    /// Pins: a token signed with the right secret but HMAC-SHA256 is refused — the algorithm is pinned, so a weaker
    /// signature over the same key is not a signature at all.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_SameSecretWeakerAlgorithm_IsRefusedAsSignature()
    {
        var tokens = Provider();
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Settings.Secret));
        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = Settings.Issuer,
            Audience = Settings.Audience,
            Expires = DateTime.UtcNow.AddMinutes(5),
            SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256)
        };
        var weaker = new JsonWebTokenHandler().CreateToken(descriptor);

        var verdict = await tokens.ValidateAsync(weaker);

        Assert.Equal(TokenRefusal.Signature, verdict.Refusal);
    }

    /// <summary>
    /// Pins the edge of the clock skew: a token four minutes past its expiry is still accepted under the five-minute
    /// default, one six minutes past is refused as expired.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ExpiredAroundTheClockSkew_FlipsAtTheSkew()
    {
        var judge = Provider();
        var fourPast = Provider(DateTimeOffset.UtcNow.AddMinutes(-64)).Create();
        var sixPast = Provider(DateTimeOffset.UtcNow.AddMinutes(-66)).Create();

        var within = await judge.ValidateAsync(fourPast);
        var beyond = await judge.ValidateAsync(sixPast);

        Assert.True(within.IsValid, within.Fault);
        Assert.Equal(TokenRefusal.Expired, beyond.Refusal);
    }

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
}
