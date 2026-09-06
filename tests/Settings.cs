using Microsoft.Extensions.Configuration;

namespace Snail.Toolkit.Authentication.JwtBearer.Tests;

/// <summary>
/// The configuration a test starts from.
/// </summary>
/// <remarks>
/// It names only the three required values and the lifetime. The validation flags are left out on
/// purpose: a test that bends one of them has to say so, and the rest prove what an incomplete
/// section produces.
/// </remarks>
internal static class Settings
{
    public const string Secret = "ayjN7KaHE2gd2cXrG2j4wyMUP7NX8SYKZxAKm0FYo3ajNKYY3h+CQ4OYnv2WF6It";

    public const string Issuer = "issuer.test";

    public const string Audience = "audience.test";

    public static Dictionary<string, string?> Values(string section = AuthOptions.SectionName) => new()
    {
        [$"{section}:{nameof(AuthOptions.Issuer)}"] = Issuer,
        [$"{section}:{nameof(AuthOptions.Audience)}"] = Audience,
        [$"{section}:{nameof(AuthOptions.SecretKey)}"] = Secret
    };

    public static IConfiguration Of(Dictionary<string, string?> values) =>
        new ConfigurationBuilder().AddInMemoryCollection(values).Build();

    public static IConfiguration Complete() => Of(Values());
}

/// <summary>
/// A clock that stands still, so a test can say when a token was issued.
/// </summary>
internal sealed class FrozenTime(DateTimeOffset now) : TimeProvider
{
    public override DateTimeOffset GetUtcNow() => now;
}
