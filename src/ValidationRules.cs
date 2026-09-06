using System.Text;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Snail.Toolkit.Authentication.JwtBearer;

/// <summary>
/// How a token is judged, for the middleware and for <see cref="ITokenProvider"/> alike.
/// </summary>
/// <remarks>
/// The two used to build their own parameters and had already drifted: only one of them honoured the
/// clock skew, and only one of them saw the settings a caller passed at registration. These rules go
/// into the named <see cref="Microsoft.AspNetCore.Authentication.JwtBearer.JwtBearerOptions"/>, and
/// the provider reads them back from there, so a caller adjusting the options adjusts both.
/// </remarks>
internal static class ValidationRules
{
    /// <summary>
    /// The signing key a secret stands for.
    /// </summary>
    public static SymmetricSecurityKey Key(string secret) => new(Encoding.UTF8.GetBytes(secret));

    /// <summary>
    /// The rules a snapshot of the settings describes.
    /// </summary>
    public static TokenValidationParameters Of(AuthOptions settings) => new()
    {
        ValidateIssuer = settings.ValidateIssuer,
        ValidIssuer = settings.Issuer,
        ValidateAudience = settings.ValidateAudience,
        ValidAudience = settings.Audience,
        ValidateLifetime = settings.ValidateLifetime,
        ValidateIssuerSigningKey = settings.ValidateIssuerSigningKey,
        IssuerSigningKey = Key(settings.SecretKey),
        ValidAlgorithms = [SecurityAlgorithms.HmacSha512],
        ClockSkew = settings.ClockSkew
    };

    /// <summary>
    /// The same rules for one named configuration, reading the signing key afresh on every token.
    /// </summary>
    /// <remarks>
    /// The middleware resolves its options once, so a key captured here would outlive a rotated
    /// secret and reject every token issued after the rotation until the process was restarted.
    /// </remarks>
    public static TokenValidationParameters Following(IOptionsMonitor<AuthOptions> settings, string optionsName)
    {
        var rules = Of(settings.Get(optionsName));
        rules.IssuerSigningKeyResolver = (_, _, _, _) => [Key(settings.Get(optionsName).SecretKey)];

        return rules;
    }
}
