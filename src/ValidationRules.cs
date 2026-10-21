using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace Snail.Toolkit.Authentication.JwtBearer;

/// <summary>
/// How a token is judged, for the middleware and for <see cref="ITokenProvider"/> alike.
/// </summary>
/// <remarks>
/// The two used to build their own parameters and had already drifted: only one of them honoured the
/// clock skew, and only one of them saw the settings a caller passed at registration. These rules go
/// into the named <see cref="Microsoft.AspNetCore.Authentication.JwtBearer.JwtBearerOptions"/>, and
/// the provider reads them back from there, so a caller adjusting the options adjusts both. The options
/// are built again whenever their section reloads, so the key here is the key of the moment and needs
/// no resolver to follow a rotated secret.
/// </remarks>
internal static class ValidationRules
{
    /// <summary>
    /// The signing key a secret stands for.
    /// </summary>
    /// <remarks>
    /// Its crypto is <see cref="KeyCrypto"/>, so the key finds its signature providers without formatting a
    /// string for every token it signs or judges.
    /// </remarks>
    public static SymmetricSecurityKey Key(string secret)
    {
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));
        key.CryptoProviderFactory = KeyCrypto.Over(key.CryptoProviderFactory);

        return key;
    }

    /// <summary>
    /// The rules a snapshot of the settings describes.
    /// </summary>
    /// <remarks>
    /// The key is named twice: as the key the provider signs with, and through a resolver that hands the handler
    /// the same key as a ready array. Left to find it by itself, the handler gathers every key it could try on each
    /// token — 130 bytes more per judgement (3.42 → 3.55 KB, measured 2026-10-21).
    /// </remarks>
    public static TokenValidationParameters Of(AuthOptions settings)
    {
        var key = Key(settings.SecretKey);
        SecurityKey[] keys = [key];

        return new()
        {
            ValidateIssuer = settings.ValidateIssuer,
            ValidIssuer = settings.Issuer,
            ValidateAudience = settings.ValidateAudience,
            ValidAudience = settings.Audience,
            ValidateLifetime = settings.ValidateLifetime,
            ValidateIssuerSigningKey = settings.ValidateIssuerSigningKey,
            IssuerSigningKey = key,
            IssuerSigningKeyResolver = (_, _, _, _) => keys,
            ValidAlgorithms = [SecurityAlgorithms.HmacSha512],
            ClockSkew = settings.ClockSkew
        };
    }
}
