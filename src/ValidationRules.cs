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
    /// The key is kept while the secret stays the same, so it is neither encoded again nor given a
    /// new identity for IdentityModel to find its signature provider by on every token.
    /// </remarks>
    public static TokenValidationParameters Following(IOptionsMonitor<AuthOptions> settings, string optionsName)
    {
        var rules = Of(settings.Get(optionsName));
        var keys = new SigningKeys();
        rules.IssuerSigningKeyResolver = (_, _, _, _) => keys.For(settings.Get(optionsName).SecretKey);

        return rules;
    }

    /// <summary>
    /// The signing key of the secret last seen, made again only when the secret changes.
    /// </summary>
    /// <remarks>
    /// The secret and its key are swapped together as one immutable pair, so a token judged
    /// while the secret rotates sees either the old pair or the new one, never a key of the
    /// other secret.
    /// </remarks>
    private sealed class SigningKeys
    {
        private Issued? _issued;

        public SecurityKey[] For(string secret)
        {
            var issued = Volatile.Read(ref _issued);

            if (issued is not null && string.Equals(issued.Secret, secret, StringComparison.Ordinal))
            {
                return issued.Keys;
            }

            var fresh = new Issued(secret, [Key(secret)]);
            Volatile.Write(ref _issued, fresh);

            return fresh.Keys;
        }

        private sealed record Issued(string Secret, SecurityKey[] Keys);
    }
}
