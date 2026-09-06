namespace Snail.Toolkit.Authentication.JwtBearer;

/// <summary>
/// The JWT settings an application supplies, bound from the <see cref="SectionName"/> section.
/// </summary>
/// <remarks>
/// Every check defaults to on and the lifetime to an hour. Left to the defaults of their types they
/// were all off, so a section missing one key silently accepted expired tokens and tokens minted for
/// another audience, while a missing lifetime made every token expire the moment it was issued.
/// </remarks>
public sealed class AuthOptions
{
    /// <summary>
    /// The configuration section these settings are read from.
    /// </summary>
    public const string SectionName = "Jwt";

    /// <summary>
    /// The principal that issues the token.
    /// </summary>
    public required string Issuer { get; set; }

    /// <summary>
    /// The recipient the token is minted for.
    /// </summary>
    public required string Audience { get; set; }

    /// <summary>
    /// The secret the signature is computed with.
    /// </summary>
    /// <remarks>
    /// HMAC-SHA512 refuses a key shorter than the hash it produces, so this has to carry at least
    /// <see cref="MinimumSecretLength"/> characters or no token can be signed at all.
    /// </remarks>
    public required string SecretKey { get; set; }

    /// <summary>
    /// Shortest secret HMAC-SHA512 accepts, in characters.
    /// </summary>
    /// <remarks>
    /// 512 bits, measured against the algorithm: a 32-character secret fails with IDX10720.
    /// </remarks>
    public const int MinimumSecretLength = 64;

    /// <summary>
    /// Whether the audience of an incoming token has to match <see cref="Audience"/>.
    /// </summary>
    public bool ValidateAudience { get; set; } = true;

    /// <summary>
    /// Whether the issuer of an incoming token has to match <see cref="Issuer"/>.
    /// </summary>
    public bool ValidateIssuer { get; set; } = true;

    /// <summary>
    /// Whether an expired token is rejected.
    /// </summary>
    public bool ValidateLifetime { get; set; } = true;

    /// <summary>
    /// Whether the signing key itself is validated.
    /// </summary>
    public bool ValidateIssuerSigningKey { get; set; } = true;

    /// <summary>
    /// How long an issued token stays valid, in minutes.
    /// </summary>
    public int TokenLifetime { get; set; } = 60;

    /// <summary>
    /// How much clock drift between issuer and validator is tolerated.
    /// </summary>
    /// <remarks>
    /// Five minutes is what the framework assumes. Set it to zero to have tokens expire exactly at
    /// their expiry, at the price of failing whenever two machines disagree about the time.
    /// </remarks>
    public TimeSpan ClockSkew { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Whether the authority has to be reached over HTTPS.
    /// </summary>
    public bool RequireHttpsMetadata { get; set; } = true;

    /// <summary>
    /// Whether a rejected request is told why it was rejected.
    /// </summary>
    /// <remarks>
    /// Off by default: the reason travels to the caller in the WWW-Authenticate header, which tells
    /// an attacker whether a token merely expired or was never signed by this application.
    /// </remarks>
    public bool IncludeErrorDetails { get; set; }
}
