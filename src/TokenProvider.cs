using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Snail.Toolkit.Authentication.JwtBearer;

/// <summary>
/// Mints and judges tokens according to one named <see cref="AuthOptions"/>.
/// </summary>
/// <remarks>
/// Judging goes by the rules of its own bearer scheme rather than by a second set built here, so
/// whatever a caller changed on the scheme's options holds for a token checked by hand as well. Minting
/// takes the issuer and audience from those same rules, so a token is always made for the validator that
/// will judge it: the settings used to be read live for minting and once for judging, and a renamed issuer
/// made the process refuse every token it minted. Only the secret follows the configuration, on both sides,
/// by the same rule — the signing credentials are made again when it changes and kept while it does not.
/// </remarks>
public sealed partial class TokenProvider : ITokenProvider, IDisposable
{
    private static readonly JsonWebTokenHandler Handler = new();

    private static readonly RefreshTokens Secrets = new();

    /// <summary>
    /// The token descriptor this thread filled last, reused for its next token.
    /// </summary>
    /// <remarks>
    /// A descriptor and the audience list the handler creates on it were allocated for every token only to be
    /// read once. Every value a token is made from is written afresh each time; the descriptor is taken off the
    /// thread while a token is made, so a token minted from inside another gets one of its own, and the claims
    /// are let go once the token is signed.
    /// </remarks>
    [ThreadStatic]
    private static SecurityTokenDescriptor? _spare;

    /// <summary>
    /// The identity this thread lent its last claims through, reused for its next token.
    /// </summary>
    [ThreadStatic]
    private static LentClaims? _lent;

    private readonly string _scheme;
    private readonly string _optionsName;
    private readonly IOptionsMonitor<AuthOptions> _settings;
    private readonly IOptionsMonitor<JwtBearerOptions> _bearer;
    private readonly TimeProvider _time;
    private readonly TokenMetrics _metrics;
    private readonly ILogger<TokenProvider>? _logger;
    private readonly OfSecret<SigningCredentials> _credentials = new(CredentialsOf);

    /// <summary>
    /// Reads one named configuration and follows it as it changes.
    /// </summary>
    /// <remarks>
    /// The scheme names the bearer options whose rules judge a token; the options name is the
    /// settings this instance signs with. For the default registration they are "Bearer" and the
    /// empty name, and for a keyed one they are both the service key.
    /// </remarks>
    public TokenProvider(
        string scheme,
        string optionsName,
        IOptionsMonitor<AuthOptions> settings,
        IOptionsMonitor<JwtBearerOptions> bearer,
        TimeProvider time,
        TokenMetrics metrics,
        ILogger<TokenProvider>? logger = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(scheme);
        ArgumentNullException.ThrowIfNull(optionsName);
        ArgumentNullException.ThrowIfNull(settings);
        ArgumentNullException.ThrowIfNull(bearer);
        ArgumentNullException.ThrowIfNull(time);
        ArgumentNullException.ThrowIfNull(metrics);

        _scheme = scheme;
        _optionsName = optionsName;
        _settings = settings;
        _bearer = bearer;
        _time = time;
        _metrics = metrics;
        _logger = logger;
    }

    /// <inheritdoc />
    public string Create(IEnumerable<Claim>? claims = null)
    {
        var settings = _settings.Get(_optionsName);
        var rules = _bearer.Get(_scheme).TokenValidationParameters;
        var issuedAt = _time.GetUtcNow().UtcDateTime;
        var subject = claims is null ? null : Lend(claims);

        var descriptor = Spare();
        descriptor.Issuer = rules.ValidIssuer ?? settings.Issuer;
        descriptor.Audience = rules.ValidAudience ?? settings.Audience;
        descriptor.IssuedAt = issuedAt;
        descriptor.NotBefore = issuedAt;
        descriptor.Expires = issuedAt.AddMinutes(settings.TokenLifetime);
        descriptor.Subject = subject;
        descriptor.SigningCredentials = _credentials.For(settings.SecretKey);

        try
        {
            var token = Handler.CreateToken(descriptor);
            _metrics.Issued(_scheme);

            return token;
        }
        finally
        {
            Return(descriptor, subject);
        }
    }

    /// <inheritdoc />
    [Obsolete("Use IRefreshTokens.Mint: a refresh token is not a JWT and none of these settings apply.")]
    public string Refresh(int size = 32) => Secrets.Mint(size);

    /// <inheritdoc />
    public async Task<TokenValidation> ValidateAsync(string token, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var verdict = await Handler.ValidateTokenAsync(token, _bearer.Get(_scheme).TokenValidationParameters);

        if (verdict.IsValid)
            return TokenValidation.Valid;

        var refusal = RefusalOf(verdict.Exception);

        _metrics.Refused(_scheme, refusal);

        if (_logger is not null)
            Refused(_logger, _scheme, refusal);

        return TokenValidation.Refused(
            refusal, verdict.Exception?.Message ?? "The token did not pass validation.");
    }

    /// <summary>
    /// Nothing to release: the signing credentials follow the secret by comparison, not by subscription.
    /// </summary>
    /// <remarks>
    /// Kept because it shipped. It used to end the subscription to the settings through which a rotated secret
    /// reached the credentials.
    /// </remarks>
    public void Dispose()
    {
    }

    [LoggerMessage(Level = LogLevel.Debug, Message = "A token of scheme {Scheme} was refused: {Refusal}.")]
    private static partial void Refused(ILogger logger, string scheme, TokenRefusal refusal);

    private static SecurityTokenDescriptor Spare()
    {
        var descriptor = _spare ?? new SecurityTokenDescriptor();
        _spare = null;

        return descriptor;
    }

    private static void Return(SecurityTokenDescriptor descriptor, LentClaims? subject)
    {
        descriptor.Subject = null;
        _spare = descriptor;

        if (subject is null)
            return;

        subject.Release();
        _lent = subject;
    }

    private static LentClaims Lend(IEnumerable<Claim> claims)
    {
        var lent = _lent ?? new LentClaims();
        _lent = null;

        return lent.Holding(claims);
    }

    private static TokenRefusal RefusalOf(Exception? fault) => fault switch
    {
        SecurityTokenExpiredException => TokenRefusal.Expired,
        SecurityTokenNotYetValidException => TokenRefusal.NotYetValid,
        SecurityTokenInvalidSignatureException or SecurityTokenSignatureKeyNotFoundException
            or SecurityTokenInvalidAlgorithmException => TokenRefusal.Signature,
        SecurityTokenInvalidAudienceException => TokenRefusal.Audience,
        SecurityTokenInvalidIssuerException => TokenRefusal.Issuer,
        SecurityTokenMalformedException or ArgumentException => TokenRefusal.Malformed,
        _ => TokenRefusal.Other
    };

    private static SigningCredentials CredentialsOf(string secret) =>
        new(ValidationRules.Key(secret), SecurityAlgorithms.HmacSha512);
}
