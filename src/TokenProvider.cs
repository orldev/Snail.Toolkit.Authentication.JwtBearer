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
/// whatever a caller changed on the scheme's options holds for a token checked by hand as well.
/// The signing credentials are built once and rebuilt when the settings change: they used to be
/// allocated on every call, and the secret was captured in the constructor of a singleton, so a
/// rotated key only took effect after a restart.
/// </remarks>
public sealed partial class TokenProvider : ITokenProvider, IDisposable
{
    private static readonly JsonWebTokenHandler Handler = new();

    private static readonly RefreshTokens Secrets = new();

    private readonly string _scheme;
    private readonly string _optionsName;
    private readonly IOptionsMonitor<AuthOptions> _settings;
    private readonly IOptionsMonitor<JwtBearerOptions> _bearer;
    private readonly TimeProvider _time;
    private readonly TokenMetrics _metrics;
    private readonly ILogger<TokenProvider>? _logger;
    private readonly IDisposable? _subscription;

    private SigningCredentials _credentials;

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
        _credentials = CredentialsOf(settings.Get(optionsName));

        _subscription = settings.OnChange(Apply);
    }

    /// <inheritdoc />
    public string Create(IEnumerable<Claim>? claims = null)
    {
        var settings = _settings.Get(_optionsName);
        var issuedAt = _time.GetUtcNow().UtcDateTime;

        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = settings.Issuer,
            Audience = settings.Audience,
            IssuedAt = issuedAt,
            NotBefore = issuedAt,
            Expires = issuedAt.AddMinutes(settings.TokenLifetime),
            Subject = claims is null ? null : new ClaimsIdentity(claims),
            SigningCredentials = _credentials
        };

        _metrics.Issued(_scheme);

        return Handler.CreateToken(descriptor);
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

    /// <inheritdoc />
    public void Dispose() => _subscription?.Dispose();

    [LoggerMessage(Level = LogLevel.Debug, Message = "A token of scheme {Scheme} was refused: {Refusal}.")]
    private static partial void Refused(ILogger logger, string scheme, TokenRefusal refusal);

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

    private void Apply(AuthOptions current, string? name)
    {
        if (string.Equals(name ?? Options.DefaultName, _optionsName, StringComparison.Ordinal))
            _credentials = CredentialsOf(current);
    }

    private static SigningCredentials CredentialsOf(AuthOptions settings) =>
        new(ValidationRules.Key(settings.SecretKey), SecurityAlgorithms.HmacSha512);
}
