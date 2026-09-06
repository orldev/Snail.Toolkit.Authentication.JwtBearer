using System.Security.Claims;

namespace Snail.Toolkit.Authentication.JwtBearer;

/// <summary>
/// Mints the tokens an application hands out and judges the ones it gets back.
/// </summary>
public interface ITokenProvider
{
    /// <summary>
    /// Mints a signed token carrying the given claims.
    /// </summary>
    string Create(IEnumerable<Claim>? claims = null);

    /// <summary>
    /// Mints a refresh token of <paramref name="size"/> random bytes.
    /// </summary>
    [Obsolete("Use IRefreshTokens.Mint: a refresh token is not a JWT and none of these settings apply.")]
    string Refresh(int size = 32);

    /// <summary>
    /// Judges a token and says why it was refused.
    /// </summary>
    Task<TokenValidation> ValidateAsync(string token, CancellationToken cancellationToken = default);

    /// <summary>
    /// Whether a token passes every configured check.
    /// </summary>
    [Obsolete("Use ValidateAsync: its answer carries the reason a token was refused.")]
    async Task<bool> Validate(string token) => (await ValidateAsync(token)).IsValid;
}
