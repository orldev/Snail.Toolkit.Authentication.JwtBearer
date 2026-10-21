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
    /// Judges a token and says why it was refused.
    /// </summary>
    Task<TokenValidation> ValidateAsync(string token, CancellationToken cancellationToken = default);
}
