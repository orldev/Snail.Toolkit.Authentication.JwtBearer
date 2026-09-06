using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

namespace Snail.Toolkit.Authentication.JwtBearer;

/// <inheritdoc />
public sealed class RefreshTokens : IRefreshTokens
{
    /// <summary>
    /// Fewest bytes a refresh token may carry.
    /// </summary>
    /// <remarks>
    /// 128 bits. A smaller size used to be taken at face value, and zero produced an empty string
    /// that every caller would have accepted as a token.
    /// </remarks>
    public const int MinimumSize = 16;

    /// <inheritdoc />
    public string Mint(int size = 32)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(size, MinimumSize);

        return Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(size));
    }
}
