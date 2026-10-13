using System.Security.Claims;

namespace Snail.Toolkit.Authentication.JwtBearer;

/// <summary>
/// The claims of a token about to be minted, handed to the handler as the caller gave them.
/// </summary>
/// <remarks>
/// A <see cref="ClaimsIdentity"/> built from claims clones every one of them to point back at itself: a copy per
/// claim on every token, while the handler reads only the type, value and value type of each, once, to write the
/// payload. This identity lends it the caller's own instead, in the same order, nulls included, so the payload
/// comes out byte for byte the same. A sequence that is not a collection is read into one first, so it is
/// enumerated once, at the moment the identity used to read it. One identity serves a thread token after token,
/// as the descriptor it travels in does, holding the claims only while their token is made.
/// </remarks>
internal sealed class LentClaims : ClaimsIdentity
{
    private IReadOnlyCollection<Claim> _claims = [];

    /// <inheritdoc />
    public override IEnumerable<Claim> Claims => _claims;

    /// <summary>
    /// Holds the given claims for the token about to be made.
    /// </summary>
    public LentClaims Holding(IEnumerable<Claim> claims)
    {
        _claims = claims as IReadOnlyCollection<Claim> ?? [.. claims];

        return this;
    }

    /// <summary>
    /// Lets go of the claims once their token is made.
    /// </summary>
    public void Release() => _claims = [];
}
