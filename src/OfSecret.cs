namespace Snail.Toolkit.Authentication.JwtBearer;

/// <summary>
/// The value made of the secret last seen, made again only when the secret changes.
/// </summary>
/// <remarks>
/// The secret and its value are swapped together as one immutable pair, so a reader during a rotation sees either
/// the old pair or the new one, never a value of the other secret. The key a token is judged by and the credentials
/// it is signed with are both kept this way, so issuing and judging follow the same secret by the same rule, and a
/// token is never signed with one secret while carrying the settings of another.
/// </remarks>
internal sealed class OfSecret<T>(Func<string, T> make) where T : class
{
    private Pair? _last;

    /// <summary>
    /// The value of <paramref name="secret"/>: the one kept while the secret is the same, a fresh one otherwise.
    /// </summary>
    public T For(string secret)
    {
        var last = Volatile.Read(ref _last);

        if (last is not null && string.Equals(last.Secret, secret, StringComparison.Ordinal))
            return last.Value;

        var fresh = new Pair(secret, make(secret));
        Volatile.Write(ref _last, fresh);

        return fresh.Value;
    }

    private sealed record Pair(string Secret, T Value);
}
