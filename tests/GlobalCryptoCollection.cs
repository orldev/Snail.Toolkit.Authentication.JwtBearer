namespace Snail.Toolkit.Authentication.JwtBearer.Tests;

/// <summary>The tests that install a crypto provider on IdentityModel's process-wide default factory, run while nothing else does.</summary>
/// <remarks>
/// Two classes set <c>CryptoProviderFactory.Default.CustomCryptoProvider</c> and clear it in <c>finally</c>. Run side by
/// side, one replaced or cleared the other's provider halfway through: the counting provider saw one creation instead of
/// two. The one-megabyte check runs here too, away from the parallel load that pushed it past its limit.
/// </remarks>
[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class GlobalCryptoCollection
{
    public const string Name = "Global crypto";
}
