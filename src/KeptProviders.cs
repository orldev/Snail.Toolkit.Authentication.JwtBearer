using System.Collections.Concurrent;
using Microsoft.IdentityModel.Tokens;

namespace Snail.Toolkit.Authentication.JwtBearer;

/// <summary>
/// The signature providers of one signing key, found by the key itself rather than by a string.
/// </summary>
/// <remarks>
/// IdentityModel's own cache finds a provider by a key it formats on every lookup — the key's type, its JWK
/// thumbprint, the algorithm and the provider's type, some 150 characters — once for every token signed and
/// once for every token judged. Here the same four facts are a tuple, the key compared by reference, so a
/// lookup allocates nothing. A provider joins and leaves this cache as it would IdentityModel's.
/// </remarks>
internal sealed class KeptProviders : CryptoProviderCache
{
    private readonly ConcurrentDictionary<(SecurityKey Key, string Algorithm, string Type, bool WillSign), SignatureProvider> _providers = new();

    /// <inheritdoc />
    public override bool TryAdd(SignatureProvider signatureProvider)
    {
        ArgumentNullException.ThrowIfNull(signatureProvider);

        var isAdded = _providers.TryAdd(Of(signatureProvider), signatureProvider);

        if (isAdded)
            signatureProvider.CryptoProviderCache = this;

        return isAdded;
    }

    /// <inheritdoc />
    public override bool TryGetSignatureProvider(
        SecurityKey securityKey,
        string algorithm,
        string typeofProvider,
        bool willCreateSignatures,
        out SignatureProvider signatureProvider) =>
        _providers.TryGetValue((securityKey, algorithm, typeofProvider, willCreateSignatures), out signatureProvider!);

    /// <inheritdoc />
    public override bool TryRemove(SignatureProvider signatureProvider)
    {
        ArgumentNullException.ThrowIfNull(signatureProvider);

        if (!ReferenceEquals(signatureProvider.CryptoProviderCache, this))
            return false;

        return _providers.TryRemove(new KeyValuePair<(SecurityKey, string, string, bool), SignatureProvider>(
            Of(signatureProvider), signatureProvider));
    }

    /// <inheritdoc />
    protected override string GetCacheKey(SignatureProvider signatureProvider)
    {
        ArgumentNullException.ThrowIfNull(signatureProvider);

        return GetCacheKey(signatureProvider.Key, signatureProvider.Algorithm, signatureProvider.GetType().ToString());
    }

    /// <inheritdoc />
    protected override string GetCacheKey(SecurityKey securityKey, string algorithm, string typeofProvider)
    {
        ArgumentNullException.ThrowIfNull(securityKey);

        return $"{securityKey.GetType()}-{securityKey.KeyId}-{algorithm}-{typeofProvider}";
    }

    private static (SecurityKey, string, string, bool) Of(SignatureProvider provider) =>
        (provider.Key, provider.Algorithm, provider.GetType().ToString(), provider.WillCreateSignatures);
}
