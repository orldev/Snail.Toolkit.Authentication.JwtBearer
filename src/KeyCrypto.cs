using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

namespace Snail.Toolkit.Authentication.JwtBearer;

/// <summary>
/// The crypto of one signing key: IdentityModel's own, with its signature providers kept in <see cref="KeptProviders"/>.
/// </summary>
/// <remarks>
/// Only the signature providers take the shorter way, and only while the factory the key was born with is plain
/// IdentityModel — no custom provider, caching on — checked on every call, so a custom provider installed later
/// takes over as it did before. Everything else, the algorithm checks behind every refusal included, is asked of
/// that factory. A provider is still created, checked, counted and released by IdentityModel's own code; the
/// cache it lands in is the only difference, and the signature is the same byte for byte.
/// </remarks>
internal sealed class KeyCrypto : CryptoProviderFactory
{
    private readonly CryptoProviderFactory _born;

    private KeyCrypto(CryptoProviderFactory born)
        : base(new KeptProviders())
    {
        _born = born;
        CacheSignatureProviders = true;
        CacheCustomProviders = born.CacheCustomProviders;
        SignatureProviderObjectPoolCacheSize = born.SignatureProviderObjectPoolCacheSize;
    }

    private bool IsBornPlain => _born.CustomCryptoProvider is null && _born.CacheSignatureProviders;

    /// <summary>
    /// The crypto a new key of a secret uses: this one when the key was born with plain IdentityModel, its own otherwise.
    /// </summary>
    /// <remarks>
    /// A factory of a type of its own may decide anything in any member, so it is left to decide.
    /// </remarks>
    public static CryptoProviderFactory Over(CryptoProviderFactory born) =>
        born.GetType() == typeof(CryptoProviderFactory) ? new KeyCrypto(born) : born;

    /// <inheritdoc />
    public override SignatureProvider CreateForSigning(SecurityKey key, string algorithm, bool cacheProvider) =>
        IsBornPlain
            ? base.CreateForSigning(key, algorithm, cacheProvider)
            : _born.CreateForSigning(key, algorithm, cacheProvider);

    /// <inheritdoc />
    public override SignatureProvider CreateForVerifying(SecurityKey key, string algorithm, bool cacheProvider) =>
        IsBornPlain
            ? base.CreateForVerifying(key, algorithm, cacheProvider)
            : _born.CreateForVerifying(key, algorithm, cacheProvider);

    /// <inheritdoc />
    public override void ReleaseSignatureProvider(SignatureProvider signatureProvider)
    {
        ArgumentNullException.ThrowIfNull(signatureProvider);

        if (signatureProvider.CryptoProviderCache is KeptProviders)
            base.ReleaseSignatureProvider(signatureProvider);
        else
            _born.ReleaseSignatureProvider(signatureProvider);
    }

    /// <inheritdoc />
    public override bool IsSupportedAlgorithm(string algorithm) => _born.IsSupportedAlgorithm(algorithm);

    /// <inheritdoc />
    public override bool IsSupportedAlgorithm(string algorithm, SecurityKey key) =>
        _born.IsSupportedAlgorithm(algorithm, key);

    /// <inheritdoc />
    public override KeyedHashAlgorithm CreateKeyedHashAlgorithm(byte[] keyBytes, string algorithm) =>
        _born.CreateKeyedHashAlgorithm(keyBytes, algorithm);

    /// <inheritdoc />
    public override HashAlgorithm CreateHashAlgorithm(HashAlgorithmName algorithm) => _born.CreateHashAlgorithm(algorithm);

    /// <inheritdoc />
    public override HashAlgorithm CreateHashAlgorithm(string algorithm) => _born.CreateHashAlgorithm(algorithm);

    /// <inheritdoc />
    public override void ReleaseHashAlgorithm(HashAlgorithm hashAlgorithm) => _born.ReleaseHashAlgorithm(hashAlgorithm);

    /// <inheritdoc />
    public override AuthenticatedEncryptionProvider CreateAuthenticatedEncryptionProvider(SecurityKey key, string algorithm) =>
        _born.CreateAuthenticatedEncryptionProvider(key, algorithm);

    /// <inheritdoc />
    public override KeyWrapProvider CreateKeyWrapProvider(SecurityKey key, string algorithm) =>
        _born.CreateKeyWrapProvider(key, algorithm);

    /// <inheritdoc />
    public override KeyWrapProvider CreateKeyWrapProviderForUnwrap(SecurityKey key, string algorithm) =>
        _born.CreateKeyWrapProviderForUnwrap(key, algorithm);

    /// <inheritdoc />
    public override void ReleaseKeyWrapProvider(KeyWrapProvider provider) => _born.ReleaseKeyWrapProvider(provider);

    /// <inheritdoc />
    public override void ReleaseRsaKeyWrapProvider(RsaKeyWrapProvider provider) => _born.ReleaseRsaKeyWrapProvider(provider);
}
