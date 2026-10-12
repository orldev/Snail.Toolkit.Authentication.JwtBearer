using System.Security.Claims;
using BenchmarkDotNet.Attributes;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Snail.Toolkit.Authentication.JwtBearer.Benchmarks;

/// <summary>
/// Measures issuing a token and judging one, the work behind every login and every authenticated request.
/// </summary>
/// <remarks>
/// Judging runs the rules the bearer middleware runs on each request, signing key resolver included, so
/// <see cref="IsValid"/> stands for the per-request cost. <see cref="IsForgeryAccepted"/> reaches the same resolver
/// and is refused on the signature, the path an attacker drives. Read the Allocated column: the times of a few
/// microseconds move with the machine, the bytes do not.
/// </remarks>
[MemoryDiagnoser]
public class Tokens
{
    private const string Secret = "ayjN7KaHE2gd2cXrG2j4wyMUP7NX8SYKZxAKm0FYo3ajNKYY3h+CQ4OYnv2WF6It";

    private static readonly Claim[] Claims = [new("sub", "user-42"), new("role", "admin"), new("tenant", "eu-1")];

    private ServiceProvider _services = null!;
    private ITokenProvider _provider = null!;
    private string _token = string.Empty;
    private string _forged = string.Empty;

    /// <summary>Registers the default issuer from configuration and mints the tokens the judging ones read.</summary>
    [GlobalSetup]
    public void Setup()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Jwt:Issuer"] = "https://issuer.example",
                ["Jwt:Audience"] = "api",
                ["Jwt:SecretKey"] = Secret
            })
            .Build();

        _services = new ServiceCollection()
            .AddLogging()
            .AddAuthJwtBearer(configuration)
            .BuildServiceProvider();

        _provider = _services.GetRequiredService<ITokenProvider>();
        _token = _provider.Create(Claims);
        _forged = string.Concat(_token.AsSpan(0, _token.LastIndexOf('.') + 1), new string('A', 86));
    }

    /// <summary>Releases the container the provider lives in.</summary>
    [GlobalCleanup]
    public void Cleanup() => _services.Dispose();

    /// <summary>Mints a signed token with three claims.</summary>
    [Benchmark]
    public string Create() => _provider.Create(Claims);

    /// <summary>Judges a valid token.</summary>
    [Benchmark]
    public async Task<bool> IsValid() => (await _provider.ValidateAsync(_token).ConfigureAwait(false)).IsValid;

    /// <summary>Judges a token whose signature was forged.</summary>
    [Benchmark]
    public async Task<bool> IsForgeryAccepted() =>
        (await _provider.ValidateAsync(_forged).ConfigureAwait(false)).IsValid;
}
