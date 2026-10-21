using System.Net;
using System.Net.Http.Headers;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace Snail.Toolkit.Authentication.JwtBearer.Tests;

/// <summary>
/// The package behind the real request pipeline. The provider's tests prove what the provider judges; only a
/// request through <c>JwtBearerHandler</c> proves that the middleware judges by the same rules, that a refused
/// caller is told nothing, and that a host with a broken section never comes up.
/// </summary>
public class MiddlewareTests
{
    [Fact]
    public async Task Request_WithAMintedToken_IsAccepted()
    {
        using var host = await Started();
        var token = host.Services.GetRequiredService<ITokenProvider>().Create();

        var response = await Ask(host, token);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task Request_WithAForgedSignature_IsRefusedWithoutAReason()
    {
        using var host = await Started();
        var token = host.Services.GetRequiredService<ITokenProvider>().Create();
        var forged = $"{token[..token.LastIndexOf('.')]}.{new string('A', 86)}";

        var response = await Ask(host, forged);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal(["Bearer"], response.Headers.WwwAuthenticate.Select(challenge => challenge.ToString()));
    }

    /// <summary>
    /// The issuer's clock stands two hours back, so every token it mints is already expired for the middleware,
    /// which keeps the real clock.
    /// </summary>
    [Fact]
    public async Task Request_WithAnExpiredToken_IsRefused()
    {
        using var host = await Started(services =>
            services.AddSingleton<TimeProvider>(new FrozenTime(DateTimeOffset.UtcNow.AddHours(-2))));
        var expired = host.Services.GetRequiredService<ITokenProvider>().Create();

        var response = await Ask(host, expired);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    /// <summary>
    /// The middleware reads the scheme's options per request, and those are built again when the section reloads:
    /// a token of the old secret is refused and one of the new secret accepted, with no restart.
    /// </summary>
    [Fact]
    public async Task Request_AfterTheSecretRotated_IsJudgedByTheNewSecret()
    {
        const string rotated = "Q3mZ8vYp2LkR7tWn5XcB1HdJ6FgS9AeU4oIy0PqVr8TuMw3NzKb2CxLj5GhD7fEs";
        var configuration = (IConfigurationRoot)Settings.Complete();
        using var host = await Started(configuration: configuration);
        var tokens = host.Services.GetRequiredService<ITokenProvider>();
        var before = tokens.Create();

        configuration[$"{AuthOptions.SectionName}:{nameof(AuthOptions.SecretKey)}"] = rotated;
        configuration.Reload();

        var old = await Ask(host, before);
        var fresh = await Ask(host, tokens.Create());

        Assert.Equal(HttpStatusCode.Unauthorized, old.StatusCode);
        Assert.Equal(HttpStatusCode.OK, fresh.StatusCode);
    }

    [Fact]
    public async Task Host_WithoutASecret_RefusesToStartNamingTheKey()
    {
        var values = Settings.Values();
        values.Remove($"{AuthOptions.SectionName}:{nameof(AuthOptions.SecretKey)}");

        var fault = await Assert.ThrowsAsync<OptionsValidationException>(() => Started(configuration: Settings.Of(values)));

        Assert.Contains($"{AuthOptions.SectionName}:{nameof(AuthOptions.SecretKey)}", fault.Message, StringComparison.Ordinal);
    }

    private static async Task<HttpResponseMessage> Ask(IHost host, string token)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "/me");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

        return await host.GetTestClient().SendAsync(request);
    }

    private static Task<IHost> Started(Action<IServiceCollection>? more = null, IConfiguration? configuration = null) =>
        new HostBuilder()
            .ConfigureWebHost(web => web
                .UseTestServer()
                .ConfigureServices(services => Register(services, more, configuration))
                .Configure(Pipeline))
            .StartAsync();

    private static void Register(IServiceCollection services, Action<IServiceCollection>? more, IConfiguration? configuration)
    {
        more?.Invoke(services);
        services.AddRouting().AddAuthJwtBearer(configuration ?? Settings.Complete());
    }

    private static void Pipeline(IApplicationBuilder app)
    {
        app.UseRouting();
        app.UseAuthentication();
        app.UseAuthorization();
        app.UseEndpoints(Endpoints);
    }

    private static void Endpoints(IEndpointRouteBuilder endpoints) =>
        endpoints.MapGet("/me", () => Results.Ok()).RequireAuthorization();
}
