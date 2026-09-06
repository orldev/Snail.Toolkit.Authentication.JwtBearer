using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Extensions.Options;

namespace Snail.Toolkit.Authentication.JwtBearer.Tests;

public class ServiceCollectionExtensionsTests
{
    [Fact]
    public void AddAuthJwtBearer_SectionWithoutFlags_KeepsEveryCheckOn()
    {
        var settings = Registered(Settings.Complete()).GetRequiredService<IOptions<AuthOptions>>().Value;

        Assert.True(settings.ValidateIssuer);
        Assert.True(settings.ValidateAudience);
        Assert.True(settings.ValidateLifetime);
        Assert.True(settings.ValidateIssuerSigningKey);
        Assert.Equal(60, settings.TokenLifetime);
    }

    /// <summary>
    /// The caller's delegate used to be combined before the defaults, which then overwrote it.
    /// </summary>
    [Fact]
    public void AddAuthJwtBearer_CallerOverridesOptions_KeepsTheOverride()
    {
        var services = new ServiceCollection()
            .AddAuthJwtBearer(Settings.Complete(), bearer =>
            {
                bearer.RequireHttpsMetadata = false;
                bearer.TokenValidationParameters.ValidateAudience = false;
            });

        var bearer = Bearer(services.BuildServiceProvider());

        Assert.False(bearer.RequireHttpsMetadata);
        Assert.False(bearer.TokenValidationParameters.ValidateAudience);
    }

    [Fact]
    public void AddAuthJwtBearer_Configuration_ReachesTheBearerOptions()
    {
        var values = Settings.Values();
        values[$"{AuthOptions.SectionName}:{nameof(AuthOptions.RequireHttpsMetadata)}"] = "false";

        var bearer = Bearer(Registered(Settings.Of(values)));

        Assert.False(bearer.RequireHttpsMetadata);
        Assert.False(bearer.IncludeErrorDetails);
        Assert.Equal([SecurityAlgorithms.HmacSha512], bearer.TokenValidationParameters.ValidAlgorithms);
    }

    [Fact]
    public void AddAuthJwtBearer_SecretTooShort_NamesTheKey()
    {
        var values = Settings.Values();
        values[$"{AuthOptions.SectionName}:{nameof(AuthOptions.SecretKey)}"] = new string('k', 32);

        var fault = Assert.Throws<OptionsValidationException>(
            () => Registered(Settings.Of(values)).GetRequiredService<IOptions<AuthOptions>>().Value);

        Assert.Contains($"{AuthOptions.SectionName}:{nameof(AuthOptions.SecretKey)}", fault.Message, StringComparison.Ordinal);
        Assert.Contains($"{AuthOptions.MinimumSecretLength}", fault.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AddAuthJwtBearer_MissingSection_NamesTheSection()
    {
        var fault = Assert.Throws<OptionsValidationException>(
            () => Registered(Settings.Of(new())).GetRequiredService<IOptions<AuthOptions>>().Value);

        Assert.Contains($"{AuthOptions.SectionName}:{nameof(AuthOptions.Issuer)}", fault.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AddAuthJwtBearer_NamedSection_BindsFromIt()
    {
        const string section = "Authentication";

        var services = new ServiceCollection()
            .AddAuthJwtBearer(Settings.Of(Settings.Values(section)), sectionName: section);

        var settings = services.BuildServiceProvider().GetRequiredService<IOptions<AuthOptions>>().Value;

        Assert.Equal(Settings.Issuer, settings.Issuer);
    }

    [Fact]
    public void AddTokenProvider_OnItsOwn_LeavesTheRequestPipelineAlone()
    {
        var services = new ServiceCollection().AddTokenProvider();

        Assert.Contains(services, registration => registration.ServiceType == typeof(ITokenProvider));
        Assert.Contains(services, registration => registration.ServiceType == typeof(IRefreshTokens));
        Assert.DoesNotContain(services, registration => registration.ServiceType == typeof(IAuthenticationService));
    }

    private static ServiceProvider Registered(IConfiguration configuration) =>
        new ServiceCollection().AddAuthJwtBearer(configuration).BuildServiceProvider();

    private static JwtBearerOptions Bearer(IServiceProvider services) =>
        services.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>().Get(JwtBearerDefaults.AuthenticationScheme);
}
