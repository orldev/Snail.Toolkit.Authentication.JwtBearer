using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;

namespace Snail.Toolkit.Authentication.JwtBearer.Tests;

/// <summary>
/// Two issuers in one application. A second call used to bind its section over the first one's
/// settings and then fail on the Bearer scheme, which was already taken.
/// </summary>
public class KeyedIssuerTests
{
    private const string Partners = "Partners";

    [Fact]
    public void AddKeyedAuthJwtBearer_AlongsideTheDefault_KeepsBothSettings()
    {
        var container = Both();

        var standard = container.GetRequiredService<IOptionsMonitor<AuthOptions>>();

        Assert.Equal(Settings.Issuer, standard.CurrentValue.Issuer);
        Assert.Equal($"{Settings.Issuer}.partners", standard.Get(Partners).Issuer);
    }

    [Fact]
    public void AddKeyedAuthJwtBearer_AlongsideTheDefault_RegistersBothSchemes()
    {
        var schemes = Both().GetRequiredService<IOptions<AuthenticationOptions>>().Value.Schemes;

        Assert.Contains(schemes, scheme => scheme.Name == JwtBearerDefaults.AuthenticationScheme);
        Assert.Contains(schemes, scheme => scheme.Name == Partners);
    }

    [Fact]
    public async Task KeyedProvider_TokenOfTheOtherIssuer_IsRefused()
    {
        var container = Both();

        var standard = container.GetRequiredService<ITokenProvider>();
        var partners = container.GetRequiredKeyedService<ITokenProvider>(Partners);

        Assert.True((await partners.ValidateAsync(partners.Create())).IsValid);
        Assert.Equal(TokenRefusal.Signature, (await partners.ValidateAsync(standard.Create())).Refusal);
    }

    [Fact]
    public void AddAuthJwtBearer_Twice_FromTheSameSection_KeepsOneRegistration()
    {
        var services = new ServiceCollection()
            .AddAuthJwtBearer(Settings.Complete())
            .AddAuthJwtBearer(Settings.Complete());

        Assert.Single(services, registration => registration.ServiceType == typeof(ITokenProvider));
    }

    [Fact]
    public void AddAuthJwtBearer_Twice_FromDifferentSections_SaysWhatToDoInstead()
    {
        var services = new ServiceCollection().AddAuthJwtBearer(Settings.Complete());

        var fault = Assert.Throws<InvalidOperationException>(
            () => services.AddAuthJwtBearer(Settings.Of(Settings.Values(Partners)), sectionName: Partners));

        Assert.Contains("AddKeyedAuthJwtBearer", fault.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AddKeyedAuthJwtBearer_OnTheDefaultScheme_SaysTheSchemeIsTaken()
    {
        var services = new ServiceCollection().AddAuthJwtBearer(Settings.Complete());

        var fault = Assert.Throws<InvalidOperationException>(
            () => services.AddKeyedAuthJwtBearer(Settings.Complete(), JwtBearerDefaults.AuthenticationScheme));

        Assert.Contains("already taken", fault.Message, StringComparison.Ordinal);
    }

    private static ServiceProvider Both()
    {
        var values = Settings.Values();

        foreach (var (key, value) in Settings.Values(Partners))
            values[key] = value;

        values[$"{Partners}:{nameof(AuthOptions.Issuer)}"] = $"{Settings.Issuer}.partners";
        values[$"{Partners}:{nameof(AuthOptions.SecretKey)}"] = new string('p', AuthOptions.MinimumSecretLength);

        var configuration = Settings.Of(values);

        return new ServiceCollection()
            .AddAuthJwtBearer(configuration)
            .AddKeyedAuthJwtBearer(configuration, Partners)
            .BuildServiceProvider();
    }
}
