using System.Diagnostics.Metrics;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Snail.Toolkit.Authentication.JwtBearer;

/// <summary>
/// Registers JWT Bearer authentication and the token provider that goes with it.
/// </summary>
public static class ServiceCollectionExtensions
{
    extension(IServiceCollection services)
    {
        /// <summary>
        /// Turns on JWT Bearer authentication, reading its settings from configuration.
        /// </summary>
        /// <param name="configuration">The configuration holding the settings section.</param>
        /// <param name="configure">Adjusts the JWT Bearer options after this package has set them.</param>
        /// <param name="sectionName">The section the settings are bound from.</param>
        /// <remarks>
        /// The settings are judged when the host starts, so a missing key refuses to bring the
        /// process up instead of surfacing on the first login. This registers the default Bearer
        /// scheme; a second issuer alongside it goes through <c>AddKeyedAuthJwtBearer</c>.
        /// </remarks>
        public IServiceCollection AddAuthJwtBearer(
            IConfiguration configuration,
            Action<JwtBearerOptions>? configure = null,
            string sectionName = AuthOptions.SectionName)
        {
            ArgumentNullException.ThrowIfNull(services);
            ArgumentNullException.ThrowIfNull(configuration);
            ArgumentException.ThrowIfNullOrWhiteSpace(sectionName);

            return services.AddIssuer(
                configuration, null, JwtBearerDefaults.AuthenticationScheme, sectionName, configure, true);
        }

        /// <summary>
        /// Turns on a second issuer of its own, under its own key, scheme and section.
        /// </summary>
        /// <param name="configuration">The configuration holding the settings section.</param>
        /// <param name="serviceKey">The key the provider is resolved by, and the scheme's name.</param>
        /// <param name="configure">Adjusts the JWT Bearer options after this package has set them.</param>
        /// <param name="sectionName">The section the settings are bound from; the key by default.</param>
        /// <remarks>
        /// Settings, scheme and provider are all named after the key, so nothing is shared with the
        /// default registration. No default scheme is set here: an endpoint says which issuer it
        /// trusts, with <c>[Authorize(AuthenticationSchemes = key)]</c>.
        /// </remarks>
        public IServiceCollection AddKeyedAuthJwtBearer(
            IConfiguration configuration,
            string serviceKey,
            Action<JwtBearerOptions>? configure = null,
            string? sectionName = null)
        {
            ArgumentNullException.ThrowIfNull(services);
            ArgumentNullException.ThrowIfNull(configuration);
            ArgumentException.ThrowIfNullOrWhiteSpace(serviceKey);

            return services.AddIssuer(
                configuration, serviceKey, serviceKey, sectionName ?? serviceKey, configure, false);
        }

        /// <summary>
        /// Registers <see cref="ITokenProvider"/> without touching the request pipeline.
        /// </summary>
        /// <remarks>
        /// For an application that mints tokens and never validates a request. The settings still
        /// have to reach <see cref="AuthOptions"/> somehow, which here means the caller configures
        /// them in code.
        /// </remarks>
        public IServiceCollection AddTokenProvider()
        {
            ArgumentNullException.ThrowIfNull(services);

            services.AddBearerRules(Options.DefaultName, JwtBearerDefaults.AuthenticationScheme, null);

            return services.AddProvider(null, Options.DefaultName, JwtBearerDefaults.AuthenticationScheme);
        }
    }

    private static IServiceCollection AddIssuer(
        this IServiceCollection services,
        IConfiguration configuration,
        string? serviceKey,
        string scheme,
        string sectionName,
        Action<JwtBearerOptions>? configure,
        bool isDefaultScheme)
    {
        if (!services.Claim(serviceKey, scheme, sectionName))
            return services;

        var optionsName = serviceKey ?? Options.DefaultName;

        services.AddAuthSettings(configuration, optionsName, sectionName);
        services.AddBearerRules(optionsName, scheme, configure);
        services.AddScheme(scheme, isDefaultScheme);

        return services.AddProvider(serviceKey, optionsName, scheme);
    }

    private static IServiceCollection AddAuthSettings(
        this IServiceCollection services, IConfiguration configuration, string optionsName, string sectionName)
    {
        services.AddOptions<AuthOptions>(optionsName)
            .Bind(configuration.GetSection(sectionName))
            .ValidateOnStart();

        services.AddSingleton<IValidateOptions<AuthOptions>>(new AuthOptionsValidator(optionsName, sectionName));

        return services;
    }

    private static IServiceCollection AddBearerRules(
        this IServiceCollection services, string optionsName, string scheme, Action<JwtBearerOptions>? configure)
    {
        services.AddOptions<JwtBearerOptions>(scheme)
            .Configure<IOptionsMonitor<AuthOptions>>((bearer, settings) =>
            {
                bearer.SaveToken = true;
                bearer.RequireHttpsMetadata = settings.Get(optionsName).RequireHttpsMetadata;
                bearer.IncludeErrorDetails = settings.Get(optionsName).IncludeErrorDetails;
                bearer.TokenValidationParameters = ValidationRules.Following(settings, optionsName);
            });

        if (configure is not null)
            services.PostConfigure(scheme, configure);

        return services;
    }

    private static IServiceCollection AddScheme(this IServiceCollection services, string scheme, bool isDefault)
    {
        var authentication = isDefault ? services.AddAuthentication(scheme) : services.AddAuthentication();

        authentication.AddJwtBearer(scheme);
        services.AddAuthorization();

        return services;
    }

    private static IServiceCollection AddProvider(
        this IServiceCollection services, string? serviceKey, string optionsName, string scheme)
    {
        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<IRefreshTokens, RefreshTokens>();
        services.TryAddSingleton(container => new TokenMetrics(container.GetService<IMeterFactory>()));

        if (serviceKey is null)
            services.TryAddSingleton<ITokenProvider>(container => Provider(container, optionsName, scheme));
        else
            services.TryAddKeyedSingleton<ITokenProvider>(
                serviceKey, (container, _) => Provider(container, optionsName, scheme));

        return services;
    }

    private static TokenProvider Provider(IServiceProvider container, string optionsName, string scheme) =>
        new(scheme,
            optionsName,
            container.GetRequiredService<IOptionsMonitor<AuthOptions>>(),
            container.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>(),
            container.GetRequiredService<TimeProvider>(),
            container.GetRequiredService<TokenMetrics>(),
            container.GetService<ILogger<TokenProvider>>());

    private static bool Claim(this IServiceCollection services, string? serviceKey, string scheme, string sectionName)
    {
        var claimed = services
            .Where(descriptor => descriptor.ServiceType == typeof(Issuer))
            .Select(descriptor => descriptor.ImplementationInstance)
            .OfType<Issuer>()
            .ToArray();

        if (Array.Find(claimed, issuer => issuer.Key == serviceKey) is { } sameKey)
        {
            if (sameKey.SectionName == sectionName && sameKey.Scheme == scheme)
                return false;

            throw new InvalidOperationException(
                $"{Named(serviceKey)} is already registered from section '{sameKey.SectionName}' as scheme " +
                $"'{sameKey.Scheme}'. A second call naming section '{sectionName}' would bind over it; " +
                "register a second issuer with AddKeyedAuthJwtBearer under its own key.");
        }

        if (Array.Find(claimed, issuer => issuer.Scheme == scheme) is { } sameScheme)
            throw new InvalidOperationException(
                $"The authentication scheme '{scheme}' is already taken by {Named(sameScheme.Key)}. " +
                "Choose another key for this issuer.");

        services.AddSingleton(new Issuer(serviceKey, scheme, sectionName));

        return true;
    }

    private static string Named(string? serviceKey) =>
        serviceKey is null ? "The default JWT bearer issuer" : $"The JWT bearer issuer keyed '{serviceKey}'";

    private sealed record Issuer(string? Key, string Scheme, string SectionName);
}
