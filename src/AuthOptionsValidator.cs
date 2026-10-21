using Microsoft.Extensions.Options;

namespace Snail.Toolkit.Authentication.JwtBearer;

/// <summary>
/// Judges the settings before a single token is signed with them.
/// </summary>
/// <remarks>
/// The checks used to sit inline in the registration, so they blamed the expression that failed
/// rather than the configuration key, ran only for settings that came from configuration, and let a
/// secret too short for the algorithm through to the first login instead of stopping the host.
/// One instance judges one named configuration and steps aside for the others, which is what lets a
/// second issuer be registered under its own key without borrowing this one's section name.
/// </remarks>
/// <param name="optionsName">The named configuration this instance judges.</param>
/// <param name="sectionName">
/// The section those settings were bound from, so a failure names the key; null when they are configured in code.
/// </param>
internal sealed class AuthOptionsValidator(string optionsName, string? sectionName) : IValidateOptions<AuthOptions>
{
    /// <summary>
    /// Longest lifetime a token may be given, in minutes: a century.
    /// </summary>
    /// <remarks>
    /// Past it a value is a typo. The validator used to ask only for a positive number, and <c>int.MaxValue</c>
    /// minted a token good until the year 6109 in silence, where every other misconfiguration stops the host.
    /// </remarks>
    public const int MaximumLifetime = 52_596_000;

    /// <summary>
    /// The named configuration this instance judges.
    /// </summary>
    public string OptionsName => optionsName;

    /// <inheritdoc />
    public ValidateOptionsResult Validate(string? name, AuthOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        if (!string.Equals(name ?? Options.DefaultName, optionsName, StringComparison.Ordinal))
            return ValidateOptionsResult.Skip;

        List<string> faults = [];

        if (string.IsNullOrWhiteSpace(options.Issuer))
            faults.Add(Missing(nameof(AuthOptions.Issuer)));

        if (string.IsNullOrWhiteSpace(options.Audience))
            faults.Add(Missing(nameof(AuthOptions.Audience)));

        if (string.IsNullOrWhiteSpace(options.SecretKey))
            faults.Add(Missing(nameof(AuthOptions.SecretKey)));
        else if (options.SecretKey.Length < AuthOptions.MinimumSecretLength)
            faults.Add(
                $"'{Key(nameof(AuthOptions.SecretKey))}' is {options.SecretKey.Length} characters; " +
                $"HMAC-SHA512 refuses a key shorter than {AuthOptions.MinimumSecretLength}.");

        if (options.TokenLifetime is <= 0 or > MaximumLifetime)
            faults.Add($"'{Key(nameof(AuthOptions.TokenLifetime))}' has to be between 1 and {MaximumLifetime} minutes.");

        if (options.ClockSkew < TimeSpan.Zero)
            faults.Add($"'{Key(nameof(AuthOptions.ClockSkew))}' cannot be negative.");

        return faults.Count is 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(faults);
    }

    private string Missing(string key) => sectionName is null
        ? $"'{key}' is not configured. The code that configures {nameof(AuthOptions)} has to set it."
        : $"'{Key(key)}' is not configured. Check that the '{sectionName}' section exists and is spelled correctly.";

    private string Key(string key) => sectionName is null ? key : $"{sectionName}:{key}";
}
