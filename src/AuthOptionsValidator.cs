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
/// <param name="sectionName">The section those settings were bound from, so a failure names the key.</param>
internal sealed class AuthOptionsValidator(string optionsName, string sectionName) : IValidateOptions<AuthOptions>
{
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

        if (options.TokenLifetime <= 0)
            faults.Add($"'{Key(nameof(AuthOptions.TokenLifetime))}' has to be a positive number of minutes.");

        if (options.ClockSkew < TimeSpan.Zero)
            faults.Add($"'{Key(nameof(AuthOptions.ClockSkew))}' cannot be negative.");

        return faults.Count is 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(faults);
    }

    private string Missing(string key) =>
        $"'{Key(key)}' is not configured. Check that the '{sectionName}' section exists and is spelled correctly.";

    private string Key(string key) => $"{sectionName}:{key}";
}
