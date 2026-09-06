using System.Reflection;

namespace Snail.Toolkit.Authentication.JwtBearer.Tests;

/// <summary>
/// Keeps the documented settings honest.
/// </summary>
/// <remarks>
/// The README promised defaults of true and a lifetime of 60 while the type defaulted every flag to
/// false and the lifetime to zero, and it asked for a 32-character secret that HMAC-SHA512 has never
/// accepted. Prose drifts from code unless a test reads both.
/// </remarks>
public class ReadmeTests
{
    private static readonly AuthOptions Defaults = new()
    {
        Issuer = Settings.Issuer,
        Audience = Settings.Audience,
        SecretKey = Settings.Secret
    };

    [Fact]
    public void Readme_DocumentedDefaults_MatchTheOptions()
    {
        var documented = Table();

        Assert.Contains(nameof(AuthOptions.ValidateLifetime), documented);
        Assert.Contains(nameof(AuthOptions.TokenLifetime), documented);
        Assert.Contains(nameof(AuthOptions.ClockSkew), documented);

        foreach (var (setting, value) in documented)
        {
            var property = typeof(AuthOptions).GetProperty(setting, BindingFlags.Public | BindingFlags.Instance);

            Assert.NotNull(property);
            Assert.Equal(value, Written(property.GetValue(Defaults)));
        }
    }

    [Fact]
    public void Readme_DocumentedSecretLength_MatchesTheAlgorithm()
    {
        Assert.Contains($"Minimum {AuthOptions.MinimumSecretLength}-character", Text(), StringComparison.Ordinal);
    }

    private static Dictionary<string, string> Table()
    {
        Dictionary<string, string> documented = [];

        foreach (var line in Text().Split('\n'))
        {
            var cells = line.Split('|', StringSplitOptions.TrimEntries);

            if (cells.Length < 5 || cells[2] is not "No")
                continue;

            documented[cells[1]] = cells[3];
        }

        return documented;
    }

    private static string Written(object? value) => value switch
    {
        bool flag => flag ? "true" : "false",
        _ => value?.ToString() ?? string.Empty
    };

    private static string Text() => File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "README.md"));
}
