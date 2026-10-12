using System.Security.Claims;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Snail.Toolkit.Authentication.JwtBearer;

var configuration = new ConfigurationBuilder()
    .AddInMemoryCollection(new Dictionary<string, string?>
    {
        ["Jwt:Issuer"] = "https://issuer.example",
        ["Jwt:Audience"] = "api",
        ["Jwt:SecretKey"] = "ayjN7KaHE2gd2cXrG2j4wyMUP7NX8SYKZxAKm0FYo3ajNKYY3h+CQ4OYnv2WF6It",
        ["Jwt:TokenLifetime"] = "15"
    })
    .Build();

using var services = new ServiceCollection()
    .AddLogging()
    .AddAuthJwtBearer(configuration)
    .BuildServiceProvider();

var settings = services.GetRequiredService<IOptionsMonitor<AuthOptions>>().Get(Options.DefaultName);
var provider = services.GetRequiredService<ITokenProvider>();
var token = provider.Create([new Claim("sub", "native")]);
var forged = string.Concat(token.AsSpan(0, token.LastIndexOf('.') + 1), new string('A', 86));

var valid = await provider.ValidateAsync(token);
var refused = await provider.ValidateAsync(forged);

var isBound = settings is { TokenLifetime: 15, Issuer: "https://issuer.example" };
var isJudged = valid.IsValid && refused.Refusal is TokenRefusal.Signature;

Console.WriteLine($"bound {isBound}, valid {valid.IsValid}, forged {refused.Refusal}");

return isBound && isJudged ? 0 : 1;
