# Snail.Toolkit.Authentication.JwtBearer

JWT Bearer authentication for ASP.NET Core in one call. The `Jwt` section is bound and validated when
the host starts, the Bearer scheme is configured from it, and `ITokenProvider` issues and checks tokens
signed with HMAC-SHA512 by the very same rules.

Every check is on by default, the caller's own options win over the package's, a rotated secret is
picked up without a restart, and a second issuer registers under its own key. .NET 10, Microsoft
dependencies only.

## Installation

```bash
dotnet add package Snail.Toolkit.Authentication.JwtBearer
```

## Configuration

### Service Registration

```csharp
// Program.cs
builder.Services.AddAuthJwtBearer(builder.Configuration);
```

### Middleware Setup

```csharp
// Program.cs
app.UseAuthentication();  // Must come before UseAuthorization
app.UseAuthorization();   // Required for [Authorize] attributes
```

### appsettings.json Configuration

```json
{
  "Jwt": {
    "Issuer": "your_issuer",
    "Audience": "your_audience",
    "SecretKey": "minimum_64_character_secure_key_here_because_hmac_sha512_says_so",
    "TokenLifetime": 60
  }
}
```

#### Configuration Options

| Setting                  | Required | Default  | Description |
|--------------------------|----------|----------|-------------|
| Issuer                   | Yes      | -        | Token publisher identifier |
| Audience                 | Yes      | -        | Intended token recipient |
| SecretKey                | Yes      | -        | Minimum 64-character secure key |
| ValidateAudience         | No       | true     | Validate token audience |
| ValidateIssuer           | No       | true     | Validate token issuer |
| ValidateLifetime         | No       | true     | Validate token expiration |
| ValidateIssuerSigningKey | No       | true     | Validate the signing key |
| TokenLifetime            | No       | 60       | Token validity in minutes |
| ClockSkew                | No       | 00:05:00 | Tolerated clock drift between issuer and validator |
| RequireHttpsMetadata     | No       | true     | Require HTTPS for the authority |
| IncludeErrorDetails      | No       | false    | Tell a rejected caller why it was rejected |

Every check defaults to **on**. Turning one off is an explicit decision, written in configuration.

The section name is a parameter, so the settings can live wherever the application keeps them:

```csharp
builder.Services.AddAuthJwtBearer(builder.Configuration, sectionName: "Partners");
```

A repeated call from the same section is a no-op; from another section it fails and says what to do
instead, rather than quietly binding over the first registration.

### A second issuer

```csharp
builder.Services.AddAuthJwtBearer(builder.Configuration);              // section Jwt,      scheme Bearer
builder.Services.AddKeyedAuthJwtBearer(builder.Configuration, "Partners"); // section Partners, scheme Partners
```

Settings, scheme and provider are all named after the key, so the two share nothing:

```csharp
public class PartnerController([FromKeyedServices("Partners")] ITokenProvider tokens) : ControllerBase
{
    [HttpGet("me"), Authorize(AuthenticationSchemes = "Partners")]
    public IActionResult Me() => Ok();
}
```

The keyed call sets no default scheme on purpose — an endpoint says which issuer it trusts.

The settings are validated when the host starts. A missing or short secret refuses to bring the
process up, naming the key it choked on, instead of failing on the first login.

## Advanced Usage

### Custom JWT Bearer Options

The delegate runs **after** this package has applied its own settings, so anything it sets wins.

```csharp
builder.Services.AddAuthJwtBearer(builder.Configuration, options =>
{
    options.Events = new JwtBearerEvents
    {
        OnAuthenticationFailed = context => Task.CompletedTask
    };
});
```

### Issuing tokens without the request pipeline

A service that only mints tokens does not need the authentication middleware:

```csharp
builder.Services.AddTokenProvider();
```

## Security Considerations

1. Always use HTTPS in production
2. Rotate `SecretKey` periodically — a reloadable configuration source is picked up without a restart
3. Set an appropriate `TokenLifetime`
4. Store `SecretKey` securely (HashiCorp Vault, Azure Key Vault, AWS Secrets Manager)
5. Leave `IncludeErrorDetails` off outside development: it tells a caller whether a token expired or
   was never signed by this application

## Samples

### 1. **Token Creation Example**
```csharp
var claims = new List<Claim>
{
    new(JwtRegisteredClaimNames.Sub, "user123"),
    new(JwtRegisteredClaimNames.Name, "John Doe"),
    new(JwtRegisteredClaimNames.Email, "john@example.com"),
    new("role", "Admin")
};

var token = tokenProvider.Create(claims);
```

Claims are written exactly as given. Prefer the short registered names above over `ClaimTypes.*`,
whose values are XML schema URIs that inflate every request and mean nothing outside .NET.

Tokens are signed with HMAC-SHA512 and carry `"alg": "HS512"`.

### 2. **Refresh Token Generation Example**

Refresh tokens live behind their own contract: nothing about them is signed, parsed or configured.

```csharp
var refreshToken = refreshTokens.Mint();       // 32 bytes
var longRefreshToken = refreshTokens.Mint(64); // 64 bytes
```

Url-safe base64, so it survives a query string or a cookie unescaped. A size below 16 bytes is
refused rather than silently producing a weak token.

### 3. **Token Validation Example**
```csharp
var verdict = await tokenProvider.ValidateAsync(token, cancellationToken);

var answer = verdict.Refusal switch
{
    TokenRefusal.None => Results.Ok(),
    TokenRefusal.Expired => Results.Unauthorized(),   // the client should refresh
    _ => Results.Forbid()                             // the client should log in again
};
```

`TokenValidation` carries the reason as `TokenRefusal` — `Expired`, `NotYetValid`, `Signature`,
`Audience`, `Issuer`, `Malformed`, `Other` — with the library's own message in `Fault`. `IsValid` is
derived from the refusal, so the two cannot disagree.

### 4. **Integration with Controllers**
```csharp
[ApiController]
[Route("auth")]
public class AuthController(ITokenProvider tokenProvider) : ControllerBase
{
    [HttpPost("login")]
    public IActionResult Login([FromBody] LoginRequest request, [FromServices] IRefreshTokens refreshTokens)
    {
        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, request.Username),
            new("custom_claim", "value")
        };

        return Ok(new
        {
            Token = tokenProvider.Create(claims),
            RefreshToken = refreshTokens.Mint()
        });
    }
}
```

## Observability

The package publishes two counters under the meter `Snail.Toolkit.Authentication.JwtBearer`:

| Instrument            | Tags                        | What it says |
|-----------------------|-----------------------------|--------------|
| `auth.tokens.issued`  | `auth.scheme`               | Access tokens this application signed |
| `auth.tokens.refused` | `auth.scheme`, `auth.refusal` | Tokens it turned away, by reason |

The meter is taken from the host's `IMeterFactory` when there is one, so `AddMetrics` and an OTLP
exporter pick it up with no further wiring. Each refusal is also logged at `Debug` when a logger is
registered: the counter answers whether tokens are expiring or arriving unsigned, the log answers
which token it was.

## Upgrading

- Every validation flag now defaults to `true`. An application that relied on one being off has to
  say so in configuration.
- The `alg` header is `HS512` instead of the XML-dsig URI, and the algorithm is pinned on validation:
  tokens issued by earlier versions are refused.
- `SecretKey` shorter than 64 characters is refused at startup; HMAC-SHA512 never accepted it.
- `ITokenProvider.Validate` is obsolete in favour of `ValidateAsync`, which carries the reason.
- Refresh tokens are url-safe base64.
- `ITokenProvider.Refresh` is obsolete in favour of `IRefreshTokens.Mint`.
- `TokenValidation` is `(TokenRefusal Refusal, string? Fault)`; `IsValid` is derived from it.

## License

Snail.Toolkit.Authentication.JwtBearer is a free and open source project, released under the permissible [MIT license](LICENSE).
