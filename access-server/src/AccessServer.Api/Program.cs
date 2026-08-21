using System.Net;
using System.Text;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using AccessServer.Api.Endpoints;
using AccessServer.Api.Grpc;
using AccessServer.Infrastructure;
using AccessServer.Infrastructure.Auth;
using AccessServer.Infrastructure.Auth.OAuth;
using AccessServer.Infrastructure.Persistence;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

// Ikkita listener ATAYLAB ajratilgan (DEV_SPEC §6.4):
//
//   Public   — REST API, HTTP/1.1+2. Internetga ochiladi.
//   Internal — AP ↔ Edge gRPC kontrakti, h2c. HECH QACHON internetga
//              chiqmaydi; sukut bo'yicha faqat loopback.
//
// ⚠️ Endpointlar oshkora ko'rsatilgani uchun ASPNETCORE_URLS va
//    launchSettings dagi applicationUrl E'TIBORGA OLINMAYDI — bu Kestrel'ning
//    xatti-harakati. Portlarni quyidagi konfiguratsiyadan o'zgartiring.
var publicAddress = builder.Configuration.GetValue("Public:Address", "0.0.0.0")!;
var publicPort = builder.Configuration.GetValue("Public:Port", 5078);
var internalAddress = builder.Configuration.GetValue("Internal:Address", "127.0.0.1")!;
var internalPort = builder.Configuration.GetValue("Internal:Port", 5081);

builder.WebHost.ConfigureKestrel(kestrel =>
{
    kestrel.Listen(IPAddress.Parse(publicAddress), publicPort,
        listen => listen.Protocols = HttpProtocols.Http1AndHttp2);

    kestrel.Listen(IPAddress.Parse(internalAddress), internalPort,
        listen => listen.Protocols = HttpProtocols.Http2);
});

var connectionString = builder.Configuration.GetConnectionString("Access")
    ?? throw new InvalidOperationException(
        "ConnectionStrings:Access sozlanmagan. Dev uchun: make dev-up va "
        + "appsettings.Development.json dagi qiymatdan foydalaning.");

builder.Services
    .AddAccessPersistence(connectionString)
    .AddAccessSecurity(builder.Configuration)
    .AddAccessUseCases();

if (builder.Environment.IsDevelopment())
{
    // Xat yubormaydi, tasdiqlash tokenini log'ga yozadi. Prod'da haqiqiy
    // provayder kerak — shuning uchun ataylab faqat Development'da.
    builder.Services.AddDevelopmentEmailSender();
}

// JWT sozlamalari IOptions orqali kechiktirilgan holda o'qiladi.
//
// ⚠️ Bu yerda `builder.Configuration.Get<JwtOptions>()` bilan DARHOL o'qish
// vasvasasi bor, lekin u nozik xatoga olib keladi: konfiguratsiya manbalari
// host qurilayotganda qo'shilishi mumkin (masalan integration testlarda),
// shunda token BIR kalit bilan imzolanib, BOSHQASI bilan tekshiriladi va
// hamma so'rov 401 qaytaradi. Ikkala tomon ham ayni bir IOptions'dan oqishi
// shart.
var authentication = builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer();

// Faqat sozlangan provayderlar ro'yxatga olinadi. Sirlar berilmagan dev
// muhitida server baribir ishga tushadi; endpoint esa
// OAUTH_PROVIDER_NOT_CONFIGURED qaytaradi.
var oauthProviders = authentication.AddAccessOAuth(builder.Configuration);

builder.Services
    .AddOptions<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme)
    .Configure<IOptions<JwtOptions>>((bearer, jwtOptions) =>
    {
        var jwt = jwtOptions.Value;

        // Standart holda ASP.NET Core kiruvchi claim nomlarini "eski" WS-Fed
        // nomlariga xaritalaydi: "sub" → ClaimTypes.NameIdentifier. Natijada
        // FindFirstValue("sub") null qaytaradi. Biz claim nomlarini tokendagi
        // holicha ishlatamiz.
        bearer.MapInboundClaims = false;

        bearer.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = jwt.Issuer,
            ValidAudience = jwt.Audience,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwt.SigningKey)),

            // Standart 5 daqiqalik "clock skew" tokenning amal qilish
            // muddatini jimgina uzaytiradi. Bizga bu kerak emas.
            ClockSkew = TimeSpan.Zero,
        };
    });

builder.Services.AddAuthorization();
builder.Services.AddGrpc();
builder.Services.AddOpenApi();
builder.Services.AddProblemDetails();

// Liveness va readiness ataylab ajratilgan:
//   /livez  — jarayon tirikmi. Baza yiqilganda ham 200 qaytaradi, aks holda
//             orkestrator konteynerni behuda qayta ishga tushiraveradi.
//   /readyz — so'rov qabul qila oladimi. Baza yo'q bo'lsa 503 → trafik
//             boshqa nusxaga yo'naltiriladi.
builder.Services.AddHealthChecks()
    .AddDbContextCheck<AccessDbContext>("database", tags: ["ready"]);

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseExceptionHandler();
app.UseAuthentication();
app.UseAuthorization();

app.MapAuthEndpoints();
app.MapTokenEndpoints();
app.MapSubdomainEndpoints();
app.MapOAuthEndpoints(oauthProviders);

// RequireHost — servis faqat ichki portda javob beradi. Public portga
// kelgan gRPC so'rovi 404 oladi.
app.MapGrpcService<TunnelAuthorizationService>()
    .RequireHost($"*:{internalPort}");

app.MapHealthChecks("/livez", new HealthCheckOptions { Predicate = _ => false })
    .ExcludeFromDescription();

app.MapHealthChecks("/readyz", new HealthCheckOptions
{
    Predicate = check => check.Tags.Contains("ready"),
}).ExcludeFromDescription();

await app.RunAsync();

/// <summary>
/// Integration testlar WebApplicationFactory&lt;Program&gt; bilan ishlashi
/// uchun sinf oshkora bo'lishi kerak (top-level Program aks holda internal).
/// </summary>
public partial class Program;
