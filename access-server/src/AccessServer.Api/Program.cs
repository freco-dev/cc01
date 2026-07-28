using AccessServer.Api.Middleware;
using AccessServer.Api.HealthChecks;
using AccessServer.Application.Authentication;
using AccessServer.Insfrastructure.Authentication;
using AccessServer.Insfrastructure.Options;
using AccessServer.Insfrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.IdentityModel.Tokens;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.Configure<JwtOptions>(builder.Configuration.GetSection("Jwt"));
builder.Services.Configure<DatabaseOptions>(builder.Configuration.GetSection("Database"));
builder.Services.Configure<RedisOptions>(builder.Configuration.GetSection("Redis"));

var jwtSection = builder.Configuration.GetSection("Jwt");
var jwtOptions = jwtSection.Get<JwtOptions>() ?? throw new InvalidOperationException("Jwt configuration is missing.");
var databaseOptions = builder.Configuration.GetSection("Database").Get<DatabaseOptions>() ?? throw new InvalidOperationException("Database configuration is missing.");
var redisOptions = builder.Configuration.GetSection("Redis").Get<RedisOptions>() ?? throw new InvalidOperationException("Redis configuration is missing.");

builder.Services.AddDbContext<AccessServerDbContext>(options => options.UseNpgsql(databaseOptions.ConnectionString));
builder.Services.AddStackExchangeRedisCache(options =>
{
    options.Configuration = redisOptions.Configuration;
    options.InstanceName = redisOptions.InstanceName;
});

builder.Services.AddScoped<IEmailCheckCache, RedisEmailCheckCache>();
builder.Services.AddScoped<IAuthService, DatabaseAuthService>();
builder.Services.AddHealthChecks()
    .AddCheck<DatabaseHealthCheck>("database")
    .AddCheck<RedisHealthCheck>("redis");

builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = jwtOptions.Issuer,
            ValidAudience = jwtOptions.Audience,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtOptions.SigningKey)),
            ClockSkew = TimeSpan.Zero
        };
    });

builder.Services.AddAuthorization();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseMiddleware<GlobalExceptionMiddleware>();
app.UseMiddleware<CorrelationIdMiddleware>();
app.UseMiddleware<RequestLoggingMiddleware>();

if (!app.Environment.IsEnvironment("Docker") && !app.Environment.IsEnvironment("Testing"))
{
    app.UseHttpsRedirection();
}

app.UseAuthentication();

app.UseAuthorization();

app.MapControllers();
app.MapHealthChecks("/health", new HealthCheckOptions
{
    ResponseWriter = HealthCheckResponseWriter.WriteResponse
});

await MigrateDatabaseAsync(app);

app.Run();

static async Task MigrateDatabaseAsync(WebApplication app)
{
    if (app.Environment.IsEnvironment("Testing"))
    {
        return;
    }

    await using var scope = app.Services.CreateAsyncScope();
    var dbContext = scope.ServiceProvider.GetRequiredService<AccessServerDbContext>();
    await dbContext.Database.MigrateAsync();
}

public partial class Program;
