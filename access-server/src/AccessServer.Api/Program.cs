using AccessServer.Api.Middleware;
using AccessServer.Application.Authentication;
using AccessServer.Insfrastructure.Authentication;
using AccessServer.Insfrastructure.Options;
using AccessServer.Insfrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddOpenApi();
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

builder.Services.AddScoped<IAuthService, DatabaseAuthService>();

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
    app.MapOpenApi();
}

app.UseMiddleware<GlobalExceptionMiddleware>();
app.UseMiddleware<CorrelationIdMiddleware>();
app.UseMiddleware<RequestLoggingMiddleware>();

app.UseHttpsRedirection();

app.UseAuthentication();

app.UseAuthorization();

app.MapControllers();

app.Run();

public partial class Program;
