using System.Buffers.Binary;
using System.Net;
using System.Net.Http.Headers;
using AccessServer.Domain.Entities;
using AccessServer.Infrastructure.Persistence;
using Google.Protobuf;
using Grpc.Core;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace AccessServer.IntegrationTests;

/// <summary>Usage testlari uchun umumiy yordamchilar.</summary>
internal static class UsageTestSupport
{
    public static string UniqueTunnel() => "tun_" + Guid.NewGuid().ToString("n");

    /// <summary>Yangi tenant (foydalanuvchisiz) — usage faqat slug'ga bog'lanadi.</summary>
    public static async Task<Tenant> CreateTenantAsync(AccessDbContext db)
    {
        var tenant = new Tenant { Slug = Application.Common.TenantSlug.Generate(), Name = "usage" };
        db.Tenants.Add(tenant);
        await db.SaveChangesAsync();
        return tenant;
    }

    /// <summary>gRPC unary so'rovi qo'lda: 1 bayt siqish bayrog'i + 4 bayt uzunlik (big-endian) + protobuf.</summary>
    public static HttpRequestMessage GrpcRequest(string method, IMessage message)
    {
        var payload = message.ToByteArray();
        var framed = new byte[5 + payload.Length];
        BinaryPrimitives.WriteUInt32BigEndian(framed.AsSpan(1, 4), (uint)payload.Length);
        payload.CopyTo(framed, 5);

        var request = new HttpRequestMessage(HttpMethod.Post, $"/cc01.v1.AccessInternalService/{method}")
        {
            Content = new ByteArrayContent(framed),
            Version = HttpVersion.Version20,
            VersionPolicy = HttpVersionPolicy.RequestVersionExact,
        };
        request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/grpc");
        request.Headers.TE.Add(new TransferCodingWithQualityHeaderValue("trailers"));
        return request;
    }

    /// <summary>grpc-status trailer'da (javob tanasi bor) yoki sarlavhada (trailers-only).</summary>
    public static string GrpcStatus(HttpResponseMessage response) =>
        response.TrailingHeaders.TryGetValues("grpc-status", out var trailer)
            ? trailer.Single()
            : response.Headers.GetValues("grpc-status").Single();
}

internal sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
{
    public override DateTimeOffset GetUtcNow() => now;
}

internal sealed class CapturingLogger<T> : ILogger<T>
{
    public sealed record Entry(LogLevel Level, string Message, IReadOnlyDictionary<string, object?> State);

    private readonly List<Entry> _entries = [];

    public IReadOnlyList<Entry> Entries
    {
        get
        {
            lock (_entries)
            {
                return [.. _entries];
            }
        }
    }

    public IDisposable? BeginScope<TState>(TState state)
        where TState : notnull => null;

    public bool IsEnabled(LogLevel logLevel) => true;

    public void Log<TState>(
        LogLevel logLevel,
        EventId eventId,
        TState state,
        Exception? exception,
        Func<TState, Exception?, string> formatter)
    {
        var values = state is IEnumerable<KeyValuePair<string, object?>> pairs
            ? pairs.ToDictionary(p => p.Key, p => p.Value)
            : [];

        lock (_entries)
        {
            _entries.Add(new Entry(logLevel, formatter(state, exception), values));
        }
    }
}

/// <summary>
/// Servisni gRPC stack'siz chaqirish uchun. HttpContext UserState'da —
/// Grpc.AspNetCore'ning GetHttpContext() shu kalitni o'qiydi (hujjatlangan
/// test usuli).
/// </summary>
internal sealed class UsageServerCallContext : ServerCallContext
{
    public UsageServerCallContext(HttpContext? httpContext = null)
    {
        UserState["__HttpContext"] = httpContext ?? new DefaultHttpContext();
    }

    protected override string MethodCore => "/cc01.v1.AccessInternalService/ReportUsage";

    protected override string HostCore => "127.0.0.1";

    protected override string PeerCore => "ipv4:127.0.0.1:0";

    protected override DateTime DeadlineCore => DateTime.MaxValue;

    protected override Metadata RequestHeadersCore { get; } = [];

    protected override CancellationToken CancellationTokenCore => CancellationToken.None;

    protected override Metadata ResponseTrailersCore { get; } = [];

    protected override Status StatusCore { get; set; }

    protected override WriteOptions? WriteOptionsCore { get; set; }

    protected override AuthContext AuthContextCore =>
        new(null, new Dictionary<string, List<AuthProperty>>());

    protected override ContextPropagationToken CreatePropagationTokenCore(ContextPropagationOptions? options) =>
        throw new NotSupportedException();

    protected override Task WriteResponseHeadersAsyncCore(Metadata responseHeaders) => Task.CompletedTask;
}
