using System.Security.Cryptography;
using System.Text;
using AccessServer.Application.Common;
using Microsoft.AspNetCore.Connections.Features;
using Microsoft.AspNetCore.Server.Kestrel.Core;

namespace AccessServer.Api.Common;

/// <summary>
/// Endpoint faqat ichki listener (Internal:Port) uchun ekanini bildiradi.
/// <see cref="InternalListenerGuardMiddleware"/> shu belgiga qaraydi.
/// </summary>
public sealed class InternalOnlyMetadata;

public static class InternalListenerExtensions
{
    /// <summary>
    /// Ulanish belgisi kaliti. Obyekt — tashqaridan (sarlavha, so'rov
    /// qiymati) uni yasab bo'lmaydi; faqat ichki listener'ning connection
    /// middleware'i qo'yadi.
    /// </summary>
    private static readonly object InternalConnectionKey = new();

    /// <summary>
    /// Ichki listener qabul qilgan HAR BIR ulanishni belgilaydi (Kestrel
    /// connection middleware, HTTP'dan oldin ishlaydi). Guard port raqamiga
    /// emas, shu belgiga qaraydi: ikki listener bir xil portda, turli
    /// IP'larda bo'lsa ham public socket'ga kelgan ulanish belgisiz qoladi.
    /// </summary>
    public static ListenOptions MarkInternal(this ListenOptions listen)
    {
        ArgumentNullException.ThrowIfNull(listen);

        listen.Use(next => connection =>
        {
            MarkInternal(connection.Items);
            return next(connection);
        });

        return listen;
    }

    /// <summary>Ulanish elementlariga ichki belgi qo'yadi (testlar ham shu orqali).</summary>
    public static void MarkInternal(IDictionary<object, object?> connectionItems)
    {
        ArgumentNullException.ThrowIfNull(connectionItems);
        connectionItems[InternalConnectionKey] = true;
    }

    /// <summary>So'rov ichki listener qabul qilgan ulanishdan keldimi.</summary>
    public static bool IsFromInternalListener(this HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var items = context.Features.Get<IConnectionItemsFeature>()?.Items;
        return items is not null
            && items.TryGetValue(InternalConnectionKey, out var marked)
            && marked is true;
    }

    /// <summary>
    /// Endpointni ichki listener'ga bog'laydi: <see cref="InternalOnlyMetadata"/>
    /// bo'yicha guard middleware so'rov HAQIQATAN ichki listener qabul qilgan
    /// ulanishdan kelganini (<see cref="MarkInternal(ListenOptions)"/> belgisi)
    /// tekshiradi.
    ///
    /// ⚠️ <c>RequireHost("*:port")</c> ATAYLAB ishlatilmaydi. U Host /
    /// :authority sarlavhasiga qaraydi — uni klient o'zi yozadi (public portga
    /// <c>Host: x:5081</c> bilan aldash mumkin, A-S19), ya'ni himoya bermaydi.
    /// Ustiga-ustak u haqiqiy klientni sindirardi: grpc-go TLS'da :authority
    /// sifatida PORTSIZ ServerName ni yuboradi ("127.0.0.1"), RequireHost esa
    /// "*:5081" ni kutib, mTLS orqali kelgan edge so'roviga 404 qaytarardi.
    ///
    /// OpenAPI hujjatidan ham chiqariladi: public portdagi /openapi/v1.json
    /// ichki endpoint mavjudligini oshkor qilmasligi kerak.
    /// </summary>
    public static TBuilder RequireInternalListener<TBuilder>(this TBuilder builder)
        where TBuilder : IEndpointConventionBuilder
    {
        ArgumentNullException.ThrowIfNull(builder);

        return builder
            .WithMetadata(new InternalOnlyMetadata())
            .ExcludeFromDescription();
    }
}

/// <summary>
/// Ichki endpoint ichki listener qabul qilmagan ulanishga kelgan bo'lsa —
/// 404, xuddi endpoint umuman yo'qdek (mavjudligini ham oshkor qilmaymiz).
/// Port raqami emas, ulanish belgisi tekshiriladi: ikki listener bir xil
/// portda (turli IP) bo'lsa ham public ulanish o'tmaydi.
///
/// Routing'dan KEYIN turishi shart: endpoint metadata'si faqat shunda ma'lum.
/// WebApplication UseRouting'ni quvur boshiga o'zi qo'yadi.
/// </summary>
public sealed class InternalListenerGuardMiddleware(
    RequestDelegate next,
    ILogger<InternalListenerGuardMiddleware> logger)
{
    public Task InvokeAsync(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var endpoint = context.GetEndpoint();
        if (endpoint?.Metadata.GetMetadata<InternalOnlyMetadata>() is null
            || context.IsFromInternalListener())
        {
            return next(context);
        }

        // Host sarlavhasi soxtalashtirilgan bo'lishi mumkin — log'ga yozamiz,
        // lekin sarlavha qiymatini emas (log in'yeksiyasi).
        logger.LogWarning(
            "Ichki endpoint ichki listener'dan boshqa ulanishga so'raldi (port={LocalPort}, ip={RemoteIp}) — 404",
            context.Connection.LocalPort, context.Connection.RemoteIpAddress);

        context.Response.StatusCode = StatusCodes.Status404NotFound;
        return Task.CompletedTask;
    }
}

/// <summary>
/// <c>X-Cc01-Admin-Key</c> sarlavhasini tekshiradi. Ichki listener pod yoki
/// klaster IP'siga bog'langan bo'lishi mumkin; u yerda mTLS (A-S5,
/// <see cref="InternalTls"/>) ulanishni edge sertifikati bilan cheklaydi,
/// admin kaliti esa chuqur himoya — tarif o'zgartirish pul bilan bog'liq
/// imtiyoz, edge sertifikati yolg'iz unga yetmasligi kerak.
///
/// Solishtirish SHA-256 digestlari ustida, doimiy vaqtda: uzunlik ham, mos
/// prefiks ham vaqt orqali sizmaydi.
/// </summary>
public sealed class AdminKeyFilter : IEndpointFilter
{
    public const string HeaderName = "X-Cc01-Admin-Key";

    private static readonly Error Invalid =
        Error.Unauthorized("ADMIN_KEY_INVALID", "Admin kaliti yo'q yoki noto'g'ri.");

    private readonly byte[] _expectedDigest;

    public AdminKeyFilter(string adminKey)
    {
        ArgumentException.ThrowIfNullOrEmpty(adminKey);
        _expectedDigest = SHA256.HashData(Encoding.UTF8.GetBytes(adminKey));
    }

    public async ValueTask<object?> InvokeAsync(
        EndpointFilterInvocationContext context,
        EndpointFilterDelegate next)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(next);

        var provided = context.HttpContext.Request.Headers[HeaderName].ToString();
        var providedDigest = SHA256.HashData(Encoding.UTF8.GetBytes(provided));

        if (provided.Length == 0
            || !CryptographicOperations.FixedTimeEquals(providedDigest, _expectedDigest))
        {
            return Invalid.ToProblem();
        }

        return await next(context);
    }
}
