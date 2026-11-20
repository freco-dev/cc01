using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.DependencyInjection;

namespace AccessServer.IntegrationTests;

/// <summary>
/// AP'ni HAQIQIY Kestrel bilan, ikkala listener'i (public va internal)
/// alohida bo'sh portlarda ko'taradi.
///
/// Nega TestServer emas: TestServer'da Kestrel listener'lari yo'q — ichki
/// listener guard'i (A-S19) esa ulanishni ichki listener qabul qilgani
/// belgisiga tayanadi, shuning uchun Host sarlavhasini soxtalashtirish
/// testlari faqat haqiqiy socket'da ma'noga ega. WebApplicationFactory.UseKestrel() (.NET 10) ishlatiladi;
/// portlar Program.cs dagi Public:Port / Internal:Port orqali beriladi.
/// </summary>
public sealed class KestrelAccessApi : IAsyncDisposable
{
    private KestrelAccessApi(AccessApiFactory factory, int publicPort, int internalPort)
    {
        Factory = factory;
        PublicPort = publicPort;
        InternalPort = internalPort;

        Public = new HttpClient { BaseAddress = new Uri($"http://127.0.0.1:{publicPort}") };

        // Ichki listener faqat HTTP/2 (h2c, prior knowledge).
        Internal = new HttpClient
        {
            BaseAddress = new Uri($"http://127.0.0.1:{internalPort}"),
            DefaultRequestVersion = HttpVersion.Version20,
            DefaultVersionPolicy = HttpVersionPolicy.RequestVersionExact,
        };
    }

    public AccessApiFactory Factory { get; }

    public int PublicPort { get; }

    public int InternalPort { get; }

    public HttpClient Public { get; }

    public HttpClient Internal { get; }

    public RecordingEmailSender Emails => Factory.Services.GetRequiredService<RecordingEmailSender>();

    /// <param name="extraSettings">
    /// Qo'shimcha sozlamalar (masalan Internal:Tls:*). mTLS yoqilsa
    /// <see cref="Internal"/> (h2c) ishlamaydi — test o'z klientini quradi.
    /// </param>
    public static KestrelAccessApi Start(
        string connectionString,
        string? adminKey,
        IReadOnlyDictionary<string, string?>? extraSettings = null)
    {
        var publicPort = FreePort();
        var internalPort = FreePort();

        var settings = new Dictionary<string, string?>
        {
            ["Public:Address"] = "127.0.0.1",
            ["Public:Port"] = publicPort.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["Internal:Address"] = "127.0.0.1",
            ["Internal:Port"] = internalPort.ToString(System.Globalization.CultureInfo.InvariantCulture),
        };

        if (adminKey is not null)
        {
            settings["Internal:AdminKey"] = adminKey;
        }

        foreach (var (key, value) in extraSettings ?? new Dictionary<string, string?>())
        {
            settings[key] = value;
        }

        var factory = new AccessApiFactory(connectionString, settings);
        factory.UseKestrel();
        factory.StartServer();

        return new KestrelAccessApi(factory, publicPort, internalPort);
    }

    public async ValueTask DisposeAsync()
    {
        Public.Dispose();
        Internal.Dispose();
        await Factory.DisposeAsync();
    }

    /// <summary>
    /// OS bergan bo'sh port. Yopish va Kestrel bog'lanishi orasida kichik
    /// poyga oynasi bor — lokal test uchun yetarli.
    /// </summary>
    private static int FreePort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }
}
