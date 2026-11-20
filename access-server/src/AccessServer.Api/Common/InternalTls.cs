using System.Net;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Server.Kestrel.Https;

namespace AccessServer.Api.Common;

/// <summary>
/// Ichki listener mTLS sozlamalari (DEV_SPEC A-S5, S-11) — konfiguratsiyadan
/// o'qilgan, hali tekshirilmagan qiymatlar.
///
/// <c>Internal:Tls:CertPath</c> bo'sh bo'lmasa mTLS YOQILGAN; u holda
/// qolgan uchtasi ham majburiy.
/// </summary>
/// <param name="CertPath">AP server sertifikati (PEM).</param>
/// <param name="KeyPath">Server sertifikatining yopiq kaliti (PEM, ECDSA P-256 yoki RSA).</param>
/// <param name="ClientCaPath">
/// Klient sertifikatlari uchun YAGONA ishonch ildizlari (PEM to'plami). Tizim
/// ildizlari hech qachon ishlatilmaydi.
/// </param>
/// <param name="AllowedClients">Ruxsat etilgan klient CN'lari (ordinal, katta-kichik harf farqli).</param>
public sealed record InternalTlsOptions(
    string CertPath,
    string KeyPath,
    string ClientCaPath,
    IReadOnlyList<string> AllowedClients)
{
    public const string SectionName = "Internal:Tls";

    /// <summary>
    /// Sozlamalarni o'qiydi. <c>null</c> — mTLS o'chirilgan (CertPath bo'sh).
    /// Fayllar bu yerda o'qilmaydi — qarang <see cref="InternalTls.Load"/>.
    /// </summary>
    public static InternalTlsOptions? Read(IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        var section = configuration.GetSection(SectionName);
        var certPath = section["CertPath"]?.Trim() ?? string.Empty;
        var keyPath = section["KeyPath"]?.Trim() ?? string.Empty;
        var clientCaPath = section["ClientCaPath"]?.Trim() ?? string.Empty;
        var allowedClients = ParseAllowedClients(section.GetSection("AllowedClients"));

        if (certPath.Length == 0)
        {
            // Yarim sozlama (masalan ClientCaPath bor, CertPath unutilgan)
            // jimgina ochiq matnli h2c'ga aylanib qolmasin.
            if (keyPath.Length > 0 || clientCaPath.Length > 0 || allowedClients.Count > 0)
            {
                throw new InvalidOperationException(
                    "Internal:Tls qisman sozlangan: KeyPath, ClientCaPath yoki AllowedClients berilgan, "
                    + "lekin Internal:Tls:CertPath bo'sh. mTLS faqat CertPath berilganda yoqiladi — "
                    + "CertPath'ni bering yoki qolgan Internal:Tls:* kalitlarini olib tashlang.");
            }

            return null;
        }

        return new InternalTlsOptions(certPath, keyPath, clientCaPath, allowedClients);
    }

    /// <summary>
    /// CN allowlist. Ikkala shakl ham qabul qilinadi (birga kelsa —
    /// birlashtiriladi):
    ///
    ///   massiv:  Internal__Tls__AllowedClients__0=edge-1  (yoki JSON massiv)
    ///   satr:    Internal__Tls__AllowedClients=edge-1,edge-2
    ///
    /// Har bir qiymat trim qilinadi, bo'shlari tashlanadi, takrorlar bitta.
    /// </summary>
    public static IReadOnlyList<string> ParseAllowedClients(IConfigurationSection section)
    {
        ArgumentNullException.ThrowIfNull(section);

        var raw = new List<string?> { section.Value };
        raw.AddRange(section.GetChildren().Select(child => child.Value));

        return raw
            .Where(value => value is not null)
            .SelectMany(value => value!.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
            .Distinct(StringComparer.Ordinal)
            .ToArray();
    }
}

/// <summary>
/// Ichki listener transporti: mTLS (A-S5) yoki faqat loopback'da h2c.
///
///   mTLS yoqilgan  — HTTPS, faqat HTTP/2, TLS 1.3, klient sertifikati
///                    MAJBURIY: ClientCaPath'ga zanjir + clientAuth EKU +
///                    CN allowlist'da. Rad etish TLS handshake'da.
///   mTLS o'chiq    — ochiq matnli h2c, lekin FAQAT loopback manzilda
///                    (127.0.0.0/8, ::1). Aks holda server ishga tushmaydi.
///
/// Admin kaliti va guard middleware o'z joyida qoladi (chuqur himoya).
/// </summary>
public sealed class InternalTls
{
    private const string ClientAuthEkuOid = "1.3.6.1.5.5.7.3.2";
    private const string CommonNameOid = "2.5.4.3";

    private readonly X509Certificate2? _serverCertificate;
    private readonly X509Certificate2Collection _clientTrustAnchors = [];
    private readonly HashSet<string> _allowedClients = new(StringComparer.Ordinal);

    private InternalTls(IPAddress address, int port)
    {
        Address = address;
        Port = port;
    }

    private InternalTls(
        IPAddress address,
        int port,
        X509Certificate2 serverCertificate,
        X509Certificate2Collection clientTrustAnchors,
        IEnumerable<string> allowedClients)
        : this(address, port)
    {
        _serverCertificate = serverCertificate;
        _clientTrustAnchors = clientTrustAnchors;
        _allowedClients.UnionWith(allowedClients);
    }

    public IPAddress Address { get; }

    public int Port { get; }

    public bool MutualTlsEnabled => _serverCertificate is not null;

    /// <summary>
    /// macOS'da .NET server tomonida Apple SecureTransport'ni ishlatadi, u
    /// TLS 1.3'ni QO'LLAMAYDI (Network.framework faqat klient tomonda). Shu
    /// sabab macOS'da (faqat dev) TLS 1.2 ham ruxsat etiladi; Linux (prod)
    /// da — faqat TLS 1.3.
    /// </summary>
    public static SslProtocols EnabledProtocols =>
        OperatingSystem.IsMacOS() ? SslProtocols.Tls12 | SslProtocols.Tls13 : SslProtocols.Tls13;

    /// <summary>
    /// Sozlamalarni o'qiydi, fayllarni yuklaydi va tekshiradi. Har qanday
    /// muammo — <see cref="InvalidOperationException"/> (server ishga
    /// tushmaydi). Yarim ishlaydigan mTLS bo'lmaydi.
    /// </summary>
    public static InternalTls Load(IConfiguration configuration, IPAddress address, int port)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentNullException.ThrowIfNull(address);

        var options = InternalTlsOptions.Read(configuration);
        if (options is null)
        {
            // mTLS'siz ichki gRPC va operator API'ni himoya qiladigan yagona
            // narsa — admin kaliti. Tarmoqqa bunday holda chiqmaymiz (S-11).
            if (!IPAddress.IsLoopback(address))
            {
                throw new InvalidOperationException(
                    $"Internal:Address loopback emas ({address}), lekin mTLS o'chirilgan "
                    + "(Internal:Tls:CertPath bo'sh). Ichki listener tarmoqqa faqat mTLS bilan "
                    + "chiqadi (A-S5): Internal:Tls:CertPath, KeyPath, ClientCaPath va "
                    + "AllowedClients'ni bering yoki Internal:Address'ni 127.0.0.1 qiling.");
            }

            return new InternalTls(address, port);
        }

        Require(options.KeyPath, "KeyPath", "server sertifikatining yopiq kaliti (PEM)");
        Require(options.ClientCaPath, "ClientCaPath", "klient sertifikatlari CA to'plami (PEM)");

        if (options.AllowedClients.Count == 0)
        {
            throw new InvalidOperationException(
                "Internal:Tls:AllowedClients bo'sh. mTLS yoqilganda kamida bitta ruxsat etilgan klient "
                + "CN'i kerak (masalan Internal__Tls__AllowedClients=edge-1,edge-2) — aks holda "
                + "hech bir edge ulana olmaydi.");
        }

        var serverCertificate = LoadServerCertificate(options.CertPath, options.KeyPath);
        var trustAnchors = LoadTrustAnchors(options.ClientCaPath);

        return new InternalTls(address, port, serverCertificate, trustAnchors, options.AllowedClients);
    }

    /// <summary>
    /// Listener protokoli va (yoqilgan bo'lsa) TLS'ni sozlaydi.
    /// <c>MarkInternal()</c> bu yerda EMAS — Program.cs'da, ko'rinib tursin.
    /// </summary>
    public void Configure(ListenOptions listen, ILogger logger)
    {
        ArgumentNullException.ThrowIfNull(listen);
        ArgumentNullException.ThrowIfNull(logger);

        listen.Protocols = HttpProtocols.Http2;

        if (_serverCertificate is null)
        {
            return;
        }

        listen.UseHttps(new HttpsConnectionAdapterOptions
        {
            ServerCertificate = _serverCertificate,
            SslProtocols = EnabledProtocols,
            ClientCertificateMode = ClientCertificateMode.RequireCertificate,

            // Revocation tekshirilmaydi: CRL/OCSP infratuzilmasi hali yo'q.
            // Tekshiruv yoqilsa, CRL nuqtasi bo'lmagan sertifikatlar
            // "RevocationStatusUnknown" bilan rad etilardi yoki har bir
            // handshake tarmoq so'roviga osilib qolardi. Kompromat bo'lgan
            // edge sertifikati hozircha AllowedClients'dan CN'ni olib
            // tashlash va/yoki CA'ni almashtirish orqali bekor qilinadi.
            CheckCertificateRevocation = false,

            // Kestrel bergan zanjir tizim ildizlari bilan qurilgan — undagi
            // xatolarga (sslPolicyErrors) qaramaymiz, zanjirni o'zimiz
            // faqat ClientCaPath bilan qayta quramiz.
            ClientCertificateValidation = (certificate, presentedChain, _) =>
            {
                if (TryValidateClientCertificate(certificate, presentedChain, out var reason))
                {
                    return true;
                }

                logger.LogWarning(
                    "Ichki listener: klient sertifikati rad etildi ({Reason}) — CN={ClientCn}, sha256={Thumbprint}",
                    reason,
                    SafeForLog(GetCommonName(certificate)),
                    certificate.GetCertHashString(HashAlgorithmName.SHA256));

                return false;
            },
        });
    }

    /// <summary>Qaysi rejim faol ekanini bir marta log'ga yozadi.</summary>
    public void LogMode(ILogger logger)
    {
        ArgumentNullException.ThrowIfNull(logger);

        if (_serverCertificate is null)
        {
            logger.LogInformation(
                "Ichki listener: {Address}:{Port}, ochiq matnli h2c (mTLS o'chiq, faqat loopback)",
                Address, Port);
            return;
        }

        logger.LogInformation(
            "Ichki listener: {Address}:{Port}, mTLS (HTTP/2, {Protocols}), ruxsat etilgan klientlar: {AllowedClients}",
            Address, Port, EnabledProtocols, string.Join(",", _allowedClients.Order(StringComparer.Ordinal)));

        if (OperatingSystem.IsMacOS())
        {
            logger.LogWarning(
                "macOS: server tomonida TLS 1.3 qo'llanmaydi (SecureTransport) — ichki listener TLS 1.2 "
                + "ham qabul qiladi. Bu faqat dev uchun; prod (Linux) faqat TLS 1.3.");
        }
    }

    /// <summary>
    /// Klient sertifikatini tekshiradi (handshake vaqtida chaqiriladi):
    ///
    /// 1. Zanjir FAQAT ClientCaPath ildizlariga (CustomRootTrust), muddat
    ///    tekshiriladi, revocation — yo'q (qarang <see cref="Configure"/>).
    /// 2. Sertifikatda EKU kengaytmasi bo'lsa — clientAuth bo'lishi shart
    ///    (serverAuth-only sertifikat klient sifatida ishlatilmaydi).
    /// 3. Subject CN — aynan bitta va allowlist'da (ordinal).
    /// </summary>
    internal bool TryValidateClientCertificate(
        X509Certificate2 certificate,
        X509Chain? presentedChain,
        out string reason)
    {
        ArgumentNullException.ThrowIfNull(certificate);

        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.AddRange(_clientTrustAnchors);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;

        // Klient yuborgan oraliq sertifikatlar faqat zanjir QURISH uchun
        // (ExtraStore ishonchli emas) — ishonch faqat CustomTrustStore'dan.
        if (presentedChain is not null)
        {
            foreach (var element in presentedChain.ChainElements)
            {
                if (!element.Certificate.RawDataMemory.Span.SequenceEqual(certificate.RawDataMemory.Span))
                {
                    chain.ChainPolicy.ExtraStore.Add(element.Certificate);
                }
            }
        }

        if (!chain.Build(certificate))
        {
            var statuses = chain.ChainStatus
                .Select(status => status.Status.ToString())
                .Distinct(StringComparer.Ordinal);
            reason = "zanjir ClientCaPath'ga qurilmadi: " + string.Join(",", statuses);
            return false;
        }

        var eku = certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>().FirstOrDefault();
        if (eku is not null
            && !eku.EnhancedKeyUsages.Cast<Oid>().Any(oid => oid.Value == ClientAuthEkuOid))
        {
            reason = "EKU'da clientAuth yo'q";
            return false;
        }

        var commonName = GetCommonName(certificate);
        if (commonName is null)
        {
            reason = "Subject'da aynan bitta CN yo'q";
            return false;
        }

        if (!_allowedClients.Contains(commonName))
        {
            reason = "CN allowlist'da yo'q";
            return false;
        }

        reason = string.Empty;
        return true;
    }

    /// <summary>
    /// Subject'dagi CN — faqat aynan bitta bo'lsa. GetNameInfo(SimpleName)
    /// ishlatilmaydi: CN bo'lmasa u jimgina e-mail yoki SAN'ga o'tib ketadi.
    /// </summary>
    internal static string? GetCommonName(X509Certificate2 certificate)
    {
        string? found = null;
        foreach (var rdn in certificate.SubjectName.EnumerateRelativeDistinguishedNames())
        {
            if (rdn.HasMultipleElements || rdn.GetSingleElementType().Value != CommonNameOid)
            {
                continue;
            }

            if (found is not null)
            {
                return null;
            }

            found = rdn.GetSingleElementValue();
        }

        return found;
    }

    private static void Require(string value, string key, string what)
    {
        if (value.Length == 0)
        {
            throw new InvalidOperationException(
                $"Internal:Tls:{key} sozlanmagan ({what}). Internal:Tls:CertPath berilgan — mTLS "
                + "yoqilgan, shuning uchun CertPath, KeyPath, ClientCaPath va AllowedClients majburiy.");
        }
    }

    private static X509Certificate2 LoadServerCertificate(string certPath, string keyPath)
    {
        RequireFile(certPath, "CertPath");
        RequireFile(keyPath, "KeyPath");

        try
        {
            // Linux/macOS'da PEM'dan yuklangan (ephemeral) kalit SslStream
            // bilan to'g'ridan-to'g'ri ishlaydi. Windows (SChannel) PKCS#12
            // orqali qayta import talab qiladi — bizda Windows nishon emas.
            var certificate = X509Certificate2.CreateFromPemFile(certPath, keyPath);
            if (!certificate.HasPrivateKey)
            {
                throw new CryptographicException("sertifikat yopiq kalitga ega emas");
            }

            return certificate;
        }
        catch (Exception ex) when (ex is CryptographicException or ArgumentException or IOException
                                       or UnauthorizedAccessException)
        {
            throw new InvalidOperationException(
                $"Internal:Tls server sertifikati yuklanmadi (CertPath={certPath}, KeyPath={keyPath}): "
                + $"{ex.Message}. PEM formatini va kalit sertifikatga mosligini tekshiring.",
                ex);
        }
    }

    private static X509Certificate2Collection LoadTrustAnchors(string clientCaPath)
    {
        RequireFile(clientCaPath, "ClientCaPath");

        var anchors = new X509Certificate2Collection();
        try
        {
            anchors.ImportFromPemFile(clientCaPath);
        }
        catch (Exception ex) when (ex is CryptographicException or IOException or UnauthorizedAccessException)
        {
            throw new InvalidOperationException(
                $"Internal:Tls:ClientCaPath o'qilmadi ({clientCaPath}): {ex.Message}", ex);
        }

        if (anchors.Count == 0)
        {
            throw new InvalidOperationException(
                $"Internal:Tls:ClientCaPath ({clientCaPath}) da birorta ham PEM sertifikat yo'q.");
        }

        return anchors;
    }

    private static void RequireFile(string path, string key)
    {
        if (!File.Exists(path))
        {
            throw new InvalidOperationException(
                $"Internal:Tls:{key} fayli topilmadi: {path}");
        }
    }

    /// <summary>
    /// CN klient nazoratida — log in'yeksiyasiga qarshi boshqaruv belgilarini
    /// almashtiramiz va uzunlikni cheklaymiz.
    /// </summary>
    private static string SafeForLog(string? value)
    {
        if (value is null)
        {
            return "(yo'q)";
        }

        var cleaned = new string(value.Select(c => char.IsControl(c) ? '?' : c).ToArray());
        return cleaned.Length <= 64 ? cleaned : cleaned[..64] + "…";
    }
}
