using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace AccessServer.IntegrationTests;

/// <summary>
/// Test uchun kichik PKI: CA, AP server sertifikati va turli klient
/// sertifikatlari — hammasi xotirada yasaladi, PEM'lari vaqtinchalik
/// papkaga yoziladi (Internal:Tls:* fayl yo'llarini kutadi).
/// </summary>
public sealed class TestPki : IDisposable
{
    public const string ClientAuthOid = "1.3.6.1.5.5.7.3.2";
    public const string ServerAuthOid = "1.3.6.1.5.5.7.3.1";

    private readonly ECDsa _caKey;

    public TestPki(string caName = "cc01 test CA")
    {
        Directory = Path.Combine(Path.GetTempPath(), "cc01-pki-" + Guid.NewGuid().ToString("n")[..12]);
        System.IO.Directory.CreateDirectory(Directory);

        _caKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest($"CN={caName}", _caKey, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));

        Ca = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-30), DateTimeOffset.UtcNow.AddYears(1));
        CaPath = Path.Combine(Directory, "ca.crt");
        File.WriteAllText(CaPath, Ca.ExportCertificatePem());
    }

    public string Directory { get; }

    public X509Certificate2 Ca { get; }

    public string CaPath { get; }

    /// <summary>AP server sertifikati: SAN localhost va 127.0.0.1, EKU serverAuth.</summary>
    public IssuedCertificate IssueServer() =>
        Issue("localhost", [ServerAuthOid], withSan: true);

    /// <summary>Klient sertifikati. <paramref name="ekus"/> null — EKU kengaytmasi umuman yo'q.</summary>
    public IssuedCertificate IssueClient(string commonName, string[]? ekus = null) =>
        Issue(commonName, ekus, withSan: false);

    public IssuedCertificate Issue(
        string commonName,
        string[]? ekus,
        bool withSan,
        DateTimeOffset? notBefore = null,
        DateTimeOffset? notAfter = null)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest($"CN={commonName}", key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));

        if (ekus is not null)
        {
            var oids = new OidCollection();
            foreach (var eku in ekus)
            {
                oids.Add(new Oid(eku));
            }

            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(oids, false));
        }

        if (withSan)
        {
            var san = new SubjectAlternativeNameBuilder();
            san.AddDnsName("localhost");
            san.AddIpAddress(IPAddress.Loopback);
            request.CertificateExtensions.Add(san.Build());
        }

        using var publicOnly = request.Create(
            Ca,
            notBefore ?? DateTimeOffset.UtcNow.AddDays(-1),
            notAfter ?? DateTimeOffset.UtcNow.AddDays(30),
            RandomNumberGenerator.GetBytes(12));

        var name = commonName + "-" + Guid.NewGuid().ToString("n")[..6];
        var certPath = Path.Combine(Directory, name + ".crt");
        var keyPath = Path.Combine(Directory, name + ".key");
        File.WriteAllText(certPath, publicOnly.ExportCertificatePem());
        File.WriteAllText(keyPath, key.ExportPkcs8PrivateKeyPem());

        return new IssuedCertificate(X509Certificate2.CreateFromPemFile(certPath, keyPath), certPath, keyPath);
    }

    public void Dispose()
    {
        _caKey.Dispose();
        Ca.Dispose();

        try
        {
            System.IO.Directory.Delete(Directory, recursive: true);
        }
        catch (IOException)
        {
            // Vaqtinchalik papka — o'chmasa ham test natijasiga ta'sir qilmaydi.
        }
    }
}

public sealed record IssuedCertificate(X509Certificate2 Certificate, string CertPath, string KeyPath);
