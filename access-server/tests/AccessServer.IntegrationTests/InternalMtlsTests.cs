using System.Buffers.Binary;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using AccessServer.Api.Common;
using Cc01.V1;
using Google.Protobuf;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace AccessServer.IntegrationTests;

/// <summary>
/// Ichki listener mTLS (A-S5, S-11) — HAQIQIY Kestrel va haqiqiy TLS
/// handshake orqali. Sertifikatlar testda yasaladi (<see cref="TestPki"/>).
/// </summary>
[Collection(PostgresCollection.Name)]
public sealed class InternalMtlsTests(PostgresFixture fixture) : IAsyncLifetime
{
    private const string AdminKey = "mtls-test-admin-key";

    private readonly TestPki _pki = new();
    private readonly TestPki _otherPki = new("cc01 boshqa CA");

    private KestrelAccessApi _api = null!;

    public Task InitializeAsync()
    {
        var server = _pki.IssueServer();

        _api = KestrelAccessApi.Start(fixture.ConnectionString, AdminKey, new Dictionary<string, string?>
        {
            ["Internal:Tls:CertPath"] = server.CertPath,
            ["Internal:Tls:KeyPath"] = server.KeyPath,
            ["Internal:Tls:ClientCaPath"] = _pki.CaPath,
            ["Internal:Tls:AllowedClients"] = " edge-1 , edge-2 ",
        });

        return Task.CompletedTask;
    }

    public async Task DisposeAsync()
    {
        await _api.DisposeAsync();
        _pki.Dispose();
        _otherPki.Dispose();
    }

    /// <summary>
    /// Ichki listener'ga HTTPS + HTTP/2 klient. Server sertifikati faqat test
    /// CA'ga nisbatan tekshiriladi. Klient sertifikati selection callback
    /// orqali MAJBURAN yuboriladi — aks holda SslStream server e'lon qilgan
    /// CA ro'yxatiga mos kelmagan sertifikatni umuman yubormasligi mumkin va
    /// "boshqa CA" testi aslida "sertifikatsiz" testiga aylanib qolardi.
    /// </summary>
    private HttpClient InternalClient(X509Certificate2? clientCertificate)
    {
        var handler = new SocketsHttpHandler
        {
            SslOptions = new SslClientAuthenticationOptions
            {
                CertificateChainPolicy = TrustTestCa(),
                LocalCertificateSelectionCallback = clientCertificate is null
                    ? null
                    : (_, _, _, _, _) => clientCertificate,
            },
        };

        // ⚠️ DefaultRequestVersion SendAsync(HttpRequestMessage) ga ta'sir
        // qilmaydi — so'rovlar versiyani o'zi beradi (qarang Http2Request).
        return new HttpClient(handler)
        {
            BaseAddress = new Uri($"https://127.0.0.1:{_api.InternalPort}"),
        };
    }

    private X509ChainPolicy TrustTestCa()
    {
        var policy = new X509ChainPolicy
        {
            TrustMode = X509ChainTrustMode.CustomRootTrust,
            RevocationMode = X509RevocationMode.NoCheck,
        };
        policy.CustomTrustStore.Add(_pki.Ca);
        return policy;
    }

    /// <summary>
    /// Ichki listener faqat HTTP/2: TLS'da ALPN orqali "h2" kelishilmasa
    /// Kestrel ulanishni yopadi.
    /// </summary>
    private static HttpRequestMessage Http2Request(HttpMethod method, string path) => new(method, path)
    {
        Version = HttpVersion.Version20,
        VersionPolicy = HttpVersionPolicy.RequestVersionExact,
    };

    /// <summary>gRPC unary qo'lda: 1 bayt siqish bayrog'i + 4 bayt uzunlik (big-endian) + protobuf.</summary>
    private static HttpRequestMessage GrpcAuthorizeRequest()
    {
        var payload = new AuthorizeTunnelRequest { Token = "cc01_invalid", Protocol = Protocol.Http }.ToByteArray();
        var framed = new byte[5 + payload.Length];
        BinaryPrimitives.WriteUInt32BigEndian(framed.AsSpan(1, 4), (uint)payload.Length);
        payload.CopyTo(framed, 5);

        var request = Http2Request(HttpMethod.Post, "/cc01.v1.AccessInternalService/AuthorizeTunnel");
        request.Content = new ByteArrayContent(framed);
        request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/grpc");
        request.Headers.TE.Add(new TransferCodingWithQualityHeaderValue("trailers"));
        return request;
    }

    private async Task AssertRejectedAsync(X509Certificate2? clientCertificate)
    {
        using var client = InternalClient(clientCertificate);
        using var request = GrpcAuthorizeRequest();

        // TLS 1.2'da handshake'ning o'zi yiqiladi; TLS 1.3'da klient
        // handshake'ni tugatgan deb hisoblaydi va server alert'ini birinchi
        // o'qishda oladi — ikkala holda ham so'rov handler'ga yetmaydi.
        await Assert.ThrowsAnyAsync<HttpRequestException>(() => client.SendAsync(request));
    }

    [Fact]
    public async Task Allowed_client_cert_reaches_grpc_AuthorizeTunnel()
    {
        using var client = InternalClient(_pki.IssueClient("edge-1", [TestPki.ClientAuthOid]).Certificate);
        using var request = GrpcAuthorizeRequest();

        using var response = await client.SendAsync(request);
        var bytes = await response.Content.ReadAsByteArrayAsync();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(HttpVersion.Version20, response.Version);
        Assert.Equal("0", response.TrailingHeaders.GetValues("grpc-status").Single());

        var reply = AuthorizeTunnelResponse.Parser.ParseFrom(bytes.AsSpan(5).ToArray());
        Assert.Equal(AuthorizeTunnelResponse.ResultOneofCase.Denial, reply.ResultCase);
        Assert.Equal(DenialCode.TokenInvalid, reply.Denial.Code);
    }

    // grpc-go TLS'da :authority sifatida PORTSIZ ServerName ni yuboradi
    // ("127.0.0.1"). Endpoint Host'ga bog'langan bo'lsa (RequireHost("*:port"))
    // haqiqiy edge so'rovi 404 olardi — make plan-demo shuni topgan.
    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("localhost")]
    public async Task Grpc_is_served_whatever_the_authority(string authority)
    {
        using var client = InternalClient(_pki.IssueClient("edge-1", [TestPki.ClientAuthOid]).Certificate);
        using var request = GrpcAuthorizeRequest();
        request.Headers.Host = authority;

        using var response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("0", response.TrailingHeaders.GetValues("grpc-status").Single());
    }

    [Fact]
    public async Task Allowed_client_cert_still_needs_admin_key_on_operator_api()
    {
        using var client = InternalClient(_pki.IssueClient("edge-2", [TestPki.ClientAuthOid]).Certificate);
        using var request = Http2Request(HttpMethod.Put, "/internal/v1/tenants/t_whatever/subscription");
        request.Content = JsonContent(new { plan = "pro" });

        using var response = await client.SendAsync(request);

        // mTLS ulanishni o'tkazdi; admin kaliti (chuqur himoya) to'xtatdi.
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal("ADMIN_KEY_INVALID", body.RootElement.GetProperty("code").GetString());
    }

    [Fact]
    public Task No_client_cert_is_rejected() => AssertRejectedAsync(null);

    [Fact]
    public Task Client_cn_not_in_allowlist_is_rejected() =>
        AssertRejectedAsync(_pki.IssueClient("edge-3", [TestPki.ClientAuthOid]).Certificate);

    [Fact]
    public Task Client_cn_match_is_case_sensitive() =>
        AssertRejectedAsync(_pki.IssueClient("EDGE-1", [TestPki.ClientAuthOid]).Certificate);

    [Fact]
    public Task Client_cert_from_other_ca_is_rejected() =>
        AssertRejectedAsync(_otherPki.IssueClient("edge-1", [TestPki.ClientAuthOid]).Certificate);

    [Fact]
    public Task Client_cert_with_server_auth_only_eku_is_rejected() =>
        AssertRejectedAsync(_pki.IssueClient("edge-1", [TestPki.ServerAuthOid]).Certificate);

    [Fact]
    public async Task Plaintext_h2c_to_internal_listener_fails()
    {
        using var request = GrpcAuthorizeRequest();

        await Assert.ThrowsAnyAsync<HttpRequestException>(() => _api.Internal.SendAsync(request));
    }

    [Fact]
    public async Task Public_listener_stays_plain_http()
    {
        using var response = await _api.Public.GetAsync("/livez");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("http", _api.Public.BaseAddress!.Scheme);
    }

    /// <summary>
    /// Linux (prod): faqat TLS 1.3, TLS 1.2 klient rad etiladi. macOS'da
    /// server tomonda TLS 1.3 yo'q (SecureTransport) — dev uchun 1.2 ga
    /// tushadi (qarang <see cref="InternalTls.EnabledProtocols"/>).
    /// </summary>
    [Fact]
    public async Task Negotiates_tls13_and_h2_except_macos_dev_fallback()
    {
        var client = _pki.IssueClient("edge-1", [TestPki.ClientAuthOid]).Certificate;

        await using (var ssl = await HandshakeAsync(client, SslProtocols.None))
        {
            var expected = OperatingSystem.IsMacOS() ? SslProtocols.Tls12 : SslProtocols.Tls13;
            Assert.Equal(expected, ssl.SslProtocol);
            Assert.Equal(SslApplicationProtocol.Http2, ssl.NegotiatedApplicationProtocol);
        }

        if (!OperatingSystem.IsMacOS())
        {
            await Assert.ThrowsAnyAsync<Exception>(() => HandshakeAsync(client, SslProtocols.Tls12));
        }
    }

    private async Task<SslStream> HandshakeAsync(X509Certificate2 clientCertificate, SslProtocols protocols)
    {
        var tcp = new TcpClient();
        await tcp.ConnectAsync(IPAddress.Loopback, _api.InternalPort);

        var ssl = new SslStream(tcp.GetStream(), leaveInnerStreamOpen: false);
        try
        {
            await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = "localhost",
                EnabledSslProtocols = protocols,
                ApplicationProtocols = [SslApplicationProtocol.Http2],
                CertificateChainPolicy = TrustTestCa(),
                LocalCertificateSelectionCallback = (_, _, _, _, _) => clientCertificate,
            });

            return ssl;
        }
        catch
        {
            await ssl.DisposeAsync();
            tcp.Dispose();
            throw;
        }
    }

    private static StringContent JsonContent(object value) =>
        new(JsonSerializer.Serialize(value), System.Text.Encoding.UTF8, "application/json");
}

/// <summary>
/// Noto'g'ri sozlama — server ishga TUSHMAYDI (haqiqiy host qurilishi orqali).
/// </summary>
[Collection(PostgresCollection.Name)]
public sealed class InternalMtlsStartupTests(PostgresFixture fixture) : IDisposable
{
    private readonly TestPki _pki = new();

    public void Dispose() => _pki.Dispose();

    private Dictionary<string, string?> ValidTls()
    {
        var server = _pki.IssueServer();
        return new Dictionary<string, string?>
        {
            ["Internal:Tls:CertPath"] = server.CertPath,
            ["Internal:Tls:KeyPath"] = server.KeyPath,
            ["Internal:Tls:ClientCaPath"] = _pki.CaPath,
            ["Internal:Tls:AllowedClients"] = "edge-1",
        };
    }

    private string StartupError(Dictionary<string, string?> overrides)
    {
        var settings = new Dictionary<string, string?>
        {
            ["Public:Address"] = "127.0.0.1",
            ["Public:Port"] = "5098",
            ["Internal:Address"] = "127.0.0.1",
            ["Internal:Port"] = "5097",
        };

        foreach (var (key, value) in overrides)
        {
            settings[key] = value;
        }

        using var factory = new AccessApiFactory(fixture.ConnectionString, settings);
        factory.UseKestrel();

        var error = Assert.ThrowsAny<Exception>(factory.StartServer);

        var messages = new List<string>();
        for (Exception? e = error; e is not null; e = e.InnerException)
        {
            messages.Add(e.Message);
        }

        return string.Join(" | ", messages);
    }

    [Theory]
    [InlineData("0.0.0.0")]
    [InlineData("10.0.0.5")]
    [InlineData("::")]
    public void Non_loopback_internal_address_without_tls_fails(string address)
    {
        var message = StartupError(new() { ["Internal:Address"] = address });

        Assert.Contains("Internal:Address loopback emas", message, StringComparison.Ordinal);
    }

    [Fact]
    public void Tls_without_client_ca_path_fails()
    {
        var settings = ValidTls();
        settings.Remove("Internal:Tls:ClientCaPath");

        Assert.Contains("Internal:Tls:ClientCaPath sozlanmagan", StartupError(settings), StringComparison.Ordinal);
    }

    [Fact]
    public void Tls_with_empty_allowlist_fails()
    {
        var settings = ValidTls();
        settings["Internal:Tls:AllowedClients"] = " , ";

        Assert.Contains("Internal:Tls:AllowedClients bo'sh", StartupError(settings), StringComparison.Ordinal);
    }

    [Fact]
    public void Tls_with_unreadable_key_fails()
    {
        var settings = ValidTls();
        File.WriteAllText(settings["Internal:Tls:KeyPath"]!, "-----BEGIN PRIVATE KEY-----\nbm9wZQ==\n-----END PRIVATE KEY-----\n");

        Assert.Contains("server sertifikati yuklanmadi", StartupError(settings), StringComparison.Ordinal);
    }
}

/// <summary>
/// <see cref="InternalTls"/> va <see cref="InternalTlsOptions"/> — Kestrel'siz.
/// </summary>
public sealed class InternalTlsTests : IDisposable
{
    private readonly TestPki _pki = new();

    public void Dispose() => _pki.Dispose();

    private static IConfiguration Config(Dictionary<string, string?> values) =>
        new ConfigurationBuilder().AddInMemoryCollection(values).Build();

    private Dictionary<string, string?> ValidTls(string allowed = "edge-1")
    {
        var server = _pki.IssueServer();
        return new Dictionary<string, string?>
        {
            ["Internal:Tls:CertPath"] = server.CertPath,
            ["Internal:Tls:KeyPath"] = server.KeyPath,
            ["Internal:Tls:ClientCaPath"] = _pki.CaPath,
            ["Internal:Tls:AllowedClients"] = allowed,
        };
    }

    private InternalTls Load(Dictionary<string, string?> values, string address = "127.0.0.1") =>
        InternalTls.Load(Config(values), IPAddress.Parse(address), 5081);

    private static InvalidOperationException LoadFails(Func<InternalTls> load) =>
        Assert.Throws<InvalidOperationException>(load);

    // ── Allowlist parser ─────────────────────────────────────────────

    [Fact]
    public void Allowlist_comma_string_is_split_and_trimmed()
    {
        var section = Config(new() { ["A:AllowedClients"] = " edge-1, edge-2 ,,edge-1 " }).GetSection("A:AllowedClients");

        Assert.Equal(["edge-1", "edge-2"], InternalTlsOptions.ParseAllowedClients(section));
    }

    [Fact]
    public void Allowlist_configuration_array_is_accepted()
    {
        var section = Config(new()
        {
            ["A:AllowedClients:0"] = "edge-1",
            ["A:AllowedClients:1"] = " edge-2 ",
            ["A:AllowedClients:2"] = "",
        }).GetSection("A:AllowedClients");

        Assert.Equal(["edge-1", "edge-2"], InternalTlsOptions.ParseAllowedClients(section));
    }

    [Fact]
    public void Allowlist_from_json_array_is_accepted()
    {
        using var json = new MemoryStream("""{ "A": { "AllowedClients": ["edge-1", "Edge-1"] } }"""u8.ToArray());
        var section = new ConfigurationBuilder().AddJsonStream(json).Build().GetSection("A:AllowedClients");

        // Ordinal: katta-kichik harf farqli — ikkalasi alohida yozuv.
        Assert.Equal(["edge-1", "Edge-1"], InternalTlsOptions.ParseAllowedClients(section));
    }

    [Fact]
    public void Allowlist_missing_is_empty()
    {
        var section = Config([]).GetSection("A:AllowedClients");

        Assert.Empty(InternalTlsOptions.ParseAllowedClients(section));
    }

    // ── Load: rejim va startup tekshiruvlari ─────────────────────────

    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("127.1.2.3")]
    [InlineData("::1")]
    public void Without_tls_loopback_is_plaintext(string address)
    {
        var tls = Load([], address);

        Assert.False(tls.MutualTlsEnabled);
    }

    [Fact]
    public void With_tls_any_address_is_allowed()
    {
        var tls = Load(ValidTls(), "0.0.0.0");

        Assert.True(tls.MutualTlsEnabled);
    }

    [Fact]
    public void Partial_tls_config_without_cert_path_fails()
    {
        var error = LoadFails(() => Load(new() { ["Internal:Tls:ClientCaPath"] = _pki.CaPath }));

        Assert.Contains("qisman sozlangan", error.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("Internal:Tls:KeyPath", "Internal:Tls:KeyPath sozlanmagan")]
    [InlineData("Internal:Tls:ClientCaPath", "Internal:Tls:ClientCaPath sozlanmagan")]
    [InlineData("Internal:Tls:AllowedClients", "Internal:Tls:AllowedClients bo'sh")]
    public void Missing_tls_key_fails(string key, string expected)
    {
        var settings = ValidTls();
        settings.Remove(key);

        Assert.Contains(expected, LoadFails(() => Load(settings)).Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("Internal:Tls:CertPath")]
    [InlineData("Internal:Tls:KeyPath")]
    [InlineData("Internal:Tls:ClientCaPath")]
    public void Missing_tls_file_fails(string key)
    {
        var settings = ValidTls();
        settings[key] = Path.Combine(_pki.Directory, "does-not-exist.pem");

        Assert.Contains("fayli topilmadi", LoadFails(() => Load(settings)).Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Key_not_matching_cert_fails()
    {
        var settings = ValidTls();
        settings["Internal:Tls:KeyPath"] = _pki.IssueClient("other").KeyPath;

        Assert.Contains("server sertifikati yuklanmadi", LoadFails(() => Load(settings)).Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Client_ca_without_certificates_fails()
    {
        var settings = ValidTls();
        var empty = Path.Combine(_pki.Directory, "empty.pem");
        File.WriteAllText(empty, "bu PEM emas\n");
        settings["Internal:Tls:ClientCaPath"] = empty;

        Assert.Contains("birorta ham PEM sertifikat yo'q", LoadFails(() => Load(settings)).Message, StringComparison.Ordinal);
    }

    // ── Klient sertifikati tekshiruvi ────────────────────────────────

    private (bool Ok, string Reason) Validate(X509Certificate2 certificate, string allowed = "edge-1")
    {
        var tls = Load(ValidTls(allowed));
        var ok = tls.TryValidateClientCertificate(certificate, presentedChain: null, out var reason);
        return (ok, reason);
    }

    [Fact]
    public void Allowed_client_auth_cert_passes()
    {
        var (ok, reason) = Validate(_pki.IssueClient("edge-1", [TestPki.ClientAuthOid]).Certificate);

        Assert.True(ok, reason);
    }

    [Fact]
    public void Cert_without_eku_extension_passes()
    {
        var (ok, reason) = Validate(_pki.IssueClient("edge-1", ekus: null).Certificate);

        Assert.True(ok, reason);
    }

    [Fact]
    public void Server_auth_only_cert_is_rejected_for_eku()
    {
        var (ok, reason) = Validate(_pki.IssueClient("edge-1", [TestPki.ServerAuthOid]).Certificate);

        Assert.False(ok);
        Assert.Contains("clientAuth", reason, StringComparison.Ordinal);
    }

    [Fact]
    public void Cn_not_in_allowlist_is_rejected()
    {
        var (ok, reason) = Validate(_pki.IssueClient("edge-9", [TestPki.ClientAuthOid]).Certificate);

        Assert.False(ok);
        Assert.Contains("allowlist", reason, StringComparison.Ordinal);
    }

    [Fact]
    public void Other_ca_is_rejected_for_chain()
    {
        using var other = new TestPki("boshqa CA");
        var (ok, reason) = Validate(other.IssueClient("edge-1", [TestPki.ClientAuthOid]).Certificate);

        Assert.False(ok);
        Assert.Contains("zanjir", reason, StringComparison.Ordinal);
    }

    [Fact]
    public void Expired_cert_is_rejected_for_chain()
    {
        var expired = _pki.Issue(
            "edge-1",
            [TestPki.ClientAuthOid],
            withSan: false,
            notBefore: DateTimeOffset.UtcNow.AddDays(-10),
            notAfter: DateTimeOffset.UtcNow.AddDays(-1)).Certificate;

        var (ok, reason) = Validate(expired);

        Assert.False(ok);
        Assert.Contains("NotTimeValid", reason, StringComparison.Ordinal);
    }

    [Fact]
    public void Self_signed_cert_with_allowed_cn_is_rejected()
    {
        // Ildiz sertifikatining o'zi: CustomTrustStore'da yo'q boshqa CA.
        using var rogue = new TestPki("edge-1");
        var (ok, _) = Validate(rogue.Ca);

        Assert.False(ok);
    }

    [Fact]
    public void Common_name_is_read_from_subject_only()
    {
        using var key = System.Security.Cryptography.ECDsa.Create();
        var request = new CertificateRequest("O=cc01, E=edge-1@example.com", key, System.Security.Cryptography.HashAlgorithmName.SHA256);
        using var noCn = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        Assert.Null(InternalTls.GetCommonName(noCn));
        Assert.Equal("edge-1", InternalTls.GetCommonName(_pki.IssueClient("edge-1").Certificate));
    }
}
