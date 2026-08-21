namespace AccessServer.Infrastructure.Auth.OAuth;

public sealed class OAuthProvidersOptions
{
    public const string SectionName = "OAuth";

    public OAuthProviderOptions Github { get; set; } = new();

    public OAuthProviderOptions Google { get; set; } = new();
}

public sealed class OAuthProviderOptions
{
    public string ClientId { get; set; } = string.Empty;

    public string ClientSecret { get; set; } = string.Empty;

    /// <summary>
    /// Sozlanmagan provayder uchun sxema ro'yxatga OLINMAYDI. Shunda dev
    /// muhitida sirlarsiz ham server ishga tushadi, endpoint esa aniq xato
    /// qaytaradi ("provider not configured") — yashirin 500 emas.
    /// </summary>
    public bool IsConfigured =>
        !string.IsNullOrWhiteSpace(ClientId) && !string.IsNullOrWhiteSpace(ClientSecret);
}
