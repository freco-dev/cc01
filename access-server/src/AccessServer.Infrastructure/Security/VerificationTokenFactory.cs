using System.Security.Cryptography;
using System.Text;
using AccessServer.Application.Abstractions;

namespace AccessServer.Infrastructure.Security;

public sealed class VerificationTokenFactory : IVerificationTokenFactory
{
    private const int SecretBytes = 32;

    public GeneratedVerificationToken Create()
    {
        var secret = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(SecretBytes));
        return new GeneratedVerificationToken(secret, ComputeHash(secret));
    }

    public byte[] ComputeHash(string token) =>
        SHA256.HashData(Encoding.UTF8.GetBytes(token));
}
