namespace AccessServer.Application.Abstractions;

public readonly record struct GeneratedVerificationToken(string Secret, byte[] Hash);

public interface IVerificationTokenFactory
{
    GeneratedVerificationToken Create();

    byte[] ComputeHash(string token);
}
