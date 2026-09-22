namespace Haley.Abstractions;

public interface ISecretTokenGenerator
{
    SecretToken Generate();
    byte[] Hash(string token);
}
