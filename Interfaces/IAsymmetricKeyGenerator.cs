using Cryptography.Context.Asymmetric;

namespace Cryptography;

public interface IAsymmetricKeyGenerator : IAsymmetricAlgorithm
{
    AsymmetricKeyPair GenerateKeyPair();
}