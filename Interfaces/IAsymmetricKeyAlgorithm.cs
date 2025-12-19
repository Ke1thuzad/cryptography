namespace Cryptography;

public interface IAsymmetricKeyAlgorithm
{
    bool HasKey { get; }
    int KeySizeBits { get; } 
    
    byte[] Encrypt(byte[] data);
    byte[] Decrypt(byte[] encryptedData);
}