namespace Cryptography;

public interface IAsymmetricCipher
{
    bool HasKey { get; }
    int KeySizeBits { get; } 
    
    byte[] Encrypt(byte[] data);
    byte[] Decrypt(byte[] encryptedData);
}