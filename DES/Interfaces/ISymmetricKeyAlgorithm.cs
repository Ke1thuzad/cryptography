namespace Cryptography.DES;

public interface ISymmetricKeyAlgorithm
{
    int BlockSize { get; }
    
    void SetKey(byte[] key);
    
    Task<byte[]> Encrypt(byte[] block);
    Task<byte[]> Decrypt(byte[] block);
}