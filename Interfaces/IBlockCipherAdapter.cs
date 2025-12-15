namespace Cryptography;

public interface IBlockCipherAdapter
{
    byte[] EncryptBlock(byte[] block, byte[] key);
    byte[] DecryptBlock(byte[] block, byte[] key);
    int BlockSize { get; }
    int KeySize { get; }
}