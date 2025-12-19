namespace Cryptography.SymmetricAlgorithms.DEAL;

public class DealFeistel(IBlockCipherAdapter blockCipher) : ICipherTransform
{
    public byte[] TransformBlock(byte[] block, byte[] roundKey) => blockCipher.EncryptBlock(block, roundKey);
}