namespace Cryptography.DES;

public interface ICipherTransform
{
    byte[] TransformBlock(byte[] block, byte[] roundKey);
}