namespace Cryptography;

public interface ICipherTransform
{
    byte[] TransformBlock(byte[] block, byte[] roundKey);
}