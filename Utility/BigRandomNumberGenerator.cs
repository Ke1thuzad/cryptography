using System.Numerics;

namespace Cryptography.Utility;

public class BigRandomNumberGenerator
{
    readonly Random random = new();

    public BigInteger GetRandomBigInteger(long bitLength)
    {
        if (bitLength < 2)
        {
            throw new ArgumentException("bitLength must be at least 2", nameof(bitLength));
        }

        long byteCount = (bitLength + 7) / 8;
        byte[] data = new byte[byteCount];
        
        random.NextBytes(data);
        
        data[0] |= 0x01;
        
        long lastBitIndex = bitLength - 1;
        long lastByteIndex = lastBitIndex / 8;
        long bitOffset = lastBitIndex % 8;
        
        data[lastByteIndex] |= (byte)(1 << (int)bitOffset);
        
        long bitsInLastByte = bitLength % 8;
        if (bitsInLastByte == 0)
        {
            bitsInLastByte = 8;
        }
        
        byte mask = (byte)((1 << (int)bitsInLastByte) - 1);
        data[lastByteIndex] &= mask;
        
        return new BigInteger(data, isUnsigned: true);
    }
}