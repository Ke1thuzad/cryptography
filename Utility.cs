using System;

namespace Cryptography;

public static class Utility
{
    public static byte[] PermuteBits(byte[] bytes, byte[] P, bool MSB = true, bool indexFromOne = true)
    {
        ArgumentNullException.ThrowIfNull(bytes);
        ArgumentNullException.ThrowIfNull(P);

        int totalBits = bytes.Length * 8;
        int resultBits = P.Length;
        byte[] result = new byte[(resultBits + 7) / 8];

        for (int i = 0; i < resultBits; i++)
        {
            int sourcePos = P[i];
            
            if (indexFromOne) 
                sourcePos--;

            if (sourcePos < 0 || sourcePos >= totalBits)
                throw new ArgumentOutOfRangeException();

            int sourceByteIndex = sourcePos / 8;
            int sourceBitIndex = sourcePos % 8;
            
            if (MSB) 
                sourceBitIndex = 7 - sourceBitIndex;
            
            bool bit = (bytes[sourceByteIndex] & (1 << sourceBitIndex)) != 0;

            int resultByteIndex = i / 8;
            int resultBitIndex = i % 8;
            
            if (MSB) 
                resultBitIndex = 7 - resultBitIndex;

            if (bit)
                result[resultByteIndex] |= (byte)(1 << resultBitIndex);
            else
                result[resultByteIndex] &= (byte)~(1 << resultBitIndex);
        }

        return result;
    }
}