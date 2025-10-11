using System;

namespace Cryptography;

public static class Utility
{
    public static byte[] PermuteBits(byte[] bytes, byte[] P, bool MSB = true, bool indexFromOne = true) {
        ArgumentNullException.ThrowIfNull(bytes);
        ArgumentNullException.ThrowIfNull(P);

        int totalBits = bytes.Length * 8;
        int resultBits = P.Length;
        byte[] result = new byte[(resultBits + 7) / 8];

        for (int i = 0; i < resultBits; i++) {
            int permutationPos = P[i];

            if (indexFromOne)
                permutationPos--;

            if (permutationPos < 0 || permutationPos >= totalBits)
                throw new ArgumentOutOfRangeException();

            SetBit(result, i, GetBit(bytes, permutationPos, MSB), MSB);
        }

        return result;
    }

    public static bool GetBit(byte[] bytes, int index, bool MSB = true) {
        int bytePos = index / 8;
        int bitPos = index % 8;

        if (MSB)
            bitPos = 7 - bitPos;

        return (bytes[bytePos] & (1 << bitPos)) != 0;
    }

    public static void SetBit(byte[] bytes, int index, bool bit, bool MSB = true) {
        int bytePos = index / 8;
        int bitPos = index % 8;

        if (MSB)
            bitPos = 7 - bitPos;

        if (bit)
            bytes[bytePos] |= (byte)(1 << bitPos);
        else
            bytes[bytePos] &= (byte)~(1 << bitPos);
    }
}