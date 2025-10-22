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

    public static byte[] XORBytes(byte[] a, byte[] b, bool MSB = true)
    {
        int maxLength = Math.Max(a.Length, b.Length);
        byte[] result = new byte[maxLength];
    
        for (int i = 0; i < maxLength; i++)
        {
            byte byteA = 0;
            byte byteB = 0;
        
            if (MSB)
            {
                int indexA = a.Length - maxLength + i;
                int indexB = b.Length - maxLength + i;
                byteA = indexA >= 0 ? a[indexA] : (byte)0;
                byteB = indexB >= 0 ? b[indexB] : (byte)0;
            }
            else
            {
                byteA = i < a.Length ? a[i] : (byte)0;
                byteB = i < b.Length ? b[i] : (byte)0;
            }
        
            result[i] = (byte)(byteA ^ byteB);
        }
    
        return result;
    }
    
    public static void IncrementCounter(byte[] counter) {
        for (int i = counter.Length - 1; i >= 0; i--)
        {
            if (++counter[i] != 0)
                break;
        }
    }
    
    public static byte[] AddBytes(byte[] a, byte[] b)
    {
        int maxLength = Math.Max(a.Length, b.Length);
        byte[] result = new byte[maxLength];
        int carry = 0;

        for (int i = 0; i < maxLength; i++)
        {
            int sum = carry;
        
            int indexA = a.Length - 1 - i;
            int indexB = b.Length - 1 - i;

            if (indexA >= 0)
                sum += a[indexA];
            if (indexB >= 0)
                sum += b[indexB];

            carry = sum / 256;
            result[result.Length - 1 - i] = (byte)(sum % 256);
        }

        return result;
    }

    public static int BytesLength(byte[][] bytes) => bytes.Length * bytes[0].Length;
}