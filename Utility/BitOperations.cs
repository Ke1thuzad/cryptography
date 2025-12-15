namespace Cryptography.Utility;

public static class BitOperations
{
    
    public static byte[] PermuteBits(byte[] bytes, byte[] P, bool MSB = true, bool indexFromOne = true) {
        ArgumentNullException.ThrowIfNull(bytes);
        ArgumentNullException.ThrowIfNull(P);

        int totalBits = bytes.Length * 8;
        int resultBits = P.Length;
        byte[] result = new byte[(resultBits + 7) / 8];

        Span<byte> bytesSpan = bytes;
        Span<byte> resultSpan = result;

        for (int i = 0; i < resultBits; i++) {
            int permutationPos = P[i];

            if (indexFromOne)
                permutationPos--;

            if (permutationPos < 0 || permutationPos >= totalBits)
                throw new ArgumentOutOfRangeException();

            SetBit(resultSpan, i, GetBit(bytesSpan, permutationPos, MSB), MSB);
        }

        return result;
    }
    
    public static bool GetBit(Span<byte> bytes, int index, bool MSB = true)
    {
        int bytePos = index >> 3;
        int bitPos = index & 0x07;

        if (MSB)
            bitPos = 7 - bitPos;

        return (bytes[bytePos] & (1 << bitPos)) != 0;
    }

    public static void SetBit(Span<byte> bytes, int index, bool bit, bool MSB = true)
    {
        int bytePos = index >> 3;
        int bitPos = index & 0x07;

        if (MSB)
            bitPos = 7 - bitPos;

        if (bit)
            bytes[bytePos] |= (byte)(1 << bitPos);
        else
            bytes[bytePos] &= (byte)~(1 << bitPos);
    }

    public static byte[] XORBytes(byte[] a, byte[] b) {
        int minLength = Math.Min(a.Length, b.Length);
        byte[] result = new byte[minLength];
        
        for (int i = 0; i < minLength; i++) {
            result[i] = (byte)(a[i] ^ b[i]);
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
    
    public static byte[] IncrementByDelta(byte[] counter, byte[] delta)
    {
        byte[] result = (byte[])counter.Clone();
        int carry = 0;

        for (int i = delta.Length - 1; i >= 0; i--)
        {
            int counterIndex = counter.Length - delta.Length + i;
            int sum = result[counterIndex] + delta[i] + carry;
            result[counterIndex] = (byte)(sum & 0xFF);
            carry = sum >> 8;
        }

        for (int i = counter.Length - delta.Length - 1; i >= 0 && carry > 0; i--)
        {
            int sum = result[i] + carry;
            result[i] = (byte)(sum & 0xFF);
            carry = sum >> 8;
        }

        return result;
    }

    public static int BytesLength(byte[][] bytes) => bytes.Length * bytes[0].Length;

    public static uint BytesToUnsignedInt(byte[] bytes) =>
        (uint)((bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3]);

    public static uint LeftShift28(uint x, int shift)
    {
        x &= 0x0FFFFFFF;
        return ((x << shift) | (x >> (28 - shift))) & 0x0FFFFFFF;
    }
    
    public static byte[] ExtendKeyWithParity(byte[] key) {
        if (key.Length == 8)
            return key;
        
        if (key.Length != 7) {
            throw new ArgumentException("Key must be exactly 7 bytes long");
        }
    
        byte[] extendedKey = new byte[8];
    
        for (int i = 0; i < 7; i++) {
            extendedKey[i] = (byte) ((key[i] & 0xFE) | ((key[i] & 0x01) << 1));
        }
    
        extendedKey[7] = (byte) ((key[6] & 0x80) >> 7);
    
        for (int i = 0; i < 8; i++) {
            extendedKey[i] = AddParityBit(extendedKey[i]);
        }
    
        return extendedKey;
    }

    static byte AddParityBit(byte b) {
        int count = 0;
        for (int i = 7; i >= 1; i--) {
            if (((b >> i) & 0x01) == 1) {
                count++;
            }
        }
        
        if (count % 2 == 0) {
            return (byte) (b | 0x01);
        }

        return (byte) (b & 0xFE);
    }
    
    public static byte[] IncrementCounterByDelta(byte[] counter, byte[] delta)
    {
        byte[] result = (byte[])counter.Clone();
        int carry = 0;

        for (int i = delta.Length - 1; i >= 0; i--)
        {
            int counterIndex = counter.Length - delta.Length + i;
            int sum = result[counterIndex] + delta[i] + carry;
            result[counterIndex] = (byte)(sum & 0xFF);
            carry = sum >> 8;
        }

        for (int i = counter.Length - delta.Length - 1; i >= 0 && carry > 0; i--)
        {
            int sum = result[i] + carry;
            result[i] = (byte)(sum & 0xFF);
            carry = sum >> 8;
        }

        return result;
    }
}