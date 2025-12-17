using Cryptography.Utility;

namespace Cryptography.SymmetricAlgorithms.AESRijndael;

class RijndaelSBox
{
    readonly byte modulus;
    readonly Lazy<byte[]> sBoxLazy;
    readonly Lazy<byte[]> invSBoxLazy;

    public byte[] Forward => sBoxLazy.Value;
    public byte[] Inverse => invSBoxLazy.Value;

    public RijndaelSBox(byte modulus)
    {
        this.modulus = modulus;
        sBoxLazy = new Lazy<byte[]>(GenerateSBox);
        invSBoxLazy = new Lazy<byte[]>(GenerateInvSBox);
    }

    byte[] GenerateSBox()
    {
        byte[] sBox = new byte[256];
        for (int i = 0; i < 256; i++)
        {
            byte inverse = GaloisField8.Inverse((byte)i, modulus);
            sBox[i] = ApplyAffineTransform(inverse);
        }
        return sBox;
    }

    byte[] GenerateInvSBox()
    {
        byte[] invSBox = new byte[256];
        for (int i = 0; i < 256; i++)
        {
            byte invAffine = ApplyInverseAffineTransform((byte)i);
            invSBox[i] = GaloisField8.Inverse(invAffine, modulus);
        }
        return invSBox;
    }

    static byte ApplyAffineTransform(byte b)
    {
        byte result = 0;
        byte c = 0x63; 
        
        for (int i = 0; i < 8; i++)
        {
            int bit = (b >> i) & 1;
            bit ^= (b >> ((i + 4) % 8)) & 1;
            bit ^= (b >> ((i + 5) % 8)) & 1;
            bit ^= (b >> ((i + 6) % 8)) & 1;
            bit ^= (b >> ((i + 7) % 8)) & 1;
            bit ^= (c >> i) & 1;
            
            result |= (byte)(bit << i);
        }
        return result;
    }

    static byte ApplyInverseAffineTransform(byte b)
    {
        byte result = 0;
        byte d = 0x05;

        for (int i = 0; i < 8; i++)
        {
            int bit = (b >> ((i + 2) % 8)) & 1;
            bit ^= (b >> ((i + 5) % 8)) & 1;
            bit ^= (b >> ((i + 7) % 8)) & 1;
            bit ^= (d >> i) & 1;

            result |= (byte)(bit << i);
        }
        return result;
    }
}