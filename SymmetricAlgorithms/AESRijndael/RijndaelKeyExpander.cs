using Cryptography.Utility;

namespace Cryptography.SymmetricAlgorithms.AESRijndael;

public class RijndaelKeyExpander : IKeyExpander
{
    readonly int nb;
    readonly int nk;
    readonly byte modulus;
    readonly byte[] sBox;
    readonly uint[] rcon;

    public RijndaelKeyExpander(int blockSizeBytes, int keySizeBytes, byte modulus, byte[] sBox)
    {
        nb = blockSizeBytes / 4;
        nk = keySizeBytes / 4;
        RoundsCount = Math.Max(nb, nk) + 6;
        this.modulus = modulus;
        this.sBox = sBox;

        rcon = new uint[30];
        InitializeRcon();
    }

    public int RoundsCount { get; }

    public byte[][] ExpandKeyToRounds(byte[] key)
    {
        if (key.Length != nk * 4)
            throw new ArgumentException("Key length does not match configuration.");

        int expandedKeyLengthWords = nb * (RoundsCount + 1);
        uint[] w = new uint[expandedKeyLengthWords];

        for (int i = 0; i < nk; i++)
        {
            w[i] = BitOperations.BytesToUnsignedInt([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]]);
        }

        for (int i = nk; i < expandedKeyLengthWords; i++)
        {
            uint temp = w[i - 1];

            if (i % nk == 0)
            {
                temp = SubWord(RotWord(temp)) ^ rcon[i / nk];
            }
            else if (nk > 6 && (i % nk) == 4)
            {
                temp = SubWord(temp);
            }

            w[i] = w[i - nk] ^ temp;
        }

        byte[][] roundKeys = new byte[RoundsCount + 1][];
        int blockSizeBytes = nb * 4;

        for (int r = 0; r <= RoundsCount; r++)
        {
            roundKeys[r] = new byte[blockSizeBytes];
            for (int c = 0; c < nb; c++)
            {
                uint word = w[r * nb + c];
                
                roundKeys[r][4 * c + 0] = (byte)((word >> 24) & 0xFF);
                roundKeys[r][4 * c + 1] = (byte)((word >> 16) & 0xFF);
                roundKeys[r][4 * c + 2] = (byte)((word >> 8) & 0xFF);
                roundKeys[r][4 * c + 3] = (byte)(word & 0xFF);
            }
        }

        return roundKeys;
    }

    uint SubWord(uint word)
    {
        return ((uint)sBox[(word >> 24) & 0xFF] << 24) |
               ((uint)sBox[(word >> 16) & 0xFF] << 16) |
               ((uint)sBox[(word >> 8) & 0xFF] << 8) |
               ((uint)sBox[word & 0xFF]);
    }

    static uint RotWord(uint word)
    {
        return (word << 8) | (word >> 24);
    }

    void InitializeRcon()
    {
        uint x = 1;
        for (int i = 1; i < rcon.Length; i++)
        {
            rcon[i] = x << 24;
            x = GaloisField8.Multiply((byte)x, 0x02, modulus);
        }
    }
}