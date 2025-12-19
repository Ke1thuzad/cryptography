using Cryptography.Utility;

namespace Cryptography.SymmetricAlgorithms.AESRijndael;

public class Rijndael : ISymmetricKeyAlgorithm
{
    readonly byte gfModulus;
    readonly RijndaelSBox sBoxProvider;
    readonly int nb;
    
    byte[][]? roundKeys;
    int nr;

    public static List<byte> AvailablePolynomials
    {
        get
        {
            return GaloisField8.GetAllIrreduciblePolysDeg8()
                .Select(p => (byte)(p & 0xFF))
                .ToList();
        }
    }
    
    public Rijndael(int blockSizeBits, byte polynomialModulus = 0x1B)
    {
        if (blockSizeBits != 128 && blockSizeBits != 192 && blockSizeBits != 256)
            throw new ArgumentException("Block size must be 128, 192, or 256 bits.", nameof(blockSizeBits));

        if (!GaloisField8.IsIrreducible(polynomialModulus))
            throw new ArgumentException($"Polynomial 0x{polynomialModulus:X} is not irreducible over GF(2^8).");
        
        BlockSize = blockSizeBits / 8;
        nb = BlockSize / 4;
        gfModulus = polynomialModulus;
        
        sBoxProvider = new RijndaelSBox(gfModulus);
    }

    public int BlockSize { get; }

    public void SetKey(byte[] key)
    {
        ArgumentNullException.ThrowIfNull(key);

        int keySizeBits = key.Length * 8;
        if (keySizeBits != 128 && keySizeBits != 192 && keySizeBits != 256)
            throw new ArgumentException("Key size must be 128, 192, or 256 bits.", nameof(key));

        RijndaelKeyExpander expander = new(BlockSize, key.Length, gfModulus, sBoxProvider.Forward);
        
        roundKeys = expander.ExpandKeyToRounds(key);
        nr = expander.RoundsCount;
    }

    public Task<byte[]> Encrypt(byte[] block)
    {
        if (block.Length != BlockSize)
            throw new ArgumentException($"Block size must be {BlockSize} bytes.", nameof(block));
        if (roundKeys == null)
            throw new InvalidOperationException("Key has not been set.");

        byte[,] state = BlockToState(block);

        AddRoundKey(state, 0);

        for (int round = 1; round < nr; round++)
        {
            SubBytes(state);
            ShiftRows(state);
            MixColumns(state);
            AddRoundKey(state, round);
        }

        SubBytes(state);
        ShiftRows(state);
        AddRoundKey(state, nr);

        return Task.FromResult(StateToBlock(state));
    }

    public Task<byte[]> Decrypt(byte[] block)
    {
        if (block.Length != BlockSize)
            throw new ArgumentException($"Block size must be {BlockSize} bytes.", nameof(block));
        if (roundKeys == null)
            throw new InvalidOperationException("Key has not been set.");

        byte[,] state = BlockToState(block);

        AddRoundKey(state, nr);

        for (int round = nr - 1; round >= 1; round--)
        {
            InvShiftRows(state);
            InvSubBytes(state);
            AddRoundKey(state, round);
            InvMixColumns(state);
        }

        InvShiftRows(state);
        InvSubBytes(state);
        AddRoundKey(state, 0);

        return Task.FromResult(StateToBlock(state));
    }

    byte[,] BlockToState(byte[] block)
    {
        byte[,] state = new byte[4, nb];
        for (int i = 0; i < BlockSize; i++)
        {
            state[i % 4, i / 4] = block[i];
        }
        return state;
    }

    byte[] StateToBlock(byte[,] state)
    {
        byte[] output = new byte[BlockSize];
        for (int i = 0; i < BlockSize; i++)
        {
            output[i] = state[i % 4, i / 4];
        }
        return output;
    }

    void SubBytes(byte[,] state)
    {
        byte[] sBox = sBoxProvider.Forward;
        for (int r = 0; r < 4; r++)
        {
            for (int c = 0; c < nb; c++)
            {
                state[r, c] = sBox[state[r, c]];
            }
        }
    }

    void InvSubBytes(byte[,] state)
    {
        byte[] invSBox = sBoxProvider.Inverse;
        for (int r = 0; r < 4; r++)
        {
            for (int c = 0; c < nb; c++)
            {
                state[r, c] = invSBox[state[r, c]];
            }
        }
    }

    void ShiftRows(byte[,] state)
    {
        ShiftRow(state, 1, 1);
        int shift2 = nb == 8 ? 3 : 2;
        ShiftRow(state, 2, shift2);
        int shift3 = nb == 8 ? 4 : 3;
        ShiftRow(state, 3, shift3);
    }

    void InvShiftRows(byte[,] state)
    {
        ShiftRow(state, 1, nb - 1);
        int shift2 = nb == 8 ? 3 : 2;
        ShiftRow(state, 2, nb - shift2);
        int shift3 = nb == 8 ? 4 : 3;
        ShiftRow(state, 3, nb - shift3);
    }

    void ShiftRow(byte[,] state, int row, int shift)
    {
        byte[] temp = new byte[nb];
        for (int c = 0; c < nb; c++)
        {
            temp[c] = state[row, (c + shift) % nb];
        }
        for (int c = 0; c < nb; c++)
        {
            state[row, c] = temp[c];
        }
    }

    void MixColumns(byte[,] state)
    {
        byte[] t = new byte[4];
        for (int c = 0; c < nb; c++)
        {
            for(int i=0; i<4; i++) t[i] = state[i, c];

            state[0, c] = GaloisField8.Add(
                GaloisField8.Add(GaloisField8.Multiply(0x02, t[0], gfModulus), GaloisField8.Multiply(0x03, t[1], gfModulus)),
                GaloisField8.Add(t[2], t[3]));
            
            state[1, c] = GaloisField8.Add(
                GaloisField8.Add(t[0], GaloisField8.Multiply(0x02, t[1], gfModulus)),
                GaloisField8.Add(GaloisField8.Multiply(0x03, t[2], gfModulus), t[3]));

            state[2, c] = GaloisField8.Add(
                GaloisField8.Add(t[0], t[1]),
                GaloisField8.Add(GaloisField8.Multiply(0x02, t[2], gfModulus), GaloisField8.Multiply(0x03, t[3], gfModulus)));

            state[3, c] = GaloisField8.Add(
                GaloisField8.Add(GaloisField8.Multiply(0x03, t[0], gfModulus), t[1]),
                GaloisField8.Add(t[2], GaloisField8.Multiply(0x02, t[3], gfModulus)));
        }
    }

    void InvMixColumns(byte[,] state)
    {
        byte[] t = new byte[4];
        for (int c = 0; c < nb; c++)
        {
            for (int i = 0; i < 4; i++) t[i] = state[i, c];

            state[0, c] = GaloisField8.Add(
                GaloisField8.Add(GaloisField8.Multiply(0x0E, t[0], gfModulus), GaloisField8.Multiply(0x0B, t[1], gfModulus)),
                GaloisField8.Add(GaloisField8.Multiply(0x0D, t[2], gfModulus), GaloisField8.Multiply(0x09, t[3], gfModulus)));

            state[1, c] = GaloisField8.Add(
                GaloisField8.Add(GaloisField8.Multiply(0x09, t[0], gfModulus), GaloisField8.Multiply(0x0E, t[1], gfModulus)),
                GaloisField8.Add(GaloisField8.Multiply(0x0B, t[2], gfModulus), GaloisField8.Multiply(0x0D, t[3], gfModulus)));

            state[2, c] = GaloisField8.Add(
                GaloisField8.Add(GaloisField8.Multiply(0x0D, t[0], gfModulus), GaloisField8.Multiply(0x09, t[1], gfModulus)),
                GaloisField8.Add(GaloisField8.Multiply(0x0E, t[2], gfModulus), GaloisField8.Multiply(0x0B, t[3], gfModulus)));

            state[3, c] = GaloisField8.Add(
                GaloisField8.Add(GaloisField8.Multiply(0x0B, t[0], gfModulus), GaloisField8.Multiply(0x0D, t[1], gfModulus)),
                GaloisField8.Add(GaloisField8.Multiply(0x09, t[2], gfModulus), GaloisField8.Multiply(0x0E, t[3], gfModulus)));
        }
    }

    void AddRoundKey(byte[,] state, int round)
    {
        byte[] roundKey = roundKeys![round];
        for (int c = 0; c < nb; c++)
        {
            state[0, c] ^= roundKey[4 * c + 0];
            state[1, c] ^= roundKey[4 * c + 1];
            state[2, c] ^= roundKey[4 * c + 2];
            state[3, c] ^= roundKey[4 * c + 3];
        }
    }
}