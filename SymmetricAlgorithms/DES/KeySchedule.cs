using Cryptography.Utility;

namespace Cryptography.SymmetricAlgorithms.DES;

using static DesTables;

public class KeySchedule : IKeyExpander
{
    const int roundsN = 16;
    
    public byte[][] ExpandKeyToRounds(byte[] key) {
        byte[][] roundKeys = new byte[roundsN][];

        byte[] permuted = BitOperations.PermuteBits(key, PC1);

        uint C = BitOperations.BytesToUnsignedInt(permuted[..4]) >> 4;
        uint D = BitOperations.BytesToUnsignedInt(permuted[3..7]) & 0x0FFFFFFF;

        for (int round = 0; round < roundsN; round++) {
            C = BitOperations.LeftShift28(C, KeyShifts[round]);
            D = BitOperations.LeftShift28(D, KeyShifts[round]);

            byte[] CD = new byte[7];
            CD[0] = (byte)(C >> 20);
            CD[1] = (byte)(C >> 12);
            CD[2] = (byte)(C >> 4);
            CD[3] = (byte)(((C & 0x0F) << 4) | (D >> 24));
            CD[4] = (byte)(D >> 16);
            CD[5] = (byte)(D >> 8);
            CD[6] = (byte)(D);

            roundKeys[round] = BitOperations.PermuteBits(CD, PC2);
        }
        
        return roundKeys;
    }
}