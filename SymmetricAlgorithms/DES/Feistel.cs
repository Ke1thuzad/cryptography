using Cryptography.Utility;

namespace Cryptography.SymmetricAlgorithms.DES;

public class Feistel : ICipherTransform
{
    public byte[] TransformBlock(byte[] block, byte[] roundKey) {
        if (block.Length != 4 || roundKey.Length != 6)
            throw new ArgumentException("Invalid block or key size");

        byte[] expanded = BitOperations.PermuteBits(block, DesTables.E);
        
        expanded = BitOperations.XORBytes(expanded, roundKey);
        
        byte[] sboxResult = ApplySBoxes(expanded);
        
        byte[] result = BitOperations.PermuteBits(sboxResult, DesTables.P);
        
        return result;
    }

    byte[] ApplySBoxes(byte[] expanded)
    {
        byte[] output = new byte[4];
        
        var sboxConfig = new (int bytePos, int shift, bool crossByte)[8];
        for (int i = 0; i < 8; i++)
        {
            int bitPos = i * 6;
            sboxConfig[i] = (bitPos / 8, bitPos % 8, (bitPos % 8) > 2);
        }

        for (int i = 0; i < 8; i++)
        {
            var (bytePos, shift, crossByte) = sboxConfig[i];
            
            int bits;
            if (!crossByte)
            {
                bits = (expanded[bytePos] >> (2 - shift)) & 0x3F;
            }
            else
            {
                bits = ((expanded[bytePos] << (shift - 2)) | 
                        (expanded[bytePos + 1] >> (10 - shift))) & 0x3F;
            }

            int row = ((bits & 0x20) >> 4) | (bits & 0x01);
            int col = (bits >> 1) & 0x0F;
            byte sboxValue = DesTables.SBoxes[i, row, col];

            int outputIndex = i >> 1;               
            int outputShift = (i & 1) == 0 ? 4 : 0; 
            
            output[outputIndex] |= (byte)(sboxValue << outputShift);
        }
        
        return output;
    }
}