namespace Cryptography.SymmetricAlgorithms.DEAL;

public class DealKeyExpander : IKeyExpander
{
    readonly IBlockCipherAdapter _blockCipher;
    readonly int _keySize;
    readonly int _rounds;

    public DealKeyExpander(IBlockCipherAdapter blockCipher, int keySize)
    {
        _blockCipher = blockCipher;
        _keySize = keySize;
            
        _rounds = keySize switch
        {
            16 => 6,
            24 => 6,  
            32 => 8,
            _  => throw new ArgumentException("Invalid key size for DEAL")
        };
    }

    public byte[][] ExpandKeyToRounds(byte[] key)
    {
        if (key.Length != _keySize)
            throw new ArgumentException($"Key must be {_keySize} bytes for DEAL-{_keySize * 8}");

        byte[][] roundKeys = new byte[_rounds][];
        int blockSize = _blockCipher.BlockSize;
            
        int keyBlocks = _keySize / blockSize;
        byte[][] keyParts = new byte[keyBlocks][];
            
        for (int i = 0; i < keyBlocks; i++)
        {
            keyParts[i] = new byte[blockSize];
            Array.Copy(key, i * blockSize, keyParts[i], 0, blockSize);
        }

        for (int i = 0; i < _rounds; i++)
        {
            byte[] constant = new byte[blockSize];
            constant[blockSize - 1] = (byte)(i + 1);
                
            int keyPartIndex = i % keyBlocks;
            byte[] currentKeyPart = keyParts[keyPartIndex];
                
            roundKeys[i] = _blockCipher.EncryptBlock(constant, currentKeyPart);
        }

        return roundKeys;
    }
}