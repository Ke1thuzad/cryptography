namespace Cryptography.SymmetricAlgorithms.FROG;

public class Frog : ISymmetricKeyAlgorithm
{
    readonly int _blockSize;
    const int NumRounds = 8;
    FrogRound[] _rounds;
    bool _isKeySet;

    public Frog(int blockSize = 16)
    {
        if (blockSize < 8 || blockSize > 128)
            throw new ArgumentException("Block size must be between 8 and 128 bytes.");
        _blockSize = blockSize;
    }

    public int BlockSize => _blockSize;

    public void SetKey(byte[] key)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (key.Length < 5 || key.Length > 125)
            throw new ArgumentException("Key length must be between 5 and 125 bytes.");

        _rounds = GenerateKeySchedule(key);
        _isKeySet = true;
    }

    public Task<byte[]> Encrypt(byte[] block)
    {
        if (!_isKeySet) throw new InvalidOperationException("Key not set.");
        if (block.Length != _blockSize) throw new ArgumentException($"Block size must be {_blockSize}");

        byte[] result = new byte[_blockSize];
        Array.Copy(block, result, _blockSize);

        for (int r = 0; r < NumRounds; r++)
        {
            var round = _rounds[r];

            for (int i = 0; i < _blockSize; i++)
            {
                result[i] ^= round.XorBu[i];
            }

            for (int i = 0; i < _blockSize; i++)
            {
                result[i] = round.Subst[result[i]];

                int targetIndex = round.BombPerm[i];
                if (targetIndex != i)
                {
                    result[i] ^= result[targetIndex];
                }
            }
        }

        return Task.FromResult(result);
    }

    public Task<byte[]> Decrypt(byte[] block)
    {
        if (!_isKeySet) throw new InvalidOperationException("Key not set.");
        if (block.Length != _blockSize) throw new ArgumentException($"Block size must be {_blockSize}");

        byte[] result = new byte[_blockSize];
        Array.Copy(block, result, _blockSize);

        for (int r = NumRounds - 1; r >= 0; r--)
        {
            var round = _rounds[r];

            for (int i = _blockSize - 1; i >= 0; i--)
            {
                int targetIndex = round.BombPerm[i];
                if (targetIndex != i)
                {
                    result[i] ^= result[targetIndex];
                }

                result[i] = round.InvSubst[result[i]];
            }

            for (int i = 0; i < _blockSize; i++)
            {
                result[i] ^= round.XorBu[i];
            }
        }

        return Task.FromResult(result);
    }

    FrogRound[] GenerateKeySchedule(byte[] userKey)
    {
        byte[] simpleKey = new byte[2304];
        int keyLen = userKey.Length;

        for (int i = 0; i < 2304; i++)
        {
            simpleKey[i] = userKey[i % keyLen];
        }

        int processed = 0;
        int lastVal = 0;
        int k = 0;
        
        for (int i = 0; i < 8; i++)
        {
            for (int j = 0; j < 2304; j++)
            {
                processed = (processed + simpleKey[j] + lastVal) & 0xFF;
                simpleKey[j] = (byte)processed;
                
                if (j < 2303)
                {
                    k = (k + simpleKey[j]) % 2304;
                    (simpleKey[j], simpleKey[k]) = (simpleKey[k], simpleKey[j]);
                }
                lastVal = simpleKey[j];
            }
        }

        FrogRound[] rounds = new FrogRound[NumRounds];
        int offset = 0;

        for (int i = 0; i < NumRounds; i++)
        {
            rounds[i] = new FrogRound(_blockSize);

            Array.Copy(simpleKey, offset, rounds[i].XorBu, 0, _blockSize);
            offset += _blockSize;

            Array.Copy(simpleKey, offset, rounds[i].Subst, 0, 256);
            offset += 256;
            
            Array.Copy(simpleKey, offset, rounds[i].BombPerm, 0, _blockSize);
            offset += _blockSize;

            MakePermutation(rounds[i].Subst, 256);
            MakePermutation(rounds[i].BombPerm, _blockSize);
            
            rounds[i].ComputeInverse();
        }

        return rounds;
    }

    void MakePermutation(byte[] array, int size)
    {
        bool[] present = new bool[size];
        
        for (int i = 0; i < size; i++)
        {
            int val = array[i];
            if (val >= size) 
            {
                val %= size;
                array[i] = (byte)val;
            }
            
            if (!present[val])
            {
                present[val] = true;
            }
            else
            {
                int k = (val + 1) % size;
                while (present[k])
                {
                    k = (k + 1) % size;
                }
                array[i] = (byte)k;
                present[k] = true;
            }
        }
    }

    class FrogRound
    {
        public byte[] XorBu;
        public byte[] Subst;
        public byte[] BombPerm;
        public byte[] InvSubst; 

        public FrogRound(int blockSize)
        {
            XorBu = new byte[blockSize];
            Subst = new byte[256];
            BombPerm = new byte[blockSize];
            InvSubst = new byte[256];
        }

        public void ComputeInverse()
        {
            for (int i = 0; i < 256; i++)
            {
                InvSubst[Subst[i]] = (byte)i;
            }
        }
    }
}