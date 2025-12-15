using Cryptography.Utility;

namespace Cryptography.Context.Symmetric;

public class CipherMode
{
    public enum Mode
    {
        ECB,
        CBC,
        PCBC,
        CFB,
        OFB,
        CTR,
        RandomDelta
    }
    
    public Mode CurrentMode;

    readonly byte[] initializationVector;

    readonly ISymmetricKeyAlgorithm symmetricKeyAlgorithm;

    public CipherMode(Mode mode, ISymmetricKeyAlgorithm symmetricKeyAlgorithm,
        byte[]? initializationVector) {
        CurrentMode = mode;
        this.symmetricKeyAlgorithm = symmetricKeyAlgorithm;
    
        if (initializationVector != null) {
            this.initializationVector = initializationVector;
            return;
        }
    
        if (CurrentMode != Mode.ECB && CurrentMode != Mode.RandomDelta) {
            throw new ArgumentOutOfRangeException(nameof(initializationVector), "This mode should use Initialization Vector (IV)");
        }

        if (CurrentMode == Mode.RandomDelta) {
            Random rd = new();

            this.initializationVector = new byte[symmetricKeyAlgorithm.BlockSize];
            rd.NextBytes(this.initializationVector);
        }
    }
    
    async Task<byte[]> ParallelCryptXORBlocks(byte[] block, byte[] counter, bool encryption = true) {
        byte[] crypted;
        
        if (encryption)
            crypted = await symmetricKeyAlgorithm.Encrypt(counter);
        else
            crypted = await symmetricKeyAlgorithm.Decrypt(counter);

        return BitOperations.XORBytes(crypted, block);
    }
    
    public async Task<byte[]> Encrypt(byte[] data) => await (CurrentMode switch {
        Mode.ECB         => EncryptECB(data),
        Mode.CBC         => EncryptCBC(data),
        Mode.PCBC        => EncryptPCBC(data),
        Mode.CFB         => EncryptCFB(data),
        Mode.OFB         => EncryptOFB(data),
        Mode.CTR         => EncryptCTR(data),
        Mode.RandomDelta => EncryptRD(data),
        _                => throw new ArgumentOutOfRangeException(nameof(CurrentMode), "This mode is not supported.")
    });

    public async Task<byte[]> Decrypt(byte[] data) => await (CurrentMode switch {
        Mode.ECB         => DecryptECB(data),
        Mode.CBC         => DecryptCBC(data),
        Mode.PCBC        => DecryptPCBC(data),
        Mode.CFB         => DecryptCFB(data),
        Mode.OFB         => DecryptOFB(data),
        Mode.CTR         => DecryptCTR(data),
        Mode.RandomDelta => DecryptRD(data),
        _                => throw new ArgumentOutOfRangeException()
    });

    #region Encryption

    async Task<byte[]> EncryptECB(byte[] data) {
        int blockSize = symmetricKeyAlgorithm.BlockSize;
        int blockCount = data.Length / blockSize;
        byte[] result = new byte[data.Length];

        for (int i = 0; i < blockCount; i++) {
            byte[] block = new byte[blockSize];
            Buffer.BlockCopy(data, i * blockSize, block, 0, blockSize);
            byte[] encrypted = await symmetricKeyAlgorithm.Encrypt(block);
            Buffer.BlockCopy(encrypted, 0, result, i * blockSize, blockSize);
        }

        return result;
    }

    async Task<byte[]> EncryptCBC(byte[] data) {
        int blockSize = symmetricKeyAlgorithm.BlockSize;
        int blockCount = data.Length / blockSize;
        byte[] result = new byte[data.Length];
        byte[] xored = initializationVector;

        for (int i = 0; i < blockCount; i++) {
            byte[] block = new byte[blockSize];
            Buffer.BlockCopy(data, i * blockSize, block, 0, blockSize);
            
            xored = BitOperations.XORBytes(xored, block);
            xored = await symmetricKeyAlgorithm.Encrypt(xored);
            
            Buffer.BlockCopy(xored, 0, result, i * blockSize, blockSize);
        }

        return result;
    }

    async Task<byte[]> EncryptPCBC(byte[] data) {
        int blockSize = symmetricKeyAlgorithm.BlockSize;
        int blockCount = data.Length / blockSize;
        byte[] result = new byte[data.Length];
        byte[] prevCipher = (byte[])initializationVector.Clone();
        byte[] prevPlain = new byte[blockSize];

        for (int i = 0; i < blockCount; i++) {
            byte[] block = new byte[blockSize];
            Buffer.BlockCopy(data, i * blockSize, block, 0, blockSize);

            byte[] xored = BitOperations.XORBytes(block, BitOperations.XORBytes(prevCipher, prevPlain));
            byte[] encrypted = await symmetricKeyAlgorithm.Encrypt(xored);
            
            Buffer.BlockCopy(encrypted, 0, result, i * blockSize, blockSize);

            prevCipher = encrypted;
            prevPlain = block;
        }

        return result;
    }

    async Task<byte[]> EncryptCFB(byte[] data) {
        int blockSize = symmetricKeyAlgorithm.BlockSize;
        int blockCount = data.Length / blockSize;
        byte[] result = new byte[data.Length];
        byte[] feedback = (byte[])initializationVector.Clone();

        for (int i = 0; i < blockCount; i++) {
            byte[] block = new byte[blockSize];
            Buffer.BlockCopy(data, i * blockSize, block, 0, blockSize);

            byte[] encryptedFeedback = await symmetricKeyAlgorithm.Encrypt(feedback);
            byte[] encryptedBlock = BitOperations.XORBytes(encryptedFeedback, block);
            
            Buffer.BlockCopy(encryptedBlock, 0, result, i * blockSize, blockSize);
            feedback = encryptedBlock;
        }

        return result;
    }

    async Task<byte[]> EncryptOFB(byte[] data) {
        int blockSize = symmetricKeyAlgorithm.BlockSize;
        int blockCount = data.Length / blockSize;
        byte[] result = new byte[data.Length];
        byte[] xored = initializationVector;

        for (int i = 0; i < blockCount; i++) {
            byte[] block = new byte[blockSize];
            Buffer.BlockCopy(data, i * blockSize, block, 0, blockSize);

            xored = await symmetricKeyAlgorithm.Encrypt(xored);
            byte[] resultBlock = BitOperations.XORBytes(xored, block);
            
            Buffer.BlockCopy(resultBlock, 0, result, i * blockSize, blockSize);
        }

        return result;
    }

    async Task<byte[]> EncryptCTR(byte[] data) {
        int blockSize = symmetricKeyAlgorithm.BlockSize;
        int blockCount = data.Length / blockSize;
        byte[] result = new byte[data.Length];
        byte[] counter = (byte[])initializationVector.Clone();

        var tasks = new Task<byte[]>[blockCount];
        
        for (int i = 0; i < blockCount; i++) {
            byte[] block = new byte[blockSize];
            Buffer.BlockCopy(data, i * blockSize, block, 0, blockSize);
            byte[] currentCounter = (byte[])counter.Clone();
            
            tasks[i] = ParallelCryptXORBlocks(block, currentCounter);
            BitOperations.IncrementCounter(counter);
        }

        byte[][] encryptedBlocks = await Task.WhenAll(tasks);
        
        for (int i = 0; i < blockCount; i++) {
            Buffer.BlockCopy(encryptedBlocks[i], 0, result, i * blockSize, blockSize);
        }

        return result;
    }

    async Task<byte[]> EncryptRD(byte[] data) {
        int blockSize = symmetricKeyAlgorithm.BlockSize;
        int blockCount = data.Length / blockSize;
        byte[] result = new byte[data.Length];

        int deltaSize = blockSize / 2;
        byte[] deltaBytes = new byte[deltaSize];
        Buffer.BlockCopy(initializationVector, blockSize - deltaSize, deltaBytes, 0, deltaSize);

        byte[] counter = new byte[blockSize];
        Array.Copy(initializationVector, 0, counter, 0, blockSize);

        for (int i = 0; i < blockCount; i++)
        {
            byte[] block = new byte[blockSize];
            Buffer.BlockCopy(data, i * blockSize, block, 0, blockSize);

            byte[] xored = BitOperations.XORBytes(block, counter);
            byte[] encrypted = await symmetricKeyAlgorithm.Encrypt(xored);

            Buffer.BlockCopy(encrypted, 0, result, i * blockSize, blockSize);

            counter = BitOperations.IncrementCounterByDelta(counter, deltaBytes);
        }

        return result;
    }

    #endregion

    #region Decryption

    async Task<byte[]> DecryptECB(byte[] data) {
        int blockSize = symmetricKeyAlgorithm.BlockSize;
        int blockCount = data.Length / blockSize;
        byte[] result = new byte[data.Length];

        for (int i = 0; i < blockCount; i++) {
            byte[] block = new byte[blockSize];
            Buffer.BlockCopy(data, i * blockSize, block, 0, blockSize);
            byte[] decrypted = await symmetricKeyAlgorithm.Decrypt(block);
            Buffer.BlockCopy(decrypted, 0, result, i * blockSize, blockSize);
        }

        return result;
    }

    async Task<byte[]> DecryptCBC(byte[] data) {
        int blockSize = symmetricKeyAlgorithm.BlockSize;
        int blockCount = data.Length / blockSize;
        byte[] result = new byte[data.Length];
        
        byte[] xored = initializationVector;

        for (int i = 0; i < blockCount; i++) {
            byte[] block = new byte[blockSize];
            Buffer.BlockCopy(data, i * blockSize, block, 0, blockSize);

            byte[] decrypted = await symmetricKeyAlgorithm.Decrypt(block);
            byte[] plain = BitOperations.XORBytes(decrypted, xored);
            
            Buffer.BlockCopy(plain, 0, result, i * blockSize, blockSize);
            xored = block;
        }

        return result;
    }

    async Task<byte[]> DecryptPCBC(byte[] data) {
        int blockSize = symmetricKeyAlgorithm.BlockSize;
        int blockCount = data.Length / blockSize;
        byte[] result = new byte[data.Length];
        byte[] prevCipher = initializationVector;
        byte[] prevPlain = new byte[blockSize];

        for (int i = 0; i < blockCount; i++) {
            byte[] block = new byte[blockSize];
            Buffer.BlockCopy(data, i * blockSize, block, 0, blockSize);

            byte[] decrypted = await symmetricKeyAlgorithm.Decrypt(block);
            byte[] plain = BitOperations.XORBytes(decrypted, BitOperations.XORBytes(prevCipher, prevPlain));
            
            Buffer.BlockCopy(plain, 0, result, i * blockSize, blockSize);

            prevCipher = block;
            prevPlain = plain;
        }

        return result;
    }

    async Task<byte[]> DecryptCFB(byte[] data) {
        int blockSize = symmetricKeyAlgorithm.BlockSize;
        int blockCount = data.Length / blockSize;
        byte[] result = new byte[data.Length];
        byte[] feedback = (byte[])initializationVector.Clone();

        for (int i = 0; i < blockCount; i++) {
            byte[] block = new byte[blockSize];
            Buffer.BlockCopy(data, i * blockSize, block, 0, blockSize);

            byte[] encryptedFeedback = await symmetricKeyAlgorithm.Encrypt(feedback);
            byte[] decryptedBlock = BitOperations.XORBytes(encryptedFeedback, block);
            
            Buffer.BlockCopy(decryptedBlock, 0, result, i * blockSize, blockSize);
            feedback = block;
        }

        return result;
    }

    async Task<byte[]> DecryptOFB(byte[] data) => await EncryptOFB(data);

    async Task<byte[]> DecryptCTR(byte[] data) => await EncryptCTR(data);

    async Task<byte[]> DecryptRD(byte[] data)
    {
        int blockSize = symmetricKeyAlgorithm.BlockSize;
        int blockCount = data.Length / blockSize;
        byte[] result = new byte[data.Length];

        int deltaSize = blockSize / 2;
        byte[] deltaBytes = new byte[deltaSize];
        Buffer.BlockCopy(initializationVector, blockSize - deltaSize, deltaBytes, 0, deltaSize);

        byte[] counter = new byte[blockSize];
        Array.Copy(initializationVector, 0, counter, 0, blockSize);

        for (int i = 0; i < blockCount; i++)
        {
            byte[] block = new byte[blockSize];
            Buffer.BlockCopy(data, i * blockSize, block, 0, blockSize);

            byte[] decrypted = await symmetricKeyAlgorithm.Decrypt(block);
            byte[] plain = BitOperations.XORBytes(decrypted, counter);

            Buffer.BlockCopy(plain, 0, result, i * blockSize, blockSize);

            counter = BitOperations.IncrementCounterByDelta(counter, deltaBytes);
        }

        return result;
    }

    #endregion
}