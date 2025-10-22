namespace Cryptography.DES;

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

        if (initializationVector == null && CurrentMode == Mode.RandomDelta) {
            Random rd = new Random();

            this.initializationVector = new byte[symmetricKeyAlgorithm.BlockSize];
            
            rd.NextBytes(this.initializationVector);
        }
    }
    
    #region Encryption

    public async Task<byte[]> Encrypt(byte[][] paddedBlocks) => await (CurrentMode switch {
        Mode.ECB         => EncryptECB(paddedBlocks),
        Mode.CBC         => EncryptCBC(paddedBlocks),
        Mode.PCBC        => EncryptPCBC(paddedBlocks),
        Mode.CFB         => EncryptCFB(paddedBlocks),
        Mode.OFB         => EncryptOFB(paddedBlocks),
        Mode.CTR         => EncryptCTR(paddedBlocks),
        Mode.RandomDelta => EncryptRD(paddedBlocks),
        _                => throw new ArgumentOutOfRangeException(nameof(CurrentMode), "This mode is not supported.")
    });

    async Task<byte[]> EncryptECB(byte[][] paddedBlocks) {
        Task<byte[]>[] tasks = new Task<byte[]>[paddedBlocks.Length];
        
        for (int i = 0; i < paddedBlocks.Length; i++) {
            tasks[i] = symmetricKeyAlgorithm.Encrypt(paddedBlocks[i]);
        }

        byte[][] encryptedBlocks = await Task.WhenAll(tasks);

        int totalLength = Utility.BytesLength(encryptedBlocks);
        byte[] result = new byte[totalLength];

        int currentPos = 0;
        foreach (byte[] block in encryptedBlocks) {
            Array.Copy(block, 0, result, currentPos, block.Length);
            
            currentPos += block.Length;
        }

        return result;
    }

    async Task<byte[]> EncryptCBC(byte[][] paddedBlocks) {
        byte[] xored = initializationVector;

        byte[] result = new byte[Utility.BytesLength(paddedBlocks)];
        int currentPos = 0;
        
        foreach (byte[] block in paddedBlocks) {
            xored = Utility.XORBytes(xored, block);
            
            xored = await symmetricKeyAlgorithm.Encrypt(xored);
            
            Array.Copy(xored, 0, result, currentPos, xored.Length);
            currentPos += xored.Length;
        }

        return result;
    }

    async Task<byte[]> EncryptPCBC(byte[][] paddedBlocks) {
        byte[] xored = initializationVector;

        byte[] result = new byte[Utility.BytesLength(paddedBlocks)];
        int currentPos = 0;
        
        foreach (byte[] block in paddedBlocks) {
            xored = Utility.XORBytes(xored, block);
            
            xored = await symmetricKeyAlgorithm.Encrypt(xored);
            
            Array.Copy(xored, 0, result, currentPos, xored.Length);
            currentPos += xored.Length;

            xored = Utility.XORBytes(xored, block);
        }

        return result;
    }

    async Task<byte[]> EncryptCFB(byte[][] paddedBlocks) {
        byte[] xored = initializationVector;

        byte[] result = new byte[Utility.BytesLength(paddedBlocks)];
        int currentPos = 0;
        
        foreach (byte[] block in paddedBlocks) {
            xored = await symmetricKeyAlgorithm.Encrypt(xored);
            
            Array.Copy(xored, 0, result, currentPos, xored.Length);
            currentPos += xored.Length;

            xored = Utility.XORBytes(xored, block);
        }

        return result;
    }

    async Task<byte[]> EncryptOFB(byte[][] paddedBlocks) {
        byte[] xored = initializationVector;

        byte[] result = new byte[Utility.BytesLength(paddedBlocks)];
        int currentPos = 0;
        
        foreach (byte[] block in paddedBlocks) {
            xored = await symmetricKeyAlgorithm.Encrypt(xored);
            
            Array.Copy(Utility.XORBytes(xored, block), 0, result, currentPos, xored.Length);
            currentPos += xored.Length;
        }

        return result;
    }


    async Task<byte[]> CounterEncryptionTask(byte[] block, byte[] counter) {
        byte[] encryptedCtr = await symmetricKeyAlgorithm.Encrypt(counter);

        return Utility.XORBytes(encryptedCtr, block);
    }
    
    async Task<byte[]> EncryptCTR(byte[][] paddedBlocks) {
        byte[] counter = initializationVector;

        Task<byte[]>[] tasks = new Task<byte[]>[paddedBlocks.Length];

        for (int i = 0; i < paddedBlocks.Length; ++i) {
            tasks[i] = CounterEncryptionTask(paddedBlocks[i], counter);
            
            Utility.IncrementCounter(counter);
        }

        byte[][] encryptedBlocks = await Task.WhenAll(tasks);
        
        byte[] result = new byte[Utility.BytesLength(paddedBlocks)];
        int currentPos = 0;

        foreach (byte[] block in encryptedBlocks) {
            Array.Copy(block, 0, result, currentPos, block.Length);

            currentPos += block.Length;
        }

        return result;
    }

    async Task<byte[]> EncryptRD(byte[][] paddedBlocks) {
        byte[] counter = initializationVector;

        Task<byte[]>[] tasks = new Task<byte[]>[paddedBlocks.Length];

        for (int i = 0; i < paddedBlocks.Length; ++i) {
            byte[] xored = Utility.XORBytes(paddedBlocks[i], counter);
            
            tasks[i] = symmetricKeyAlgorithm.Encrypt(xored);

            int size = counter.Length;
            
            Utility.AddBytes(counter, counter[(size / 2)..]);
        }

        byte[][] encryptedBlocks = await Task.WhenAll(tasks);
        
        byte[] result = new byte[Utility.BytesLength(paddedBlocks)];
        int currentPos = 0;

        foreach (byte[] block in encryptedBlocks) {
            Array.Copy(block, 0, result, currentPos, block.Length);

            currentPos += block.Length;
        }

        return result;
    }
    #endregion
    
    #region Decryption
    
    public async Task<byte[]> Decrypt(byte[][] paddedBlocks) => await (CurrentMode switch {
        Mode.ECB         => DecryptECB(paddedBlocks),
        Mode.CBC         => DecryptCBC(paddedBlocks),
        Mode.PCBC        => DecryptPCBC(paddedBlocks),
        Mode.CFB         => DecryptCFB(paddedBlocks),
        Mode.OFB         => DecryptOFB(paddedBlocks),
        Mode.CTR         => DecryptCTR(paddedBlocks),
        Mode.RandomDelta => DecryptRD(paddedBlocks),
        _                => throw new ArgumentOutOfRangeException()
    });

    async Task<byte[]> DecryptECB(byte[][] paddedBlocks) {
        Task<byte[]>[] tasks = new Task<byte[]>[paddedBlocks.Length];
        
        for (int i = 0; i < paddedBlocks.Length; i++) {
            tasks[i] = symmetricKeyAlgorithm.Decrypt(paddedBlocks[i]);
        }

        byte[][] encryptedBlocks = await Task.WhenAll(tasks);

        int totalLength = Utility.BytesLength(encryptedBlocks);
        byte[] result = new byte[totalLength];

        int currentPos = 0;
        foreach (byte[] block in encryptedBlocks) {
            Array.Copy(block, 0, result, currentPos, block.Length);
            
            currentPos += block.Length;
        }

        return result;
    }

    async Task<byte[]> DecryptCBC(byte[][] paddedBlocks) {
        byte[] xored = initializationVector;

        byte[] result = new byte[Utility.BytesLength(paddedBlocks)];
        int currentPos = 0;
        
        foreach (byte[] block in paddedBlocks) {
            byte[] decryptedBlock = await symmetricKeyAlgorithm.Decrypt(block);

            xored = Utility.XORBytes(decryptedBlock, xored);
            
            Array.Copy(xored, 0, result, currentPos, xored.Length);
            currentPos += xored.Length;
        }

        return result;
    }

    async Task<byte[]> DecryptPCBC(byte[][] paddedBlocks) {
        byte[] xored = initializationVector;

        byte[] result = new byte[Utility.BytesLength(paddedBlocks)];
        int currentPos = 0;
        
        foreach (byte[] block in paddedBlocks) {
            xored = Utility.XORBytes(xored, block);
            
            xored = await symmetricKeyAlgorithm.Decrypt(xored);
            
            Array.Copy(xored, 0, result, currentPos, xored.Length);
            currentPos += xored.Length;

            xored = Utility.XORBytes(xored, block);
        }

        return result;
    }

    async Task<byte[]> DecryptCFB(byte[][] paddedBlocks) {
        byte[] xored = initializationVector;

        byte[] result = new byte[Utility.BytesLength(paddedBlocks)];
        int currentPos = 0;
        
        foreach (byte[] block in paddedBlocks) {
            xored = await symmetricKeyAlgorithm.Decrypt(xored);
            
            Array.Copy(xored, 0, result, currentPos, xored.Length);
            currentPos += xored.Length;

            xored = Utility.XORBytes(xored, block);
        }

        return result;
    }

    async Task<byte[]> DecryptOFB(byte[][] paddedBlocks) {
        byte[] xored = initializationVector;

        byte[] result = new byte[Utility.BytesLength(paddedBlocks)];
        int currentPos = 0;
        
        foreach (byte[] block in paddedBlocks) {
            xored = await symmetricKeyAlgorithm.Decrypt(xored);
            
            Array.Copy(Utility.XORBytes(xored, block), 0, result, currentPos, xored.Length);
            currentPos += xored.Length;
        }

        return result;
    }

    async Task<byte[]> DecryptCTR(byte[][] paddedBlocks) {
        throw new NotImplementedException();
    }

    async Task<byte[]> DecryptRD(byte[][] paddedBlocks) {
        throw new NotImplementedException();
    }
    #endregion
}