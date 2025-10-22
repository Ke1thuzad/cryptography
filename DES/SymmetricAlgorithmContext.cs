using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace Cryptography.DES;

public class SymmetricAlgorithmContext
{
    readonly CipherMode cipherMode;
    readonly Padding padding;

    int algorithmBlockSize;

    public SymmetricAlgorithmContext(ISymmetricKeyAlgorithm algorithm, byte[] key, CipherMode.Mode cipherMode, Padding.Mode paddingMode,
        [Optional] byte[] initializationVector, [Optional] params object[] additionalArguments) {
        algorithm.SetKey(key);

        algorithmBlockSize = algorithm.BlockSize;
        
        this.cipherMode = new CipherMode(cipherMode, algorithm, initializationVector);
        padding = new Padding(paddingMode);
    }

    public async Task<byte[]> Encrypt(byte[] data) {
        byte[] paddedData = padding.Apply(data, algorithmBlockSize);

        int blockLength = algorithmBlockSize;
        int nBlocks = paddedData.Length / blockLength;
        
        byte[][] blocks = new byte[nBlocks][];

        for (int i = 0; i < nBlocks; i++) {
            blocks[i] = new byte[blockLength];
        }
        
        

        throw new NotImplementedException();
    }
    
    public async void Encrypt(string inputFilepath, string outputFilepath) => throw new NotImplementedException();

    public async Task<byte[]> Decrypt(byte[] block) => throw new NotImplementedException();
    public async void Decrypt(string inputFilepath, string outputFilepath) => throw new NotImplementedException();

    
}