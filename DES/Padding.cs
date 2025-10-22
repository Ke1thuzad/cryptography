namespace Cryptography.DES;

public class Padding(Padding.Mode mode)
{
    public enum Mode
    {
        Zeros,
        ANSI_X923,
        PKCS7,
        ISO10126
    }

    public Mode CurrentMode = mode;
    
    public byte[] Apply(byte[] data, int algorithmBlockSize) {
        if (data.Length % algorithmBlockSize == 0)
            return data;

        int prevSize = data.Length;
        int blockSize = prevSize % algorithmBlockSize;
        byte sizeDelta = (byte)(algorithmBlockSize - blockSize);

        Array.Resize(ref data, prevSize + sizeDelta);

        switch (CurrentMode) {
            case Mode.Zeros:
                for (int i = blockSize; i < algorithmBlockSize; i++) 
                    data[prevSize + i] = 0;
                
                break;
            case Mode.ANSI_X923:
                for (int i = blockSize; i < algorithmBlockSize; i++) {
                    if (i != algorithmBlockSize - 1)
                        data[prevSize + i] = 0;
                    else
                        data[prevSize + i] = sizeDelta;
                }
                
                break;
            case Mode.PKCS7:
                for (int i = blockSize; i < algorithmBlockSize; i++) 
                    data[prevSize + i] = sizeDelta;
                
                break;
            case Mode.ISO10126:
                Random random = new();
                
                random.NextBytes(data.AsSpan(prevSize, sizeDelta - 1));

                data[prevSize + sizeDelta - 1] = sizeDelta;
                
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(CurrentMode), "Padding mode is not supported");
        }

        return data;
    }
}