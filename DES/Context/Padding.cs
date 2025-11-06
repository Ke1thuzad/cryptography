namespace Cryptography.DES.Context;

public class Padding(Padding.Mode mode, int algorithmBlockSize)
{
    public enum Mode
    {
        Zeros,
        ANSI_X923,
        PKCS7,
        ISO10126
    }

    public Mode CurrentMode = mode;

    public byte[] Apply(byte[] data) {
        if (data.Length == 0 || data.Length % algorithmBlockSize == 0) {
            return data;
        }
        
        int sizeDelta = algorithmBlockSize - (data.Length % algorithmBlockSize);
        int targetLength = data.Length + sizeDelta;

        byte[] result = new byte[targetLength];
        Array.Copy(data, 0, result, 0, data.Length);

        switch (CurrentMode) {
            case Mode.Zeros:
                for (int i = data.Length; i < targetLength; i++)
                    result[i] = 0;
                break;

            case Mode.ANSI_X923:
                for (int i = data.Length; i < targetLength - 1; i++) {
                    result[i] = 0;
                }
                result[targetLength - 1] = (byte)sizeDelta;
                break;

            case Mode.PKCS7:
                for (int i = data.Length; i < targetLength; i++)
                    result[i] = (byte)sizeDelta;
                break;

            case Mode.ISO10126:
                Random random = new();
                random.NextBytes(result.AsSpan(data.Length, sizeDelta - 1));
                result[targetLength - 1] = (byte)sizeDelta;
                break;

            default:
                throw new ArgumentOutOfRangeException(nameof(CurrentMode), "Padding mode is not supported");
        }

        return result;
    }

    public byte[] Remove(byte[] data) {
        if (data.Length == 0) return data;

        if (data.Length % algorithmBlockSize != 0) {
            return data;
        }

        if (CurrentMode == Mode.Zeros) {
            int zerosEnd = data.Length;
            while (zerosEnd > 0 && data[zerosEnd - 1] == 0)
                zerosEnd--;

            return data[..zerosEnd];
        }

        byte padSize = data[^1];
        
        if (padSize == 0 || padSize > algorithmBlockSize || padSize > data.Length)
            return data;

        switch (CurrentMode) {
            case Mode.ANSI_X923:
                for (int i = data.Length - padSize; i < data.Length - 1; i++) {
                    if (data[i] != 0)
                        return data;
                }
                break;
                
            case Mode.PKCS7:
                for (int i = data.Length - padSize; i < data.Length; i++) {
                    if (data[i] != padSize)
                        return data;
                }
                break;
                
            case Mode.ISO10126:
                break;

            default:
                throw new ArgumentOutOfRangeException(nameof(CurrentMode));
        }

        return data[..^padSize];
    }
}