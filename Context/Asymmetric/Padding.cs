using System.Security.Cryptography;

namespace Cryptography.Context.Asymmetric;

public class PkcsPadding
{
    static readonly RandomNumberGenerator Rng = RandomNumberGenerator.Create();

    public byte[] AddPadding(byte[] data, int modulusByteLength)
    {
        if (data.Length > modulusByteLength - 11)
        {
            throw new ArgumentException($"Data too long for key size. Max length is {modulusByteLength - 11} bytes.");
        }

        byte[] paddedData = new byte[modulusByteLength];

        paddedData[1] = 0x02;

        int psLength = modulusByteLength - data.Length - 3;
        byte[] ps = new byte[psLength];
        
        byte[] tempBuffer = new byte[psLength];
        Rng.GetBytes(tempBuffer);
        
        for (int i = 0; i < psLength; i++)
        {
            while (tempBuffer[i] == 0)
            {
                byte[] singleByte = new byte[1];
                Rng.GetBytes(singleByte);
                tempBuffer[i] = singleByte[0];
            }
            paddedData[2 + i] = tempBuffer[i];
        }

        paddedData[2 + psLength] = 0x00;

        Array.Copy(data, 0, paddedData, 2 + psLength + 1, data.Length);

        return paddedData;
    }

    public byte[] RemovePadding(byte[] paddedData)
    {
        if (paddedData.Length < 11)
            throw new ArgumentException("Decrypted data is too short to contain padding.");

        int blockTypeIndex = -1;
        if (paddedData[0] == 0x02) 
            blockTypeIndex = 0;
        else if (paddedData[0] == 0x00 && paddedData[1] == 0x02) 
            blockTypeIndex = 1;

        if (blockTypeIndex == -1)
            throw new CryptographicException("Invalid padding: Block type 0x02 not found.");

        int separatorIndex = -1;
        
        for (int i = blockTypeIndex + 9; i < paddedData.Length; i++)
        {
            if (paddedData[i] == 0x00)
            {
                separatorIndex = i;
                break;
            }
        }

        if (separatorIndex == -1)
            throw new CryptographicException("Invalid padding: Separator 0x00 not found.");

        int dataLength = paddedData.Length - separatorIndex - 1;
        byte[] data = new byte[dataLength];
        
        Array.Copy(paddedData, separatorIndex + 1, data, 0, dataLength);
        
        return data;
    }
}