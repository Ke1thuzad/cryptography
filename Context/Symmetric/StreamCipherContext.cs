namespace Cryptography.Context.Symmetric;

public class StreamCipherContext(ISymmetricKeyAlgorithm algorithm, byte[] key)
{
    const int BufferSize = 1024 * 64;

    public async Task Encrypt(string inputFile, string outputFile)
    {
        await ProcessFile(inputFile, outputFile);
    }

    public async Task Decrypt(string inputFile, string outputFile)
    {
        await ProcessFile(inputFile, outputFile);
    }

    async Task ProcessFile(string inputFile, string outputFile)
    {
        algorithm.SetKey(key);

        await using FileStream inStream = new(inputFile, FileMode.Open, FileAccess.Read);
        await using FileStream outStream = new(outputFile, FileMode.Create, FileAccess.Write);

        byte[] buffer = new byte[BufferSize];
        int bytesRead;

        while ((bytesRead = await inStream.ReadAsync(buffer)) > 0)
        {
            byte[] chunk;
            if (bytesRead < BufferSize)
            {
                chunk = new byte[bytesRead];
                Array.Copy(buffer, chunk, bytesRead);
            }
            else
            {
                chunk = buffer;
            }

            byte[] processedChunk = await algorithm.Encrypt(chunk);

            await outStream.WriteAsync(processedChunk);
        }
    }
}