using System.Text;
using Cryptography.Context.Symmetric;
using Cryptography.SymmetricAlgorithms.RC4;

namespace Tests.CipherAlgorithms;

public class Rc4Tests : TestBase
{
    [Fact]
    public async Task Rc4_EncryptDecrypt_StreamContext()
    {
        byte[] key = Encoding.ASCII.GetBytes("SecretKeyRC4");
        var rc4 = new Rc4();
        var context = new StreamCipherContext(rc4, key);

        string inputFile = CreateTempFile("RC4 Data " + Guid.NewGuid());
        string encFile = GetTempFilePath();
        string decFile = GetTempFilePath();

        await context.Encrypt(inputFile, encFile);
        await context.Decrypt(encFile, decFile);

        await AssertFilesEqual(inputFile, decFile, Padding.Mode.Zeros);
    }

    [Fact]
    public async Task Rc4_EncryptDecrypt_MaxKeySize()
    {
        byte[] key = new byte[256];
        Random.Shared.NextBytes(key);
        
        var rc4 = new Rc4();
        var context = new StreamCipherContext(rc4, key);

        string inputFile = CreateTempFile("RC4 Max Key Data");
        string encFile = GetTempFilePath();
        string decFile = GetTempFilePath();

        await context.Encrypt(inputFile, encFile);
        await context.Decrypt(encFile, decFile);

        await AssertFilesEqual(inputFile, decFile, Padding.Mode.Zeros);
    }

    [Fact]
    public async Task Rc4_EmptyFile_NoErrors()
    {
        byte[] key = new byte[16];
        var rc4 = new Rc4();
        var context = new StreamCipherContext(rc4, key);

        string inputFile = CreateEmptyTempFile();
        string encFile = GetTempFilePath();
        string decFile = GetTempFilePath();

        await context.Encrypt(inputFile, encFile);
        await context.Decrypt(encFile, decFile);

        await AssertFilesEqual(inputFile, decFile, Padding.Mode.Zeros);
    }
}