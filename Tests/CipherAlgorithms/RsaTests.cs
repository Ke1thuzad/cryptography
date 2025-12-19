using Cryptography.AsymmetricAlgorithms.RSA;
using Cryptography.Context.Asymmetric;
using Cryptography.Context.Symmetric;

namespace Tests.CipherAlgorithms;

public class RsaTests : TestBase
{
    [Fact]
    public async Task Rsa1024_EncryptDecrypt_Standard()
    {
        var rsa = new Rsa(Rsa.PrimalityTestType.MillerRabin, 0.999, 1024, false);
        rsa.GenerateKeys();
        
        var context = new AsymmetricAlgorithmContext(rsa);

        string inputFile = CreateTempFile("RSA 1024 Data");
        string encFile = GetTempFilePath();
        string decFile = GetTempFilePath();

        await context.Encrypt(inputFile, encFile);
        await context.Decrypt(encFile, decFile);

        await AssertFilesEqual(inputFile, decFile, Padding.Mode.Zeros);
    }

    [Fact]
    public async Task Rsa2048_EncryptDecrypt_LargeContent()
    {
        var rsa = new Rsa(Rsa.PrimalityTestType.MillerRabin, 0.999, 2048, false);
        rsa.GenerateKeys();
        
        var context = new AsymmetricAlgorithmContext(rsa);

        string inputFile = CreateTempFile(new string('X', 5000));
        string encFile = GetTempFilePath();
        string decFile = GetTempFilePath();

        await context.Encrypt(inputFile, encFile);
        await context.Decrypt(encFile, decFile);

        await AssertFilesEqual(inputFile, decFile, Padding.Mode.Zeros);
    }
}