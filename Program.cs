using System.Numerics;
using System.Text;
using Cryptography.AsymmetricAlgorithms.DiffieHellman;
using Cryptography.Context.Symmetric;
using Cryptography.SymmetricAlgorithms.DEAL;
using Cryptography.SymmetricAlgorithms.DES;
using Cryptography.SymmetricAlgorithms.TripleDES;
using Cryptography.AsymmetricAlgorithms.RSA;
using Cryptography.AsymmetricAlgorithms.RSA.Attacks;
using Cryptography.Context.Asymmetric;
using Cryptography.SymmetricAlgorithms.AESRijndael;
using Cryptography.SymmetricAlgorithms.FROG;
using Cryptography.SymmetricAlgorithms.RC4;

namespace Cryptography;

class Program
{
    static async Task Main(string[] args) {
        // await RsaTest();
        // await DesTest();
        // await AesTest();
        // await DiffieHellmanTest();
        // await Rc4Test();
        await FrogTest();
    }
    
    static async Task FrogTest()
    {
        byte[] key = "qwerfvgbhq7y3r8hyh"u8.ToArray(); 
        byte[] iv = new byte[16]; 
        
        Frog frog = new(16);
        SymmetricAlgorithmContext context = new(frog, key, CipherMode.Mode.ECB, Padding.Mode.PKCS7, iv);

        await context.Encrypt("qewrew.mp4", "encryptedqewrew.mp4");
        
        await context.Decrypt("encryptedqewrew.mp4", "decryptedqewrew.mp4");
    }
    
     static async Task DiffieHellmanTest()
    {
        Console.WriteLine("=== Diffie-Hellman Protocol Demonstration ===\n");

        DiffieHellmanGroup group = DiffieHellmanGroup.Group14;
        Console.WriteLine($"[Public] Group parameters accepted (RFC 3526, 2048-bit MODP).");

        DiffieHellman aliceDh = new (group);
        DiffieHellman bobDh = new (group);

        Console.WriteLine("\n[Alice] Generating key pair...");
        BigInteger alicePrivate = aliceDh.GeneratePrivateKey();
        BigInteger alicePublic = aliceDh.CalculatePublicKey(alicePrivate);

        Console.WriteLine("[Bob]   Generating key pair...");
        BigInteger bobPrivate = bobDh.GeneratePrivateKey();
        BigInteger bobPublic = bobDh.CalculatePublicKey(bobPrivate);

        Console.WriteLine($"\n[Network] Alice sends public key: {TruncateHex(alicePublic)}...");
        Console.WriteLine($"[Network] Bob sends public key:   {TruncateHex(bobPublic)}...");

        Console.WriteLine("\n[Alice] Calculating shared secret...");
        BigInteger aliceSharedSecret = aliceDh.CalculateSharedSecret(bobPublic, alicePrivate);

        Console.WriteLine("[Bob]   Calculating shared secret...");
        BigInteger bobSharedSecret = bobDh.CalculateSharedSecret(alicePublic, bobPrivate);

        if (aliceSharedSecret != bobSharedSecret)
        {
            Console.WriteLine("\n[Error] Shared secrets do not match!");
            return;
        }

        Console.WriteLine($"\n[Success] Shared secrets match: {TruncateHex(aliceSharedSecret)}...");

        byte[] aliceSymmetricKey = aliceDh.DeriveSymmetricKey(aliceSharedSecret, 32);
        byte[] bobSymmetricKey = bobDh.DeriveSymmetricKey(bobSharedSecret, 32);

        Console.WriteLine($"[Derived] Symmetric key (256-bit) derived.");

        Console.WriteLine("\n=== Encryption Test (Rijndael-256) ===");
        
        string message = "Secret message passed via DH key exchange!";
        Console.WriteLine($"[Alice] Message: \"{message}\"");

        Rijndael aliceCipher = new(256); 
        aliceCipher.SetKey(aliceSymmetricKey);

        byte[] dataBlock = new byte[32]; 
        byte[] msgBytes = Encoding.UTF8.GetBytes(message);
        Array.Copy(msgBytes, dataBlock, Math.Min(msgBytes.Length, 32));

        byte[] encrypted = await aliceCipher.Encrypt(dataBlock);
        Console.WriteLine($"[Alice] Encrypted (Hex): {Convert.ToHexString(encrypted)}");

        Rijndael bobCipher = new(256);
        bobCipher.SetKey(bobSymmetricKey);

        byte[] decrypted = await bobCipher.Decrypt(encrypted);
        string decryptedText = Encoding.UTF8.GetString(decrypted).TrimEnd('\0');
        
        Console.WriteLine($"[Bob]   Decrypted: \"{decryptedText}\"");
    }
    
    static string TruncateHex(BigInteger bi)
    {
        string hex = bi.ToString("X");
        return hex.Length > 16 ? hex[..16] : hex;
    }
    
    static async Task Rc4Test()
    {
        Console.WriteLine("=== RC4 Algorithm Test (via StreamCipherContext) ===");
        
        byte[] key = "Wiki"u8.ToArray();
        
        Rc4 rc4 = new();
        StreamCipherContext context = new(rc4, key);

        string inputFile = "rc4_test.txt";
        string encryptedFile = "rc4_test.enc";
        string decryptedFile = "rc4_test_dec.txt";

        string content = "Hello, World!";
        await File.WriteAllTextAsync(inputFile, content);
        Console.WriteLine($"Original:  {content}");

        await context.Encrypt(inputFile, encryptedFile);
        Console.WriteLine("File encrypted.");

        await context.Decrypt(encryptedFile, decryptedFile);
        Console.WriteLine("File decrypted.");

        string decryptedContent = await File.ReadAllTextAsync(decryptedFile);
        Console.WriteLine($"Decrypted: {decryptedContent}");
    }
     
    static async Task AesTest() {
        Rijndael aes = new(128);
        
        byte[] key = [
            0x08, 0x2B, 0x04, 0xA9, 0x6E, 0x0E, 0xB6, 0x2D, 
            0xC8, 0x1A, 0xFF, 0x78, 0x7F, 0x0F, 0xF0, 0xF3 
        ];
        
        byte[] iv = [
            0x69, 0xA5, 0xA0, 0x91, 0x5D, 0x73, 0x20, 0xFB, 
            0xAA, 0x55, 0x74, 0xFD, 0x0E, 0x34, 0x9E, 0x2B 
        ];

        SymmetricAlgorithmContext context = new(aes, key, CipherMode.Mode.ECB, Padding.Mode.PKCS7, iv);

        await context.Encrypt("qewrew.mp4", "encryptedqewrew.mp4");
        
        await context.Decrypt("encryptedqewrew.mp4", "decryptedqewrew.mp4");
    }

    static async Task RsaTest() {
        Rsa rsa = new(Rsa.PrimalityTestType.MillerRabin, 0.999, 2048, false);
        
        rsa.GenerateKeys();

        Console.WriteLine("Keys has been generated");

        AsymmetricAlgorithmContext context = new(rsa);

        await context.Encrypt("qewrew.mp4", "encryptedqewrew.mp4");
        
        await context.Decrypt("encryptedqewrew.mp4", "decryptedqewrew.mp4");

        // WienerAttack wienerAttack = new();
        //
        // while (true) {
        //     rsa.GenerateKeys();
        //     Console.WriteLine("Keys has been generated");
        //     
        //     WienerAttackResult result = wienerAttack.RecoverPrivateKey(rsa.PublicPair.Exponent, rsa.PublicPair.Modulus);
        //
        //     if (result.Success) {
        //         Console.WriteLine("Wiener Attack was successful! Private key is: " + result.D);
        //         break;
        //     }
        //
        //     Console.WriteLine("Wiener Attack was not successful!");
        // }
    }
    
    static async Task DesTest() {
        Des des = new();
        Deal deal = new(32);
        TripleDes tripleDes = new();
        TripleDes tripleDes2key = new(false);
        
        // byte[] key = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];
        byte[] key = [119, 99, 111, 30, 241, 164, 43, 34];
        
        // byte[] iv = (byte[])key.Clone();
        byte[] iv = [165, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
        
        byte[] key1 = new byte[] { 
            0x08, 0x2B, 0x04, 0xA9, 0x6E, 0x0E, 0xB6, 0x2D, 
            0xC8, 0x1A, 0xFF, 0x78, 0x7F, 0x0F, 0xF0, 0xF3 
        };
        byte[] iv1 = new byte[] { 
            0x69, 0xA5, 0xA0, 0x91, 0x5D, 0x73, 0x20, 0xFB, 
            0xAA, 0x55, 0x74, 0xFD, 0x0E, 0x34, 0x9E, 0x2B 
        };

        byte[] key2 = new byte[] { 
            0xDC, 0x01, 0xFC, 0x8B, 0xAC, 0x33, 0x2B, 0x42, 
            0x9A, 0x45, 0x43, 0x22, 0x4F, 0x3C, 0x0A, 0xD1, 
            0xD6, 0x7C, 0xDF, 0xD5, 0x6F, 0x0A, 0x8B, 0x55 
        };
        byte[] iv2 = new byte[] { 
            0x05, 0x86, 0x46, 0xFE, 0x95, 0x5C, 0x64, 0x41, 
            0xAE, 0x07, 0xF7, 0x8A, 0x39, 0x3E, 0x8D, 0x55 
        };

        byte[] key3 = new byte[] { 
            0x5A, 0x94, 0x32, 0x58, 0x4E, 0xBE, 0x0C, 0x72, 
            0x7E, 0x6B, 0xBC, 0x37, 0xB2, 0xCF, 0x1F, 0x40, 
            0xD5, 0xAA, 0x58, 0x4A, 0x92, 0xE9, 0xA4, 0xB5, 
            0x52, 0xA6, 0xEB, 0x0E, 0xDD, 0x09, 0x64, 0x52 
        };
        byte[] iv3 = new byte[] { 
            0xB4, 0x5C, 0x7F, 0x4A, 0x1F, 0x0F, 0xE2, 0x90, 
            0xD8, 0x80, 0xC4, 0x53, 0x12, 0x2A, 0xE5, 0x2D 
        };
        
        SymmetricAlgorithmContext context = new(des, key, CipherMode.Mode.RandomDelta, Padding.Mode.Zeros, iv);
        // SymmetricAlgorithmContext context = new(deal, key3, CipherMode.Mode.ECB, Padding.Mode.Zeros, iv3);
        // SymmetricAlgorithmContext context = new(tripleDes, key2, CipherMode.Mode.RandomDelta, Padding.Mode.Zeros, iv);
        // SymmetricAlgorithmContext contextdeal = new(deal, key_deal, CipherMode.Mode.RandomDelta, Padding.Mode.PKCS7, (byte[])key_deal.Clone());
        
        // context.Encrypt("repeattest", "encryptedrepeattest").Wait();
        
        // context.Decrypt("encryptedrepeattest", "decryptedrepeattest").Wait();
        
        await context.Encrypt("qewrew.mp4", "encryptedqewrew");
        
        await context.Decrypt("encryptedqewrew", "decryptedqewrew.mp4");
    }
}