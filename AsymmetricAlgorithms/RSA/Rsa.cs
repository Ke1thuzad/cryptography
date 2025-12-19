using System.Numerics;
using Cryptography.Utility;
using Cryptography.Context.Asymmetric;

namespace Cryptography.AsymmetricAlgorithms.RSA;

public class Rsa : IAsymmetricKeyAlgorithm
{
    public enum PrimalityTestType
    {
        Fermat,
        SolovayStrassen,
        MillerRabin
    }

    BigInteger n;
    BigInteger e;
    BigInteger d;
    
    BigInteger p;
    BigInteger q;
    BigInteger dP;
    BigInteger dQ;
    BigInteger qInv;
    
    readonly KeyGenerator keyGenerator;
    readonly PkcsPadding padding;

    public int KeySizeBits => n.GetBitLength() == 0 ? 0 : (int)n.GetBitLength();
    
    public RsaKeyPair PublicPair => new(e, n);
    
    public RsaKeyPair PrivatePair => new(d, n); 

    public bool HasKey => n != 0;

    public Rsa(PrimalityTestType testType, double minProbability, int keyBitLength, bool enableWienerVulnerability = false)
    {
        keyGenerator = new KeyGenerator(testType, minProbability, keyBitLength, enableWienerVulnerability);
        padding = new PkcsPadding();
    }

    public void GenerateKeys()
    {
        AsymmetricKeyPair baseKeys = keyGenerator.GenerateKeyPair();
        
        if (baseKeys is not RsaFullKeyPair keys)
            throw new InvalidOperationException("Invalid key pair type generated.");
        
        e = keys.E;
        d = keys.D;
        n = keys.N;
        p = keys.P;
        q = keys.Q;
        dP = keys.DP;
        dQ = keys.DQ;
        qInv = keys.QInv;
    }

    public byte[] Encrypt(byte[] data)
    {
        if (!HasKey) 
            throw new InvalidOperationException("Keys not generated.");
        
        int modulusLen = (int)(n.GetBitLength() + 7) / 8;
        
        byte[] padded = padding.AddPadding(data, modulusLen);
        
        BigInteger m = new BigInteger(padded, isUnsigned: true, isBigEndian: true);
        
        BigInteger c = MathAlgorithms.ModExp(m, e, n);
        
        return AlignBytes(c.ToByteArray(isUnsigned: true, isBigEndian: true), modulusLen);
    }

    public byte[] Decrypt(byte[] encryptedData)
    {
        if (!HasKey) throw new InvalidOperationException("Keys not generated.");
        int modulusLen = (int)(n.GetBitLength() + 7) / 8;

        if (encryptedData.Length != modulusLen)
            throw new ArgumentException($"Data size mismatch. Expected {modulusLen}, got {encryptedData.Length}");

        BigInteger c = new BigInteger(encryptedData, isUnsigned: true, isBigEndian: true);
        
        BigInteger m1 = MathAlgorithms.ModExp(c, dP, p);
        BigInteger m2 = MathAlgorithms.ModExp(c, dQ, q);
        
        BigInteger diff = m1 - m2;
        
        while (diff < 0) 
            diff += p;
        
        BigInteger h = (diff * qInv) % p;
        
        BigInteger m = m2 + (h * q);

        byte[] padded = AlignBytes(m.ToByteArray(isUnsigned: true, isBigEndian: true), modulusLen);
        
        return padding.RemovePadding(padded);
    }

    byte[] AlignBytes(byte[] input, int targetLength)
    {
        if (input.Length == targetLength) 
            return input;

        if (input.Length > targetLength)
        {
            byte[] trimmed = new byte[targetLength];
            Array.Copy(input, input.Length - targetLength, trimmed, 0, targetLength);
            return trimmed;
        }

        byte[] padded = new byte[targetLength];
        Array.Copy(input, 0, padded, targetLength - input.Length, input.Length);
        return padded;
    }

    public readonly record struct RsaKeyPair(BigInteger Exponent, BigInteger Modulus)
    {
        public override string ToString() => $"Exponent: {Exponent}\nModulus: {Modulus}";
    }
}