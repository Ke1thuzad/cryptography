using System.Numerics;
using Cryptography.AsymmetricAlgorithms.RSA.PrimeTests;
using Cryptography.Context.Asymmetric;
using Cryptography.Utility;

namespace Cryptography.AsymmetricAlgorithms.RSA;

public class KeyGenerator : IAsymmetricKeyGenerator
{
    readonly Rsa.PrimalityTestType testType;
    readonly double minProbability;
    readonly int bitLength;
    readonly bool generateWeakKey;
    readonly BigRandomNumberGenerator rng;
    
    static readonly int[] SmallPrimes = {
        3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 
        101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199,
        211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331,
        337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457,
        461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541
    };

    public KeyGenerator(Rsa.PrimalityTestType testType, double minProbability, int bitLength, bool generateWeakKey = false)
    {
        if (bitLength < 128) 
            throw new ArgumentException("Bit length too small for RSA", nameof(bitLength));
        
        this.testType = testType;
        this.minProbability = minProbability;
        this.bitLength = bitLength;
        this.generateWeakKey = generateWeakKey;
        rng = new BigRandomNumberGenerator();
    }

    public AsymmetricKeyPair GenerateKeyPair()
    {
        int primeBitLength = bitLength / 2;

        BigInteger p = 0, q = 0, n, phi, e, d;

        int attempts = 0;
        
        while (true) {
            ++attempts;

            if (attempts > 100_000) {
                throw new TimeoutException("RSA Key Primes search has timed out");
            }
            
            Parallel.Invoke(
                () => p = GeneratePrime(primeBitLength),
                () => q = GeneratePrime(primeBitLength)
            );

            if (p == q) continue;

            BigInteger diff = BigInteger.Abs(p - q);
            BigInteger minDiff = BigInteger.One << ((primeBitLength / 2) - 1);
            
            if (diff < minDiff)
                continue;

            n = p * q;
            
            if (n.GetBitLength() != bitLength)
                continue;

            phi = (p - 1) * (q - 1);
            
            if (generateWeakKey)
            {
                BigInteger nRoot4 = BigIntegerSqrt(BigIntegerSqrt(n));
                BigInteger maxD = nRoot4 / 3;

                if (maxD < 5) continue;

                long maxDBits = maxD.GetBitLength();
                
                d = rng.GetRandomBigInteger(maxDBits);
                
                while (d >= maxD || d <= 1)
                {
                    d = rng.GetRandomBigInteger(maxDBits);
                }

                while (MathAlgorithms.Gcd(d, phi) != 1)
                {
                    d++;
                    if (d >= maxD) d = 2; 
                }

                e = CalculateModularInverse(d, phi);
            }
            else
            {
                e = 65537;
            
                if (e >= phi || MathAlgorithms.Gcd(e, phi) != 1)
                {
                    e = 3;
                    bool foundE = false;
                    while (e < phi && e < 100000)
                    {
                        if (MathAlgorithms.Gcd(e, phi) == 1)
                        {
                            foundE = true;
                            break;
                        }
                        e += 2;
                    }
                    if (!foundE) 
                        continue;
                }

                d = CalculateModularInverse(e, phi);

                if (!CheckWienerResistance(d, n))
                    continue;
            }

            break;
        }
        
        BigInteger dP = d % (p - 1);
        BigInteger dQ = d % (q - 1);
        BigInteger qInv = CalculateModularInverse(q, p);

        return new RsaFullKeyPair(e, d, n, p, q, dP, dQ, qInv);
    }

    BigInteger GeneratePrime(int bits)
    {
        IPrimeTest test = CreatePrimeTest(testType);
        
        while (true)
        {
            BigInteger candidate = rng.GetRandomBigInteger(bits);
            
            if (candidate.IsEven) candidate |= 1;

            bool isComposite = SmallPrimes.Any(smallPrime => candidate % smallPrime == 0);

            if (isComposite)
                continue;
            
            if (test.IsProbablyPrime(candidate, minProbability))
            {
                return candidate;
            }
        }
    }

    static IPrimeTest CreatePrimeTest(Rsa.PrimalityTestType type) =>
        type switch
        {
            Rsa.PrimalityTestType.Fermat          => new FermatPrimeTest(),
            Rsa.PrimalityTestType.SolovayStrassen => new SolovayStrassenPrimeTest(),
            Rsa.PrimalityTestType.MillerRabin     => new MillerRabinPrimeTest(),
            _                                     => throw new ArgumentOutOfRangeException(nameof(type))
        };

    static BigInteger CalculateModularInverse(BigInteger a, BigInteger m)
    {
        (BigInteger gcd, BigInteger x, BigInteger y) = MathAlgorithms.ExtendedGcd(a, m);
        
        if (gcd != 1) 
            throw new ArithmeticException("Modular inverse does not exist.");
        
        return (x % m + m) % m;
    }

    static bool CheckWienerResistance(BigInteger d, BigInteger n)
    {
        if (d.GetBitLength() * 4 >= n.GetBitLength())
            return true;
            
        BigInteger lhs = 3 * d;
        return BigInteger.Pow(lhs, 4) >= n;
    }

    BigInteger BigIntegerSqrt(BigInteger value)
    {
        if (value < 0) throw new ArgumentException("Negative argument.");
        if (value == 0) return 0;
        if (value <= 3) return 1;

        int bitLength = (int)value.GetBitLength();
        BigInteger x = BigInteger.One << ((bitLength + 1) / 2);

        while (true)
        {
            BigInteger nextX = (x + value / x) >> 1;
            if (nextX >= x) return x;
            x = nextX;
        }
    }
}