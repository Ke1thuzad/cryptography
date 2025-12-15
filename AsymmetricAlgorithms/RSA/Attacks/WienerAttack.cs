using System.Numerics;
using System.Diagnostics;

namespace Cryptography.AsymmetricAlgorithms.RSA.Attacks;

public class WienerAttack
{
    public WienerAttackResult RecoverPrivateKey(BigInteger e, BigInteger n)
    {
        Stopwatch stopwatch = Stopwatch.StartNew();
        List<Fraction> convergents = [];

        foreach (BigInteger coeff in GetContinuedFractionCoefficients(e, n))
        {
            Fraction convergent = ComputeConvergent(convergents, coeff);
            convergents.Add(convergent);

            BigInteger k = convergent.Numerator;
            BigInteger d = convergent.Denominator;

            if (k == 0 || d == 0) 
                continue;

            BigInteger edMinus1 = e * d - 1;
            
            if (edMinus1 % k != 0)
                continue;

            BigInteger phi = edMinus1 / k;

            if (IsPhiValid(n, phi))
            {
                stopwatch.Stop();
                return new WienerAttackResult
                {
                    Success = true,
                    D = d,
                    Phi = phi,
                    Convergents = convergents,
                    Duration = stopwatch.Elapsed
                };
            }
        }

        stopwatch.Stop();
        return new WienerAttackResult
        {
            Success = false,
            Convergents = convergents,
            Duration = stopwatch.Elapsed
        };
    }

    IEnumerable<BigInteger> GetContinuedFractionCoefficients(BigInteger a, BigInteger b)
    {
        while (b != 0)
        {
            BigInteger q = a / b;
            BigInteger r = a % b;
            
            yield return q;
            
            a = b;
            b = r;
        }
    }

    Fraction ComputeConvergent(List<Fraction> previousConvergents, BigInteger currentCoeff)
    {
        BigInteger num;
        BigInteger den;
        int i = previousConvergents.Count;

        switch (i) {
            case 0:
                num = currentCoeff;
                den = 1;
                break;
            case 1:
                num = currentCoeff * previousConvergents[0].Numerator + 1;
                den = currentCoeff * previousConvergents[0].Denominator;
                break;
            default:
                num = currentCoeff * previousConvergents[i - 1].Numerator + previousConvergents[i - 2].Numerator;
                den = currentCoeff * previousConvergents[i - 1].Denominator + previousConvergents[i - 2].Denominator;
                break;
        }

        return new Fraction(num, den);
    }

    bool IsPhiValid(BigInteger n, BigInteger phi)
    {
        BigInteger b = n - phi + 1;
        BigInteger discriminant = b * b - 4 * n;

        if (discriminant < 0) return false;

        BigInteger sqrtD = BigIntegerSqrt(discriminant);
        
        if (sqrtD * sqrtD != discriminant) return false;

        BigInteger numerator1 = b + sqrtD;
        if (numerator1 % 2 != 0 || numerator1 < 0) return false;
        
        BigInteger p = numerator1 / 2;
        BigInteger q = n / p;

        return p * q == n;
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
            
            if (nextX >= x) 
                return x;
                
            x = nextX;
        }
    }
}