using System.Numerics;
using Cryptography.Utility;

namespace Cryptography.AsymmetricAlgorithms.RSA.PrimeTests;

public class MillerRabinPrimeTest : PrimeTestBase
{
    protected override int CalculateIterationsCount(double minProbability) => (int)Math.Ceiling(Math.Log(1.0 / (1.0 - minProbability), 4));

    protected override double CalculateActualProbability(int iterations) => 1.0 - Math.Pow(0.25, iterations);

    protected override bool PerformSingleTest(BigInteger n, BigInteger a)
    {
        BigInteger d = n - 1;
        int s = 0;
        
        while (d % 2 == 0)
        {
            d /= 2;
            s++;
        }
        
        BigInteger x = MathAlgorithms.ModExp(a, d, n);
        
        if (x == 1 || x == n - 1)
            return true;
            
        for (int r = 1; r < s; r++)
        {
            x = MathAlgorithms.ModExp(x, 2, n);
            
            if (x == n - 1)
                return true;
            
            if (x == 1)
                return false;
        }
        
        return false;
    }
}