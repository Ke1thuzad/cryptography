using System.Numerics;
using Cryptography.Utility;

namespace Cryptography.AsymmetricAlgorithms.RSA.PrimeTests;

public abstract class PrimeTestBase : IPrimeTest
{
    protected readonly BigRandomNumberGenerator rng = new();
    protected int iterationsCount;
    protected double actualProbability;
    
    public double ActualProbability => actualProbability;
    public int IterationsCount => iterationsCount;

    public bool IsProbablyPrime(BigInteger n, double minProbability)
    {
        if (n <= 0)
            throw new ArgumentException("Number must be positive", nameof(n));
            
        if (minProbability is < 0.5 or >= 1.0)
            throw new ArgumentException(
                "Minimum probability must be in range [0.5, 1)", 
                nameof(minProbability));
        
        iterationsCount = 0;
        actualProbability = 0.0;
        
        if (n <= 1) return false;
        if (n <= 3) return true;
        if (n % 2 == 0) return false;
        
        int k = CalculateIterationsCount(minProbability);
        
        if (k < 1) k = 1;

        bool result = PerformTestIterations(n, k);
        
        actualProbability = CalculateActualProbability(iterationsCount);
        
        return result;
    }
    
    protected abstract int CalculateIterationsCount(double minProbability);

    bool PerformTestIterations(BigInteger n, int iterations)
    {
        for (int i = 0; i < iterations; i++)
        {
            iterationsCount++;
            
            BigInteger a = GenerateWitness(n);
            
            if (!PerformSingleTest(n, a))
                return false;
        }
        
        return true;
    }
    
    protected virtual double CalculateActualProbability(int iterations) 
        => 1.0 - Math.Pow(0.5, iterations);

    protected virtual BigInteger GenerateWitness(BigInteger n)
    {
        BigInteger randomVal = rng.GetRandomBigInteger(n.GetBitLength());
        BigInteger witness = (randomVal % (n - 3)) + 2;
        
        return witness;
    }

    protected abstract bool PerformSingleTest(BigInteger n, BigInteger a);
}