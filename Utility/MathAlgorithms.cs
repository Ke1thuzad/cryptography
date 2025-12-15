using System.Numerics;

namespace Cryptography.Utility;

public static class MathAlgorithms
{
    public static int LegendreSymbol(BigInteger a, BigInteger p)
    {
        if (p <= 2 || p % 2 == 0)
            throw new ArgumentException("p must be a prime");

        a = ((a % p) + p) % p;
        
        if (a == 0)
            return 0;

        BigInteger result = ModExp(a, (p - 1) / 2, p);
        return result == p - 1 ? -1 : (int)result;
    }

    public static int JacobiSymbol(BigInteger a, BigInteger n)
    {
        if (n <= 0 || n % 2 == 0)
            throw new ArgumentException("n must be positive and odd");

        a = ((a % n) + n) % n;
        int result = 1;

        while (a != 0)
        {
            int t = 0;
            while (a % 2 == 0)
            {
                a /= 2;
                t++;
            }
            
            if (t % 2 == 1)
            {
                BigInteger temp = (n % 8);
                if (temp == 3 || temp == 5)
                    result = -result;
            }

            if (a % 4 == 3 && n % 4 == 3)
                result = -result;

            BigInteger temp2 = a;
            a = n % temp2;
            n = temp2;
        }

        return n == 1 ? result : 0;
    }

    public static BigInteger Gcd(BigInteger a, BigInteger b)
    {
        a = BigInteger.Abs(a);
        b = BigInteger.Abs(b);
        
        while (b != 0)
        {
            BigInteger temp = b;
            b = a % b;
            a = temp;
        }
        return a;
    }

    public static (BigInteger gcd, BigInteger x, BigInteger y) ExtendedGcd(BigInteger a, BigInteger b)
    {
        if (a < 0 || b < 0)
            throw new ArgumentException("Arguments must be non-negative");

        BigInteger x0 = 1, y0 = 0, x1 = 0, y1 = 1;
        BigInteger q, r, xTemp, yTemp;

        while (b != 0)
        {
            q = a / b;
            r = a % b;
            
            xTemp = x0 - q * x1;
            yTemp = y0 - q * y1;
            
            a = b;
            b = r;
            
            x0 = x1;
            y0 = y1;
            x1 = xTemp;
            y1 = yTemp;
        }

        return (a, x0, y0);
    }

    public static BigInteger ModExp(BigInteger a, BigInteger p, BigInteger m)
    {
        if (m <= 0)
            throw new ArgumentException("Modulus must be positive");
        
        a = ((a % m) + m) % m;
        BigInteger result = 1;
        
        while (p > 0)
        {
            if ((p & 1) == 1)
                result = (result * a) % m;
            
            a = (a * a) % m;
            p >>= 1;
        }
        
        return result;
    }
}