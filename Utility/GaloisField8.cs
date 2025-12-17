namespace Cryptography.Utility;

public class ReducibleModulusException(string message) : Exception(message);

public static class GaloisField8
{
    public static byte Add(byte a, byte b) => (byte)(a ^ b);

    public static byte Multiply(byte a, byte b, byte modulus) {
        uint fullModulus = 0x100U | modulus;

        if (!CheckIrreducibilityInternal(fullModulus)) {
            throw new ReducibleModulusException($"Modulus 0x{fullModulus:X} is reducible over GF(2).");
        }
        
        byte p = 0;
        for (int i = 0; i < 8; i++) {
            if ((b & 1) != 0) {
                p ^= a;
            }
            
            bool highBitSet = (a & 0x80) != 0;

            a <<= 1;
            
            if (highBitSet) {
                a ^= modulus;
            }

            b >>= 1;
        }

        return p;
    }


    public static byte Inverse(byte a, byte modulus) {
        if (a == 0) return 0;

        uint fullModulus = 0x100U | modulus;

        if (!CheckIrreducibilityInternal(fullModulus)) {
            throw new ReducibleModulusException($"Modulus 0x{fullModulus:X} is reducible over GF(2).");
        }

        uint r0 = fullModulus;
        uint r1 = a;
        uint t0 = 0;
        uint t1 = 1;

        while (r1 > 0) {
            uint q = PolyDiv(r0, r1, out uint remainder);


            uint prod = PolyMulNoMod(q, t1);
            uint tNext = t0 ^ prod;
            
            r0 = r1;
            r1 = remainder;
            t0 = t1;
            t1 = tNext;
        }
        
        if (r0 != 1)
            throw new ArithmeticException("Inverse element does not exist (GCD != 1).");

        return (byte)(t0 & 0xFF);
    }

    public static bool IsIrreducible(byte modulusPart) {
        uint poly = 0x100U | modulusPart;
        return CheckIrreducibilityInternal(poly);
    }
    
    public static List<uint> GetAllIrreduciblePolysDeg8() {
        List<uint> irreducibles = [];

        for (int i = 0; i <= 255; i++) {
            uint poly = 0x100U | (uint)i;

            if (CheckIrreducibilityInternal(poly)) {
                irreducibles.Add(poly);
            }
        }

        return irreducibles;
    }

    public static List<ulong> Factorize(ulong poly) {
        List<ulong> factors = [];

        if (poly is 0 or 1) {
            factors.Add(poly);
            return factors;
        }

        while ((poly & 1) == 0) {
            factors.Add(2);
            poly >>= 1;
        }

        if (poly == 1) return factors;

        ulong divisor = 3;

        while (true) {
            int degPoly = GetDegree(poly);
            int degDiv = GetDegree(divisor);

            if (degDiv * 2 > degPoly) {
                factors.Add(poly);
                break;
            }

            ulong remainder = PolyMod(poly, divisor);

            if (remainder == 0) {
                factors.Add(divisor);

                poly = PolyDiv(poly, divisor, out _);
            }
            else {
                divisor += 2;
            }

            if (poly == 1) break;
        }

        return factors;
    }

    static bool CheckIrreducibilityInternal(uint poly) {
        int degree = GetDegree(poly);

        if ((poly & 1) == 0) return false;

        long limit = 1L << (degree / 2 + 1);

        for (uint d = 3; d < limit; d += 2) {
            if (PolyMod(poly, d) == 0) return false;
        }

        return true;
    }


    static int GetDegree(ulong v) {
        if (v == 0) return -1;
        int r = 0;
        if ((v & 0xFFFFFFFF00000000) != 0) {
            v >>= 32;
            r += 32;
        }

        if ((v & 0xFFFF0000) != 0) {
            v >>= 16;
            r += 16;
        }

        if ((v & 0xFF00) != 0) {
            v >>= 8;
            r += 8;
        }

        if ((v & 0xF0) != 0) {
            v >>= 4;
            r += 4;
        }

        if ((v & 0xC) != 0) {
            v >>= 2;
            r += 2;
        }

        if ((v & 0x2) != 0) {
            v >>= 1;
            r += 1;
        }

        return r;
    }

    static int GetDegree(uint v) => GetDegree((ulong)v);

    static uint PolyDiv(uint dividend, uint divisor, out uint remainder) {
        uint quotient = 0;
        int degDividend = GetDegree(dividend);
        int degDivisor = GetDegree(divisor);

        while (degDividend >= degDivisor) {
            int shift = degDividend - degDivisor;
            uint val = 1U << shift;
            quotient ^= val;
            dividend ^= (divisor << shift);
            degDividend = GetDegree(dividend);
        }

        remainder = dividend;
        return quotient;
    }

    static ulong PolyDiv(ulong dividend, ulong divisor, out ulong remainder) {
        ulong quotient = 0;
        int degDividend = GetDegree(dividend);
        int degDivisor = GetDegree(divisor);

        while (degDividend >= degDivisor && dividend != 0) {
            int shift = degDividend - degDivisor;
            ulong val = 1UL << shift;
            quotient ^= val;
            dividend ^= (divisor << shift);
            degDividend = GetDegree(dividend);
        }

        remainder = dividend;
        return quotient;
    }

    static uint PolyMod(uint dividend, uint divisor) {
        int degDividend = GetDegree(dividend);
        int degDivisor = GetDegree(divisor);

        while (degDividend >= degDivisor) {
            int shift = degDividend - degDivisor;
            dividend ^= (divisor << shift);
            degDividend = GetDegree(dividend);
        }

        return dividend;
    }

    static ulong PolyMod(ulong dividend, ulong divisor) {
        int degDividend = GetDegree(dividend);
        int degDivisor = GetDegree(divisor);

        while (degDividend >= degDivisor) {
            int shift = degDividend - degDivisor;
            dividend ^= (divisor << shift);
            degDividend = GetDegree(dividend);
        }

        return dividend;
    }

    static uint PolyMulNoMod(uint a, uint b) {
        uint res = 0;
        while (b > 0) {
            if ((b & 1) != 0) res ^= a;
            a <<= 1;
            b >>= 1;
        }

        return res;
    }
}