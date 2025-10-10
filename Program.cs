using System;

namespace Cryptography
{
    internal class Program
    {
        static void Main(string[] args) {
            byte[] data = [0b11001010, 0b10101101, 0b00110100, 0b11110001, 0b01011011, 0b10001100, 0b01100111, 0b00011101];
            byte[] pBlock = [
                58, 50, 42, 34, 26, 18, 10, 2,
                60, 52, 44, 36, 28, 20, 12, 4,
                62, 54, 46, 38, 30, 22, 14, 6,
                64, 56, 48, 40, 32, 24, 16, 8,
                57, 49, 41, 33, 25, 17, 9, 1,
                59, 51, 43, 35, 27, 19, 11, 3,
                61, 53, 45, 37, 29, 21, 13, 5,
                63, 55, 47, 39, 31, 23, 15, 7
            ];

            byte[] permutedData = Utility.PermuteBits(data, pBlock, true, true);
        
            Console.Write("Hex: ");
            foreach (byte b in permutedData)
            {
                Console.Write($"{b:X2} ");
            }
            Console.WriteLine();
        }
    }
}