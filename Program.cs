namespace Cryptography;

internal class Program
{
    static void Main(string[] args) {
        PermutationTest();
    }

    static void PermutationTest() {
        byte[] data = [0b10101010];
        byte[] pBlock = [8, 7, 6, 5, 4, 3, 2, 1];

        byte[] permutedData = Utility.PermuteBits(data, pBlock);
        
        foreach (byte b in permutedData)
        {
            Console.Write(Convert.ToString(b, 2).PadLeft(8, '0'));
        }
        
        Console.WriteLine();
        Console.WriteLine();
        
        
        data = [0b11111111, 0b00000000];
        pBlock = [16, 1, 15, 2, 14, 3, 13, 4, 12, 5, 11, 6, 10, 7, 9, 8];

        permutedData = Utility.PermuteBits(data, pBlock);
        
        foreach (byte b in permutedData)
        {
            Console.Write(Convert.ToString(b, 2).PadLeft(8, '0') + ' ');
        }
    }
}