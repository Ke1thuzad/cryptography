using Cryptography.Context.Symmetric;

namespace Tests.CipherAlgorithms;

public static class TestData
{
    public static IEnumerable<object[]> GetBlockCipherParams()
    {
        CipherMode.Mode[] modes = Enum.GetValues<CipherMode.Mode>();
        Padding.Mode[] paddings = Enum.GetValues<Padding.Mode>();
        
        foreach (CipherMode.Mode mode in modes)
        {
            foreach (Padding.Mode padding in paddings)
            {
                yield return [mode, padding];
            }
        }
    }
}