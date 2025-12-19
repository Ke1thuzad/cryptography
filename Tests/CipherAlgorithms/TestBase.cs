using Cryptography.Context.Symmetric;

namespace Tests.CipherAlgorithms;

public abstract class TestBase : IDisposable
{
    readonly List<string> tempFiles = [];
    
    protected string CreateTempFile(string content)
    {
        string path = GetTempFilePath();
        File.WriteAllText(path, content);
        return path;
    }

    protected string CreateEmptyTempFile()
    {
        string path = GetTempFilePath();
        File.WriteAllText(path, string.Empty);
        return path;
    }

    protected string GetTempFilePath()
    {
        string path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString() + ".tmp");
        tempFiles.Add(path);
        return path;
    }

    protected async Task AssertFilesEqual(string path1, string path2, Padding.Mode padding)
    {
        if (padding == Padding.Mode.Zeros)
        {
            byte[] f1 = await File.ReadAllBytesAsync(path1);
            byte[] f2 = await File.ReadAllBytesAsync(path2);
        
            int len1 = f1.Length;
            while (len1 > 0 && f1[len1 - 1] == 0) len1--;

            int len2 = f2.Length;
            while (len2 > 0 && f2[len2 - 1] == 0) len2--;

            Assert.Equal(f1.Take(len1), f2.Take(len2));
        }
        else
        {
            byte[] f1 = await File.ReadAllBytesAsync(path1);
            byte[] f2 = await File.ReadAllBytesAsync(path2);
            Assert.Equal(f1, f2);
        }
    }

    public void Dispose() {
        foreach (string file in tempFiles.Where(File.Exists)) {
            try { File.Delete(file); }
            catch {
                // ignored
            }
        }
    }
}