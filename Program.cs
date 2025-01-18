using System.Text;
using System.Security.Cryptography;
using System.Threading.Tasks;
using System.Formats.Tar;
using System.IO.Compression;


class Program
{
    static async Task Main(string[] args)
    {
        if (args.Length != 3)
        {
            Console.WriteLine("Usage: ha-backup-decrypt <input> <output> <key>" + Environment.NewLine + Environment.NewLine);
            Console.WriteLine("  <input>    encypted single tar.gz file or complete .tar backup with multiple encrypted tar.gz files");
            Console.WriteLine("  <output>   output filename or destination directory");
            return;
        }

        string inputFilePath = args[0];
        string outputFilePath = args[1];
        string password = args[2];

        //check if it's single encrypted .tar.gz?
        if(inputFilePath.EndsWith(".tar.gz", StringComparison.InvariantCultureIgnoreCase))
        {
            //single encrypted .tar.gz
            if(DecryptBackup(inputFilePath, outputFilePath, password))
                Console.WriteLine($"Decryption successful! Decrypted file saved to: {outputFilePath}");                   
        }
        else if(inputFilePath.EndsWith(".tar", StringComparison.InvariantCultureIgnoreCase))
        {
            //tar archive with multiple encrypted .tar.gz files
            //first, extract it
            string outputDir = outputFilePath.Replace(".tar.gz", "", StringComparison.InvariantCultureIgnoreCase).Replace(".tar", "", StringComparison.InvariantCultureIgnoreCase) + "\\";
            DirectoryInfo d = new DirectoryInfo(outputDir);
            if(!Directory.Exists(outputDir)) Directory.CreateDirectory(outputDir);
            await TarFile.ExtractToDirectoryAsync(inputFilePath, outputDir, true);
            foreach (var file in d.GetFiles("*.tar.gz"))
            {
                //decrypt .tar.gz
                string sFileNameDecrypted = file.ToString().Replace(".tar.gz", "_decypted.tar.gz", StringComparison.InvariantCultureIgnoreCase);
                string sFileName = file.ToString();                
                if(DecryptBackup(sFileName, sFileNameDecrypted, password))
                {
                    //decryption successfull
                    file.Delete();
                    File.Move(sFileNameDecrypted, sFileName);
                    Console.WriteLine($"Decryption successful! Decrypted file saved to: {sFileName}");                   
                }
            }
        }

    }

    static bool DecryptBackup(string inputFilePath, string outputFilePath, string password)
    {
        bool bSuccess = false;
        try
        {
            byte[] key = GetPasswordHash(password);

            using (FileStream inputFile = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read))
            using (FileStream outputFile = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write))
            {
                byte[] cbcRand = new byte[16];
                inputFile.Read(cbcRand, 0, 16);

                byte[] iv = GenerateIV(key, cbcRand);

                // Decrypt
                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.PKCS7;

                    using (CryptoStream cryptoStream = new CryptoStream(inputFile, aes.CreateDecryptor(), CryptoStreamMode.Read))
                    {
                        cryptoStream.CopyTo(outputFile);
                    }
                }
            }

            bSuccess = true;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error during decryption: {ex.Message}");
        }
        return bSuccess;
    }

    static byte[] GetPasswordHash(string password)
    {
        // Derive the key using SHA-256 (100 iterations)
        byte[] data = Encoding.UTF8.GetBytes(password);
        using (SHA256 sha256 = SHA256.Create())
        {
            for (int i = 0; i < 100; i++)
            {
                data = sha256.ComputeHash(data);
            }
        }
        // Return the first 16 bytes (128 bits)
        byte[] key = new byte[16];
        Array.Copy(data, key, 16);
        return key;
    }

    static byte[] GenerateIV(byte[] key, byte[] salt)
    {
        // Combine key and salt, then hash 100 times to generate the IV
        byte[] iv = new byte[key.Length + salt.Length];
        Buffer.BlockCopy(key, 0, iv, 0, key.Length);
        Buffer.BlockCopy(salt, 0, iv, key.Length, salt.Length);

        using (SHA256 sha256 = SHA256.Create())
        {
            for (int i = 0; i < 100; i++)
            {
                iv = sha256.ComputeHash(iv);
            }
        }

        // Return the first 16 bytes (128 bits)
        byte[] finalIV = new byte[16];
        Array.Copy(iv, finalIV, 16);
        return finalIV;
    }
   
}
