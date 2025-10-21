using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

class FileCryptoUtility
{
    // Encrypts a file using AES and returns the ciphertext, key, and IV
    public static (byte[] CipherText, byte[] Key, byte[] IV) EncryptFile(string? inputFilePath)
    {
        if (string.IsNullOrEmpty(inputFilePath) || !File.Exists(inputFilePath))
            throw new FileNotFoundException("Input file not found.", inputFilePath);

        using Aes aes = Aes.Create();
        aes.KeySize = 256;
        aes.GenerateKey();
        aes.GenerateIV();

        using ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
        using MemoryStream ms = new MemoryStream();
        using CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write);
        using FileStream fs = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read);
        fs.CopyTo(cs);

        return (ms.ToArray(), aes.Key, aes.IV);
    }

    // Decrypts an AES-encrypted file and saves it to outputFilePath
    public static void DecryptFile(byte[]? cipherText, byte[]? key, byte[]? iv, string? outputFilePath)
    {
        if (cipherText == null || key == null || iv == null)
            throw new ArgumentNullException("Ciphertext, key, or IV cannot be null.");
        if (string.IsNullOrEmpty(outputFilePath))
            throw new ArgumentNullException(nameof(outputFilePath), "Output file path cannot be null or empty.");

        try
        {
            using Aes aes = Aes.Create();
            aes.Key = key;
            aes.IV = iv;

            Console.WriteLine($"Key length: {key.Length} bytes, IV length: {iv.Length} bytes, Ciphertext length: {cipherText.Length} bytes");
            using ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
            using MemoryStream ms = new MemoryStream(cipherText);
            using CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read);
            using FileStream fs = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write);
            cs.CopyTo(fs);
            fs.Flush();
            Console.WriteLine("Decryption completed successfully.");
        }
        catch (CryptographicException ex)
        {
            Console.WriteLine($"Cryptographic error: {ex.Message}");
            throw new CryptographicException("Decryption failed. Ensure the key and IV are correct.", ex);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Unexpected error: {ex.Message}");
            throw;
        }
    }

    // Encodes file contents to Base64 or Hex
    public static string EncodeFile(string? inputFilePath, string? format = "Base64")
    {
        if (string.IsNullOrEmpty(inputFilePath) || !File.Exists(inputFilePath))
            throw new FileNotFoundException("Input file not found.", inputFilePath);
        if (string.IsNullOrEmpty(format))
            format = "Base64";

        byte[] fileBytes = File.ReadAllBytes(inputFilePath);
        return format.ToLower() switch
        {
            "hex" => BitConverter.ToString(fileBytes).Replace("-", "").ToLower(),
            _ => Convert.ToBase64String(fileBytes)
        };
    }

    // Decodes Base64 or Hex string to a file
    public static void DecodeToFile(string? encodedData, string? outputFilePath, string? format = "Base64")
    {
        if (string.IsNullOrEmpty(encodedData))
            throw new ArgumentNullException(nameof(encodedData), "Encoded data cannot be null or empty.");
        if (string.IsNullOrEmpty(outputFilePath))
            throw new ArgumentNullException(nameof(outputFilePath), "Output file path cannot be null or empty.");
        if (string.IsNullOrEmpty(format))
            format = "Base64";

        byte[] fileBytes = format.ToLower() switch
        {
            "hex" => Convert.FromHexString(encodedData),
            _ => Convert.FromBase64String(encodedData)
        };

        File.WriteAllBytes(outputFilePath, fileBytes);
    }

    // Computes hash (MD5, SHA1, SHA256, SHA384, SHA512) of a file
    public static string ComputeFileHash(string? inputFilePath, string? algorithm = "SHA256", string? outputFormat = "Base64")
    {
        if (string.IsNullOrEmpty(inputFilePath) || !File.Exists(inputFilePath))
            throw new FileNotFoundException("Input file not found.", inputFilePath);
        if (string.IsNullOrEmpty(algorithm))
            algorithm = "SHA256";
        if (string.IsNullOrEmpty(outputFormat))
            outputFormat = "Base64";

        byte[] hashBytes;
        using FileStream fs = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read);
        switch (algorithm.ToUpper())
        {
            case "MD5":
                using (MD5 md5 = MD5.Create())
                {
                    hashBytes = md5.ComputeHash(fs);
                }
                break;
            case "SHA1":
                using (SHA1 sha1 = SHA1.Create())
                {
                    hashBytes = sha1.ComputeHash(fs);
                }
                break;
            case "SHA256":
                using (SHA256 sha256 = SHA256.Create())
                {
                    hashBytes = sha256.ComputeHash(fs);
                }
                break;
            case "SHA384":
                using (SHA384 sha384 = SHA384.Create())
                {
                    hashBytes = sha384.ComputeHash(fs);
                }
                break;
            case "SHA512":
                using (SHA512 sha512 = SHA512.Create())
                {
                    hashBytes = sha512.ComputeHash(fs);
                }
                break;
            default:
                throw new ArgumentException($"Unsupported hash algorithm: {algorithm}. Supported: MD5, SHA1, SHA256, SHA384, SHA512");
        }

        return outputFormat.ToLower() switch
        {
            "hex" => BitConverter.ToString(hashBytes).Replace("-", "").ToLower(),
            _ => Convert.ToBase64String(hashBytes)
        };
    }

    // Saves data to a file
    public static void SaveToFile(string? data, string? filePath)
    {
        if (string.IsNullOrEmpty(data))
            throw new ArgumentNullException(nameof(data), "Data cannot be null or empty.");
        if (string.IsNullOrEmpty(filePath))
            throw new ArgumentNullException(nameof(filePath), "File path cannot be null or empty.");

        File.WriteAllText(filePath, data);
    }

    static void Main(string[] args)
    {
        while (true)
        {
            Console.WriteLine("\nFile Crypto Utility Menu:");
            Console.WriteLine("1. Encrypt File (AES)");
            Console.WriteLine("2. Decrypt File (AES)");
            Console.WriteLine("3. Encode File (Base64/Hex)");
            Console.WriteLine("4. Decode to File (Base64/Hex)");
            Console.WriteLine("5. Compute File Hash (MD5/SHA1/SHA256/SHA384/SHA512)");
            Console.WriteLine("6. Exit");
            Console.Write("Select an option (1-6): ");

            string? choice = Console.ReadLine();
            if (string.IsNullOrEmpty(choice))
            {
                Console.WriteLine("Invalid option. Please select 1-6.");
                continue;
            }

            try
            {
                switch (choice)
                {
                    case "1":
                        Console.Write("Enter input file path (e.g., document.docx, image.png): ");
                        string? encryptInput = Console.ReadLine();
                        Console.Write("Enter output file path for ciphertext (e.g., encrypted.bin): ");
                        string? encryptOutput = Console.ReadLine();
                        Console.Write("Output format for key/IV (Base64/Hex): ");
                        string? encryptFormat = Console.ReadLine();
                        var (cipherText, key, iv) = EncryptFile(encryptInput);
                        File.WriteAllBytes(encryptOutput ?? throw new ArgumentNullException(nameof(encryptOutput)), cipherText);
                        SaveToFile(Encode(key, encryptFormat), $"{encryptOutput}.key.txt");
                        SaveToFile(Encode(iv, encryptFormat), $"{encryptOutput}.iv.txt");
                        Console.WriteLine($"Ciphertext saved to: {encryptOutput}");
                        Console.WriteLine($"Key saved to: {encryptOutput}.key.txt");
                        Console.WriteLine($"IV saved to: {encryptOutput}.iv.txt");
                        break;

                    case "2":
                        Console.Write("Enter ciphertext file path (e.g., encrypted.bin): ");
                        string? decryptInput = Console.ReadLine();
                        Console.Write("Enter key file path (e.g., encrypted.bin.key.txt): ");
                        string? keyFile = Console.ReadLine();
                        Console.Write("Enter IV file path (e.g., encrypted.bin.iv.txt): ");
                        string? ivFile = Console.ReadLine();
                        Console.Write("Enter output file path (e.g., decrypted.docx): ");
                        string? decryptOutput = Console.ReadLine();
                        Console.Write("Input format for key/IV (Base64/Hex): ");
                        string? decryptFormat = Console.ReadLine();
                        try
                        {
                            byte[] cipherBytes = File.ReadAllBytes(decryptInput ?? throw new ArgumentNullException(nameof(decryptInput)));
                            byte[] keyBytes = Decode(File.ReadAllText(keyFile ?? throw new ArgumentNullException(nameof(keyFile))), decryptFormat);
                            byte[] ivBytes = Decode(File.ReadAllText(ivFile ?? throw new ArgumentNullException(nameof(ivFile))), decryptFormat);
                            DecryptFile(cipherBytes, keyBytes, ivBytes, decryptOutput);
                            Console.WriteLine($"Decrypted file saved to: {decryptOutput}");
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"Error during decryption: {ex.Message}");
                        }
                        break;

                    case "3":
                        Console.Write("Enter input file path (e.g., document.pdf): ");
                        string? encodeInput = Console.ReadLine();
                        Console.Write("Enter output file path for encoded data (e.g., encoded.txt): ");
                        string? encodeOutput = Console.ReadLine();
                        Console.Write("Output format (Base64/Hex): ");
                        string? encodeFormat = Console.ReadLine();
                        string encodedData = EncodeFile(encodeInput, encodeFormat);
                        SaveToFile(encodedData, encodeOutput);
                        Console.WriteLine($"Encoded data saved to: {encodeOutput}");
                        break;

                    case "4":
                        Console.Write("Enter encoded file path (e.g., encoded.txt): ");
                        string? decodeInput = Console.ReadLine();
                        Console.Write("Enter output Screenshot of the build error message file path (e.g., restored.jpg): ");
                        string? decodeOutput = Console.ReadLine();
                        Console.Write("Input format (Base64/Hex): ");
                        string? decodeFormat = Console.ReadLine();
                        string encodedText = File.ReadAllText(decodeInput ?? throw new ArgumentNullException(nameof(decodeInput)));
                        DecodeToFile(encodedText, decodeOutput, decodeFormat);
                        Console.WriteLine($"Decoded file saved to: {decodeOutput}");
                        break;

                    case "5":
                        Console.Write("Enter input file path (e.g., image.jpeg): ");
                        string? hashInput = Console.ReadLine();
                        Console.Write("Hash algorithm (MD5/SHA1/SHA256/SHA384/SHA512): ");
                        string? hashAlgo = Console.ReadLine();
                        Console.Write("Output format (Base64/Hex): ");
                        string? hashFormat = Console.ReadLine();
                        string hash = ComputeFileHash(hashInput, hashAlgo, hashFormat);
                        Console.WriteLine($"Hash: {hash}");
                        Console.Write("Save hash to file? (y/n): ");
                        string? saveHash = Console.ReadLine();
                        if (saveHash?.ToLower() == "y")
                        {
                            Console.Write("Enter output file path for hash: ");
                            string? hashOutput = Console.ReadLine();
                            SaveToFile(hash, hashOutput);
                            Console.WriteLine($"Hash saved to: {hashOutput}");
                        }
                        break;

                    case "6":
                        Console.WriteLine("Exiting...");
                        return;

                    default:
                        Console.WriteLine("Invalid option. Please select 1-6.");
                        break;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }
    }

    // Encodes bytes to Base64 or Hex
    private static string Encode(byte[] data, string? format)
    {
        if (data == null)
            throw new ArgumentNullException(nameof(data), "Data cannot be null.");
        if (string.IsNullOrEmpty(format))
            format = "Base64";

        return format.ToLower() switch
        {
            "hex" => BitConverter.ToString(data).Replace("-", "").ToLower(),
            _ => Convert.ToBase64String(data)
        };
    }

    // Decodes Base64 or Hex to bytes
    private static byte[] Decode(string? input, string? format)
    {
        if (string.IsNullOrEmpty(input))
            throw new ArgumentNullException(nameof(input), "Input cannot be null or empty.");
        if (string.IsNullOrEmpty(format))
            format = "Base64";

        return format.ToLower() switch
        {
            "hex" => Convert.FromHexString(input),
            _ => Convert.FromBase64String(input)
        };
    }
}