FileCryptoUtility User Manual
Overview
FileCryptoUtility is a C# console application designed to perform cryptographic operations on files of any format, including documents (.docx, .pdf, .xlsx, .pptx) and images (.png, .jpg, .jpeg). The program supports:

Encryption: Encrypts files using AES-256, saving the ciphertext, key, and initialization vector (IV) in Base64 or Hex format.
Decryption: Decrypts AES-encrypted files back to their original format using the provided key and IV.
Encoding: Converts file contents to Base64 or Hex, saving as a text file.
Decoding: Restores Base64 or Hex-encoded text to the original file format.
Hashing: Computes file hashes using MD5, SHA-1, SHA-256, SHA-384, or SHA-512, with output in Base64 or Hex.

The program uses a menu-driven console interface, processes files as byte streams for universal compatibility, and includes robust error handling. It is suitable for securing files, verifying integrity, or encoding binary data for transmission.
System Requirements

Operating System: Windows, macOS, or Linux with .NET support.
.NET Runtime: .NET Core 3.1, .NET 5, 6, 7, 8, or .NET Framework 4.5+.
Development Environment: Visual Studio, Visual Studio Code, or any C# IDE/compiler.
Dependencies: Uses standard .NET libraries (System.Security.Cryptography) for all operations; no external packages required.
Disk Space: Sufficient space for input/output files (depends on file sizes).
Permissions: Read/write access to input/output directories.
Optional: Nullable reference types enabled for enhanced null safety.

Installation and Setup
Step 1: Create a Project

Open your preferred IDE (e.g., Visual Studio, Visual Studio Code).
Create a new Console Application project (e.g., FileCryptoUtility).
Replace the default Program.cs with the provided FileCryptoUtility.cs code, or add it as a new file and ensure the Main method is the entry point.
File path: C:\Users\pehya\Downloads\test\encryption_software\encryption_softwareV2\Program.cs (based on your previous error).



Step 2: Configure the Project

Nullable Reference Types (recommended for null safety):
Edit the .csproj file to include:<PropertyGroup>
  <OutputType>Exe</OutputType>
  <TargetFramework>net6.0</TargetFramework> <!-- or net8.0, netcoreapp3.1, etc. -->
  <Nullable>enable</Nullable>
</PropertyGroup>


If nullable reference types are disabled, remove all string? annotations in the code, replacing them with string. The program’s null checks ensure safety.


Dependencies: No external packages are required, as the program uses only standard .NET libraries for AES, MD5, SHA-1, SHA-256, SHA-384, and SHA-512.

Step 3: Build the Project

Visual Studio: Click Build > Rebuild Solution (Ctrl+Shift+B).
Visual Studio Code/Command Line: Navigate to the project directory (C:\Users\pehya\Downloads\test\encryption_software\encryption_softwareV2) and run:dotnet build


Ensure no compilation errors occur. The provided code eliminates the previous Org.BouncyCastle error by removing SHA3-256 support.

Step 4: Run the Program

Visual Studio: Press F5 or click Start.
Visual Studio Code/Command Line: Run:dotnet run


The console displays the menu:File Crypto Utility Menu:
1. Encrypt File (AES)
2. Decrypt File (AES)
3. Encode File (Base64/Hex)
4. Decode to File (Base64/Hex)
5. Compute File Hash (MD5/SHA1/SHA256/SHA384/SHA512)
6. Exit
Select an option (1-6):



Usage Instructions
General Notes

File Paths: Use full paths (e.g., C:\Files\document.docx) or relative paths (e.g., document.docx if in the project directory). Ensure files exist and directories are writable.
File Formats: Supports any file type (.docx, .pdf, .xlsx, .pptx, .png, .jpg, .jpeg, etc.) by processing files as byte streams.
Input Format: Enter Base64 or Hex (case-insensitive) for encoding, decoding, or key/IV output. Defaults to Base64 if invalid or empty.
Hash Algorithms: Supports MD5, SHA1, SHA256, SHA384, SHA512 (case-insensitive). Defaults to SHA256 if invalid or empty.
Error Handling: Catches and displays errors (e.g., file not found, invalid key/IV, unsupported algorithm).
Security: Store encryption keys and IVs securely (e.g., in a key vault for production use). The program saves them as text files for simplicity.

Option 1: Encrypt File (AES)
Encrypts a file using AES-256, saving the ciphertext, key, and initialization vector (IV) to separate files.

Steps:
Select option 1.
Enter the input file path (e.g., C:\Files\image.png).
Enter the output file path for the ciphertext (e.g., C:\Files\encrypted.bin).
Enter the output format for the key and IV (Base64 or Hex).


Output:
Ciphertext saved to the specified file (e.g., encrypted.bin).
Key saved to <output>.key.txt (e.g., encrypted.bin.key.txt).
IV saved to <output>.iv.txt (e.g., encrypted.bin.iv.txt).


Example:Select an option (1-6): 1
Enter input file path (e.g., document.docx, image.png): C:\Files\report.pdf
Enter output file path for ciphertext (e.g., encrypted.bin): C:\Files\encrypted.bin
Output format for key/IV (Base64/Hex): Base64
Ciphertext saved to: C:\Files\encrypted.bin
Key saved to: C:\Files\encrypted.bin.key.txt
IV saved to: C:\Files\encrypted.bin.iv.txt


Notes:
Supports any file type.
The ciphertext is a binary file, not viewable as text.
Keep the key and IV files secure, as they are required for decryption.



Option 2: Decrypt File (AES)
Decrypts an AES-encrypted file back to its original format using the ciphertext, key, and IV.

Steps:
Select option 2.
Enter the ciphertext file path (e.g., C:\Files\encrypted.bin).
Enter the key file path (e.g., C:\Files\encrypted.bin.key.txt).
Enter the IV file path (e.g., C:\Files\encrypted.bin.iv.txt).
Enter the output file path for the decrypted file (e.g., C:\Files\decrypted.pdf).
Enter the input format for the key and IV (Base64 or Hex).


Output:
Decrypted file saved to the specified path (e.g., decrypted.pdf).


Example:Select an option (1-6): 2
Enter ciphertext file path (e.g., encrypted.bin): C:\Files\encrypted.bin
Enter key file path (e.g., encrypted.bin.key.txt): C:\Files\encrypted.bin.key.txt
Enter IV file path (e.g., encrypted.bin.iv.txt): C:\Files\encrypted.bin.iv.txt
Enter output file path (e.g., decrypted.docx): C:\Files\decrypted.pdf
Input format for key/IV (Base64/Hex): Base64
Decrypted file saved to: C:\Files\decrypted.pdf


Notes:
Use the correct file extension (e.g., .pdf, .png) to match the original file type.
The key, IV, and format must match the encryption settings, or decryption will fail with an error like “Decryption failed. Ensure the key and IV are correct.”



Option 3: Encode File (Base64/Hex)
Encodes a file’s contents to Base64 or Hex, saving the result as a text file.

Steps:
Select option 3.
Enter the input file path (e.g., C:\Files\document.docx).
Enter the output file path for the encoded data (e.g., C:\Files\encoded.txt).
Enter the output format (Base64 or Hex).


Output:
Encoded data saved to the specified text file (e.g., encoded.txt).


Example:Select an option (1-6): 3
Enter input file path (e.g., document.pdf): C:\Files\photo.jpg
Enter output file path for encoded data (e.g., encoded.txt): C:\Files\encoded.txt
Output format (Base64/Hex): Hex
Encoded data saved to: C:\Files\encoded.txt


Notes:
Useful for converting binary files (e.g., images) to text for transmission or storage.
Hex encoding produces larger output than Base64 (twice the size).



Option 4: Decode to File (Base64/Hex)
Decodes a Base64 or Hex-encoded text file back to its original binary format.

Steps:
Select option 4.
Enter the encoded file path (e.g., C:\Files\encoded.txt).
Enter the output file path for the decoded file (e.g., C:\Files\restored.jpg).
Enter the input format (Base64 or Hex).


Output:
Decoded file saved to the specified path (e.g., restored.jpg).


Example:Select an option (1-6): 4
Enter encoded file path (e.g., encoded.txt): C:\Files\encoded.txt
Enter output file path (e.g., restored.jpg): C:\Files\restored.jpg
Input format (Base64/Hex): Hex
Decoded file saved to: C:\Files\restored.jpg


Notes:
Ensure the output file extension matches the original file type (e.g., .jpg, .docx).
The encoded file must contain valid Base64 or Hex data, or decoding will fail.



Option 5: Compute File Hash (MD5/SHA1/SHA256/SHA384/SHA512)
Computes a hash of a file using one of five algorithms, with an option to save the result to a file.

Steps:
Select option 5.
Enter the input file path (e.g., C:\Files\image.jpeg).
Enter the hash algorithm (MD5, SHA1, SHA256, SHA384, SHA512, case-insensitive).
Enter the output format (Base64 or Hex).
Choose whether to save the hash to a file (y or n).
If y, enter the output file path for the hash (e.g., C:\Files\hash.txt).


Output:
Hash displayed in the console.
If saved, hash written to the specified file.


Example:Select an option (1-6): 5
Enter input file path (e.g., image.jpeg): C:\Files\image.jpeg
Hash algorithm (MD5/SHA1/SHA256/SHA384/SHA512): SHA256
Output format (Base64/Hex): Base64
Hash: dGh3a2VyZQ==
Save hash to file? (y/n): y
Enter output file path for hash: C:\Files\hash.txt
Hash saved to: C:\Files\hash.txt


Hash Algorithm Details:
MD5: 128-bit (16 bytes), fast, not secure for cryptographic purposes (Base64: ~24 chars, Hex: 32 chars).
Use Case: Legacy checksums, non-security-critical tasks.


SHA-1: 160-bit (20 bytes), deprecated for security due to collision vulnerabilities (Base64: ~28 chars, Hex: 40 chars).
Use Case: Legacy systems.


SHA-256: 256-bit (32 bytes), secure, widely used (Base64: ~44 chars, Hex: 64 chars).
Use Case: General-purpose secure hashing.


SHA-384: 384-bit (48 bytes), high security, part of SHA-2 family (Base64: ~64 chars, Hex: 96 chars).
Use Case: High-security applications.


SHA-512: 512-bit (64 bytes), maximum security within SHA-2 (Base64: ~88 chars, Hex: 128 chars).
Use Case: Maximum security, slower than SHA-256.




Notes:
MD5 and SHA-1 are insecure for cryptographic purposes (e.g., password hashing, digital signatures); use for legacy or non-security tasks only.
SHA-256, SHA-384, and SHA-512 are cryptographically secure and recommended for modern applications.
Hashes verify file integrity (e.g., to detect changes or corruption).



Option 6: Exit
Exits the program.

Steps:
Select option 6.


Output:Exiting...



Example Workflow

Encrypt a Document:
Input: C:\Files\report.docx
Output: C:\Files\encrypted.bin, format Base64
Result: Creates encrypted.bin, encrypted.bin.key.txt, encrypted.bin.iv.txt.


Decrypt the Document:
Input: C:\Files\encrypted.bin, encrypted.bin.key.txt, encrypted.bin.iv.txt
Output: C:\Files\decrypted.docx, format Base64
Result: Restores decrypted.docx, openable in Microsoft Word.


Encode an Image:
Input: C:\Files\photo.png
Output: C:\Files\encoded.txt, format Hex
Result: Creates a text file with Hex-encoded image data.


Decode the Image:
Input: C:\Files\encoded.txt
Output: C:\Files\restored.png, format Hex
Result: Restores restored.png, viewable as an image.


Hash a Presentation:
Input: C:\Files\slides.pptx, algorithm SHA512, format Base64
Output: Displays hash; optionally saves to C:\Files\hash.txt.



Best Practices

Test with Small Files: Start with small files (e.g., 1 MB .txt or .png) to verify functionality before processing large files (e.g., 100 MB .pdf).
Secure Key/IV Storage: In production, use a secure key management system (e.g., Azure Key Vault, AWS KMS) instead of text files.
Backup Files: Keep backups of original files before encryption or encoding, as errors (e.g., lost keys) may prevent recovery.
File Extensions: Use correct extensions for decrypted/decoded files (e.g., .pdf, .jpg) to ensure compatibility with applications.
File Permissions: Ensure read access for input files and write access for output directories.
Hash Security: Avoid MD5 and SHA-1 for cryptographic purposes; use SHA-256, SHA-384, or SHA-512 for secure applications.
Large Files: The program uses streaming (FileStream, CryptoStream) for efficiency, but very large files may take time to process.

Troubleshooting

Error: “Input file not found”:
Verify the file path is correct and the file exists.
Use full paths (e.g., C:\Files\image.png) to avoid relative path issues.


Error: “Decryption failed. Ensure the key and IV are correct”:
Ensure the key, IV, and format match the encryption settings.
Check key/IV files for valid Base64 or Hex content (no extra spaces or newlines).
Example:
Base64 key (32 bytes): ~44 chars, e.g., qX8j9k2m3n4p5q6r7s8t9u0v1w2x3y4z5A==.
Base64 IV (16 bytes): ~24 chars, e.g., dGh3a2VyZQ==.
Hex key: 64 chars, e.g., a1b2c3d4e5f60718293a4b5c6d7e8f90.
Hex IV: 32 chars, e.g., 1a2b3c4d5e6f7890.


Re-encrypt and decrypt a test file to confirm key/IV integrity.


Error: “Unsupported hash algorithm”:
Ensure the algorithm is MD5, SHA1, SHA256, SHA384, or SHA512 (case-insensitive).
Check for typos (e.g., SHA-256 instead of SHA256).


Error: “The type or namespace name 'Org' could not be found”:
This error should no longer occur, as SHA3-256 (requiring BouncyCastle.Cryptography) has been removed.
If you see this, ensure you’re using the provided code and rebuild the project.


Slow Performance: Large files or slower algorithms (e.g., SHA-512) may take time. This is normal due to cryptographic operations.
Output File Not Opening: Ensure the decrypted/decoded file has the correct extension (e.g., .docx, .png) matching the original file type.
Decryption Succeeds but Shows Error:
If decryption produces a valid file but shows “Decryption failed,” check the console output for detailed errors (e.g., Cryptographic error: ...).
Verify the ciphertext file isn’t corrupted and matches the key/IV.



Technical Details

Encryption: Uses AES-256 with a 256-bit key and 128-bit IV. Employs PKCS#7 padding and CBC mode for security.
Decryption: Requires the exact key (32 bytes) and IV (16 bytes) used during encryption. Uses streaming for efficiency.
Encoding/Decoding: Supports Base64 (compact) and Hex (human-readable but larger) formats.
Hashing:
MD5: 128-bit (16 bytes), fast, not secure for cryptography.
SHA-1: 160-bit (20 bytes), deprecated for security.
SHA-256: 256-bit (32 bytes), secure, widely used.
SHA-384: 384-bit (48 bytes), high security.
SHA-512: 512-bit (64 bytes), maximum security, slower.


File Handling: Processes files as byte streams, ensuring compatibility with all formats.
Error Handling: Catches file not found, cryptographic, and input errors, displaying user-friendly messages.
Performance: Uses FileStream and CryptoStream for streaming, minimizing memory usage for large files.
Security:
Generates unique keys and IVs per encryption.
MD5 and SHA-1 are insecure for cryptographic purposes; use SHA-256 or higher for security-critical tasks.



Limitations

RSA Encryption: Not included due to size limitations (RSA is suitable for small data, not files). AES is used for file encryption.
Directory Creation: The program does not create output directories; ensure they exist.
Key Management: Keys and IVs are saved as text files; use secure storage in production.
Console Interface: GUI or automation requires additional development.
SHA3-256: Excluded to avoid external dependencies. To add SHA3-256, install BouncyCastle.Cryptography and use the previous code version.

Support
For issues or enhancements:

Check Errors: Review console error messages for details (e.g., file not found, invalid key).
Verify Inputs: Ensure file paths, formats, and key/IV files are correct.
Contact: Provide specific details (e.g., error messages, file types, console output) to your support channel or developer.
Test Case: For decryption issues, try encrypting and decrypting a small file (e.g., 1 KB .txt) and share results.

This manual was generated on October 22, 2025, for the FileCryptoUtility program. For updates or additional features, consult the developer or refer to the source code.
