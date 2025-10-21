# FileCryptoUtility User Manual

## Overview
`FileCryptoUtility` is a C# console application designed to perform cryptographic operations on files of any format, including documents (`.docx`, `.pdf`, `.xlsx`, `.pptx`) and images (`.png`, `.jpg`, `.jpeg`). The program supports:

1. **Encryption**: Encrypts files using AES-256, saving the ciphertext, key, and initialization vector (IV) in Base64 or Hex format.
2. **Decryption**: Decrypts AES-encrypted files back to their original format using the provided key and IV.
3. **Encoding**: Converts file contents to Base64 or Hex, saving as a text file.
4. **Decoding**: Restores Base64 or Hex-encoded text to the original file format.
5. **Hashing**: Computes file hashes using MD5, SHA-1, SHA-256, SHA-384, SHA-512, or SHA3-256, with output in Base64 or Hex.

The program uses a menu-driven console interface, processes files as byte streams for universal compatibility, and includes robust error handling. It is suitable for securing files, verifying integrity, or encoding binary data for transmission.

## System Requirements
- **Operating System**: Windows, macOS, or Linux with .NET support.
- **.NET Runtime**: .NET Core 3.1, .NET 5, 6, 7, 8, or .NET Framework 4.5+.
- **Development Environment**: Visual Studio, Visual Studio Code, or any C# IDE/compiler.
- **Dependencies**: 
  - Standard .NET libraries for AES, MD5, SHA-1, SHA-256, SHA-384, SHA-512.
  - `BouncyCastle.Cryptography` NuGet package for SHA3-256 (optional; see setup instructions).
- **Disk Space**: Sufficient space for input/output files (depends on file sizes).
- **Permissions**: Read/write access to input/output directories.
- **Optional**: Nullable reference types enabled for enhanced null safety.

## Installation and Setup

### Step 1: Create a Project
1. Open your preferred IDE (e.g., Visual Studio, Visual Studio Code).
2. Create a new **Console Application** project (e.g., `FileCryptoUtility`).
3. Replace the default `Program.cs` with the provided `FileCryptoUtility.cs` code, or add it as a new file and ensure the `Main` method is the entry point.

### Step 2: Install Dependencies
- **For SHA3-256 (Optional)**:
  - Install the `BouncyCastle.Cryptography` NuGet package:
    - **Visual Studio**: Go to **Tools > NuGet Package Manager > Manage NuGet Packages for Solution**, search for `BouncyCastle.Cryptography`, and install version 2.3.0 or later.
    - **Visual Studio Code/Command Line**: Run `dotnet add package BouncyCastle.Cryptography` in the project directory.
    - Update the `.csproj` file:
      ```xml
      <ItemGroup>
        <PackageReference Include="BouncyCastle.Cryptography" Version="2.3.0" />
      </ItemGroup>
      ```
  - If you don’t want SHA3-256, comment out the SHA3-256 case in the `ComputeFileHash` method and remove `SHA3-256` from the menu prompt (see code comments).
- **Other Algorithms**: MD5, SHA-1, SHA-256, SHA-384, and SHA-512 use standard .NET libraries, requiring no additional dependencies.

### Step 3: Configure the Project
- **Nullable Reference Types** (recommended for null safety):
  - Edit the `.csproj` file to include:
    ```xml
    <PropertyGroup>
      <OutputType>Exe</OutputType>
      <TargetFramework>net6.0</TargetFramework> <!-- or net8.0, netcoreapp3.1, etc. -->
      <Nullable>enable</Nullable>
    </PropertyGroup>
    ```
  - If nullable reference types are disabled, remove all `string?` annotations in the code, replacing them with `string`. The program remains functional but loses compile-time null checks.
- **Build the Project**:
  - **Visual Studio**: Click **Build > Build Solution** (`Ctrl+Shift+B`).
  - **Visual Studio Code/Command Line**: Run `dotnet build` in the project directory.
  - Ensure no compilation errors occur.

### Step 4: Run the Program
- **Visual Studio**: Press `F5` or click **Start**.
- **Visual Studio Code/Command Line**: Run `dotnet run` in the project directory.
- The console displays the menu:
  ```
  File Crypto Utility Menu:
  1. Encrypt File (AES)
  2. Decrypt File (AES)
  3. Encode File (Base64/Hex)
  4. Decode to File (Base64/Hex)
  5. Compute File Hash (MD5/SHA1/SHA256/SHA384/SHA512/SHA3-256)
  6. Exit
  Select an option (1-6):
  ```

## Usage Instructions

### General Notes
- **File Paths**: Use full paths (e.g., `C:\Files\document.docx`) or relative paths (e.g., `document.docx` if in the project directory). Ensure files exist and directories are writable.
- **File Formats**: Supports any file type (`.docx`, `.pdf`, `.xlsx`, `.pptx`, `.png`, `.jpg`, `.jpeg`, etc.) by processing files as byte streams.
- **Input Format**: Enter `Base64` or `Hex` (case-insensitive) for encoding, decoding, or key/IV output. Defaults to `Base64` if invalid or empty.
- **Hash Algorithms**: Supports `MD5`, `SHA1`, `SHA256`, `SHA384`, `SHA512`, `SHA3-256` (case-insensitive). Defaults to `SHA256` if invalid or empty.
- **Error Handling**: Catches and displays errors (e.g., file not found, invalid key/IV, unsupported algorithm).
- **Security**: Store encryption keys and IVs securely (e.g., in a key vault for production use). The program saves them as text files for simplicity.

### Option 1: Encrypt File (AES)
Encrypts a file using AES-256, saving the ciphertext, key, and IV to separate files.

- **Steps**:
  1. Select option `1`.
  2. Enter the **input file path** (e.g., `C:\Files\image.png`).
  3. Enter the **output file path** for the ciphertext (e.g., `C:\Files\encrypted.bin`).
  4. Enter the **output format** for the key and IV (`Base64` or `Hex`).
- **Output**:
  - Ciphertext saved to the specified file (e.g., `encrypted.bin`).
  - Key saved to `<output>.key.txt` (e.g., `encrypted.bin.key.txt`).
  - IV saved to `<output>.iv.txt` (e.g., `encrypted.bin.iv.txt`).
- **Example**:
  ```
  Select an option (1-6): 1
  Enter input file path (e.g., document.docx, image.png): C:\Files\report.pdf
  Enter output file path for ciphertext (e.g., encrypted.bin): C:\Files\encrypted.bin
  Output format for key/IV (Base64/Hex): Base64
  Ciphertext saved to: C:\Files\encrypted.bin
  Key saved to: C:\Files\encrypted.bin.key.txt
  IV saved to: C:\Files\encrypted.bin.iv.txt
  ```
- **Notes**:
  - Supports any file type.
  - The ciphertext is a binary file, not viewable as text.
  - Keep the key and IV files secure for decryption.

### Option 2: Decrypt File (AES)
Decrypts an AES-encrypted file back to its original format using the ciphertext, key, and IV.

- **Steps**:
  1. Select option `2`.
  2. Enter the **ciphertext file path** (e.g., `C:\Files\encrypted.bin`).
  3. Enter the **key file path** (e.g., `C:\Files\encrypted.bin.key.txt`).
  4. Enter the **IV file path** (e.g., `C:\Files\encrypted.bin.iv.txt`).
  5. Enter the **output file path** for the decrypted file (e.g., `C:\Files\decrypted.pdf`).
  6. Enter the **input format** for the key and IV (`Base64` or `Hex`).
- **Output**:
  - Decrypted file saved to the specified path (e.g., `decrypted.pdf`).
- **Example**:
  ```
  Select an option (1-6): 2
  Enter ciphertext file path (e.g., encrypted.bin): C:\Files\encrypted.bin
  Enter key file path (e.g., encrypted.bin.key.txt): C:\Files\encrypted.bin.key.txt
  Enter IV file path (e.g., encrypted.bin.iv.txt): C:\Files\encrypted.bin.iv.txt
  Enter output file path (e.g., decrypted.docx): C:\Files\decrypted.pdf
  Input format for key/IV (Base64/Hex): Base64
  Decrypted file saved to: C:\Files\decrypted.pdf
  ```
- **Notes**:
  - Use the correct file extension (e.g., `.pdf`, `.png`) to match the original file type.
  - The key, IV, and format must match the encryption settings, or decryption will fail.

### Option 3: Encode File (Base64/Hex)
Encodes a file’s contents to Base64 or Hex, saving as a text file.

- **Steps**:
  1. Select option `3`.
  2. Enter the **input file path** (e.g., `C:\Files\document.docx`).
  3. Enter the **output file path** for the encoded data (e.g., `C:\Files\encoded.txt`).
  4. Enter the **output format** (`Base64` or `Hex`).
- **Output**:
  - Encoded data saved to the specified text file (e.g., `encoded.txt`).
- **Example**:
  ```
  Select an option (1-6): 3
  Enter input file path (e.g., document.pdf): C:\Files\photo.jpg
  Enter output file path for encoded data (e.g., encoded.txt): C:\Files\encoded.txt
  Output format (Base64/Hex): Hex
  Encoded data saved to: C:\Files\encoded.txt
  ```
- **Notes**:
  - Useful for converting binary files to text for transmission.
  - Hex produces larger output than Base64.

### Option 4: Decode to File (Base64/Hex)
Decodes a Base64 or Hex-encoded text file back to its original binary format.

- **Steps**:
  1. Select option `4`.
  2. Enter the **encoded file path** (e.g., `C:\Files\encoded.txt`).
  3. Enter the **output file path** for the decoded file (e.g., `C:\Files\restored.jpg`).
  4. Enter the **input format** (`Base64` or `Hex`).
- **Output**:
  - Decoded file saved to the specified path (e.g., `restored.jpg`).
- **Example**:
  ```
  Select an option (1-6): 4
  Enter encoded file path (e.g., encoded.txt): C:\Files\encoded.txt
  Enter output file path (e.g., restored.jpg): C:\Files\restored.jpg
  Input format (Base64/Hex): Hex
  Decoded file saved to: C:\Files\restored.jpg
  ```
- **Notes**:
  - Ensure the output file extension matches the original file type.
  - The encoded file must contain valid Base64 or Hex data.

### Option 5: Compute File Hash (MD5/SHA1/SHA256/SHA384/SHA512/SHA3-256)
Computes a hash of a file using one of six algorithms, with an option to save the result.

- **Steps**:
  1. Select option `5`.
  2. Enter the **input file