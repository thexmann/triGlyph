# triGlyph Encryptor/Decryptor

## Overview
`triGlyph` is a file and text symetrical encryption/decryption tool that uses unique character mappings and random number generators based on a user-provided key. It supports encryption and decryption of both files and strings. The project includes a command-line interface (`CLI`), a graphical user interface (`GUI`), and Windows executable files for easy usage without needing Python installed.

## Features
- Encrypt and decrypt files or strings using a secret key.
- Specify encryption version (currently version 1 supported).
- GUI for easy file encryption/decryption without command-line commands.
- Windows executables for direct use without installing Python.
- Randomized output filenames for encrypted files.
- Uses advanced cryptographic techniques, including custom character mapping and shuffling.
- Checksum verification to ensure data integrity after decryption.

## Components
### triGlyph.py (CLI)
This is the core script that handles the encryption and decryption processes via the command line. It supports the following functionalities:
- **Encrypting Files and Strings:** Encrypt files with a specified output file name or randomly generated name.
- **Decrypting Files and Strings:** Decrypt encrypted files back to their original content.
- **Encryption Versions:** Users can specify which version of encryption to use (default is version 1).
- **Verbose Mode:** Enables detailed debug output for troubleshooting.

### Command-Line Usage
python triGlyph.py [options] &lt;input&gt; &lt;key&gt;

## Examples:
### Get help
- python triGlyph.py -h
- triGlyph.exe -h

### Run the GUI
- python triGlyphGUI.py
- triGlyphGUI.exe

### Encrypt file
- python triGlyph.py -f -e /path/to/input.txt mysecretkey &lt;-o /path/to/output.enc&gt; &lt;-V 1&gt;
- triGlyph.exe -f -e /path/to/input.txt mysecretkey &lt;-o /path/to/output.enc&gt; &lt;-V 1&gt;

### Decrypt file
-python triGlyph.py -f -d /path/to/input.enc mysecretkey
- triGlyph.exe -f -d /path/to/input.enc mysecretkey

### Encrypt string
- python triGlyph.py -e "Hello, World!" mysecretkey
- triGlyph.exe -e "Hello, World!" mysecretkey
