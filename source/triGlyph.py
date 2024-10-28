#!/usr/bin/env python3

# Author: Charles Christmann
# Version: 1.0
# License: GPL General version 3.0


import random
import hashlib
import os
import sys
import base64
import string

# Global variable for verbose mode
ENCRYPTION_VERSION = 1
verbose = False

def debug_path(path):
    """Print detailed path information for debugging."""
    if not verbose:
        return
    print("\nPath Debug Information:")
    print(f"Original path: {path}")
    print(f"Path exists? {os.path.exists(path)}")
    print(f"Is absolute? {os.path.isabs(path)}")
    try:
        print(f"Absolute path: {os.path.abspath(path)}")
    except Exception as e:
        print(f"Error getting absolute path: {e}")
    print(f"Directory of path: {os.path.dirname(path)}")
    print(f"Parent directory exists? {os.path.exists(os.path.dirname(path))}")
    print("Path components:")
    parts = path.split(os.sep)
    for i, part in enumerate(parts):
        print(f"  {i}: {part}")
    print(f"Working directory: {os.getcwd()}\n")

def get_input_set():
    """Generate a set of input characters for mapping."""
    return [chr(i) for i in range(32, 127)]

def get_output_set(start_hex, end_hex):
    """Generate a set of characters within a specified Unicode range."""
    start = int(start_hex, 16)
    end = int(end_hex, 16)
    return [chr(i) for i in range(start, end + 1)]

def generate_mappings(key, input_set):
    """Generate encryption and decryption mappings based on the key."""
    mapping_seed = int(hashlib.sha512(key.encode('utf-8')).hexdigest(), 16)
    mapping_rng = random.Random(mapping_seed)

    set1 = get_output_set('2600', '26FF')
    set2 = get_output_set('2700', '27BF')
    set3 = get_output_set('2B00', '2BFF')

    set1 = set1[:95]
    set2 = set2[:95]
    set3 = set3[:95]

    mapping_rng.shuffle(set1)
    mapping_rng.shuffle(set2)
    mapping_rng.shuffle(set3)

    mapping = {}
    inverse_mapping = {}

    for i, char in enumerate(input_set):
        mapping[char] = [set1[i], set2[i], set3[i]]
        inverse_mapping[set1[i]] = char
        inverse_mapping[set2[i]] = char
        inverse_mapping[set3[i]] = char

    return mapping, inverse_mapping

def generate_shift_rng(key):
    
    """Generate a random number generator for shifting characters."""
    shift_seed1 = hashlib.sha512((key + "shift").encode('utf-8')).hexdigest()
    shift_seed2 = hashlib.blake2b((shift_seed1 + "shift").encode('utf-8'), digest_size=64).hexdigest()
    shift_seed3 = hashlib.sha3_512((shift_seed2 + "shift").encode('utf-8')).hexdigest()
    return random.Random(int(shift_seed3, 16))

def generate_choice_rng(key):
    """Generate a random number generator for choosing mapped characters."""
    choice_seed1 = hashlib.sha512((key + "choice").encode('utf-8')).hexdigest()
    choice_seed2 = hashlib.sha3_512((choice_seed1 + "choice").encode('utf-8')).hexdigest()
    choice_seed3 = hashlib.blake2b((choice_seed2 + "choice").encode('utf-8'), digest_size=64).hexdigest()
    return random.Random(int(choice_seed3, 16))

## Encryption versions
def v1_encrypt_message(message, mapping, shift_rng, choice_rng, output_ranges):
    """Internal function to encrypt a message based on mappings and RNGs."""
    # if verbose:
    #     print(f"Encrypting message: {message}")
    
    encrypted_message = []
    for char in message:
        if char in mapping:
            mapped_char = choice_rng.choice(mapping[char])
            for start, end in output_ranges:
                if start <= ord(mapped_char) <= end:
                    range_start, range_end = start, end
                    break
            else:
                encrypted_message.append(mapped_char)
                continue

            r = shift_rng.randint(1, 95)
            shifted_code = ord(mapped_char) + r
            if shifted_code > range_end:
                shifted_code = range_start + (shifted_code - range_end - 1)
            shifted_char = chr(shifted_code)
            encrypted_message.append(shifted_char)
        else:
            encrypted_message.append(char)
    
    return ''.join(encrypted_message)


def encrypt_file(input_file_path, key, output_file=None):
    """Encrypt a file and include the original filename, saving it under a specified or random name."""
    global ENCRYPTION_VERSION

    if verbose:
        print(f"Encrypting file: {input_file_path} using version {ENCRYPTION_VERSION:03d}")
    
    # Read the file content
    try:
        with open(input_file_path, 'rb') as infile:
            file_content = infile.read()
    except FileNotFoundError:
        print(f"Error: File not found: {input_file_path}")
        return None

    # Convert file content to Base64 to safely handle binary data
    file_content_base64 = base64.b64encode(file_content).decode('utf-8')
    
    # Add the original filename to the start of the encrypted content
    original_filename = os.path.basename(input_file_path)
    content_to_encrypt = f"{original_filename}|{file_content_base64}"
    
    # Generate mappings, RNGs, etc. based on key
    input_set = get_input_set()
    mapping, _ = generate_mappings(key, input_set)
    choice_rng = generate_choice_rng(key)
    shift_rng = generate_shift_rng(key)

    output_ranges = [
        (int('2600', 16), int('26FF', 16)),
        (int('2700', 16), int('27BF', 16)),
        (int('2B00', 16), int('2BFF', 16))
    ]
    
    # Encrypt the content
    encrypted_content = v1_encrypt_message(content_to_encrypt, mapping, shift_rng, choice_rng, output_ranges)
    
    # Prepend version to the content
    final_encrypted_output = f"{ENCRYPTION_VERSION:03d}{encrypted_content}"

    # Use the provided output file name or generate a random one
    if output_file is None:
        random_name = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8)) + ".enc"
        output_file_path = os.path.join(os.path.dirname(input_file_path), random_name)
    else:
        output_file_path = output_file

    # Save the encrypted output to the specified or randomly generated file name
    try:
        with open(output_file_path, 'w', encoding='utf-8') as outfile:
            outfile.write(final_encrypted_output)
        if verbose:
            print(f"Encryption complete. Encrypted file saved to: {output_file_path}")
    except Exception as e:
        print(f"Failed to write encrypted file: {e}")



def encrypt(message, key):
    """Encrypt a message based on provided mappings and RNGs, with a version integer."""
    global ENCRYPTION_VERSION
    
    if verbose:
        print(f"Encrypting: {message} using version {ENCRYPTION_VERSION:03d}")
    
    # Generate mappings, RNGs, etc. based on key
    input_set = get_input_set()
    mapping, _ = generate_mappings(key, input_set)
    choice_rng = generate_choice_rng(key)
    shift_rng = generate_shift_rng(key)

    output_ranges = [
        (int('2600', 16), int('26FF', 16)),
        (int('2700', 16), int('27BF', 16)),
        (int('2B00', 16), int('2BFF', 16))
    ]
    
    # Generate a SHA-256 hash of the original message
    checksum = hashlib.sha256(message.encode('utf-8')).hexdigest()
    
    # Append the checksum to the message
    message_with_checksum = message + "|" + checksum
    
    # Encrypt the message with the checksum
    encrypted_message = v1_encrypt_message(message_with_checksum, mapping, shift_rng, choice_rng, output_ranges)
    
    # Prepend version as a 3-digit integer (e.g., "001")
    version_str = f"{ENCRYPTION_VERSION:03d}"
    return version_str + encrypted_message

## Decryption versions
def v1_decrypt_message(encrypted_message, inverse_mapping, shift_rng, output_ranges):
    """Internal function to decrypt a message based on mappings and RNGs."""
    # if verbose:
    #     print(f"Decrypting: {encrypted_message}")
    decrypted_message = []
    
    for char in encrypted_message:
        in_range = False
        for start, end in output_ranges:
            if start <= ord(char) <= end:
                in_range = True
                range_start, range_end = start, end
                break

        if in_range:
            # Reverse the shifting operation
            r = shift_rng.randint(1, 95)
            shifted_code = ord(char) - r
            if shifted_code < range_start:
                shifted_code = range_end - (range_start - shifted_code - 1)
            shifted_char = chr(shifted_code)
            original_char = inverse_mapping.get(shifted_char, shifted_char)
            decrypted_message.append(original_char)
        else:
            decrypted_message.append(char)

    return ''.join(decrypted_message)

def decrypt_file(encrypted_file_path, key, output_file=None):
    try:
        with open(encrypted_file_path, 'r', encoding='utf-8') as infile:
            content = infile.read()
    except FileNotFoundError:
        print(f"Error: Encrypted file not found: {encrypted_file_path}")
        return None

    version_str = content[:3]
    try:
        version = int(version_str)
    except ValueError:
        print(f"Error: Invalid version format '{version_str}'.")
        return None

    if version != ENCRYPTION_VERSION:
        print(f"Unsupported encryption version: {version}")
        return None

    encrypted_content = content[3:]
    input_set = get_input_set()
    _, inverse_mapping = generate_mappings(key, input_set)
    shift_rng = generate_shift_rng(key)

    output_ranges = [
        (int('2600', 16), int('26FF', 16)),
        (int('2700', 16), int('27BF', 16)),
        (int('2B00', 16), int('2BFF', 16))
    ]

    decrypted_content_base64 = v1_decrypt_message(encrypted_content, inverse_mapping, shift_rng, output_ranges)
    
    try:
        original_filename, file_content_base64 = decrypted_content_base64.split("|", 1)
        decrypted_content = base64.b64decode(file_content_base64.encode('utf-8'))
    except Exception as e:
        print(f"Decryption failed: {e}")
        return None

    # Use the provided output file name or append ".dec" to the original filename
    if output_file is None:
        output_file_path = os.path.join(os.path.dirname(encrypted_file_path), original_filename + ".dec")
    else:
        output_file_path = output_file

    try:
        with open(output_file_path, 'wb') as outfile:
            outfile.write(decrypted_content)
        print(f"Decryption complete. Decrypted file saved to: {output_file_path}")
    except Exception as e:
        print(f"Failed to write decrypted file: {e}")


def decrypt(encrypted_message, key):
    """Decrypt a message based on the version integer and provided key."""
    if verbose:
        print(f"Decrypting message: {encrypted_message}")

    # Read the first 3 characters as the version integer
    version_str = encrypted_message[:3]
    try:
        version = int(version_str)
    except ValueError:
        print(f"Error: Invalid version format '{version_str}'.")
        return None

    # Remove the version integer from the encrypted message
    encrypted_message = encrypted_message[3:]

    # Adjust decryption logic based on the version
    if version == 1:
        # Version 1 decryption setup
        input_set = get_input_set()
        _, inverse_mapping = generate_mappings(key, input_set)
        shift_rng = generate_shift_rng(key)
        
        output_ranges = [
            (int('2600', 16), int('26FF', 16)),
            (int('2700', 16), int('27BF', 16)),
            (int('2B00', 16), int('2BFF', 16))
        ]
        
        # Decrypt the message
        decrypted_message_with_checksum = v1_decrypt_message(encrypted_message, inverse_mapping, shift_rng, output_ranges)
        
        # Split the decrypted message into the actual message and checksum
        try:
            decrypted_message, checksum = decrypted_message_with_checksum.rsplit("|", 1)
        except ValueError:
            print("Decryption failed: Invalid key or corrupted data.")
            return None
        
        # Verify the checksum
        expected_checksum = hashlib.sha256(decrypted_message.encode('utf-8')).hexdigest()
        if checksum == expected_checksum:
            return decrypted_message
        else:
            print("Decryption failed: Invalid key or corrupted data.")
            return None
    else:
        print(f"Unsupported encryption version: {version}")
        return None



def print_help():
    """Display help information for the script usage."""
    help_text = f"""
Usage: python triGlyph.py [options] <input> <key>

Options:
  -h             Show this help message and exit.
  -v             Enable verbose mode for detailed debugging output.
  -f             Treat <input> as a file path. Without this flag, <input> is treated as a direct string.
  -e             Encrypt the input (either string or file). Required unless -d is used.
  -d             Decrypt the input (either string or file). Required unless -e is used.
  -V <version>   Specify the encryption version to use (must be <= {ENCRYPTION_VERSION}).
  -o <output>    Specify the output file name. If not provided, a random name will be generated for encryption, 
                 or the original name with ".dec" will be used for decryption.

Examples:
  1. Encrypt a file and specify an output file name:
     python triGlyph.py -f -e /path/to/input.txt mysecretkey -o /path/to/output.enc -V 1

  2. Decrypt a file and specify an output file name:
     python triGlyph.py -f -d /path/to/input.enc mysecretkey -o /path/to/decrypted_output.txt

  3. Encrypt a file with a random output file name:
     python triGlyph.py -f -e /path/to/input.txt mysecretkey

  4. Decrypt a file using the original name with ".dec":
     python triGlyph.py -f -d /path/to/input.enc mysecretkey

  5. Encrypt a string:
     python triGlyph.py -e "Hello, World!" mysecretkey -V 1

  6. Decrypt a string:
     python triGlyph.py -d "EncryptedTextHere" mysecretkey

  7. Direct user input for string encryption/decryption:
     python triGlyph.py

Note:
  - If the file path contains a "$" character, it must be entered manually as a string when prompted.
    """
    print(help_text)




def main():
    global verbose, ENCRYPTION_VERSION
    if '-h' in sys.argv:
        print_help()
        sys.exit(0)
    
    verbose = '-v' in sys.argv
    is_file = '-f' in sys.argv
    is_encoding = '-e' in sys.argv
    is_decoding = '-d' in sys.argv

    # Check for version flag
    if '-V' in sys.argv:
        try:
            version_index = sys.argv.index('-V')
            requested_version = int(sys.argv[version_index + 1])
            
            # Check if requested version is greater than allowed global version
            if requested_version > ENCRYPTION_VERSION:
                print(f"Error: Requested version {requested_version} is not supported. Maximum allowed version is {ENCRYPTION_VERSION}.")
                sys.exit(1)
            
            # Set the encryption version to the requested one
            ENCRYPTION_VERSION = requested_version
            
            # Remove the version flag and number from the argument list
            sys.argv.remove('-V')
            sys.argv.pop(version_index)
        except (IndexError, ValueError):
            print("Invalid version specified. Usage: -V <version_number>")
            sys.exit(1)

    if is_encoding and is_decoding:
        print("Error: Cannot use both -e and -d flags simultaneously.")
        sys.exit(1)

    if verbose:
        sys.argv.remove('-v')
        print(f"[DEBUG] Command-line arguments: {sys.argv}")
    if is_file:
        sys.argv.remove('-f')
    if is_encoding:
        sys.argv.remove('-e')
    if is_decoding:
        sys.argv.remove('-d')

    if is_file:
        # Check if file name is provided or ask for it manually
        if len(sys.argv) != 3:
            print("File path not provided. Please enter the file path:")
            raw_path = input().strip()
            print("Please enter the encryption/decryption key:")
            key = input().strip()
        else:
            # File operation
            raw_path = sys.argv[1]
            key = sys.argv[2]

        if verbose:
            print(f"[DEBUG] Raw command-line input: {sys.argv}")
            print(f"[DEBUG] Extracted file path: {raw_path}")
            print(f"[DEBUG] Provided encryption/decryption key: {key}")

        # Resolve absolute path
        input_file = os.path.abspath(raw_path)
        
        if verbose:
            print(f"[DEBUG] Normalized absolute file path: {input_file}")
        
        # Check if the file exists
        if not os.path.exists(input_file):
            print(f"Error: File not found: {input_file}")
            sys.exit(1)

        if verbose:
            print(f"[DEBUG] File exists check passed for: {input_file}")
        
        # Decide whether to encrypt or decrypt
        if is_encoding:
            if verbose:
                print(f"[DEBUG] Proceeding to encrypt the file: {input_file}")
            encrypt_file(input_file, key)
        elif is_decoding:
            if verbose:
                print(f"[DEBUG] Proceeding to decrypt the file: {input_file}")
            decrypt_file(input_file, key)
        else:
            print("Please specify whether to encrypt (-e) or decrypt (-d) the file.")
            sys.exit(1)

    else:
        # String operation
        if len(sys.argv) == 1:
            print("Please enter the text to be processed:")
            input_text = input()
            print("Please enter the encryption/decryption key:")
            key = input()
        elif len(sys.argv) == 2:
            input_text = sys.argv[1]
            print("Please enter the encryption/decryption key:")
            key = input()
        else:
            print("Usage: python triGlyph.py [-v] <text> <key>")
            sys.exit(1)
        
        # Encrypt or decrypt string
        if is_encoding:
            result = encrypt(input_text, key)
            print(f"Encrypted text: {result}")
        elif is_decoding:
            result = decrypt(input_text, key)
            print(f"Decrypted text: {result}")
        else:
            operation = input("Would you like to encode or decode the text? (E/D): ").strip().upper()
            if operation == 'E':
                result = encrypt(input_text, key)
                print(f"Encrypted text: {result}")
            elif operation == 'D':
                result = decrypt(input_text, key)
                print(f"Decrypted text: {result}")
            else:
                print("Invalid option. Please choose 'E' for encoding or 'D' for decoding.")
                sys.exit(1)

if __name__ == "__main__":
    main()

