# Author: Charles Christmann
# Version: 1.0
# License: GPL General version 3.0

import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk
import os
import random
import string
import triGlyph  # Import the triGlyph module

def set_encryption_version(version):
    """Set the encryption version in triGlyph."""
    triGlyph.ENCRYPTION_VERSION = version

class triGlyphApp:
    def __init__(self, root):
        self.root = root
        self.root.title("triGlyph File Encryptor/Decryptor")
        self.root.geometry("800x450")  # Adjust the window size for more space
        self.root.iconbitmap("triGlyph.ico")  # Set the custom window icon
        self.create_widgets()

    def create_widgets(self):
        # Title Label
        title_label = ttk.Label(self.root, text="triGlyph Encryptor/Decryptor", font=("Arial", 14, "bold"))
        title_label.pack(pady=10)

        # Frame for content
        frame = ttk.Frame(self.root, padding="10")
        frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        # Configure grid columns to stretch
        frame.columnconfigure(0, weight=1)
        frame.columnconfigure(1, weight=3)
        frame.columnconfigure(2, weight=1)

        # Key Input
        key_label = ttk.Label(frame, text="Encryption/Decryption Key:")
        key_label.grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.key_entry = ttk.Entry(frame, width=40)
        self.key_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew", columnspan=2)

        # File Selection
        file_label = ttk.Label(frame, text="Select File:")
        file_label.grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.file_path = ttk.Entry(frame, width=30)
        self.file_path.grid(row=1, column=1, padx=5, pady=5, sticky="ew")
        browse_button = ttk.Button(frame, text="Browse", command=self.browse_file)
        browse_button.grid(row=1, column=2, padx=5, pady=5)

        # Output File Name
        output_label = ttk.Label(frame, text="Encrypted Output File Name:")
        output_label.grid(row=2, column=0, padx=5, pady=5, sticky="w")
        self.output_name = ttk.Entry(frame, width=30)
        self.output_name.grid(row=2, column=1, padx=5, pady=5, sticky="ew")

        # Version Checkbox and Entry
        self.use_version = tk.BooleanVar(value=False)
        version_checkbox = ttk.Checkbutton(frame, text="Enable Version (-V):", variable=self.use_version, command=self.toggle_version_entry)
        version_checkbox.grid(row=3, column=0, padx=5, pady=5, sticky="w")

        self.version_var = tk.IntVar(value=1)
        self.version_entry = ttk.Entry(frame, textvariable=self.version_var, width=5, state="disabled")
        self.version_entry.grid(row=3, column=1, padx=5, pady=5, sticky="w")

        # Encrypt/Decrypt Buttons
        encrypt_button = ttk.Button(frame, text="Encrypt File", command=self.encrypt_file)
        encrypt_button.grid(row=5, column=0, padx=5, pady=15, sticky="e")
        decrypt_button = ttk.Button(frame, text="Decrypt File", command=self.decrypt_file)
        decrypt_button.grid(row=5, column=1, padx=5, pady=15, sticky="w")

        # Exit Button
        exit_button = ttk.Button(self.root, text="Exit", command=self.root.quit)
        exit_button.pack(pady=10)

    def toggle_version_entry(self):
        """Enable or disable the version entry based on the checkbox state."""
        if self.use_version.get():
            self.version_entry.config(state="normal")
        else:
            self.version_entry.config(state="disabled")

    def browse_file(self):
        filename = filedialog.askopenfilename()
        self.file_path.delete(0, tk.END)
        self.file_path.insert(0, filename)

    def encrypt_file(self):
        """Encrypt the selected file using the key and version (if enabled)."""
        key = self.key_entry.get()
        file_path = self.file_path.get()
        
        # Generate a random output name if none is provided by the user
        output_name = self.output_name.get()
        if not output_name.strip():
            output_name = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8)) + ".enc"

        version = 1  # Default version

        if self.use_version.get():
            version = self.version_var.get()
            max_version = triGlyph.ENCRYPTION_VERSION
            
            if version > max_version:
                messagebox.showerror("Error", f"Version {version} exceeds the maximum allowed version {max_version}.")
                return

        if not key or not file_path:
            messagebox.showerror("Error", "Please provide both key and file path.")
            return

        # Set encryption version
        set_encryption_version(version)

        # Create the output file path using the same base directory as the input file
        base_dir = os.path.dirname(file_path)
        output_file_path = os.path.join(base_dir, output_name)

        if messagebox.askyesno("Encrypt File", f"Are you sure you want to encrypt '{file_path}'?"):
            try:
                triGlyph.encrypt_file(file_path, key, output_file_path)
                messagebox.showinfo("Success", f"File '{output_file_path}' encrypted successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Encryption failed: {e}")

    def decrypt_file(self):
        """Decrypt the selected file using the key."""
        key = self.key_entry.get()
        file_path = self.file_path.get()
        if not key or not file_path:
            messagebox.showerror("Error", "Please provide both key and file path.")
            return

        if messagebox.askyesno("Decrypt File", f"Are you sure you want to decrypt '{file_path}'?"):
            try:
                triGlyph.decrypt_file(file_path, key)
                output_file_name = os.path.basename(file_path).replace(".encrypted", "")
                messagebox.showinfo("Success", f"File '{output_file_name}' decrypted successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Decryption failed: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = triGlyphApp(root)
    root.mainloop()
