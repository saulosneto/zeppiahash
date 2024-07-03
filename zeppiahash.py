import hashlib
import xxhash
from Crypto.Hash import SHA3_256
import blake3
import zlib
import pyblake2
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext

class ZeppiaHashApp:
    def __init__(self, root):
        self.root = root
        self.root.title("ZeppiaHash")
        self.root.attributes('-fullscreen', True)  # Maximiza a janela ao iniciar

        self.create_menu()
        self.create_widgets()

    def create_menu(self):
        menubar = tk.Menu(self.root)

        filemenu = tk.Menu(menubar, tearoff=0)
        filemenu.add_command(label="Escolher Arquivo", command=self.calcular_hashes_arquivo)
        filemenu.add_separator()
        filemenu.add_command(label="Sair", command=self.root.quit)
        menubar.add_cascade(label="Arquivo", menu=filemenu)

        helpmenu = tk.Menu(menubar, tearoff=0)
        helpmenu.add_command(label="Sobre", command=self.show_about)
        menubar.add_cascade(label="Ajuda", menu=helpmenu)

        self.root.config(menu=menubar)

    def create_widgets(self):
        self.textbox = scrolledtext.ScrolledText(self.root, width=60, height=20, wrap=tk.WORD)
        self.textbox.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)  # Faz a caixa de texto expandir

    def calcular_md5(self, filename):
        hash_md5 = hashlib.md5()
        with open(filename, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()

    def calcular_sha256(self, filename):
        hash_sha256 = hashlib.sha256()
        with open(filename, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()

    def calcular_sha512(self, filename):
        hash_sha512 = hashlib.sha512()
        with open(filename, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha512.update(chunk)
        return hash_sha512.hexdigest()

    def calcular_xxhash(self, filename):
        xxh = xxhash.xxh64()
        with open(filename, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                xxh.update(chunk)
        return xxh.hexdigest()

    def calcular_sha3_256(self, filename):
        hash_sha3 = SHA3_256.new()
        with open(filename, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha3.update(chunk)
        return hash_sha3.hexdigest()

    def calcular_blake2b_256(self, filename):
        hash_blake2b = pyblake2.blake2b(digest_size=32)
        with open(filename, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_blake2b.update(chunk)
        return hash_blake2b.hexdigest()

    def calcular_blake3(self, filename):
        hash_blake3 = blake3.blake3()
        with open(filename, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_blake3.update(chunk)
        return hash_blake3.hexdigest()

    def calcular_crc32(self, filename):
        crc32_hash = 0
        with open(filename, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                crc32_hash = zlib.crc32(chunk, crc32_hash)
        return "%08x" % (crc32_hash & 0xFFFFFFFF)

    def calcular_hashes_arquivo(self):
        arquivo = filedialog.askopenfilename(filetypes=[("Todos os arquivos", "*.*")])
        if arquivo:
            self.exibir_resultados(arquivo)

    def exibir_resultados(self, filename):
        resultado = ""
        resultado += f"Arquivo: {filename}\n"
        resultado += f"MD5:       {self.calcular_md5(filename)}\n"
        resultado += f"SHA-256:   {self.calcular_sha256(filename)}\n"
        resultado += f"SHA-512:   {self.calcular_sha512(filename)}\n"
        resultado += f"xxHash:    {self.calcular_xxhash(filename)}\n"
        resultado += f"SHA-3(256): {self.calcular_sha3_256(filename)}\n"
        resultado += f"Blake2B(256): {self.calcular_blake2b_256(filename)}\n"
        resultado += f"Blake3:     {self.calcular_blake3(filename)}\n"
        resultado += f"CRC32:     {self.calcular_crc32(filename)}\n"

        self.textbox.delete(1.0, tk.END)
        self.textbox.insert(tk.END, resultado)

    def show_about(self):
        messagebox.showinfo("Sobre", "ZeppiaHash\nSaulo dos Santos Neto\nperitosauloneto@gmail.com")

def main():
    root = tk.Tk()
    app = ZeppiaHashApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
