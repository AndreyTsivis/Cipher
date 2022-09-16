from base64 import urlsafe_b64encode as b64encode
from cryptography.fernet import Fernet
from os import remove, system, urandom
from art import text2art
from json import load as json_load
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class colors:
    RESET = '\033[0m'
    BLUE = '\033[94m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    GREEN = '\u001b[32m'
    CUR_CLR = '\033[90m'

    ERROR = '\033[91m'
    SUCCESS = '\u001b[38;5;82m'
    WARNING = '\033[93m'

class Cipher:
    def __init__(self):
        conf = json_load(open("config.json", "r"))

        while True:
            system("cls||clear")
            print(f"{colors.GREEN + text2art(conf['AppName'], 'tarty1') + colors.CUR_CLR}\nver {conf['AppVersion'] + colors.RESET}\n")

            print(f"{colors.YELLOW}[1]{colors.RESET} Encrypt\n{colors.YELLOW}[2]{colors.RESET} Decrypt\n{colors.YELLOW}[3]{colors.RESET} Generate new key\n{colors.YELLOW}[4]{colors.RESET} Exit")
            select = int(input(f"Select:{colors.YELLOW} "))
            print(colors.RESET)

            match select:
                case 1:
                    key = self.load_key()
                    file = input(f"Enter file name:{colors.YELLOW} ")
                    self.encrypt(file, key)
                case 2:
                    key = self.load_key()
                    file = input(f"Enter file name:{colors.YELLOW} ")
                    self.decrypt(file, key)
                case 3:
                    password = input(f"Enter password:{colors.YELLOW} ")
                    self.write_key(password)
                case 4:
                    exit()
                case _:
                    print(f"{colors.ERROR}[!]{colors.RESET} Wrong choice.")

    def write_key(self, password:str):
        salt = urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=390000,
        )
        pass_bytes = password.encode("utf-8")
        key = b64encode(kdf.derive(pass_bytes))
        open("crypto.key", "wb").write(key)

    def load_key(self):
        return open("crypto.key", "rb").read()

    def encrypt(self, filename:str, key:bytes):
        f = Fernet(key)
        file_data = open(filename, "rb").read()
        encrypted_data = f.encrypt(file_data)
        open(f"{filename}.encrypted", "wb").write(encrypted_data)
        remove(filename)

    def decrypt(self, filename:str, key:bytes):
        f = Fernet(key)
        if ".encrypted" not in filename:
            encrypted_data = open(f"{filename}.encrypted", "rb").read()
            data = f.decrypt(encrypted_data)
            open(filename, "wb").write(data)
            remove(f"{filename}.encrypted")
        elif ".encrypted" in filename:
            encrypted_data = open(filename, "rb").read()
            data = f.decrypt(encrypted_data)
            open(filename[:-10], "wb").write(data)
            remove(filename)

if __name__ == "__main__":
    Cipher()