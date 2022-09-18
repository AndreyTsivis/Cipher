from base64 import urlsafe_b64encode as b64encode
from itertools import count
from cryptography.fernet import Fernet
from os import remove, system, urandom, chdir, getcwd, listdir
from os.path import abspath, isdir
from json import load as json_load
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from time import sleep

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
        system("cls||clear")
        self.prev_dir = getcwd()
        chdir( abspath(f"{__file__}/..") )
        conf = json_load(open("config.json", "rb"))
        print(f"{colors.GREEN + conf['AppArt'] + colors.CUR_CLR}\nver {conf['AppVersion'] + colors.RESET}\n")

        while True:
            print(f"{colors.YELLOW + getcwd() + colors.RESET}")
            send_cmd = input(f"{colors.CUR_CLR}>> {colors.RESET}").split(" ")

            if "exit" in send_cmd:
                print(f"{colors.YELLOW}Exiting...{colors.RESET}")
                sleep(2)
                chdir(abspath(self.prev_dir))
                break

            print(self.cmd_parse(send_cmd))

    
    def cmd_parse(self, cmd:list):
        if "encrypt" in cmd:
            key = self.load_key()
            return self.encrypt(cmd[1], key)
        elif "decrypt" in cmd:
            key = self.load_key()
            return self.decrypt(cmd[1], key)
        elif "cd" in cmd:
            chdir(abspath(cmd[1]))
            return ""
        elif "ls" in cmd:
            wet_list = listdir()
            dirlist = ""

            for path in wet_list:
                if( isdir(path) == 1 ):
                    dirlist = f"{ dirlist + colors.BLUE + path + colors.RESET }\n"
                elif( isdir(path) == 0 and ".encrypted" in path ):
                    dirlist = f"{ dirlist + colors.YELLOW + path + colors.RESET }\n"
                elif( isdir(path) == 0 and ".encrypted" not in path ):
                    dirlist = f"{ dirlist + path }\n"
                
            return f"{dirlist}"
        elif "keygen" in cmd:
            password = input(f"Key file password:{colors.YELLOW} ")
            return self.write_key(password)
        else:
            return f"{colors.ERROR}[!]{colors.RESET} Command not found.\n"

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
        open(abspath(f"{__file__}/../crypto.key"), "wb").write(key)
        return f"{colors.RESET}Key file generated."

    def load_key(self):
        return open(abspath(f"{__file__}/../crypto.key"), "rb").read()

    def encrypt(self, filename:str, key:bytes):
        fernet = Fernet(key)
        if "*" in filename:
            wet_file_list = listdir()
            file_list = list()

            for file in wet_file_list:
                if isdir(file) == 0:
                    file_list.append(file)

            for file in file_list:
                with open(file, "rb") as f:
                    file_data = f.read()
                    encrypted_data = fernet.encrypt(file_data)
                open(f"{file}.encrypted", "wb").write(encrypted_data)
                remove(file)

            return f"{colors.SUCCESS}[+]{colors.RESET} {colors.YELLOW + str(len(file_list)) + colors.RESET} files were successfully encrypted.\n"
        else:
            with open(filename, "rb") as f:
                    file_data = f.read()
                    encrypted_data = fernet.encrypt(file_data)
            open(f"{filename}.encrypted", "wb").write(encrypted_data)
            remove(filename)

            return f"{colors.SUCCESS}[+]{colors.RESET} File '{colors.YELLOW + filename + colors.RESET}' encrypted successfully.\n"

    def decrypt(self, filename:str, key:bytes):
        fernet = Fernet(key)
        if "*" in filename:
            wet_file_list = listdir()
            file_list = list()

            for file in wet_file_list:
                if isdir(file) == 0 and ".encrypted" in file:
                    file_list.append(file)

            for file in file_list:
                with open(file, "rb") as f:
                    encrypted_data = f.read()
                    data = fernet.decrypt(encrypted_data)
                open(file[:-10], "wb").write(data)
                remove(file)

            return f"{colors.SUCCESS}[+]{colors.RESET} {colors.YELLOW + str(len(file_list)) + colors.RESET} files were successfully decrypted.\n"
        else:
            if ".encrypted" not in filename:
                encrypted_data = open(f"{filename}.encrypted", "rb").read()
                data = fernet.decrypt(encrypted_data)
                open(filename, "wb").write(data)
                remove(f"{filename}.encrypted")

                return f"{colors.SUCCESS}[+]{colors.RESET} File '{colors.YELLOW + f'{filename}.encrypted' + colors.RESET}' decrypted successfully.\n"
            elif ".encrypted" in filename:
                encrypted_data = open(filename, "rb").read()
                data = fernet.decrypt(encrypted_data)
                open(filename[:-10], "wb").write(data)
                remove(filename)

                return f"{colors.SUCCESS}[+]{colors.RESET} File '{colors.YELLOW + filename + colors.RESET}' decrypted successfully.\n"



if __name__ == "__main__":
    Cipher()