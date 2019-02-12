hashlibinstall = False
cryptographyinstall = False
colorinstall = False
brewinstall = False
hashcatinstall = False
aircrackinstall = False
crunchinstall = False
currentframe = None
updateisavailable = False
uninstalledapps = []
from time import sleep
import sys
import os
import base64
import datetime
import signal
import platform
import re
import subprocess


def updatescript():
    os.popen('curl -o update.py -L https://raw.githubusercontent.com/OsOmE1/pycrypt/master/pycrypt.py').read()
    try:
        updatedscript = open('update.py', 'r').read()
    except:
        print(colored('File cant be downloaded', 'red'))
        stop()
    from sys import argv
    script = argv
    f = open(script[0], 'w')
    f.write(updatedscript)
    f.close()
    os.popen('rm update.py')
    print('The script has been updated you can now restart it for it to take effect')
    stop()

def hashcatmd5menu():
    try:
        os.system('clear')
        printcreds()
        currentframe = 'hashcatmd5menu'
        print(colored('Hashcat MD5 Password cracking menu', 'blue'))
        print('=========================')
        print(colored('0. Exit script', 'green'))
        print(colored('1. Go back to main menu', 'green'))
        print('---------------------------')
        print(colored('2. Bruteforce attack on single string', 'green'))
        print(colored('3. Bruteforce attack on .hash file', 'green'))
        option = str(input('> '))
        if option == '0':
            stop()
        elif option == '1':
            mainmenu()
        elif option == '2':
            passlength = 0
            hash = str(input(colored('Input your md5 hash: ', 'yellow')))
            while hash == "":
                hash = str(input(colored('Input your md5 hash: ', 'yellow')))
            f = open('hashtemp.hash', 'w')
            f.write(hash)
            f.close()
            passlength = input(colored('Input length: ', 'yellow'))
            while not passlength:
                passlength = input(colored('Input length: ', 'yellow'))
            brutelength = ""
            for i in range(int(passlength)):
                brutelength = brutelength + '?a'
            command = 'hashcat --potfile-disable -a 3 -m 0 hashtemp.hash ' + brutelength
            os.system(command)
            wait()
            hashcatmd5menu()
        else:
            print(colored('Invalid option selected!', 'red'))
            wait()
            hashcatmd5menu()
    except KeyboardInterrupt:
        os.system('clear')
        awnser = input(colored('KeyboardInterrupt detected do you really want to quit? [Y/N] ', 'red'))
        if awnser.lower() == 'y':
            stop()
        elif awnser.lower() == 'n':
            hashcatmd5menu()
        else:
            print(colored('Invalid option selected!', 'red'))
            wait()
            hashcatmd5menu()

def wpa2menu():
    try:
        os.system('clear')
        printcreds()
        currentframe = 'wpa2menu'
        print(colored('WPA2 Password cracking menu', 'blue'))
        print('=========================')
        print(colored('0. Exit script', 'green'))
        print(colored('1. Go back to main menu', 'green'))
        print('---------------------------')
        print(colored('Aircrack/Crunch', 'blue'))
        print('---------------------------')
        print(colored('2. Aircrack + Crunch bruteforce attack', 'green'))
        print('')
        print('---------------------------')
        print(colored('Hashcat', 'blue'))
        print('---------------------------')
        print(colored('4. Here will be the hascat options', 'green'))
        option = str(input('> '))
        if option == '0':
            stop()
        elif option == '1':
            mainmenu()
        elif option == '2':
            min_len = str(input(colored('Minimum Password length: ', 'yellow')))
            while min_len == "":
                min_len = str(input(colored('Minimum Password length: ', 'yellow')))
            max_len = str(input(colored('Maximum Password length: ', 'yellow')))
            while max_len == "":
                min_len = str(input(colored('Minimum Password length: ', 'yellow')))
            os.system('clear')
            printcreds()
            print('Choose a charset:')
            print('========================')
            print(colored('1. Only lowercase (abcdefghijklmnopqrstuvwxyz)', 'green'))
            print(colored('2. Only lowercase (ABCDEFGHIJKLMNOPQRSTUVWXYZ)', 'green'))
            print(colored('3. Only numbers (1234567890)', 'green'))
            print(colored('4. Only symbols (!#$%/=?{}()[]-*:;@^&,.)', 'green'))
            print(colored('5. Lowercase and uppercase (abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ)', 'green'))
            print(colored('6. Lowercase and numbers (abcdefghijklmnopqrstuvwxyz1234567890)', 'green'))
            print(colored('7. Lowercase and symbols (abcdefghijklmnopqrstuvwxyz!#$%/=?{}()[]-*:;@^&,.)', 'green'))
            print(colored('8. Uppercase and numbers (ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890)', 'green'))
            print(colored('9. Uppercase and symbols (ABCDEFGHIJKLMNOPQRSTUVWXYZ!#$%/=?{}()[]-*:;@^&,.)', 'green'))
            print(colored('10. Numbers and symbols (!#$%/=?{}()[]-*:;@^&,.1234567890)', 'green'))
            print(colored('11. Lowercase, uppercase and numbers (abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890)', 'green'))
            print(colored('12. Lowercase, uppercase, numbers and symbols (abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!#$%/=?{}()[]-*:;@^&,.)', 'green'))
            print(colored('13. Create your own charset', 'green'))
            opt0 = str(input('> '))
            if opt0 == '1':
                charset = "abcdefghijklmnopqrstuvwxyz"
                print('')
                print(colored('Make sure the cape file is in the same folder as the script', 'blue'))
                cap = input(colored('Insert name of the cap file: ', 'yellow'))
                print('')
                essid = input(colored('Insert essid(name) of the network: ', 'yellow'))
                command = 'crunch ' + min_len + ' ' + max_len + ' ' + charset + ' | aircrack-ng -e ' + essid + ' -w - ' + cap
                os.system(command)
                wait()
                wpa2menu()
            elif opt0 == '2':
                charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                print('')
                print(colored('Make sure the cape file is in the same folder as the script', 'blue'))
                cap = input(colored('Insert name of the cap file: ', 'yellow'))
                print('')
                essid = input(colored('Insert essid(name) of the network: ', 'yellow'))
                command = 'crunch ' + min_len + ' ' + max_len + ' ' + charset + ' | aircrack-ng -e ' + essid + ' -w - ' + cap
                os.system(command)
                wait()
                wpa2menu()
            elif opt0 == '3':
                charset = "1234567890"
                print('')
                print(colored('Make sure the cape file is in the same folder as the script', 'blue'))
                cap = input(colored('Insert name of the cap file: ', 'yellow'))
                print('')
                essid = input(colored('Insert essid(name) of the network: ', 'yellow'))
                command = 'crunch ' + min_len + ' ' + max_len + ' ' + charset + ' | aircrack-ng -e ' + essid + ' -w - ' + cap
                os.system(command)
                wait()
                wpa2menu()
            elif opt0 == '4':
                charset = "!#$%/=?{}()[]-*:;@^&,."
                print('')
                print(colored('Make sure the cape file is in the same folder as the script', 'blue'))
                cap = input(colored('Insert name of the cap file: ', 'yellow'))
                print('')
                essid = input(colored('Insert essid(name) of the network: ', 'yellow'))
                command = 'crunch ' + min_len + ' ' + max_len + ' ' + charset + ' | aircrack-ng -e ' + essid + ' -w - ' + cap
                os.system(command)
                wait()
                wpa2menu()
            elif opt0 == '5':
                charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
                print('')
                print(colored('Make sure the cape file is in the same folder as the script', 'blue'))
                cap = input(colored('Insert name of the cap file: ', 'yellow'))
                print('')
                essid = input(colored('Insert essid(name) of the network: ', 'yellow'))
                command = 'crunch ' + min_len + ' ' + max_len + ' ' + charset + ' | aircrack-ng -e ' + essid + ' -w - ' + cap
                os.system(command)
                wait()
                wpa2menu()
            elif opt0 == '6':
                charset = "abcdefghijklmnopqrstuvwxyz1234567890"
                print('')
                print(colored('Make sure the cape file is in the same folder as the script', 'blue'))
                cap = input(colored('Insert name of the cap file: ', 'yellow'))
                print('')
                essid = input(colored('Insert essid(name) of the network: ', 'yellow'))
                command = 'crunch ' + min_len + ' ' + max_len + ' ' + charset + ' | aircrack-ng -e ' + essid + ' -w - ' + cap
                os.system(command)
                wait()
                wpa2menu()
            elif opt0 == '7':
                charset = "abcdefghijklmnopqrstuvwxyz!#$%/=?{}()[]-*:;@^&,."
                print('')
                print(colored('Make sure the cape file is in the same folder as the script', 'blue'))
                cap = input(colored('Insert name of the cap file: ', 'yellow'))
                print('')
                essid = input(colored('Insert essid(name) of the network: ', 'yellow'))
                command = 'crunch ' + min_len + ' ' + max_len + ' ' + charset + ' | aircrack-ng -e ' + essid + ' -w - ' + cap
                os.system(command)
                wait()
                wpa2menu()
            elif opt0 == '8':
                charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
                print('')
                print(colored('Make sure the cape file is in the same folder as the script', 'blue'))
                cap = input(colored('Insert name of the cap file: ', 'yellow'))
                print('')
                essid = input(colored('Insert essid(name) of the network: ', 'yellow'))
                command = 'crunch ' + min_len + ' ' + max_len + ' ' + charset + ' | aircrack-ng -e ' + essid + ' -w - ' + cap
                os.system(command)
                wait()
                wpa2menu()
            elif opt0 == '9':
                charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ!#$%/=?{}()[]-*:;@^&,."
                print('')
                print(colored('Make sure the cape file is in the same folder as the script', 'blue'))
                cap = input(colored('Insert name of the cap file: ', 'yellow'))
                print('')
                essid = input(colored('Insert essid(name) of the network: ', 'yellow'))
                command = 'crunch ' + min_len + ' ' + max_len + ' ' + charset + ' | aircrack-ng -e ' + essid + ' -w - ' + cap
                os.system(command)
                wait()
                wpa2menu()
            elif opt0 == '10':
                charset = "!#$%/=?{}()[]-*:;@^&,.1234567890"
                print('')
                print(colored('Make sure the cape file is in the same folder as the script', 'blue'))
                cap = input(colored('Insert name of the cap file: ', 'yellow'))
                print('')
                essid = input(colored('Insert essid(name) of the network: ', 'yellow'))
                command = 'crunch ' + min_len + ' ' + max_len + ' ' + charset + ' | aircrack-ng -e ' + essid + ' -w - ' + cap
                os.system(command)
                wait()
                wpa2menu()
            elif opt0 == '11':
                charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
                print('')
                print(colored('Make sure the cape file is in the same folder as the script', 'blue'))
                cap = input(colored('Insert name of the cap file: ', 'yellow'))
                print('')
                essid = input(colored('Insert essid(name) of the network: ', 'yellow'))
                command = 'crunch ' + min_len + ' ' + max_len + ' ' + charset + ' | aircrack-ng -e ' + essid + ' -w - ' + cap
                os.system(command)
                wait()
                wpa2menu()
            elif opt0 == '12':
                charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!#$%/=?{}()[]-*:;@^&,."
                print('')
                print(colored('Make sure the cape file is in the same folder as the script', 'blue'))
                cap = input(colored('Insert name of the cap file: ', 'yellow'))
                print('')
                essid = input(colored('Insert essid(name) of the network: ', 'yellow'))
                command = 'crunch ' + min_len + ' ' + max_len + ' ' + charset + ' | aircrack-ng -e ' + essid + ' -w - ' + cap
                os.system(command)
                wait()
                wpa2menu()
            elif opt0 == '13':
                charset = str(input(colored('Input you own range of characters: ', 'yellow')))
                print('')
                print(colored('Make sure the cape file is in the same folder as the script', 'blue'))
                cap = input(colored('Insert name of the cap file: ', 'yellow'))
                print('')
                essid = input(colored('Insert essid(name) of the network: ', 'yellow'))
                command = 'crunch ' + min_len + ' ' + max_len + ' ' + charset + ' | aircrack-ng -e ' + essid + ' -w - ' + cap
                os.system(command)
                wait()
                wpa2menu()
            else:
                print('Something went really wrong')
        elif option == '3':
            pass
        else:
            print(colored('Invalid option selected!', 'red'))
            wait()

            wpa2menu()

    except KeyboardInterrupt:
        os.system('clear')
        awnser = input(colored('KeyboardInterrupt detected do you really want to quit? [Y/N] ', 'red'))
        if awnser.lower() == 'y':
            stop()
        elif awnser.lower() == 'n':
            wpa2menu()
        else:
            print(colored('Invalid option selected!', 'red'))
            wait()

            wpa2menu()


def sha256menu():
    try:
        os.system('clear')
        printcreds()
        currentframe = 'sha256menu'
        print(colored('SHA256 en/decryptions menu', 'blue'))
        print('==================')
        print(colored('0. Exit script', 'green'))
        print(colored('1. Go back to main menu', 'green'))
        print('---------------------------')
        print(colored('Fernet SHA256 options', 'blue'))
        print('---------------------------')
        print(colored('2. Generate Fernet Key', 'green'))
        print(colored('3. Encrypt String with random key', 'green'))
        print(colored('4. Encrypt String with your own key', 'green'))
        option = str(input('> '))
        if option == '0':
            stop()
        elif option == '1':
            mainmenu()
        elif option == '2':
            keyword = b"8cdb4f710a277214de7bcdf8e1cc7569"
            salt = os.urandom(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            key = base64.urlsafe_b64encode(kdf.derive(keyword))
            print("============================================")
            print(str(key.decode()))
            print("============================================")
            wait()
            sha256menu()
        elif option == '3':
            keyword = b"8cdb4f710a277214de7bcdf8e1cc7569"
            salt = os.urandom(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            key = base64.urlsafe_b64encode(kdf.derive(keyword))
            f = Fernet(key)
            data = str(input(colored('Insert the text you want to encrypt here: ', 'yellow')))
            while not data:
                data = str(input(colored('Insert the text you want to encrypt here: ', 'yellow')))
            data_enc = data.encode()
            dataenc = f.encrypt(data_enc)
            fdata = dataenc.decode()
            equals = ""
            print('Key:')
            print("============================================")
            print(str(key.decode()))
            print("============================================")
            print('Data:')
            for char in fdata:
                equals = equals + '='
            print(equals)
            print(str(fdata))
            print(equals)
            wait()
            sha256menu()
        elif option == '4':
            key = input(colored('Insert Your key: ', 'yellow'))
            while not key:
                key = input(colored('Insert Your key: ', 'yeloow'))
            try:
                f = Fernet(key.encode())
            except:
                print(colored('Please insert a valid key', 'red'))
                wait()
                sha256menu()
            data = str(input(colored('Insert the text you want to encrypt here: ', 'yellow')))
            while not data:
                data = str(input(colored('Insert the text you want to encrypt here: ', 'yellow')))
            data_enc = data.encode()
            try:
                dataenc = f.encrypt(data_enc)
                fdata = dataenc.decode()
                equals = ""
                print('\n')
                print('Key:')
                print("============================================")
                print(str(key))
                print("============================================")
                print('Data:')
                for char in fdata:
                    equals = equals + '='
                print(equals)
                print(str(fdata))
                print(equals)
            except:
                print(colored('Please insert a valid key', 'red'))
            wait()
            sha256menu()
        else:
            print(colored('Invalid option selected!', 'red'))
            wait()

            sha256menu()

    except KeyboardInterrupt:
        os.system('clear')
        awnser = input(colored('KeyboardInterrupt detected do you really want to quit? [Y/N] ', 'red'))
        if awnser.lower() == 'y':
            stop()
        elif awnser.lower() == 'n':
            sha256menu()
        else:
            print(colored('Invalid option selected!', 'red'))
            wait()

            wpa2menu()

def md5menu():
    try:
        os.system('clear')
        printcreds()
        currentframe = 'md5menu'
        print(colored('MD5 Hasher menu', 'blue'))
        print('==================')
        print(colored('0. Exit script', 'green'))
        print(colored('1. Go back to main menu', 'green'))
        print(colored('2. Create MD5 hash from string', 'green'))
        print(colored('3. MD5 Hash file(Per Line)', 'green'))
        print(colored('4. MD5 Hash file(all at once)', 'green'))
        option = str(input('> '))
        if option == '0':
            stop()
        elif option == '1':
            mainmenu()
        elif option == '2':
            print('Input the string you want to be hashed')
            string = str(input('> '))
            while string == "":
                string = str(input('> '))
            m = hashlib.md5()
            m.update(string.encode('utf-8'))
            print('================================')
            print(m.hexdigest())
            print('================================')
            wait()
            md5menu()
        elif option == '3':
            print('Make sure that the file you want to use is in the same folder')
            file = input('Put in the name of the file: ')
            while file == "":
                file = input('Put in the name of the file: ')
            try:
                lines = open(file).read().splitlines()
            except:
                print(colored('Could not read file', 'red'))
                wait()
                md5menu()
            alllines = []
            for line in lines:
                m = hashlib.md5()
                m.update(line.encode('utf-8'))
                data = m.hexdigest()
                alllines.append(data)
                print(str(data))
            opt = str(input('Do you want to create a dump.txt file with all the data? [Y/N] '))
            if opt == 'y':
                f = open('dump.txt', 'w')
                print(colored('Printing...', 'blue'))
                sleep(1)
                for line in alllines:
                    f.write(line)
                f.close()
                md5menu()
            elif opt == 'n':
                wait()
            else:
                wait()

        elif option == '4':
            print('Make sure that the file you want to use is in the same folder')
            file = input('Put in the name of the file: ')
            while file == "":
                file = input('Put in the name of the file: ')
            try:
                lines = open(file).read()
            except:
                print(colored('Could not read file', 'red'))
                wait()
                md5menu()
            f = open('dump.txt', 'w')
            m = hashlib.md5()
            m.update(lines.encode('utf-8'))
            data = m.hexdigest()
            print(str(data))
            opt = str(input('Do you want to create a dump.txt file with all the data? [Y/N] '))
            if opt == 'y':
                print(colored('Printing...', 'blue'))
                sleep(1)
                f.write(repr(data))
                wait()
                md5menu()
            elif opt == 'n':
                print(colored('Returning to menu..', 'blue'))
                sleep(1)
                md5menu()
        else:
            print('Please select a valid option')
            wait()
            md5menu()
    except KeyboardInterrupt:
        os.system('clear')
        awnser = input(colored('KeyboardInterrupt detected do you really want to quit? [Y/N] ', 'red'))
        if awnser.lower() == 'y':
            stop()
        elif awnser.lower() == 'n':
            md5menu()
        else:
            print(colored('Invalid option selected!', 'red'))
            wait()

            md5menu()

def mainmenu():
    try:
        os.system('clear')
        printcreds()
        currentframe = 'mainmenu'
        print(colored('==================================================================', 'cyan'))
        print(colored('Welcome to the main menu pick one of the options below to continue', 'blue'))
        print(colored('==================================================================', 'cyan'))
        print(colored('0. Exit script', 'green'))
        print('')
        print(colored('Encryption/Decryption Tools', 'blue'))
        print('----------------')
        print(colored('1. MD5 Hasher menu', 'green'))
        print(colored('2. SHA256 Menu', 'green'))
        print('----------------')
        print('')
        print(colored('Password Cracking Tools', 'blue'))
        print('----------------')
        if aircrackinstall == False or crunchinstall == False:
            print(colored('3. WPA2 Cracking Menu(Not available)', 'red'))
        else:
            print(colored('3. WPA2 Cracking Menu', 'green'))
        if hashcatinstall == False:
            print(colored('4. Hashcat MD5 Cracking Menu(Not available)', 'red'))
        else:
            print(colored('4. Hashcat MD5 Cracking Menu', 'green'))
        print('----------------')
        print(colored('5. Update the script', 'green'))
        option = str(input('> '))
        if option == '0':
            print(colored('Ok script exiting..', 'red'))
            stop()
        elif option == '1':
            md5menu()
        elif option == '2':
            sha256menu()
        elif option == '3':
            if aircrackinstall == False or crunchinstall == False:
                print(colored('This option is not available because you dont have the nessecairy tools installed!', 'red'))
                mainmenu()
            else:
                wpa2menu()
        elif option == '4':
            if hashcatinstall == False:
                print(colored('This option is not available because you dont have the nessecairy tools installed!', 'red'))
                mainmenu()
            else:
                hashcatmd5menu()
        elif option == '5':
            updatescript()
        else:
            print('Please select a valid option')
            wait()
            mainmenu()
    except KeyboardInterrupt:
        os.system('clear')
        awnser = input(colored('KeyboardInterrupt detected do you really want to quit? [Y/N] ', 'red'))
        if awnser.lower() == 'y':
            stop()
        elif awnser.lower() == 'n':
            mainmenu()
        else:
            print(colored('Invalid option selected!', 'red'))
            wait()

            mainmenu()


def printcreds():
    print(colored("=====================================PYCRYPT====================================", 'green'))
    print(colored("====================================By OsOmE1===================================", 'green'))
    print(colored("===================================Version 1.0==================================", 'green'))
    print('')
    print('')

def wait():
    print('\n')
    input(colored('Press any key to continue..', 'blue'))
def waitstop():
    print('\n')
    input(colored('Press any key to stop the process..', 'blue'))
def stop():
    print('\n')
    print(colored('Clearing temp files..', 'blue'))
    try:
        open('hashtemp.hash', 'r')
        hashtemp = True
    except:
        hashtemp = False
    if hashtemp == True:
        os.popen('rm hashtemp.hash').read()
    else:
        pass
    try:
        open('dump.txt', 'r')
        dump = True
    except:
        dump = False
    if dump == True:
        os.popen('rm dump.txt').read()
    else:
        pass
    print(colored('Scipt exiting..', 'red'))
    sleep(1)
    exit(0)


operatingsytem = platform.system()
if operatingsytem == "Darwin":
    macosx = True
    Linux = False
elif operatingsystem == "Linux":
    macosx = False
    Linux = True
else:
    print(colored('Non compatible operating system detected'))
    stop()

os.system('clear')

try:
    line1 = "=====================================PYCRYPT===================================="
    for char in line1:
        sleep(0.02)
        sys.stdout.write(char)
        sys.stdout.flush()
    print('')
    line2 = "====================================By OsOmE1==================================="
    for char in line2:
        sleep(0.02)
        sys.stdout.write(char)
        sys.stdout.flush()
    print('\n')
    print('Checking required modules..')
    sleep(0.5)

    try:
        from termcolor import colored, cprint
        colorinstall = True
        print('Termcolor... OK')
    except:
        print('Termcolor... Error')
        awnser = input('You dont have termcolor installed the script needs it to continue do you want to install it now? [Y/N] ')
        if awnser.lower() == "y":
            os.system('pip3 install termcolor')
        elif awnser.lower() == "n":
            print('\n')
            print(colored('Clearing temp files..'))
            os.popen('rm hashtemp.hash').read()
            print('Scipt exiting..')
            sleep(1)
            exit(0)
    sleep(0.5)

    def is_tool(name):
        from shutil import which
        return which(name) is not None

    brew = is_tool('brew')
    if brew == True:
        print('Brew... ' + colored('OK', 'green'))
        brewinstall = True
        updateisavailable = True
    else:
        brewinstall = False
        updateisavailable = False
    aircrack = is_tool('aircrack-ng')
    if aircrack == True:
        print('Aircrack-ng... ' + colored('OK', 'green'))
        aircrackinstall = True
    else:
        print('Aircrack... ' + colored('Error', 'red'))
        aircrackinstall = False
        uninstalledapps.append('aircrack-ng')
    crunch = is_tool('crunch')
    if crunch == True:
        print('Crunch... ' + colored('OK', 'green'))
        crunchinstall = True
    else:
        print('Crunch... ' + colored('Error', 'red'))
        crunchinstall = False
        uninstalledapps.append('crunch')

    hashcat = is_tool('hashcat')
    if hashcat == True:
        print('Hashcat... ' + colored('OK', 'green'))
        hashcatinstall = True
    else:
        print('Hashcat... ' + colored('Error', 'red'))
        hashcatinstall = False
        uninstalledapps.append('hashcat')

    try:
        import hashlib
        hashlibinstall = True
        print('Hashlib... ' + colored('OK', 'green'))
    except:
        print('Hashlib... ' + colored('Error', 'red'))
        hashlibinstall = False
    sleep(0.5)

    try:
        from cryptography.fernet import Fernet
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        cryptographyinstall = True
        print('Cryptography... ' + colored('OK', 'green'))
    except:
        print('Cryptography... ' + colored('Error', 'red'))
        cryptographyinstall = False
    if colorinstall == False:
        print('\n')
        awnser = input(colored('Termcolor is not installed do you want to install it now? [Y/N] ', 'red'))
        if str(awnser.lower()) == 'y':
            os.popen('pip3 install termcolor').read()
            print('Termcolor installed!')
            colorinstall = True
        elif str(awnser.lower()) == 'n':
            stop()
    if hashlibinstall == False:
        print('\n')
        awnser = input(colored('Hashlib is not installed do you want to install it now? [Y/N] ', 'red'))
        if str(awnser.lower()) == 'y':
            os.system('pip3 install hashlib')
            hashlibinstall = True
        elif str(awnser.lower()) == 'n':
            stop()
    if cryptographyinstall == False:
        print('\n')
        awnser = input(colored('Cryptography is not installed do you want to install it now? [Y/N] ', 'red'))
        if str(awnser.lower()) == 'y':
            os.system('pip3 install cryptography')
            cryptographyinstall = True
        elif str(awnser.lower()) == 'n':
            stop()
    if brewinstall == False:
        print('\n')
        awnser = input(colored('Brew is not installed it is required to install optional tools do you want to install it now? [Y/N] ', 'red'))
        if str(awnser.lower()) == 'y':
            os.popen('/usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"').read()
            print(colored('Homebrew installed!', 'blue'))
            updateisavailable = True
        else:
            updateisavailable = False
    else:
        pass
    if not uninstalledapps:
        pass
    elif uninstalledapps:
        os.system('clear')
        print('Uninstalled Tools')
        print('====================')
        print('\n')
        toolnum = 1
        for tool in uninstalledapps:
            print(str(toolnum) + '. ' + tool.capitalize())
            toolnum = toolnum + 1
        if brewinstall == False:
            awnser = input(colored('Brew is not installed it is required to install optional tools do you want to install it now? [Y/N] ', 'red'))
            if str(awnser.lower()) == 'y':
                os.popen('/usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"').read()
                print(colored('Homebrew installed!', 'blue'))
                updateisavailable = True
            else:
                updateisavailable = False
        elif updateisavailable == True:
            opt1 = input(colored('The Tools listed above are not installed do you want to install them to achieve full script functionality? [Y/N]', 'yellow'))
            if str(opt1.lower()) == "y":
                for tool in uninstalledapps:
                    if macosx == True:
                        print(colored('Installing ' + tool.capitalize() + '....', 'blue'))
                        os.popen('brew install ' + tool).read()
                        print(colored(tool.capitalize() + ' installed!', 'blue'))
                        fullfunc = True
                    elif Linux == True:
                        print(colored('Installing ' + tool.capitalize() + '....', 'blue'))
                        os.popen('sudo apt-get install ' + tool).read()
                        print(colored(tool.capitalize() + ' installed!', 'blue'))
                        fullfunc = True
            else:
                fullfunc = False
                pass
            if fullfunc == True:
                hashcatinstall = True
                aircrackinstall = True
                crunchinstall = True


except KeyboardInterrupt:
    os.system('clear')
    if colorinstall == False:
        awnser = input('KeyboardInterrupt detected do you really want to quit? [Y/N] ')
        if awnser.lower() == 'y':
            print('Scipt exiting..')
            exit(0)
        elif awnser.lower() == 'n':
            pass
        else:
            print('Invalid option selected!')
            exit(0)
    else:
        awnser = input(colored('KeyboardInterrupt detected do you really want to quit? [Y/N] ', 'red'))
        if awnser.lower() == 'y':
            stop()
        elif awnser.lower() == 'n':
            pass
        else:
            print('Invalid option selected!')
            exit(0)

sleep(0.5)
wait()
mainmenu()
