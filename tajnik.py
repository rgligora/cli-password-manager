import os
import shutil
import json
import sys
import argparse
import base64
from Cryptodome.Random import get_random_bytes
from Cryptodome.Hash import HMAC, SHA256, SHA512
from Cryptodome.Protocol.KDF import PBKDF2
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad

def initDatabase(masterPassword, vaultDirectoryPath):
    os.makedirs(vaultDirectoryPath, mode=0o700)
    salt = get_random_bytes(16)
    saltPath = os.path.join(vaultDirectoryPath, 'databasesalt')
    with open(saltPath, 'wb') as saltFile:
        saltFile.write(salt)
    jsonFilePath = os.path.join(vaultDirectoryPath, 'passwords.json')

    websitePwdSalt = get_random_bytes(16)
    ivW = get_random_bytes(AES.block_size)
    ivP = get_random_bytes(AES.block_size)

    with open(jsonFilePath, 'w', newline='') as jsonFile:
        data = {
        "websitePwdSalt": base64.b64encode(websitePwdSalt).decode('utf-8')
        }
        json.dump(data, jsonFile)
    databaseHMAC(masterPassword, vaultDirectoryPath)
            

def databaseHMAC(masterPassword, vaultDirectoryPath):
    salt = getDatabaseSalt(vaultDirectoryPath)
    key = PBKDF2(masterPassword, salt, dkLen=32, count=100000, hmac_hash_module=SHA256)
    h_obj = HMAC.new(key, digestmod=SHA256)
    jsonFilePath = os.path.join(vaultDirectoryPath, 'passwords.json')
    hashFilePath = os.path.join(vaultDirectoryPath, 'passwords.sha256')
    with open(jsonFilePath, 'rb') as jsonFile:
        h_obj.update(jsonFile.read())
    with open(hashFilePath, 'w') as hashFile:
        hashFile.write(h_obj.hexdigest())

def checkMasterPasswordAndItegrity(masterPassword, vaultDirectoryPath):
    salt = getDatabaseSalt(vaultDirectoryPath)
    key = PBKDF2(masterPassword, salt, dkLen=32, count=100000, hmac_hash_module=SHA256)
    new_h_obj = HMAC.new(key, digestmod=SHA256)
    jsonFilePath = os.path.join(vaultDirectory, 'passwords.json')
    hashFilePath = os.path.join(vaultDirectoryPath, 'passwords.sha256')
    with open(jsonFilePath, 'rb') as jsonFile:
        new_h_obj.update(jsonFile.read())
    with open(hashFilePath, 'r') as hashFile:
        hexStoredHash = hashFile.read()
        storedHash = bytes.fromhex(hexStoredHash)

    try:
        new_h_obj.verify(storedHash)
    except ValueError:
        print("Master password incorrect or integrity check failed.")
        sys.exit(1)

def put(masterPassword, website, password, vaultDirectoryPath):
    checkMasterPasswordAndItegrity(masterPassword, vaultDirectoryPath)
    jsonFilePath = os.path.join(vaultDirectoryPath, 'passwords.json')
    with open(jsonFilePath, 'r') as jsonFile:
        hashMap = json.load(jsonFile)
    websitePwdSalt = base64.b64decode(hashMap["websitePwdSalt"])

    keys = PBKDF2(masterPassword, websitePwdSalt, dkLen=64, count=100000, hmac_hash_module=SHA512)
    keyW = keys[:32]
    


    for encryptedWebsite, values in hashMap.items():
        if encryptedWebsite in ["websitePwdSalt"]:
            continue
        try:
            ivW = base64.b64decode(values["ivW"])
            cipherW = AES.new(keyW, AES.MODE_CBC, ivW)
            decryptedWebsite = unpad(cipherW.decrypt(base64.b64decode(encryptedWebsite)), AES.block_size).decode('utf-8')
            if decryptedWebsite == website:
                ivP = base64.b64decode(values["ivP"])
                keyP = keys[32:]
                cipherP = AES.new(keyP, AES.MODE_CBC, ivP)
                ciphertextPassword = cipherP.encrypt(pad(password.encode('utf-8'), AES.block_size))
                hashMap[encryptedWebsite] = {"password" : base64.b64encode(ciphertextPassword).decode('utf-8'), "ivW" : base64.b64encode(ivW).decode('utf-8'), "ivP" : base64.b64encode(ivP).decode('utf-8')}
                break
        except (ValueError, KeyError):
            pass
    
    
    keyP = keys[32:]
    ivW = get_random_bytes(AES.block_size)
    ivP = get_random_bytes(AES.block_size)
    cipherW = AES.new(keyW, AES.MODE_CBC, ivW)
    cipherP = AES.new(keyP, AES.MODE_CBC, ivP)
    

    ciphertextWebsite = cipherW.encrypt(pad(website.encode('utf-8'), AES.block_size))
    ciphertextPassword = cipherP.encrypt(pad(password.encode('utf-8'), AES.block_size))
    hashMap[base64.b64encode(ciphertextWebsite).decode('utf-8')] = {"password" : base64.b64encode(ciphertextPassword).decode('utf-8'), "ivW" : base64.b64encode(ivW).decode('utf-8'), "ivP" : base64.b64encode(ivP).decode('utf-8')}
    with open(jsonFilePath, 'w', newline='') as jsonfile:
        json.dump(hashMap, jsonfile)
    databaseHMAC(masterPassword, vaultDirectoryPath)

def get(masterPassword, website, vaultDirectoryPath):
    checkMasterPasswordAndItegrity(masterPassword, vaultDirectoryPath)
    jsonFilePath = os.path.join(vaultDirectoryPath, 'passwords.json')
    with open(jsonFilePath, 'r') as jsonFile:
        hashMap = json.load(jsonFile)
    websitePwdSalt = base64.b64decode(hashMap["websitePwdSalt"])

    keys = PBKDF2(masterPassword, websitePwdSalt, dkLen=64, count=100000, hmac_hash_module=SHA512)
    keyW = keys[:32]


    for encryptedWebsite, values in hashMap.items():
        if encryptedWebsite in ["websitePwdSalt"]:
            continue
        ivW = base64.b64decode(values["ivW"])
        cipherW = AES.new(keyW, AES.MODE_CBC, ivW)
        try:
            decryptedWebsite = unpad(cipherW.decrypt(base64.b64decode(encryptedWebsite)), AES.block_size).decode('utf-8')
            if decryptedWebsite == website:
                ivP = base64.b64decode(values["ivP"])
                keyP = keys[32:]
                encryptedPassword = values["password"]
                cipherP = AES.new(keyP, AES.MODE_CBC, ivP)
                decryptedPassword = unpad(cipherP.decrypt(base64.b64decode(encryptedPassword)), AES.block_size).decode('utf-8')
                return decryptedPassword
        except (ValueError, KeyError):
            pass
    return None

def getDatabaseSalt(vaultDirectoryPath):
    saltFilePath = os.path.join(vaultDirectoryPath, 'databasesalt')
    with open(saltFilePath, 'rb') as saltFile:
        salt = saltFile.read()
    return salt

def initParser():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest='command', required=True)

    parser_init = subparsers.add_parser('init', help='Initialize the password database')
    parser_init.add_argument('masterPassword', type=str, help='master password for the password manager')

    parser_put = subparsers.add_parser('put', help='Store a new password')
    parser_put.add_argument('masterPassword', type=str, help='master password')
    parser_put.add_argument('website', type=str, help='website for which the password is stored')
    parser_put.add_argument('password', type=str, help='password to store')

    parser_get = subparsers.add_parser('get', help='Retrieve a stored password')
    parser_get.add_argument('masterPassword', type=str, help='master password')
    parser_get.add_argument('website', type=str, help='website for which to retrieve the password')
    return parser



parser = initParser()
args = parser.parse_args()

if args.command in ['init', 'put', 'get']:
    vaultDirectory = os.path.expanduser('~/.tajnikVault')

    if not os.path.exists(vaultDirectory):
        if args.command == 'init':
            #inicijaliziraj bazu
            initDatabase(args.masterPassword, vaultDirectory)
            print('Password manager initialized.')
        else: 
            print("Error! Tajnik is not initialised. First run the init command.", file=sys.stderr)
            sys.exit(1)
    else:
        if args.command == 'init':
            notConfirmed = True
            while notConfirmed:
                confirmation = input("Are you sure that you want to reinitialise your Tajnik? This action will delete all of the passwords! [Y/n] ")
                if confirmation == 'Y':
                    try:
                        shutil.rmtree(vaultDirectory)
                    except Exception as e:
                        print(f"Error occurred while trying to delete {vaultDirectory}: {e}")
                    initDatabase(args.masterPassword, vaultDirectory)
                    print('Password manager initialized.')
                    notConfirmed = False
                elif confirmation == 'n':
                    notConfirmed = False
                    sys.exit(1)
                else: 
                    print("Invalid input")
        else:
            checkMasterPasswordAndItegrity(args.masterPassword, vaultDirectory)
            if args.command == 'put':
                put(args.masterPassword, args.website, args.password, vaultDirectory)
                print(f'Stored password for: {args.website}')
            elif args.command == 'get':
                password = get(args.masterPassword, args.website, vaultDirectory)
                if password != None:
                    print(f'Password for {args.website} is: {password}.')
                else:
                    print('Error! Website inccorect.')