#!/usr/bin/python3
import itertools
import hashlib
import sys

args = sys.argv

def hash(string, hash):
    if hash == 'md5':
        hash = hashlib.md5(string.encode('utf-8'))
        return hash.hexdigest()
    elif hash == 'sha1':
        hash = hashlib.sha1(string.encode('utf-8'))
        return hash.hexdigest()
    elif hash == 'sha256':
        hash = hashlib.sha256(string.encode('utf-8'))
        return hash.hexdigest()
    elif hash == 'sha224':
        hash = hashlib.sha224(string.encode('utf-8'))
        return hash.hexdigest()
    elif hash == 'sha384':
        hash = hashlib.sha384(string.encode('utf-8'))
        return hash.hexdigest()
    elif hash == 'sha512':
        hash = hashlib.sha512(string.encode('utf-8'))
        return hash.hexdigest()
    elif hash == 'blake2s':
        hash = hashlib.blake2s(string.encode('utf-8'))
        return hash.hexdigest()
    elif hash == 'blake2b':
        hash = hashlib.blake2b(string.encode('utf-8'))
        return hash.hexdigest()
    elif hash == 'sha3_224':
        hash = hashlib.sha3_224(string.encode('utf-8'))
        return hash.hexdigest()
    elif hash == 'sha3_256':
        hash = hashlib.sha3_256(string.encode('utf-8'))
        return hash.hexdigest()
    elif hash == 'sha3_384':
        hash = hashlib.sha3_384(string.encode('utf-8'))
        return hash.hexdigest()
    elif hash == 'sha3_512':
        hash = hashlib.sha3_512(string.encode('utf-8'))
        return hash.hexdigest()

valid_hash = ('md5', 'sha1', 'sha256', 'sha512', 'sha224', 'sha384', 'blake2b', 'sha3_224', 'sha3_256', 'sha3_384', 'sha3_512')

if "-h" in args or "--help" in args: #help message
    name=args[0] #dynamic help message
    print("rainbowtable-cli - simple python3 rainbow table tool")
    print("====================================================")
    print(name+" gen [ HASH_ALGORITHM ] [ FILE ] [ -c luds ]")
    print(name+" hash [ HASH_ALGORITHM ] [ STRING ]")
    print()
    print("OPTIONS:")
    print("-h, --help       Show this help message")
    print("-c, --chars      Set the character set")
    print("                 l - lowercase")
    print("                 u - uppercase")
    print("                 d - digits")
    print("                 s - symbols")
    print()
    print("VALID HASH ALGORITHMS:")
    print("md5, sha1, sha256, sha512, sha224, sha384, blake2b,")
    print("sha3_224, sha3_256, sha3_384, sha3_512")

    exit(0)

mode = 0
modeIndex = 0
i=1
chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890`~!@#$%^&*()_-+=[{]}|:;'\",<.>/?\\"

while i< len(args):
    if (args[i].lower() == 'gen' or args[i].lower == 'generate') and mode==0:
        mode = 1
        modeIndex = i
        i+=2
    if args[i].lower() == 'hash' and mode==0:
        mode = 2
        modeIndex = i
        i+=2
    if args[i].lower() == '-c' or args[i].lower() == '--chars':
        chars = ""
        i+=1
        if args[i].lower().count('l') > 0:
            chars+="abcdefghijklmnopqrstuvwxyz"
        if args[i].lower().count('u') > 0:
            chars+="ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        if args[i].lower().count('d') > 0:
            chars+="1234567890"
        if args[i].lower().count('s') > 0:
            chars+="`~!@#$%^&*()_-+=[{]}|:;'\",<.>/?\\"

    i+=1


if mode == 1: #rainbow table generate mode
    hash_type = args[modeIndex+1].lower()
    if not hash_type in valid_hash:
        print("Invalid hash algorithm")
        exit(1)
    path = args[modeIndex+2]
    try:
        open(path)
        print("File already exists, will be overwritten")
        prompt = input("Do you want to continue? [Y/n]: ")
        prompt = prompt.lower()
        if prompt == "y" or prompt == "yes":
            print("File is being overwritten")
        else:
            print("Operation canceled")
            exit(1)
    except IOError:
        pass
    table = open(path,"w+")
    attempts = 0
    table.write("rainbowtablekit " + hash_type + "\n")
    for i in range(1, 9):
        for letter in itertools.product(chars, repeat=i):
            attempts += 1
            letter = ''.join(letter)
            table.write(str(letter) + ' ' + str(hash(letter, hash_type)) + '\n')
            print(str(letter) + ' ' + str(hash(letter, hash_type)))

if mode == 2: #string hash mode
    hash_type = args[modeIndex+1].lower()
    if not hash_type in valid_hash:
        print("Invalid hash algorithm")
        exit(1)
    print(str(hash(args[modeIndex+2], hash_type)))

else:
    print("Invalid arguments given")
    name=args[0]
    print("Try running '"+name+" -h' for help")
    exit(1)


