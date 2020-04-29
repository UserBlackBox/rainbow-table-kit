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
    print("==========================================================================================")
    print(name+" [ COMMAND ] [ OPTIONS ]")
    print()
    print("COMMANDS")
    print("gen, generate          Generate rainbow table")
    print(name+" gen [ HASH_ALGORITHM ] [ FILE ] [ -c luds ] [ -n ] [ -h N ] [ -l N ] [ -q ]")
    print("hash                   Hash given string")
    print(name+" hash [ HASH_ALGORITHM ] [ STRING ]")
    print("ss, stringsearch       Search table for hash of string")
    print(name+" ss [ TABLE_FILE ] [ STRING ]")
    print("hs, hashsearch         Search table for plaintext of hash")
    print(name+" hs [ TABLE_FILE ] [ HASH ]")
    print()
    print("OPTIONS:")
    print("-h, --help             Show this help message")
    print("-c, --chars            Set the character set")
    print("                           l - lowercase")
    print("                           u - uppercase")
    print("                           d - digits")
    print("                           s - symbols")
    print("-n, --nofile           Don't save table to file")
    print("-l, --limit            Stop generation after given amount of hashes")
    print("-q, --quiet            No generation terminal output")
    print()
    print("VALID HASH ALGORITHMS:")
    print("md5, sha1, sha256, sha512, sha224, sha384, blake2b,")
    print("sha3_224, sha3_256, sha3_384, sha3_512")

    exit(0)

mode = 0
limit = float("inf")
modeIndex = 0
i=1
noFile = False
quiet = False
chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890`~!@#$%^&*()_-+=[{]}|:;'\",<.>/?\\"

if "-n" in args or "--nofile" in args: #nofile option
    noFile = True

while i< len(args): #argument parsing
    if (args[i].lower() == 'gen' or args[i].lower == 'generate') and mode==0:
        mode = 1
        modeIndex = i
        if noFile == False:
            i+=2
        else: i+=1
    if args[i].lower() == 'hash' and mode==0:
        mode = 2
        modeIndex = i
        i+=2
    if (args[i].lower() == 'ss' or args[i].lower == 'stringsearch') and mode==0:
        mode = 3
        modeIndex = i
        i+=2
    if (args[i].lower() == 'hs' or args[i].lower == 'hashsearch') and mode==0:
        mode = 4
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
    if args[i].lower() == '-l' or args[i].lower() == '--limit':
        i += 1
        try:
            limit = float(args[i])
        except ValueError:
            print("Invalid Arguments")
            exit(1)
    if args[i].lower() == '-q' or args[i].lower() == '--quiet':
        quiet = True

    i+=1

try:
    if mode == 1: #rainbow table generate mode
        hash_type = args[modeIndex+1].lower()
        if not hash_type in valid_hash:
            print("Invalid hash algorithm")
            exit(1)
        if noFile == False:
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
                    if quiet == False:
                        print(str(letter) + ' ' + str(hash(letter, hash_type)))
                    if attempts >= limit:
                        print("Generation Limit Reached")
                        exit(0)
        else:
            attempts = 0
            for i in range(1, 9):
                for letter in itertools.product(chars, repeat=i):
                    attempts += 1
                    letter = ''.join(letter)
                    if quiet == False:
                        print(str(letter) + ' ' + str(hash(letter, hash_type)))
                    if attempts >= limit:
                        print("Generation Limit Reached")
                        exit(0)

    elif mode == 2: #string hash mode
        hash_type = args[modeIndex+1].lower()
        if not hash_type in valid_hash:
            print("Invalid hash algorithm")
            exit(1)
        print(str(hash(args[modeIndex+2], hash_type)))

    elif mode == 3: #string table search
        path = args[modeIndex+1]
        search = args[modeIndex+2]
        try:
            with open(path, 'r') as table:
                line_num = 0
                found = False
                for line in table:
                    line_num += 1
                    current = line.split(' ')
                    if line_num == 1:
                        if current[0] != "rainbowtablekit":
                            print("Invalid table file")
                            exit(1)
                        hash_type = current[1][:-1]
                    else:
                        if current[0] == search:
                            print(hash_type + " hash of \"" + search + "\" found on file line " + str(line_num))
                            print(hash_type + " hash: " + current[1][:-1])
        except FileNotFoundError:
            print("File does not exist")
            exit(1)

    elif mode == 4: #hash table search
        path = args[modeIndex+1]
        search = args[modeIndex+2]
        try:
            with open(path, 'r') as table:
                line_num = 0
                found = False
                for line in table:
                    line_num += 1
                    current = line.split(' ')
                    if line_num == 1:
                        if current[0] != "rainbowtablekit":
                            print("Invalid table file")
                            exit(1)
                        hash_type = current[1][:-1]
                    else:
                        if current[1][:-1] == search:
                            print("Plaintext of \"" + search + "\" found on file line " + str(line_num))
                            print("plaintext: " + current[0])
        except FileNotFoundError:
            print("File does not exist")
            exit(1)

    else: #invalid
        print("Invalid arguments given")
        name=args[0]
        print("Try running '"+name+" -h' for help")
        exit(1)

except KeyboardInterrupt:
    print("Operation Interrupted")
    exit(0)
