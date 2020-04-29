# rainbow-table-kit
Simple Python program to create and search rainbow tables. Hashes are done using `hashlib`. 

## Features
* Rainbow table generation
* Rainbow table searching given either hash or plaintext
* String hashing function
* CLI interface

## Usage
```
rainbowtable-cli - simple python3 rainbow table tool
==========================================================================================
./RainbowTableCLI.py [ COMMAND ] [ OPTIONS ]

COMMANDS
gen, generate          Generate rainbow table
./RainbowTableCLI.py gen [ HASH_ALGORITHM ] [ FILE ] [ -c luds ] [ -n ] [ -h N ] [ -l N ] [ -q ]
hash                   Hash given string
./RainbowTableCLI.py hash [ HASH_ALGORITHM ] [ STRING ]
ss, stringsearch       Search table for hash of string
./RainbowTableCLI.py ss [ TABLE_FILE ] [ STRING ]
hs, hashsearch         Search table for plaintext of hash
./RainbowTableCLI.py hs [ TABLE_FILE ] [ HASH ]

OPTIONS:
-h, --help             Show this help message
-c, --chars            Set the character set
                           l - lowercase
                           u - uppercase
                           d - digits
                           s - symbols
-n, --nofile           Don't save table to file
-l, --limit            Stop generation after given amount of hashes
-q, --quiet            No generation terminal output

VALID HASH ALGORITHMS:
md5, sha1, sha256, sha512, sha224, sha384, blake2b,
sha3_224, sha3_256, sha3_384, sha3_512
```

## TODO
* Tkinter GUI
* More hashes