# Compiling in local

## Windows Installation:
1. Download MSYS2 (msys2.org)

2. execute:
```
pacman -Syu
pacman -S mingw-w64-x86_64-gcc
pacman -S mingw-w64-x86_64-make
pacman -S mingw-w64-x86_64-openssl
```

## Add g++ to MSYS2 path
in MSYS2 console:
`echo 'export PATH="/mingw64/bin:$PATH"' >> ~/.bashrc`
Reload and test with
`g++ --version`

## VSC configuration of settings.json
```json
"terminal.integrated.profiles.windows": {
        "MSYS2 MinGW64": {
            "path": "C:\\msys64\\usr\\bin\\bash.exe",
            "args": ["--login", "-i"],
        },        
    },
```

## Compilation

`g++ -o encoder main.cpp -lssl -lcrypto -march=native -O3` 

Flags:
`-lssl -lcrypto`Compiles with linked libraries

`-march=native` lets the compiler automatically use highest level instruction supported by CPU
`-O3` allows the highest level of optimization
Source: https://blog.csdn.net/www_dong/article/details/145621322

<<<<<<< HEAD
Note: these 2 flags optimized my Encoding from 22 seconds to run 100 times to 1.90 seconds to run 100 times.
=======
Note: these 2 flags optimized my Encoding from 22 seconds to run 100 times to 1.82 seconds to run 100 times.


>>>>>>> 027bdf3 (optimization of runs and compilation)

I am using g++.exe (Rev8, Built by MSYS2 project) 15.2.0


## My Root folder
`/c/Users/Julio/Documents/git/ComputingModule-EncryptionTool-Cplusplus`

# Use

To cypher file:
`./encoder 1 file.png`

To de-cypher file:
`./encoder 0 file_encrypted.png`

## Benchmark
to encrypt 100 times
`./encoder 1 file.png benchmark 100`

to decrypt 100 times:
`./encoder 0 file_encrypted.png benchmark 100`