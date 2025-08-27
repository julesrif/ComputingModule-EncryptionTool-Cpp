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
`g++ main.cpp -o main.exe`

## Root folder
`/c/Users/Julio/Documents/git/ComputingModule-EncryptionTool-Cplusplus`
