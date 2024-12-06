## How to build shellcode loader.

```
x86_64-w64-mingw32-g++-win32 shellcode_loader.cpp syscall.obj -static -o shellcode_loader.exe -mwindows -O3
```