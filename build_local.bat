set OUT_DIR=D:\Job\2017_crack\asm_rewriter\
set LIB_DIR=C:\Program Files (x86)\Windows Kits\8.1\Lib\winv6.3\um\x86\
set NASM=C:\Program Files\NASM\nasm.exe
set VCVARSALLBAT="C:\Program Files (x86)\Microsoft Visual Studio 14.0\VC\vcvarsall.bat"
python pe_asm_rewriter.py --file crackme --rva 0xda
"%NASM%" -fwin32 myresult_result.asm
CALL %VCVARSALLBAT% x86
link /subsystem:console /entry:start_func "%OUT_DIR%myresult_result.obj" "%LIB_DIR%kernel32.Lib" -out:"%OUT_DIR%result.exe"
