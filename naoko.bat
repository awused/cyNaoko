@echo off
if not exist python goto FALLBACK
python naoko\main.py
goto END
:FALLBACK
if not exist C:\Python27\python.exe goto NOPYTHON
C:\Python27\python.exe naoko\main.py
goto END
:NOPYTHON
echo No Python found.
pause
:END
