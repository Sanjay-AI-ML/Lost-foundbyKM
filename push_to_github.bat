@echo off
title Push to GitHub
echo =======================================================
echo Pushing Lost and Found project to GitHub...
echo =======================================================
echo.
"C:\Users\kathi\AppData\Local\Programs\Git\cmd\git.exe" push --force -u origin main
echo.
echo =======================================================
if %ERRORLEVEL% EQU 0 (
    echo SUCCESS! Your code has been pushed to GitHub!
) else (
    echo An error occurred. Please check your GitHub login.
)
echo =======================================================
pause
