@echo off
setlocal
cd /d "%~dp0"

echo ============================================
echo   CheDNS - сборка CheDNS.exe
echo ============================================
echo.

echo [1/3] Установка зависимостей...
python -m pip install --upgrade pip >nul
python -m pip install -r requirements.txt
if errorlevel 1 goto error

echo.
echo [2/3] Очистка старых сборок...
if exist build rmdir /s /q build
if exist dist rmdir /s /q dist

echo.
echo [3/3] Сборка exe (может занять 1-2 минуты)...
pyinstaller --clean --noconfirm che_dns.spec
if errorlevel 1 goto error

echo.
echo ============================================
echo   ГОТОВО!
echo   Файл: dist\CheDNS.exe
echo ============================================
echo.
echo Скопируй dist\CheDNS.exe в любую папку на целевой машине
echo и запускай от имени администратора (правой кнопкой).
echo.
pause
exit /b 0

:error
echo.
echo [ОШИБКА] Сборка не удалась. Смотри вывод выше.
pause
exit /b 1