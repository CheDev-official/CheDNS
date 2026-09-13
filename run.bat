@echo off
chcp 65001 >nul
title CheDNS - запуск из исходников
echo ============================================
echo   CheDNS - запуск из исходников
echo ============================================
echo.
echo   Внимание: для запуска нужен Python 3.10+
echo   Для обычного использования скачай CheDNS.exe
echo   из раздела Releases.
echo.
echo   Запуск от имени администратора обязателен
echo   (для порта 53).
echo.
pause

python chedns.py
pause
