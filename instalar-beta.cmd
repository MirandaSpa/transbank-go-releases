@echo off
rem Instalar el agente Transbank (canal beta)
rem Doble clic con la sesion de Windows de la caja (no "Ejecutar como
rem administrador"). Descarga y corre install.ps1 de
rem https://github.com/MirandaSpa/transbank-go-releases.
title Instalar el agente Transbank (canal beta)
powershell -NoProfile -ExecutionPolicy Bypass -Command "[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072; try { & ([scriptblock]::Create((Invoke-RestMethod 'https://raw.githubusercontent.com/MirandaSpa/transbank-go-releases/main/install.ps1' -UseBasicParsing))) -Canal beta } catch { Write-Host ('ERROR: ' + $_.Exception.Message) -ForegroundColor Red; exit 1 }"
echo.
pause
