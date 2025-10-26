# WinVulnScanner v1.3 - Instalación Automática
# Versión: final_CORREGIDA
# Características: PowerShell compatible + Acceso Directo en Escritorio

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  WinVulnScanner v1.3" -ForegroundColor Cyan
Write-Host "  Búsqueda por CPE - final_CORREGIDA" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Verificar si se ejecuta como Administrador
$IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

if (-not $IsAdmin) {
    Write-Host "[!] ADVERTENCIA: Se recomienda ejecutar como Administrador" -ForegroundColor Yellow
    Write-Host "    Para ejecutar como Admin: Haz clic derecho en PowerShell > Ejecutar como Administrador" -ForegroundColor Yellow
    Write-Host ""
}

try {
    # Paso 1: Desbloquear archivos (si es necesario)
    Write-Host "[*] Desbloqueando archivos..." -ForegroundColor White
    Get-ChildItem -Path $ScriptDir -Recurse -ErrorAction SilentlyContinue | Unblock-File -ErrorAction SilentlyContinue
    Write-Host "[+] Archivos desbloqueados" -ForegroundColor Green

    # Paso 2: Establecer política de ejecución (solo en el proceso actual)
    Write-Host "[*] Configurando política de ejecución..." -ForegroundColor White
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned -Force -ErrorAction SilentlyContinue
    Write-Host "[+] Política de ejecución configurada" -ForegroundColor Green

    # Paso 3: Crear directorio de instalación
    $TargetRoot = Join-Path $env:LOCALAPPDATA "WinVulnScanner_v1.3"
    Write-Host "[*] Creando directorio: $TargetRoot" -ForegroundColor White
    New-Item -ItemType Directory -Path $TargetRoot -Force | Out-Null
    Write-Host "[+] Directorio creado" -ForegroundColor Green

    # Paso 4: Copiar archivos
    Write-Host "[*] Copiando archivos de aplicación..." -ForegroundColor White
    $FilesToCopy = @("scanner_cpe.py", "main.py", "ui.py", "requirements.txt", "README.md", "WinVulnScanner_v1.3_Documentacion_Azul.html")

    foreach ($File in $FilesToCopy) {
        if (Test-Path $File) {
            Copy-Item $File -Destination $TargetRoot -Force
            Write-Host "  [+] Copiado: $File" -ForegroundColor Green
        }
    }
    Write-Host "[+] Archivos copiados correctamente" -ForegroundColor Green

    # Paso 5: Verificar Python
    Write-Host "[*] Verificando Python..." -ForegroundColor White
    $PythonCheck = python --version 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "[+] Python encontrado: $PythonCheck" -ForegroundColor Green
    } else {
        Write-Host "[!] Python NO encontrado. Por favor instala Python 3.10+" -ForegroundColor Red
        Write-Host "    Descárgalo de: https://www.python.org/downloads/" -ForegroundColor Yellow
        exit 1
    }

    # Paso 6: Instalar dependencias
    Write-Host "[*] Instalando dependencias Python..." -ForegroundColor White
    $RequirementsFile = Join-Path $TargetRoot "requirements.txt"

    if (Test-Path $RequirementsFile) {
        pip install --quiet -r $RequirementsFile
        if ($LASTEXITCODE -eq 0) {
            Write-Host "[+] Dependencias instaladas correctamente" -ForegroundColor Green
        } else {
            Write-Host "[!] Hubo problemas al instalar algunas dependencias" -ForegroundColor Yellow
            Write-Host "    Intenta instalarlas manualmente: pip install -r $RequirementsFile" -ForegroundColor Yellow
        }
    }

    # Paso 7: Crear acceso directo en el Escritorio
    Write-Host "[*] Creando acceso directo en el Escritorio..." -ForegroundColor White

    $DesktopPath = [Environment]::GetFolderPath("Desktop")
    $ShortcutPath = Join-Path $DesktopPath "WinVulnScanner v1.3.lnk"
    $PythonExe = (Get-Command python).Source
    $MainScript = Join-Path $TargetRoot "main.py"

    try {
        $WshShell = New-Object -ComObject WScript.Shell
        $Shortcut = $WshShell.CreateShortcut($ShortcutPath)
        $Shortcut.TargetPath = $PythonExe
        $Shortcut.Arguments = """$MainScript"""
        $Shortcut.WorkingDirectory = $TargetRoot
        $Shortcut.Description = "WinVulnScanner v1.3 - Escáner de Vulnerabilidades"
        $Shortcut.IconLocation = "C:\Windows\System32\cmd.exe,0"
        $Shortcut.WindowStyle = 1
        $Shortcut.Save()

        Write-Host "[+] Acceso directo creado en el Escritorio" -ForegroundColor Green
        Write-Host "    Ubicación: $ShortcutPath" -ForegroundColor White
    } catch {
        Write-Host "[!] No se pudo crear el acceso directo (puede requerirse Admin)" -ForegroundColor Yellow
        Write-Host "    Pero la aplicación se puede ejecutar manualmente" -ForegroundColor Yellow
    }

    # Paso 8: Resumen final
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "  [OK] Instalación Completada" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Ubicación de instalación:" -ForegroundColor Cyan
    Write-Host "  $TargetRoot" -ForegroundColor White
    Write-Host ""
    Write-Host "Formas de ejecutar WinVulnScanner:" -ForegroundColor Cyan
    Write-Host "  1. Haz doble clic en el acceso directo del Escritorio" -ForegroundColor Yellow
    Write-Host "  2. Línea de comandos: python $TargetRoot\main.py" -ForegroundColor Yellow
    Write-Host "  3. PowerShell: & python ""$MainScript""" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Para acceder a la documentación:" -ForegroundColor Cyan
    Write-Host "  $TargetRoot\WinVulnScanner_v1.3_Documentacion_Azul.html" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Documentación completa (README):" -ForegroundColor Cyan
    Write-Host "  $TargetRoot\README.md" -ForegroundColor Yellow
    Write-Host ""

} catch {
    Write-Host "[ERROR] Algo salió mal durante la instalación:" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    exit 1
}
