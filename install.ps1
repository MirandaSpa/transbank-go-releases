# Instala o reinstala el agente Transbank en esta caja, desde los releases
# publicos de MirandaSpa/transbank-go-releases.
#
# Se corre en PowerShell normal (no como administrador), con el usuario de
# Windows de la caja. Solo la carpeta y su exclusion del antivirus piden
# permiso de administrador (UAC).
#
#   & ([scriptblock]::Create((irm https://raw.githubusercontent.com/MirandaSpa/transbank-go-releases/main/install.ps1)))
#
# Con parametros, por ejemplo una caja del canal beta:
#
#   & ([scriptblock]::Create((irm https://raw.githubusercontent.com/MirandaSpa/transbank-go-releases/main/install.ps1))) -Canal beta
#
# O con doble clic en instalar-estable.cmd o instalar-beta.cmd (publicados
# junto a este script).
#
# No usar "irm ... | iex": Invoke-Expression no acepta el bloque param.
#
# Confianza: el .exe se comprueba contra el SHA-256 del manifiesto, que esta en
# el mismo repo que este script; la firma ed25519 la comprueba el agente en
# cada actualizacion. Por eso solo el pipeline de release debe poder escribir
# en ese repo.
#
# El texto va sin tildes a proposito: Windows PowerShell 5.1 lee un .ps1 sin
# BOM como ANSI.

[CmdletBinding()]
param(
    # Canal de actualizaciones: estable o beta. Si no se indica, se mantiene
    # el que tenga la caja, o estable si es nueva.
    [string]$Canal = '',
    # Carpeta del agente.
    [string]$Carpeta = 'C:\Transbank\agente',
    # No agrega la exclusion de Windows Defender.
    [switch]$SinExclusion,
    # No crea los accesos directos del escritorio y de Inicio.
    [switch]$SinAccesos,
    # No abre el agente al terminar.
    [switch]$NoAbrir,
    # Permite correrlo como administrador.
    [switch]$PermitirAdmin,
    # Instala aunque el Control inteligente de aplicaciones este activado.
    [switch]$IgnorarControlInteligente
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

if ($Canal -ne '' -and $Canal -notin @('estable', 'beta')) {
    throw "Canal no valido: '$Canal'. Usa estable o beta."
}
$Repo = 'MirandaSpa/transbank-go-releases'
$Carpeta = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Carpeta).TrimEnd('\')
$Exe = Join-Path $Carpeta 'transbank.exe'
$ConfigDir = Join-Path $env:APPDATA 'repuestos_miranda\transbank'
$ConfigPath = Join-Path $ConfigDir 'config.json'
$Puerto = 3000

function Write-Paso([string]$Texto) { Write-Host "-> $Texto" -ForegroundColor Cyan }

function Read-Config {
    if (-not (Test-Path $ConfigPath)) { return [pscustomobject]@{} }
    $texto = [IO.File]::ReadAllText($ConfigPath)
    if ($texto.Trim() -eq '') { return [pscustomobject]@{} }
    try {
        return $texto | ConvertFrom-Json
    } catch {
        throw "$ConfigPath no es un JSON valido. Corrigelo o borralo y vuelve a correr el script."
    }
}

# El agente lee config.json con Go, que no acepta el BOM: UTF-8 sin BOM.
function Save-Config($Config) {
    New-Item -ItemType Directory -Force $ConfigDir | Out-Null
    $json = $Config | ConvertTo-Json -Depth 10
    [IO.File]::WriteAllText($ConfigPath, $json, (New-Object Text.UTF8Encoding($false)))
}

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# El programa que usa el puerto 3000, si no es este agente: el POS antiguo
# (posintegrado.exe, Node) u otro. Los dos no pueden atender a la caja.
function Get-OcupaPuerto {
    $conexiones = @(Get-NetTCPConnection -LocalPort $Puerto -State Listen -ErrorAction SilentlyContinue)
    foreach ($c in $conexiones) {
        $p = Get-CimInstance Win32_Process -Filter "ProcessId = $($c.OwningProcess)" -ErrorAction SilentlyContinue
        if ($p -and $p.ExecutablePath -ne $Exe) { $p }
    }
}

# Accesos directos de Inicio que abren el POS antiguo al encender.
function Get-InicioAntiguo {
    $shell = New-Object -ComObject WScript.Shell
    $dirs = @([Environment]::GetFolderPath('Startup'), [Environment]::GetFolderPath('CommonStartup'))
    foreach ($dir in $dirs) {
        Get-ChildItem $dir -Filter *.lnk -ErrorAction SilentlyContinue | Where-Object {
            $l = $shell.CreateShortcut($_.FullName)
            $destino = "$($l.TargetPath) $($l.Arguments) $($l.WorkingDirectory)"
            $l.TargetPath -ne $Exe -and $destino -match 'posintegrado|pos-client|PostIntegrado|\\Pos\\|pos\.exe'
        }
    }
}

if ((Test-Admin) -and -not $PermitirAdmin) {
    throw 'Corre esto sin "Ejecutar como administrador", con la sesion de la caja: el permiso de administrador se pide cuando hace falta.'
}

# 1. El POS antiguo abierto: se cierra a mano antes de seguir (ocupa el puerto
# 3000 y el puerto COM del POS).
$otros = @(Get-OcupaPuerto)
if ($otros.Count -gt 0) {
    $lista = ($otros | ForEach-Object { "  - $($_.Name) (PID $($_.ProcessId)) $($_.ExecutablePath)" }) -join "`n"
    throw "Otro programa usa el puerto $Puerto (probablemente el POS antiguo). Cierralo, quitalo del inicio de Windows y vuelve a correr el script:`n$lista"
}

# 1b. Control inteligente de aplicaciones (Windows 11): bloquea programas sin
# firma de codigo que Microsoft no conoce, y cada version del agente es un
# .exe nuevo. Desactivarlo lo decide una persona, no este script.
$control = $null
try { $control = (Get-MpComputerStatus).SmartAppControlState } catch { }
if ($control -in @('On', 'Eval') -and -not $IgnorarControlInteligente) {
    $estado = if ($control -eq 'On') { 'activado' } else { 'en evaluacion (puede activarse solo mas adelante)' }
    throw ("El Control inteligente de aplicaciones de Windows esta $estado y bloquearia el agente en cada actualizacion. No se instalo nada.`n" +
        "Desactivalo y vuelve a correr el instalador:`n" +
        "  1. Seguridad de Windows > Control de aplicaciones y navegador > Configuracion de Control inteligente de aplicaciones.`n" +
        "  2. Elige Desactivado.")
}

# 2. El canal: el indicado, o el que ya tenga la caja.
$config = Read-Config
if ($Canal -eq '') {
    $Canal = 'estable'
    if ($config.PSObject.Properties['canal'] -and $config.canal -eq 'beta') { $Canal = 'beta' }
}
Write-Paso "Canal: $Canal"

# 3. La ultima version del canal, comprobada con el SHA-256 del manifiesto.
try {
    $manifest = Invoke-RestMethod "https://raw.githubusercontent.com/$Repo/main/$Canal/manifest.json" -UseBasicParsing
} catch {
    if ($_.Exception.Response -and [int]$_.Exception.Response.StatusCode -eq 404) {
        throw "Aun no hay versiones publicadas en el canal $Canal. No se instalo nada."
    }
    throw "No se pudo consultar la ultima version ($($_.Exception.Message)). Revisa la conexion a internet."
}
$version = '^v\d+\.\d+\.\d+(-[0-9A-Za-z.]+)?$'
$url = '^https://github\.com/MirandaSpa/transbank-go-releases/releases/download/v[0-9A-Za-z.\-]+/transbank_go-v[0-9A-Za-z.\-]+\.exe$'
if ("$($manifest.version)" -notmatch $version -or "$($manifest.url)" -notmatch $url -or "$($manifest.url)" -match '\.\.' -or "$($manifest.sha256)" -notmatch '^[0-9a-f]{64}$') {
    throw "El manifiesto del canal $Canal no es valido. No se instalo nada."
}
Write-Paso "Descargando $($manifest.version)"
$descarga = Join-Path $env:TEMP "transbank-$($manifest.version).exe"
Invoke-WebRequest $manifest.url -OutFile $descarga -UseBasicParsing
$sha = (Get-FileHash $descarga -Algorithm SHA256).Hash.ToLower()
if ($sha -ne $manifest.sha256) {
    Remove-Item $descarga -Force
    throw "El archivo descargado no es el publicado (SHA-256 distinto). No se instalo nada."
}

# 4. La carpeta, solo escribible por este usuario y los administradores, y su
# exclusion del antivirus: el agente se reemplaza a si mismo al actualizarse.
if (-not $SinExclusion) {
    Write-Paso "Preparando $Carpeta y su exclusion de Windows Defender (pide permiso de administrador)"
    $usuario = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $c = [Management.Automation.Language.CodeGeneration]::EscapeSingleQuotedStringContent($Carpeta)
    $comando = "try { " +
        "New-Item -ItemType Directory -Force '$c' | Out-Null; " +
        "& icacls.exe '$c' /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*$($usuario):(OI)(CI)M' | Out-Null; " +
        "if (`$LASTEXITCODE -ne 0) { exit 2 }; " +
        "Add-MpPreference -ExclusionPath '$c' -ErrorAction Stop; exit 0 } catch { exit 1 }"
    $codificado = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($comando))
    try {
        $p = Start-Process powershell -Verb RunAs -Wait -PassThru -WindowStyle Hidden `
            -ArgumentList '-NoProfile', '-EncodedCommand', $codificado
    } catch {
        Remove-Item $descarga -Force
        throw "No se dio el permiso de administrador. No se instalo nada; vuelve a correr el script y acepta el aviso de Windows."
    }
    if ($p.ExitCode -ne 0) {
        Remove-Item $descarga -Force
        if ($p.ExitCode -eq 2) { throw "No se pudieron fijar los permisos de $Carpeta. No se instalo nada." }
        throw "No se pudo excluir $Carpeta de Windows Defender. Si la caja usa otro antivirus, excluye la carpeta en el y vuelve a correr con -SinExclusion."
    }
} else {
    New-Item -ItemType Directory -Force $Carpeta | Out-Null
}

# 5. El .exe: se cierra este agente si esta abierto y se aparta el anterior
# como .old (Windows deja renombrar un .exe en uso, no sobrescribirlo).
$abiertos = @(Get-Process transbank -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $Exe })
if ($abiertos.Count -gt 0) {
    Write-Paso 'Cerrando el agente abierto'
    $abiertos | Stop-Process -Force
    $abiertos | Wait-Process -Timeout 10 -ErrorAction SilentlyContinue
}
try {
    if (Test-Path $Exe) { Move-Item $Exe "$Exe.old" -Force }
    Move-Item $descarga $Exe -Force
} catch {
    throw "No se pudo reemplazar $Exe ($($_.Exception.Message)). Cierra el agente y vuelve a correr el script."
}
Unblock-File $Exe
Remove-Item "$Exe.new" -Force -ErrorAction SilentlyContinue
Write-Paso "Instalado $Exe ($($manifest.version))"

# 6. El canal en config.json, sin tocar lo demas (puerto recordado).
$config = Read-Config
$config | Add-Member -NotePropertyName canal -NotePropertyValue $Canal -Force
Save-Config $config

# 7. Accesos directos: escritorio, e Inicio para que abra al encender.
if (-not $SinAccesos) {
    $shell = New-Object -ComObject WScript.Shell
    foreach ($dir in @([Environment]::GetFolderPath('Desktop'), [Environment]::GetFolderPath('Startup'))) {
        $acceso = $shell.CreateShortcut((Join-Path $dir 'Agente Transbank.lnk'))
        $acceso.TargetPath = $Exe
        $acceso.WorkingDirectory = $Carpeta
        $acceso.Save()
    }
    Write-Paso 'Accesos directos en el escritorio y en Inicio'
}
$antiguos = @(Get-InicioAntiguo)
if ($antiguos.Count -gt 0) {
    Write-Warning ("Estos accesos de Inicio abren el POS antiguo al encender; quitalos o el agente no podra abrir el puerto ${Puerto}:`n" +
        (($antiguos | ForEach-Object { "  - $($_.FullName)" }) -join "`n"))
}

# 8. Abrir el agente: busca el POS solo.
if (-not $NoAbrir) {
    Start-Process $Exe -WorkingDirectory $Carpeta
}
Write-Host "Listo: agente Transbank $($manifest.version), canal $Canal." -ForegroundColor Green
