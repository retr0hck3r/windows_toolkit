# ============================================================
#               ГЛАВНЫЙ ЦЕНТРАЛИЗОВАННЫЙ ХАБ УПРАВЛЕНИЯ (WINDOWS)
# ============================================================
# Позволяет запускать аудит безопасности, СЗИ-проверки и внешние сканеры.

$ErrorActionPreference = "Stop"

# Проверка на запуск от имени Администратора
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Ошибка: Этот скрипт должен быть запущен от имени Администратора." -ForegroundColor Red
    Read-Host "Нажмите Enter для выхода..."
    Exit 1
}

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ScriptsDir = Join-Path $ScriptDir "scripts"
$ServiceDir = Join-Path $ScriptDir "service"
$ReportDir = Join-Path $ScriptDir "report"
$ToolsDir = Join-Path $ScriptDir "tools"

# Создание необходимых папок
foreach ($dir in @($ScriptsDir, $ServiceDir, $ReportDir, $ToolsDir)) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
}

# Подгрузка TUI модуля
$tuiHelper = Join-Path $ServiceDir "tui_helper.ps1"
if (Test-Path $tuiHelper) {
    . $tuiHelper
} else {
    Write-Host "Ошибка: Файл $tuiHelper не найден!" -ForegroundColor Red
    Read-Host "Нажмите Enter для выхода..."
    Exit 1
}

# Файл настроек СЗИ по умолчанию
$SziConfigFile = Join-Path $ServiceDir "szi_settings.conf"
if (-not (Test-Path $SziConfigFile)) {
    "ExpectedSZI=None" | Out-File $SziConfigFile -Encoding utf8
}

function Get-ExpectedSzi {
    if (Test-Path $SziConfigFile) {
        $content = Get-Content $SziConfigFile -ErrorAction SilentlyContinue
        foreach ($line in $content) {
            if ($line -match "ExpectedSZI=(.*)") {
                return $Matches[1].Trim()
            }
        }
    }
    return "None"
}

# Проверка наличия утилит
function Get-DependenciesStatus {
    $missing = @()
    $tools = @{
        "ScanOVAL.exe" = "ScanOval"
        "usbdeview.exe" = "USBDeview"
        "HWInfo64.exe" = "HWInfo"
        "WinAudit.exe" = "WinAudit"
    }
    
    foreach ($tool in $tools.Keys) {
        $path1 = Join-Path $ToolsDir $tool
        $path2 = Join-Path (Join-Path $ToolsDir ($tool -replace '\.exe$','')) $tool
        if (-not (Test-Path $path1) -and -not (Test-Path $path2)) {
            $missing += $tools[$tool]
        }
    }
    
    if ($missing.Count -gt 0) {
        return @{
            "Status" = "Warning"
            "Message" = "ВНИМАНИЕ: Отсутствуют утилиты: " + ($missing -join ", ") + " (Пункт 4 -> Установка)"
        }
    } else {
        return @{
            "Status" = "OK"
            "Message" = "Все утилиты диагностики обнаружены в tools/."
        }
    }
}

function Run-Script {
    param([string]$ScriptName, [array]$ArgsList = @())
    $scriptPath = Join-Path $ScriptsDir $ScriptName
    if (-not (Test-Path $scriptPath)) {
        Show-TuiMessage -Title "Ошибка" -Message "Скрипт $scriptPath не найден!"
        return
    }
    
    try {
        & $scriptPath @ArgsList
    } catch {
        Show-TuiMessage -Title "Критическая ошибка" -Message "Ошибка при выполнении скрипта $ScriptName :`n`n$_"
    }
}

# Основной цикл меню
while ($true) {
    $dep = Get-DependenciesStatus
    $szi = Get-ExpectedSzi
    $sziRus = switch ($szi) {
        "DallasLock" { "Dallas Lock" }
        "SNS" { "Secret Net Studio" }
        default { "Не выбрано (только средства ОС)" }
    }
    
    $title = "АО НИИ 'РУБИН' - Windows Security Checker"
    $subtitle = "Статус: $($dep.Message)`n  Целевое СЗИ для проверок соответствия: $sziRus"
    
    $options = @(
        "Аудит и СЗИ (политики ФСТЭК, реестр USB, аудит ПО)",
        "Внешние утилиты (ScanOval, USBDeview, HWInfo, WinAudit)",
        "Установка антивирусного ПО и выбор СЗИ",
        "Инструменты (Менеджер зависимостей)",
        "Выход"
    )
    
    $choice = Show-TuiMenu -Title $title -Subtitle $subtitle -Options $options
    
    switch ($choice) {
        0 { Run-Script "security_checker.ps1" }
        1 { Run-Script "scanoval_checker.ps1" }
        2 { Run-Script "antivirus_installer.ps1" }
        3 { Run-Script "repo_manager.ps1" }
        4 {
            Write-Host "`nЗавершение работы хаба управления..." -ForegroundColor Yellow
            Start-Sleep -Seconds 1
            break
        }
        -1 {
            Write-Host "`nЗавершение работы хаба управления..." -ForegroundColor Yellow
            Start-Sleep -Seconds 1
            break
        }
    }
}

