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
        "ScanOVAL.exe" = "ScanOval сканирование"
        "usbdeview.exe" = "USBDeview (анализ USB)"
        "HWInfo64.exe" = "HWInfo (сведения о железе)"
        "WinAudit.exe" = "WinAudit (системный аудит)"
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
            "Message" = "ВНИМАНИЕ: Отсутствуют утилиты диагностики: " + ($missing -join ", ") + "`nНастройте папку tools или запустите поиск во вкладке 'Инструменты' (пункт 4)."
        }
    } else {
        return @{
            "Status" = "OK"
            "Message" = "Все диагностические утилиты найдены в папке tools."
        }
    }
}

function Show-Header {
    Clear-Host
    Write-Host "========================================================================" -ForegroundColor Cyan
    Write-Host '                    АО НИИ "РУБИН" - Windows Security Checker           ' -ForegroundColor Cyan
    Write-Host "========================================================================" -ForegroundColor Cyan
    
    $dep = Get-DependenciesStatus
    if ($dep.Status -eq "Warning") {
        Write-Host $dep.Message -ForegroundColor Yellow
    } else {
        Write-Host $dep.Message -ForegroundColor Green
    }
    
    $szi = Get-ExpectedSzi
    $sziRus = switch ($szi) {
        "DallasLock" { "Dallas Lock" }
        "SNS" { "Secret Net Studio" }
        default { "Не выбрано (только средства ОС)" }
    }
    Write-Host "Целевое СЗИ для проверок соответствия: $sziRus" -ForegroundColor Gray
    Write-Host "------------------------------------------------------------------------" -ForegroundColor Cyan
}

function Run-Script {
    param([string]$ScriptName, [array]$ArgsList = @())
    $scriptPath = Join-Path $ScriptsDir $ScriptName
    if (-not (Test-Path $scriptPath)) {
        Write-Host "Ошибка: Скрипт $scriptPath не найден!" -ForegroundColor Red
        Read-Host "Нажмите Enter для возврата..."
        return
    }
    
    try {
        & $scriptPath @ArgsList
    } catch {
        Write-Host "Критическая ошибка при выполнении скрипта:`n$_" -ForegroundColor Red
        Read-Host "Нажмите Enter для продолжения..."
    }
}

# Основной цикл меню
while ($true) {
    Show-Header
    Write-Host "Выберите инструмент для запуска:"
    Write-Host "1) Аудит и СЗИ" -ForegroundColor Green
    Write-Host "2) Внешние утилиты (ScanOval, USBDeview, HWInfo, WinAudit)" -ForegroundColor Green
    Write-Host "3) Установка антивирусного ПО и выбор СЗИ" -ForegroundColor Green
    Write-Host "4) Инструменты (Менеджер зависимостей)" -ForegroundColor Green
    Write-Host "0) Выход" -ForegroundColor Red
    Write-Host "------------------------------------------------------------------------" -ForegroundColor Cyan
    
    $choice = Read-Host "Введите номер действия"
    
    switch ($choice) {
        "1" {
            Run-Script "security_checker.ps1"
        }
        "2" {
            Run-Script "scanoval_checker.ps1"
        }
        "3" {
            Run-Script "antivirus_installer.ps1"
        }
        "4" {
            Run-Script "repo_manager.ps1"
        }
        "0" {
            Write-Host "Завершение работы хаба управления..." -ForegroundColor Yellow
            Start-Sleep -Seconds 1
            break
        }
        default {
            Write-Host "Неверный выбор. Пожалуйста, введите число от 0 до 4." -ForegroundColor Red
            Start-Sleep -Seconds 1
        }
    }
}

