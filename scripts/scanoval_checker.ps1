# ============================================================
#               ЗАПУСК ВНЕШНИХ ДИАГНОСТИЧЕСКИХ УТИЛИТ
# ============================================================
# Выполняет автоматический запуск ScanOval, USBDeview, HWInfo
# и WinAudit при их наличии, генерируя локальные отчеты.

$ErrorActionPreference = "Continue"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectDir = Split-Path -Parent $ScriptDir
$ReportDir = Join-Path $ProjectDir "report"
$ToolsDir = Join-Path $ProjectDir "tools"

# Проверка на запуск от имени Администратора
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Ошибка: Этот скрипт требует запуска от имени Администратора." -ForegroundColor Red
    Read-Host "Нажмите Enter для выхода..."
    Exit 1
}

if (-not (Test-Path $ReportDir)) { New-Item -ItemType Directory -Path $ReportDir -Force | Out-Null }

# Функция поиска утилиты по имени (в корне tools или подпапках)
function Find-Tool {
    param([string]$ExeName, [string]$SubFolder)
    $path1 = Join-Path $ToolsDir $ExeName
    if (Test-Path $path1) { return $path1 }
    
    $path2 = Join-Path (Join-Path $ToolsDir $SubFolder) $ExeName
    if (Test-Path $path2) { return $path2 }
    
    # Поиск по всей папке tools
    $found = Get-ChildItem -Path $ToolsDir -Filter $ExeName -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($found) { return $found.FullName }
    
    return $null
}

# 1. Запуск WinAudit
function Run-WinAudit {
    $exe = Find-Tool "WinAudit.exe" "winaudit"
    Write-Host "`n[1/4] Проверка WinAudit..." -ForegroundColor Cyan
    if ($exe) {
        $outFile = Join-Path $ReportDir "winaudit_report.html"
        Write-Host "Запуск WinAudit для сбора системного аудита (это может занять до 1-2 минут)..." -ForegroundColor Gray
        Write-Host "Файл отчета: $outFile" -ForegroundColor DarkGray
        
        # Запуск в фоновом режиме без GUI
        $p = Start-Process -FilePath $exe -ArgumentList "/r=gsoPxuTUeERNtnzDaIbMpmidcSArCOHG", "/o=HTMLi", "/f=`"$outFile`"" -NoNewWindow -PassThru -Wait
        if ($p.ExitCode -eq 0 -and (Test-Path $outFile)) {
            Write-Host "[Успешно] Отчет WinAudit сгенерирован!" -ForegroundColor Green
        } else {
            Write-Host "[Ошибка] WinAudit завершился с кодом $($p.ExitCode)" -ForegroundColor Red
        }
    } else {
        Write-Host "Пропущено: WinAudit.exe не найден в tools/." -ForegroundColor Yellow
    }
}

# 2. Запуск USBDeview
function Run-USBDeview {
    $exe = Find-Tool "usbdeview.exe" "usbdeview"
    Write-Host "`n[2/4] Проверка USBDeview..." -ForegroundColor Cyan
    if ($exe) {
        $outFile = Join-Path $ReportDir "usbdeview_report.html"
        Write-Host "Запуск USBDeview для экспорта истории подключений USB..." -ForegroundColor Gray
        
        $p = Start-Process -FilePath $exe -ArgumentList "/shtml", "`"$outFile`"" -NoNewWindow -PassThru -Wait
        if (Test-Path $outFile) {
            Write-Host "[Успешно] Отчет USBDeview сгенерирован!" -ForegroundColor Green
        } else {
            Write-Host "[Ошибка] USBDeview не создал файл отчета." -ForegroundColor Red
        }
    } else {
        Write-Host "Пропущено: usbdeview.exe не найден в tools/." -ForegroundColor Yellow
    }
}

# 3. Запуск HWInfo
function Run-HWInfo {
    $exe = Find-Tool "HWInfo64.exe" "hwinfo"
    if (-not $exe) { $exe = Find-Tool "HWInfo32.exe" "hwinfo" }
    
    Write-Host "`n[3/4] Проверка HWInfo..." -ForegroundColor Cyan
    if ($exe) {
        $outFile = Join-Path $ReportDir "hwinfo_report.txt"
        Write-Host "Запуск HWInfo для экспорта характеристик оборудования..." -ForegroundColor Gray
        
        # HWiNFO64 поддерживает ключ /log для тихого текстового экспорта в Pro-версии,
        # в бесплатной версии может открыться GUI. Запускаем с ожиданием.
        $p = Start-Process -FilePath $exe -ArgumentList "/log=`"$outFile`"" -NoNewWindow -PassThru -Wait
        if (Test-Path $outFile) {
            Write-Host "[Успешно] Отчет HWInfo сохранен в: $outFile" -ForegroundColor Green
        } else {
            Write-Host "[Информация] HWInfo запущен. Сформируйте текстовый отчет вручную через меню 'Report' и сохраните в папку report как hwinfo_report.txt" -ForegroundColor Yellow
        }
    } else {
        Write-Host "Пропущено: HWInfo64.exe не найден в tools/." -ForegroundColor Yellow
    }
}

# 4. Запуск ScanOval
function Run-ScanOval {
    $exe = Find-Tool "ScanOVAL.exe" "scanoval"
    Write-Host "`n[4/4] Проверка ScanOval..." -ForegroundColor Cyan
    if ($exe) {
        Write-Host "Запуск ScanOVAL (движка сканера уязвимостей ФСТЭК)..." -ForegroundColor Gray
        
        # Поиск OVAL-файла базы уязвимостей ФСТЭК в папке service
        $ovalFile = Get-ChildItem -Path (Join-Path $ProjectDir "service") -Filter "*.xml" | Where-Object { $_.Name -like "*oval*" -or $_.Name -like "*vulnerabilities*" } | Select-Object -First 1
        
        $outFileXml = Join-Path $ReportDir "scanoval_results.xml"
        $outFileHtml = Join-Path $ReportDir "scanoval_report.html"
        
        if ($ovalFile) {
            Write-Host "Обнаружена локальная OVAL-база: $($ovalFile.FullName)" -ForegroundColor Green
            Write-Host "Запуск сканирования с базой ФСТЭК..." -ForegroundColor Gray
            # Вызов ScanOVAL с базой. ScanOVAL CLI аргументы:
            # ScanOVAL.exe -o <oval-xml> -r <results-xml> -h <report-html>
            # Запускаем в фоновом режиме
            $p = Start-Process -FilePath $exe -ArgumentList "-o `"$($ovalFile.FullName)`"", "-r `"$outFileXml`"", "-h `"$outFileHtml`"" -NoNewWindow -PassThru -Wait
            if (Test-Path $outFileHtml) {
                Write-Host "[Успешно] Сканирование ScanOval завершено! Отчет: $outFileHtml" -ForegroundColor Green
            } else {
                Write-Host "[Информация] ScanOVAL запущен в интерактивном режиме. Загрузите базу $($ovalFile.Name) и выполните проверку вручную." -ForegroundColor Yellow
            }
        } else {
            Write-Host "ВНИМАНИЕ: База определений OVAL ФСТЭК (*.xml) не найдена в папке service/." -ForegroundColor Yellow
            Write-Host "Запуск интерфейса ScanOVAL для ручной работы..." -ForegroundColor Gray
            Start-Process -FilePath $exe
        }
    } else {
        Write-Host "Пропущено: ScanOVAL.exe не найден в tools/." -ForegroundColor Yellow
    }
}

# Выполнение проверок
Run-WinAudit
Run-USBDeview
Run-HWInfo
Run-ScanOval

Write-Host "`n=== Запуск внешних проверок завершен ===" -ForegroundColor Green
Write-Host "Сформированные отчеты доступны в каталоге: $ReportDir" -ForegroundColor Cyan
Read-Host "`nНажмите Enter для возврата в меню..."


