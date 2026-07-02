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

if (Test-Path $ReportDir) {
    # Удаляем предыдущие отчеты внешних утилит, чтобы старые результаты не отображались, если утилиты будут пропущены в текущем запуске
    $filesToClear = @("winaudit_report.html", "usbdeview_report.html", "hwinfo_report.txt", "scanoval_report.html", "scanoval_results.xml")
    foreach ($file in $filesToClear) {
        $filePath = Join-Path $ReportDir $file
        if (Test-Path $filePath) { Remove-Item $filePath -Force | Out-Null }
    }
} else {
    New-Item -ItemType Directory -Path $ReportDir -Force | Out-Null
}

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
        
        # Прямой запуск через оператор & для наследования привилегий и работы в одной консоли
        & $exe "/r=gsoPxuTUeERNtnzDaIbMpmidcSArCOHG" "/o=HTMLi" "/f=$outFile"
        if (Test-Path $outFile) {
            Write-Host "[Успешно] Отчет WinAudit сгенерирован!" -ForegroundColor Green
        } else {
            Write-Host "[Ошибка] WinAudit не создал файл отчета." -ForegroundColor Red
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
        
        & $exe /shtml "$outFile"
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
    $outFile = Join-Path $ReportDir "hwinfo_report.txt"
    
    if ($exe) {
        Write-Host "Запуск HWInfo для экспорта характеристик оборудования..." -ForegroundColor Gray
        Write-Host "ВНИМАНИЕ: Если используется бесплатная версия HWInfo, откроется GUI (требуется версия Pro для тихого сбора)." -ForegroundColor Yellow
        Write-Host "Вы можете сохранить отчет вручную через меню 'Report -> Save Report -> Short Text' в папку report как 'hwinfo_report.txt'." -ForegroundColor Yellow
        Write-Host "Или просто закройте программу, и скрипт автоматически соберет данные средствами ОС." -ForegroundColor Yellow
        
        try {
            & $exe "/log=$outFile"
        } catch {
            Write-Host "Не удалось запустить HWInfo автоматически." -ForegroundColor Yellow
        }
    } else {
        Write-Host "Пропущено: HWInfo64.exe не найден в tools/." -ForegroundColor Yellow
    }
    
    # Резервный сбор информации об оборудовании средствами Windows, если файл отчета не был создан
    if (-not (Test-Path $outFile)) {
        Write-Host "Генерация резервного отчета об оборудовании средствами ОС..." -ForegroundColor Gray
        try {
            $cpuInfo = Get-CimInstance Win32_Processor | Select-Object Name, Manufacturer, NumberOfCores, NumberOfLogicalProcessors
            $biosInfo = Get-CimInstance Win32_Bios | Select-Object Manufacturer, Name, Version, ReleaseDate
            $compInfo = Get-CimInstance Win32_ComputerSystem | Select-Object Manufacturer, Model, TotalPhysicalMemory
            $osInfo = Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, OSArchitecture
            $diskInfo = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" | Select-Object DeviceID, VolumeName, Size, FreeSpace
            $gpuInfo = Get-CimInstance Win32_VideoController | Select-Object Name, DriverVersion
            $netInfo = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True" | Select-Object Description, MACAddress, IPAddress
            
            $hwReport = @(
                "============================================================",
                "   РЕЗЕРВНЫЙ ОТЧЕТ ОБ ОБОРУДОВАНИИ (ОС WINDOWS)",
                "============================================================",
                "Сгенерировано автоматически: $(Get-Date -Format 'dd.MM.yyyy HH:mm:ss')",
                "",
                "[Операционная система]",
                "  Название: $($osInfo.Caption)",
                "  Версия: $($osInfo.Version)",
                "  Архитектура: $($osInfo.OSArchitecture)",
                "",
                "[Материнская плата и Система]",
                "  Производитель: $($compInfo.Manufacturer)",
                "  Модель: $($compInfo.Model)",
                "  BIOS Производитель: $($biosInfo.Manufacturer)",
                "  BIOS Версия: $($biosInfo.Version)",
                "  BIOS Дата выпуска: $($biosInfo.ReleaseDate)",
                "",
                "[Процессор (CPU)]",
                "  Модель: $($cpuInfo.Name)",
                "  Производитель: $($cpuInfo.Manufacturer)",
                "  Физических ядер: $($cpuInfo.NumberOfCores)",
                "  Логических процессоров: $($cpuInfo.NumberOfLogicalProcessors)",
                "",
                "[Оперативная память (RAM)]",
                "  Общий объем: $([Math]::Round($compInfo.TotalPhysicalMemory / 1GB, 2)) ГБ",
                "",
                "[Видеокарта (GPU)]",
                "  Модель: $($gpuInfo.Name)",
                "  Версия драйвера: $($gpuInfo.DriverVersion)",
                "",
                "[Накопители (Диски)]"
            )
            
            foreach ($disk in $diskInfo) {
                $sizeGb = [Math]::Round($disk.Size / 1GB, 2)
                $freeGb = [Math]::Round($disk.FreeSpace / 1GB, 2)
                $hwReport += "  Диск $($disk.DeviceID) ($($disk.VolumeName)) - Всего: $sizeGb ГБ, Свободно: $freeGb ГБ"
            }
            
            $hwReport += ""
            $hwReport += "[Сетевые адаптеры]"
            foreach ($net in $netInfo) {
                $ips = $net.IPAddress -join ", "
                $hwReport += "  Адаптер: $($net.Description)"
                $hwReport += "    MAC-адрес: $($net.MACAddress)"
                $hwReport += "    IP-адрес: $ips"
            }
            
            $hwReport | Out-File -FilePath $outFile -Encoding utf8
            Write-Host "[Успешно] Резервный отчет об оборудовании сохранен в: $outFile" -ForegroundColor Green
        } catch {
            Write-Host "Не удалось создать резервный отчет об оборудовании: $($_.Exception.Message)" -ForegroundColor Red
        }
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
            
            # Прямой вызов ScanOVAL с наследованием админ-прав
            & $exe -o "$($ovalFile.FullName)" -r "$outFileXml" -h "$outFileHtml"
            if (Test-Path $outFileHtml) {
                Write-Host "[Успешно] Сканирование ScanOval завершено! Отчет: $outFileHtml" -ForegroundColor Green
            } else {
                Write-Host "[Информация] ScanOVAL запущен в интерактивном режиме. Загрузите базу $($ovalFile.Name) и выполните проверку вручную." -ForegroundColor Yellow
            }
        } else {
            Write-Host "ВНИМАНИЕ: База определений OVAL ФСТЭК (*.xml) не найдена в папке service/." -ForegroundColor Yellow
            Write-Host "Запуск интерфейса ScanOVAL для ручной работы..." -ForegroundColor Gray
            & $exe
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



