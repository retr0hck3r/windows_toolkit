# ============================================================
#       СКРИПТ ВЫБОРА СЗИ И ПРОВЕРКИ АНТИВИРУСНОГО ПО
# ============================================================
# Позволяет настраивать ожидаемое СЗИ (Dallas Lock / SNS)
# и контролирует состояние антивирусного ПО.

$ErrorActionPreference = "Continue"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectDir = Split-Path -Parent $ScriptDir
$ServiceDir = Join-Path $ProjectDir "service"
$SziConfigFile = Join-Path $ServiceDir "szi_settings.conf"

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

function Set-ExpectedSzi {
    param([string]$SziType)
    "ExpectedSZI=$SziType" | Out-File $SziConfigFile -Encoding utf8
    Write-Host "Целевое СЗИ установлено в: $SziType" -ForegroundColor Green
}

# Функция проверки антивирусной защиты и СЗИ в системе
function Test-SecuritySoftware {
    Write-Host "`n=== ПРОВЕРКА УСТАНОВЛЕННЫХ СЗИ И АНТИВИРУСОВ ===" -ForegroundColor Cyan
    
    # 1. Проверка Windows Defender
    $defenderService = Get-Service -Name "WinDefend" -ErrorAction SilentlyContinue
    Write-Host "- Windows Defender: " -NoNewline -ForegroundColor Gray
    if ($defenderService) {
        $statusColor = If ($defenderService.Status -eq "Running") { "Green" } else { "Yellow" }
        Write-Host "Служба $($defenderService.Name) находится в состоянии: $($defenderService.Status)" -ForegroundColor $statusColor
    } else {
        Write-Host "Не найден (отключен или удален)" -ForegroundColor Yellow
    }
    
    # 2. Поиск Kaspersky
    $kasperskyServices = Get-Service | Where-Object { $_.Name -like "*avp*" -or $_.DisplayName -like "*Kaspersky*" }
    Write-Host "- Kaspersky Endpoint Security: " -NoNewline -ForegroundColor Gray
    if ($kasperskyServices) {
        $runningCount = ($kasperskyServices | Where-Object { $_.Status -eq "Running" }).Count
        $statusColor = If ($runningCount -gt 0) { "Green" } else { "Yellow" }
        Write-Host "Найдено $($kasperskyServices.Count) служб ($runningCount запущено)" -ForegroundColor $statusColor
        foreach ($s in $kasperskyServices) {
            Write-Host "  * $($s.DisplayName) [$($s.Name)] - $($s.Status)" -ForegroundColor DarkGray
        }
    } else {
        Write-Host "Не обнаружен" -ForegroundColor Gray
    }
    
    # 3. Поиск Dr.Web
    $drwebServices = Get-Service | Where-Object { $_.Name -like "*drweb*" -or $_.DisplayName -like "*Dr.Web*" }
    Write-Host "- Dr.Web Security Space: " -NoNewline -ForegroundColor Gray
    if ($drwebServices) {
        $runningCount = ($drwebServices | Where-Object { $_.Status -eq "Running" }).Count
        $statusColor = If ($runningCount -gt 0) { "Green" } else { "Yellow" }
        Write-Host "Найдено $($drwebServices.Count) служб ($runningCount запущено)" -ForegroundColor $statusColor
        foreach ($s in $drwebServices) {
            Write-Host "  * $($s.DisplayName) [$($s.Name)] - $($s.Status)" -ForegroundColor DarkGray
        }
    } else {
        Write-Host "Не обнаружен" -ForegroundColor Gray
    }
    
    # 4. Поиск Dallas Lock
    $dlServices = Get-Service | Where-Object { $_.Name -like "Dl*" -or $_.DisplayName -like "*Dallas Lock*" }
    Write-Host "- Dallas Lock СЗИ: " -NoNewline -ForegroundColor Gray
    if ($dlServices) {
        $runningCount = ($dlServices | Where-Object { $_.Status -eq "Running" }).Count
        $statusColor = If ($runningCount -gt 0) { "Green" } else { "Yellow" }
        Write-Host "Найдено $($dlServices.Count) служб ($runningCount запущено)" -ForegroundColor $statusColor
        foreach ($s in $dlServices) {
            Write-Host "  * $($s.DisplayName) [$($s.Name)] - $($s.Status)" -ForegroundColor DarkGray
        }
    } else {
        Write-Host "Не обнаружен" -ForegroundColor Gray
    }
    
    # 5. Поиск Secret Net Studio
    $snsServices = Get-Service | Where-Object { $_.Name -like "sns*" -or $_.DisplayName -like "*Secret Net*" -or $_.DisplayName -like "*SecretNet*" }
    Write-Host "- Secret Net Studio СЗИ: " -NoNewline -ForegroundColor Gray
    if ($snsServices) {
        $runningCount = ($snsServices | Where-Object { $_.Status -eq "Running" }).Count
        $statusColor = If ($runningCount -gt 0) { "Green" } else { "Yellow" }
        Write-Host "Найдено $($snsServices.Count) служб ($runningCount запущено)" -ForegroundColor $statusColor
        foreach ($s in $snsServices) {
            Write-Host "  * $($s.DisplayName) [$($s.Name)] - $($s.Status)" -ForegroundColor DarkGray
        }
    } else {
        Write-Host "Не обнаружен" -ForegroundColor Gray
    }
}

# Функция сканирования съемных носителей на предмет установочных пакетов СЗИ/Антивирусов
function Scan-InstallPackages {
    Write-Host "`n=== ПОИСК УСТАНОВОЧНЫХ ПАКЕТОВ НА СЪЕМНЫХ НОСИТЕЛЯХ ===" -ForegroundColor Cyan
    $drives = Get-Volume | Where-Object { $_.DriveType -eq 'CD-ROM' -or $_.DriveType -eq 'Removable' }
    
    if (-not $drives) {
        Write-Host "Съемные диски (флешки, CD-ROM) не обнаружены." -ForegroundColor Yellow
        return
    }
    
    $masks = @("kes*.exe", "kes*.msi", "drweb*.exe", "dl*.exe", "dl*.msi", "sns*.exe", "sns*.msi", "secretnet*.exe", "secretnet*.msi")
    $foundCount = 0
    
    foreach ($drive in $drives) {
        $driveLetter = $drive.DriveLetter
        if (-not $driveLetter) { continue }
        $drivePath = "${driveLetter}:\"
        Write-Host "Поиск на диске $drivePath ..." -ForegroundColor Gray
        
        foreach ($mask in $masks) {
            $files = Get-ChildItem -Path $drivePath -Filter $mask -Recurse -File -ErrorAction SilentlyContinue
            foreach ($file in $files) {
                Write-Host "  [+] Найдено: $($file.Name)" -ForegroundColor Green
                Write-Host "      Путь: $($file.FullName)" -ForegroundColor DarkGray
                $foundCount++
            }
        }
    }
    
    if ($foundCount -eq 0) {
        Write-Host "Установочные пакеты СЗИ или антивирусов не найдены." -ForegroundColor Gray
    } else {
        Write-Host "Всего найдено пакетов: $foundCount" -ForegroundColor Green
    }
}

# Подгрузка TUI модуля
$tuiHelper = Join-Path $ServiceDir "tui_helper.ps1"
if (Test-Path $tuiHelper) { . $tuiHelper }

# Меню выбора и проверок
:avMenuLoop while ($true) {
    $expectedSzi = Get-ExpectedSzi
    $sziName = switch ($expectedSzi) {
        "DallasLock" { "Dallas Lock" }
        "SNS" { "Secret Net Studio" }
        default { "Не выбрано (только средства ОС)" }
    }
    
    $title = "АНТИВИРУСНОЕ ПО И СИСТЕМЫ ЗАЩИТЫ (СЗИ)"
    $subtitle = "Текущий выбор целевого СЗИ: $sziName"
    
    $options = @(
        "Выбрать СЗИ Dallas Lock",
        "Выбрать СЗИ Secret Net Studio",
        "Сбросить выбор СЗИ (проверять только настройки ОС)",
        "Проверить статус активных защитных систем в ОС",
        "Найти установочные пакеты на флешках",
        "Назад в главное меню"
    )
    
    $choice = Show-TuiMenu -Title $title -Subtitle $subtitle -Options $options
    
    switch ($choice) {
        0 {
            Set-ExpectedSzi "DallasLock"
            Start-Sleep -Seconds 1
        }
        1 {
            Set-ExpectedSzi "SNS"
            Start-Sleep -Seconds 1
        }
        2 {
            Set-ExpectedSzi "None"
            Start-Sleep -Seconds 1
        }
        3 {
            Test-SecuritySoftware
            Read-Host "`nНажмите Enter для продолжения..."
        }
        4 {
            Scan-InstallPackages
            Read-Host "`nНажмите Enter для продолжения..."
        }
        5 {
            break avMenuLoop
        }
        -1 {
            break avMenuLoop
        }
    }
}



