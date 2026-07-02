# ============================================================
#               СКРИПТ АУДИТА БЕЗОПАСНОСТИ И КОМПЛАЕНСА
# ============================================================
# Считывает требования из compliance_standards.conf,
# опрашивает параметры системы, СЗИ и реестр USB,
# формирует отчеты в текстовом и HTML форматах.

$ErrorActionPreference = "Continue"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectDir = Split-Path -Parent $ScriptDir
$ServiceDir = Join-Path $ProjectDir "service"
$ReportDir = Join-Path $ProjectDir "report"
$SziConfigFile = Join-Path $ServiceDir "szi_settings.conf"
$StandardsFile = Join-Path $ServiceDir "compliance_standards.conf"

$SoftwareDir = Join-Path $ReportDir "software"
$ComplianceDir = Join-Path $ReportDir "compliance"

# Очистка предыдущих результатов комплаенса и списков ПО перед новым сканированием
if (Test-Path $ReportDir) {
    $oldSoftware = Join-Path $SoftwareDir "installed_software.txt"
    if (Test-Path $oldSoftware) { Remove-Item $oldSoftware -Force | Out-Null }
    
    $oldMainReport = Join-Path $ReportDir "security_report.html"
    if (Test-Path $oldMainReport) { Remove-Item $oldMainReport -Force | Out-Null }
    
    if (Test-Path $ComplianceDir) {
        Get-ChildItem -Path $ComplianceDir -Filter "compliance_report_*.txt" -ErrorAction SilentlyContinue | Remove-Item -Force | Out-Null
    }
}

# Функция парсинга INI-файла стандартов
function Get-ComplianceStandards {
    param([string]$FilePath, [string]$Section)
    $standards = @{
        req_len = 6
        req_hist = 0
        req_max_days = 180
        req_deny = 5
        req_unlock_time = 300
        req_tmout = 1800
        req_secdel = "optional"
        req_swap = "optional"
        req_console = "optional"
        req_ptrace = "optional"
        req_interpreters = "optional"
        req_audit = "optional"
    }
    
    if (-not (Test-Path $FilePath)) {
        return $standards
    }
    
    $currentSection = "Default"
    $lines = Get-Content $FilePath
    foreach ($line in $lines) {
        $trimmed = $line.Trim()
        if ($trimmed -match "^\[(.*)\]$") {
            $currentSection = $Matches[1].Trim()
        } elseif ($currentSection -eq $Section -and $trimmed -match "^([^#=]+)=(.*)$") {
            $key = $Matches[1].Trim()
            $value = $Matches[2].Trim()
            $value = $value -replace "^['`"]|['`"]$" # Снимаем кавычки
            $standards[$key] = $value
        }
    }
    return $standards
}

# Подгрузка TUI модуля
$tuiHelper = Join-Path $ServiceDir "tui_helper.ps1"
if (Test-Path $tuiHelper) { . $tuiHelper }

# Выбор класса защищенности
function Choose-SecurityClass {
    $classes = @("3Б", "2Б", "1Д", "1Г", "3А", "2А", "1В", "1Б", "1А")
    $options = @()
    foreach ($c in $classes) { $options += "Класс $c" }
    $options += "Назад"
    
    $choice = Show-TuiMenu -Title "ВЫБОР КЛАССА ЗАЩИЩЕННОСТИ АС" -Subtitle "Выберите целевой класс защищенности информационной системы для аудита:" -Options $options
    
    if ($choice -eq -1 -or $choice -eq $classes.Count) {
        return $null
    }
    return $classes[$choice]
}

# Основная процедура аудита
$targetClass = Choose-SecurityClass
if (-not $targetClass) { return }

Write-Host "`nИнициализация проверки для класса $targetClass..." -ForegroundColor Green
$std = Get-ComplianceStandards $StandardsFile $targetClass

# Сбор настроек безопасности (secedit)
Write-Host "Сбор политик учетных записей..." -ForegroundColor Gray
$secCfgPath = Join-Path $env:TEMP "local_sec_audit.cfg"
if (Test-Path $secCfgPath) { Remove-Item $secCfgPath -Force }

# Экспорт настроек secedit
$proc = Start-Process -FilePath "secedit.exe" -ArgumentList "/export /cfg `"$secCfgPath`" /areas SECURITYPOLICY" -NoNewWindow -PassThru -Wait
$secPolicy = @{}
if (Test-Path $secCfgPath) {
    $content = Get-Content $secCfgPath
    foreach ($line in $content) {
        $trimmed = $line.Trim()
        if ($trimmed -match "^([a-zA-Z0-9_]+)\s*=\s*(.*)$") {
            $key = $Matches[1].Trim()
            $val = $Matches[2].Trim()
            $secPolicy[$key] = $val
        }
    }
    Remove-Item $secCfgPath -Force
}

# fallback к ADSI, если secedit не дал результатов
$adsi = [ADSI]"WinNT://$env:COMPUTERNAME"

$cur_len = If ($secPolicy.ContainsKey("MinimumPasswordLength")) { [int]$secPolicy["MinimumPasswordLength"] } else { $adsi.MinPasswordLength[0] }
$cur_hist = If ($secPolicy.ContainsKey("PasswordHistorySize")) { [int]$secPolicy["PasswordHistorySize"] } else { $adsi.PasswordHistoryLength[0] }
$cur_max_days = If ($secPolicy.ContainsKey("MaximumPasswordAge")) { 
    $val = [int]$secPolicy["MaximumPasswordAge"]
    if ($val -eq -1) { 9999 } else { $val }
} else { 
    [int]($adsi.MaxPasswordAge[0] / 86400) 
}
$cur_deny = If ($secPolicy.ContainsKey("LockoutBadCount")) { [int]$secPolicy["LockoutBadCount"] } else { 0 }
$cur_unlock_time = If ($secPolicy.ContainsKey("LockoutDuration")) { [int]$secPolicy["LockoutDuration"] * 60 } else { 0 }

# Таймаут сессии (InactivityTimeoutSecs)
Write-Host "Проверка таймаутов сессии..." -ForegroundColor Gray
$regSystemPolicy = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
$cur_tmout = 0
if (Test-Path $regSystemPolicy) {
    $val = (Get-ItemProperty -Path $regSystemPolicy -Name "InactivityTimeoutSecs" -ErrorAction SilentlyContinue).InactivityTimeoutSecs
    if ($val) { $cur_tmout = [int]$val }
}
# Проверка screensaver, если системный таймаут не задан
if ($cur_tmout -eq 0) {
    $scrActive = (Get-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaveActive" -ErrorAction SilentlyContinue).ScreenSaveActive
    $scrTimeout = (Get-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaveTimeOut" -ErrorAction SilentlyContinue).ScreenSaveTimeOut
    if ($scrActive -eq "1" -and $scrTimeout) {
        $cur_tmout = [int]$scrTimeout
    }
}

# Очистка Swap/Pagefile
Write-Host "Проверка очистки файла подкачки..." -ForegroundColor Gray
$regMemMan = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
$clearPageFile = 0
if (Test-Path $regMemMan) {
    $val = (Get-ItemProperty -Path $regMemMan -Name "ClearPageFileAtShutdown" -ErrorAction SilentlyContinue).ClearPageFileAtShutdown
    if ($val) { $clearPageFile = [int]$val }
}
$cur_swap = If ($clearPageFile -eq 1) { "Включен" } else { "Выключен" }

# Защита процессов LSA (ptrace аналог)
Write-Host "Проверка защиты процессов LSA..." -ForegroundColor Gray
$regLsa = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$runAsPPL = 0
if (Test-Path $regLsa) {
    $val = (Get-ItemProperty -Path $regLsa -Name "RunAsPPL" -ErrorAction SilentlyContinue).RunAsPPL
    if ($val) { $runAsPPL = [int]$val }
}
$cur_ptrace = If ($runAsPPL -eq 1) { "Включен" } else { "Выключен" }

# Ограничение выполнения скриптов
Write-Host "Проверка политики выполнения PowerShell..." -ForegroundColor Gray
$execPolicy = Get-ExecutionPolicy
$cur_interpreters = $execPolicy.ToString()

# Блокировка консоли
$scrSecure = (Get-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaverIsSecure" -ErrorAction SilentlyContinue).ScreenSaverIsSecure
$cur_console = If ($scrSecure -eq "1" -or $cur_tmout -gt 0) { "Включен" } else { "Выключен" }

# Режим аудита событий безопасности
Write-Host "Анализ политик аудита..." -ForegroundColor Gray
# Простая проверка через реестр AuditBaseObjects
$auditBase = 0
if (Test-Path $regLsa) {
    $val = (Get-ItemProperty -Path $regLsa -Name "AuditBaseObjects" -ErrorAction SilentlyContinue).AuditBaseObjects
    if ($val) { $auditBase = [int]$val }
}
$cur_audit = If ($auditBase -eq 1) { "Включен" } else { "Выключен" }

# Сбор информации о целевом СЗИ
Write-Host "Аудит СЗИ..." -ForegroundColor Gray
$expectedSzi = "None"
if (Test-Path $SziConfigFile) {
    $content = Get-Content $SziConfigFile
    foreach ($line in $content) {
        if ($line -match "ExpectedSZI=(.*)") { $expectedSzi = $Matches[1].Trim() }
    }
}

$sziStatus = @{ Installed = $false; Name = $expectedSzi; Active = $false; Details = "" }
if ($expectedSzi -eq "DallasLock") {
    $sziStatus.Name = "Dallas Lock"
    $dlReg = Test-Path "HKLM:\SOFTWARE\Dallas Lock"
    $dlRegWow = Test-Path "HKLM:\SOFTWARE\WOW6432Node\Dallas Lock"
    $dlDir = (Test-Path "C:\Program Files\Dallas Lock") -or (Test-Path "C:\Program Files (x86)\Dallas Lock")
    
    if ($dlReg -or $dlRegWow -or $dlDir) {
        $sziStatus.Installed = $true
        # Службы Dallas Lock
        $dlServices = Get-Service | Where-Object { $_.Name -like "DlSrv*" -or $_.DisplayName -like "*Dallas Lock*" }
        if ($dlServices) {
            $running = $dlServices | Where-Object { $_.Status -eq "Running" }
            $sziStatus.Active = ($running.Count -gt 0)
            $sziStatus.Details = "Найдено служб: $($dlServices.Count), запущено: $($running.Count)"
        } else {
            $sziStatus.Details = "Установлен, но службы защиты не зарегистрированы"
        }
    } else {
        $sziStatus.Details = "СЗИ Dallas Lock не обнаружено на АРМ"
    }
} elseif ($expectedSzi -eq "SNS") {
    $sziStatus.Name = "Secret Net Studio"
    $snsReg = Test-Path "HKLM:\SOFTWARE\Security Code\Secret Net"
    $snsDir = (Test-Path "C:\Program Files\Security Code\Secret Net Studio") -or (Test-Path "C:\Program Files (x86)\Security Code\Secret Net Studio")
    
    if ($snsReg -or $snsDir) {
        $sziStatus.Installed = $true
        # Службы SNS
        $snsServices = Get-Service | Where-Object { $_.Name -like "sns*" -or $_.DisplayName -like "*Secret Net*" -or $_.DisplayName -like "*SecretNet*" }
        if ($snsServices) {
            $running = $snsServices | Where-Object { $_.Status -eq "Running" }
            $sziStatus.Active = ($running.Count -gt 0)
            $sziStatus.Details = "Найдено служб SNS: $($snsServices.Count), запущено: $($running.Count)"
        } else {
            $sziStatus.Details = "Установлен, но службы SNS не зарегистрированы"
        }
    } else {
        $sziStatus.Details = "СЗИ Secret Net Studio не обнаружено на АРМ"
    }
} else {
    $sziStatus.Name = "Не выбрано"
    $sziStatus.Details = "Проверки специализированных СЗИ отключены"
}

# Сбор ПО
Write-Host "Формирование перечня ПО..." -ForegroundColor Gray
$uninstallKeys = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
)
$installedSoftware = Get-ItemProperty $uninstallKeys -ErrorAction SilentlyContinue | 
    Where-Object { $_.DisplayName -and $_.SystemComponent -ne 1 } | 
    Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | 
    Sort-Object DisplayName

$SoftwareDir = Join-Path $ReportDir "software"
if (-not (Test-Path $SoftwareDir)) { New-Item -ItemType Directory -Path $SoftwareDir -Force | Out-Null }
$softwareFile = Join-Path $SoftwareDir "installed_software.txt"
$installedSoftware | ForEach-Object {
    "$($_.DisplayName) | $($_.DisplayVersion) | $($_.Publisher) | $($_.InstallDate)"
} | Out-File $softwareFile -Encoding utf8

# Сбор реестра подключенных USB-устройств
Write-Host "Чтение реестра подключенных USB-устройств..." -ForegroundColor Gray
$usbDevices = @()
$usbstorPath = "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR"
if (Test-Path $usbstorPath) {
    Get-ChildItem -Path $usbstorPath -ErrorAction SilentlyContinue | ForEach-Object {
        $deviceKey = $_.Name
        Get-ChildItem -Path "Registry::$deviceKey" -ErrorAction SilentlyContinue | ForEach-Object {
            $instanceKey = $_.Name
            $friendlyName = (Get-ItemProperty -Path "Registry::$instanceKey" -Name "FriendlyName" -ErrorAction SilentlyContinue).FriendlyName
            $deviceDesc = (Get-ItemProperty -Path "Registry::$instanceKey" -Name "DeviceDesc" -ErrorAction SilentlyContinue).DeviceDesc
            
            $usbDevices += [PSCustomObject]@{
                Device = ($deviceKey -split '\\')[-1]
                Serial = ($instanceKey -split '\\')[-1]
                FriendlyName = If ($friendlyName) { $friendlyName } else { "Съемный диск" }
                Description = If ($deviceDesc) { $deviceDesc } else { "" }
            }
        }
    }
}

# Генерация текстового отчета соответствия требованиям ФСТЭК
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$ComplianceDir = Join-Path $ReportDir "compliance"
if (-not (Test-Path $ComplianceDir)) { New-Item -ItemType Directory -Path $ComplianceDir -Force | Out-Null }
$compTextFile = Join-Path $ComplianceDir "compliance_report_${targetClass}_${timestamp}.txt"

$reportLines = @()
$reportLines += "========================================================================"
$reportLines += "         ОТЧЕТ КОНТРОЛЯ СООТВЕТСТВИЯ ТРЕБОВАНИЯМ РД АС (ГОСТЕХКОМИССИЯ)"
$reportLines += "========================================================================"
$reportLines += "Целевой класс защищенности АС: $targetClass"
$reportLines += "Дата проверки: $(Get-Date -Format 'dd.MM.yyyy HH:mm:ss')"
$reportLines += "Хост: $env:COMPUTERNAME"
$reportLines += "СЗИ от НСД: $($sziStatus.Name) - Инициализировано: $($sziStatus.Installed), Активно: $($sziStatus.Active)"
$reportLines += "------------------------------------------------------------------------"
$reportLines += ""

# Проверки соответствия
$score = 0
$totalChecks = 0

function Audit-Check {
    param([string]$Name, [string]$Current, [string]$Required, [string]$Recommend, [bool]$Pass)
    $script:totalChecks++
    $status = "[  !!  ]"
    if ($Pass) {
        $script:score++
        $status = "[  OK  ]"
    }
    $res = "$status $Name : $Current (требуется: $Required)"
    $script:reportLines += $res
    if (-not $Pass) {
        $script:reportLines += "         -> РЕКОМЕНДАЦИЯ: $Recommend"
    }
    $script:reportLines += ""
}

# 1. Длина пароля
$pass = ($cur_len -ge $std.req_len)
Audit-Check "Минимальная длина пароля" "$cur_len" ">= $($std.req_len)" "Измените параметры политики паролей в локальных групповых политиках (secpol.msc -> Политики учетных записей -> Политика паролей -> Минимальная длина пароля)." $pass

# 2. История паролей
$pass = ($cur_hist -ge $std.req_hist)
Audit-Check "История сохранения паролей" "$cur_hist" ">= $($std.req_hist)" "Измените параметры политики паролей в локальных групповых политиках (secpol.msc -> Политики учетных записей -> Политика паролей -> Требование неповторяемости паролей)." $pass

# 3. Срок действия пароля
$pass = ($cur_max_days -le $std.req_max_days)
Audit-Check "Максимальный срок действия пароля (дн.)" "$cur_max_days" "<= $($std.req_max_days)" "Измените параметры политики паролей в локальных групповых политиках (secpol.msc -> Политики учетных записей -> Политика паролей -> Максимальный срок действия пароля)." $pass

# 4. Порог блокировки
$pass = ($std.req_deny -eq 0 -or ($cur_deny -gt 0 -and $cur_deny -le $std.req_deny))
Audit-Check "Число неудачных входов до блокировки" "$cur_deny" "<= $($std.req_deny)" "Настройте блокировку учетной записи при неверном вводе пароля (secpol.msc -> Политики учетных записей -> Политика блокировки учетной записи -> Порог блокировки)." $pass

# 5. Время блокировки
$pass = ($std.req_unlock_time -eq 0 -or ($cur_unlock_time -ge $std.req_unlock_time))
Audit-Check "Время блокировки аккаунта (сек)" "$cur_unlock_time" ">= $($std.req_unlock_time)" "Настройте время блокировки учетной записи (secpol.msc -> Политики учетных записей -> Политика блокировки учетной записи -> Продолжительность блокировки учетной записи)." $pass

# 6. Таймаут сессии
$pass = ($std.req_tmout -eq 0 -or ($cur_tmout -gt 0 -and $cur_tmout -le $std.req_tmout))
Audit-Check "Таймаут неактивности сессии (сек)" "$cur_tmout" "<= $($std.req_tmout)" "Настройте блокировку сессии при простое через групповые политики (Конфигурация компьютера -> Параметры Windows -> Параметры безопасности -> Локальные политики -> Параметры безопасности -> Интерактивный вход: предел неактивности компьютера) или через параметры заставки." $pass

# 7. Очистка Swap/Pagefile
$pass = ($std.req_swap -eq "optional" -or $cur_swap -eq $std.req_swap)
Audit-Check "Очистка виртуальной памяти (Pagefile)" "$cur_swap" "$($std.req_swap)" "Включите очистку файла подкачки при выключении (реестр HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management, ключ ClearPageFileAtShutdown = 1)." $pass

# 8. Защита процессов LSA
$pass = ($std.req_ptrace -eq "optional" -or $cur_ptrace -eq $std.req_ptrace)
Audit-Check "Защита подсистемы LSA (RunAsPPL)" "$cur_ptrace" "$($std.req_ptrace)" "Включите дополнительную защиту LSA (реестр HKLM\SYSTEM\CurrentControlSet\Control\Lsa, ключ RunAsPPL = 1)." $pass

# 9. Консоль / Блокировка
$pass = ($std.req_console -eq "optional" -or $cur_console -eq $std.req_console)
Audit-Check "Блокировка экрана паролем при заставке" "$cur_console" "$($std.req_console)" "Включите запрос пароля при выходе из режима ожидания/заставки." $pass

# 10. Аудит безопасности
$pass = ($std.req_audit -eq "optional" -or $cur_audit -eq "Включен" -or $cur_audit -like "*строгие*")
Audit-Check "Режим системного аудита безопасности" "$cur_audit" "$($std.req_audit)" "Включите политики аудита безопасности событий (через auditpol.exe или secpol.msc -> Локальные политики -> Политика аудита)." $pass

# 11. СЗИ от НСД
$sziPass = $true
if ($expectedSzi -ne "None") {
    $sziPass = $sziStatus.Installed -and $sziStatus.Active
}
Audit-Check "Специализированное СЗИ от НСД ($($sziStatus.Name))" "Инициализировано: $($sziStatus.Installed), Активно: $($sziStatus.Active)" "Активно" "Установите, настройте или запустите службы СЗИ $($sziStatus.Name) на АРМ." $sziPass

$reportLines += "========================================================================"
$reportLines += "ИТОГ ПРОВЕРКИ: Пройдено проверок: $score из $totalChecks ($( [Math]::Round($score * 100 / $totalChecks) )%)"
$reportLines += "========================================================================"

$reportLines | Out-File $compTextFile -Encoding utf8

# Запуск генерации HTML-отчета
Write-Host "Генерация интерактивного HTML-отчета..." -ForegroundColor Green
$generatorScript = Join-Path $ServiceDir "report_generator.ps1"
if (Test-Path $generatorScript) {
    & $generatorScript -targetClass $targetClass -score $score -totalChecks $totalChecks -cur_len $cur_len -cur_hist $cur_hist -cur_max_days $cur_max_days -cur_deny $cur_deny -cur_unlock_time $cur_unlock_time -cur_tmout $cur_tmout -cur_swap $cur_swap -cur_ptrace $cur_ptrace -cur_interpreters $cur_interpreters -cur_console $cur_console -cur_audit $cur_audit -sziStatus $sziStatus -usbDevices $usbDevices -installedSoftwareCount $installedSoftware.Count -compReportTxtPath $compTextFile
} else {
    Write-Host "Предупреждение: Скрипт генератора отчетов report_generator.ps1 не найден." -ForegroundColor Yellow
}

Write-Host "`nАудит успешно завершен!" -ForegroundColor Green
Write-Host "Текстовый отчет сохранен в: $compTextFile" -ForegroundColor Cyan
Write-Host "HTML отчет сохранен в: $ProjectDir\report\security_report.html" -ForegroundColor Cyan
Read-Host "`nНажмите Enter для продолжения..."




