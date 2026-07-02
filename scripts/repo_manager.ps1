# ============================================================
#               МЕНЕДЖЕР ЗАВИСИМОСТЕЙ И РЕПОЗИТОРИЕВ
# ============================================================
# Выполняет автоматический поиск утилит на съемных накопителях
# или скачивает их напрямую из интернета (при наличии связи).

$ErrorActionPreference = "Continue"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectDir = Split-Path -Parent $ScriptDir
$ToolsDir = Join-Path $ProjectDir "tools"

if (-not (Test-Path $ToolsDir)) {
    New-Item -ItemType Directory -Path $ToolsDir -Force | Out-Null
}

$toolsList = @(
    @{ Name = "ScanOVAL.exe"; Descr = "ScanOval (движок сканера)"; SubFolder = "scanoval" }
    @{ Name = "oscap.exe"; Descr = "OpenSCAP (OVAL-сканер)"; SubFolder = "openscap" }
    @{ Name = "usbdeview.exe"; Descr = "USBDeview (анализ USB)"; SubFolder = "usbdeview" }
    @{ Name = "HWInfo64.exe"; Descr = "HWInfo64 (инвентаризация железа)"; SubFolder = "hwinfo" }
    @{ Name = "WinAudit.exe"; Descr = "WinAudit (системный аудит)"; SubFolder = "winaudit" }
)

# Проверка наличия интернет-подключения
function Test-InternetConnection {
    try {
        $ping = New-Object System.Net.NetworkInformation.Ping
        $reply = $ping.Send("8.8.8.8", 1000)
        if ($reply.Status -eq "Success") { return $true }
    } catch {}
    
    try {
        $request = [System.Net.WebRequest]::Create("https://bdu.fstec.ru")
        $request.Timeout = 2000
        $response = $request.GetResponse()
        if ($response) {
            $response.Close()
            return $true
        }
    } catch {}
    
    return $false
}

# Поиск файлов на всех съемных и оптических дисках
function Scan-RemovableDrives {
    Write-Host "`n=== Сканирование съемных накопителей ===" -ForegroundColor Cyan
    $drives = Get-Volume | Where-Object { $_.DriveType -eq 'CD-ROM' -or $_.DriveType -eq 'Removable' }
    
    if (-not $drives) {
        Write-Host "Съемные диски (флешки, CD-ROM) не обнаружены." -ForegroundColor Yellow
        return
    }
    
    $copiedCount = 0
    foreach ($drive in $drives) {
        $driveLetter = $drive.DriveLetter
        if (-not $driveLetter) { continue }
        $drivePath = "${driveLetter}:\"
        Write-Host "Сканирование диска $drivePath ..." -ForegroundColor Gray
        
        foreach ($tool in $toolsList) {
            $destPath = Join-Path $ToolsDir $tool.Name
            $destSubPath = Join-Path (Join-Path $ToolsDir $tool.SubFolder) $tool.Name
            
            # Если утилита уже есть в корне tools или подпапке, пропускаем
            if (Test-Path $destPath) { continue }
            if (Test-Path $destSubPath) { continue }
            
            # Поиск файла на накопителе
            $foundFile = Get-ChildItem -Path $drivePath -Filter $tool.Name -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($foundFile) {
                Write-Host "Найден файл $($tool.Name) на диске $drivePath. Копирование..." -ForegroundColor Green
                $targetSubFolder = Join-Path $ToolsDir $tool.SubFolder
                if (-not (Test-Path $targetSubFolder)) { New-Item -ItemType Directory -Path $targetSubFolder -Force | Out-Null }
                Copy-Item -Path $foundFile.FullName -Destination $targetSubFolder -Force
                Write-Host "Успешно скопировано в $targetSubFolder\$($tool.Name)" -ForegroundColor Green
                $copiedCount++
            }
        }
    }
    
    if ($copiedCount -eq 0) {
        Write-Host "Новых diagnostic-файлов на внешних носителях не обнаружено." -ForegroundColor Gray
    } else {
        Write-Host "Успешно скопировано утилит со съемных дисков: $copiedCount" -ForegroundColor Green
    }
}

# Автоматическое скачивание утилит из интернета
function Download-Utilities {
    Write-Host "`n=== Запуск автозагрузки утилит из интернета ===" -ForegroundColor Cyan
    if (-not (Test-InternetConnection)) {
        Write-Host "Ошибка: Подключение к интернету отсутствует или заблокировано." -ForegroundColor Red
        return
    }
    
    $tempDir = Join-Path $env:TEMP "SecurityCheckerDownloads"
    if (-not (Test-Path $tempDir)) { New-Item -ItemType Directory -Path $tempDir -Force | Out-Null }
    
    # Обход проверки SSL-сертификатов (для работы с bdu.fstec.ru без российских корневых сертификатов Минцифры)
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

    $urls = @{
        "usbdeview.exe" = @{
            Url = "https://www.nirsoft.net/utils/usbdeview-x64.zip"
            IsZip = $true
            ExeName = "USBDeview.exe"
            SubFolder = "usbdeview"
        }
        "HWInfo64.exe" = @{
            Url = "https://www.sac.sk/download/utildiag/hwi_848.zip"
            IsZip = $true
            ExeName = "HWiNFO64.exe"
            SubFolder = "hwinfo"
        }
        "WinAudit.exe" = @{
            Url = "https://raw.githubusercontent.com/jbarcia/PCI-Audit-Script/master/tools/WinAudit.exe"
            IsZip = $false
            ExeName = "WinAudit.exe"
            SubFolder = "winaudit"
        }
        "oscap.exe" = @{
            Url = "https://github.com/OpenSCAP/openscap/releases/download/1.3.0/OpenSCAP-1.3.0-win32.msi"
            IsMsi = $true
            ExeName = "oscap.exe"
            SubFolder = "openscap"
        }
    }
    
    # Ссылка на OVAL-базу ФСТЭК
    $ovalUrl = "https://bdu.fstec.ru/files/scanoval.zip"
    
    foreach ($tool in $urls.Keys) {
        $targetFolder = Join-Path $ToolsDir $urls[$tool].SubFolder
        $targetPath = Join-Path $targetFolder $tool
        
        if (Test-Path $targetPath) {
            Write-Host "Утилита $tool уже скачана." -ForegroundColor Gray
            continue
        }
        
        Write-Host "Скачивание $tool ..." -ForegroundColor Gray
        $dlInfo = $urls[$tool]
        
        $ext = ""
        if ($dlInfo.IsZip) { $ext = ".zip" }
        elseif ($dlInfo.IsMsi) { $ext = ".msi" }
        $tempFile = Join-Path $tempDir ($tool + $ext)
        
        try {
            # Установка TLS 1.2
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            
            # Скачивание файла
            $webClient = New-Object System.Net.WebClient
            $webClient.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
            $webClient.DownloadFile($dlInfo.Url, $tempFile)
            
            if (-not (Test-Path $targetFolder)) { New-Item -ItemType Directory -Path $targetFolder -Force | Out-Null }
            
            if ($dlInfo.IsZip) {
                Write-Host "Распаковка $tool..." -ForegroundColor Gray
                $zipExtractTemp = Join-Path $tempDir ($tool + "_extracted")
                if (Test-Path $zipExtractTemp) { Remove-Item -Path $zipExtractTemp -Recurse -Force | Out-Null }
                New-Item -ItemType Directory -Path $zipExtractTemp -Force | Out-Null
                
                Expand-Archive -Path $tempFile -DestinationPath $zipExtractTemp -Force
                
                $extractedExe = Get-ChildItem -Path $zipExtractTemp -Filter $dlInfo.ExeName -Recurse -File | Select-Object -First 1
                if ($extractedExe) {
                    Copy-Item -Path $extractedExe.FullName -Destination (Join-Path $targetFolder $tool) -Force
                    Write-Host "Успешно скачан и установлен: $tool" -ForegroundColor Green
                } else {
                    Write-Host "Ошибка: Файл $($dlInfo.ExeName) не найден внутри архива." -ForegroundColor Red
                }
            } elseif ($dlInfo.IsMsi) {
                Write-Host "Распаковка MSI для $tool..." -ForegroundColor Gray
                $msiExtractTemp = Join-Path $tempDir ($tool + "_extracted")
                if (Test-Path $msiExtractTemp) { Remove-Item -Path $msiExtractTemp -Recurse -Force | Out-Null }
                New-Item -ItemType Directory -Path $msiExtractTemp -Force | Out-Null
                
                # Запуск msiexec для административной распаковки MSI
                $p = Start-Process -FilePath msiexec.exe -ArgumentList "/a `"$tempFile`"", "/qb", "TARGETDIR=`"$msiExtractTemp`"" -Wait -NoNewWindow -PassThru
                
                # Поиск папки OpenSCAP и копирование всех ее файлов
                $sourceDir = Get-ChildItem -Path $msiExtractTemp -Directory -Recurse | Where-Object { $_.Name -like "*OpenSCAP*" } | Select-Object -First 1
                if ($sourceDir) {
                    Get-ChildItem -Path $sourceDir.FullName -File | ForEach-Object {
                        Copy-Item -Path $_.FullName -Destination (Join-Path $targetFolder $_.Name) -Force
                    }
                    Write-Host "Успешно скачан и установлен: $tool" -ForegroundColor Green
                } else {
                    Write-Host "Ошибка: Содержимое OpenSCAP не найдено в распакованном MSI." -ForegroundColor Red
                }
            } else {
                Copy-Item -Path $tempFile -Destination $targetPath -Force
                Write-Host "Успешно скачан и установлен: $tool" -ForegroundColor Green
            }
        } catch {
            Write-Host "Ошибка при скачивании $($tool): $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    
    # Скачивание базы OVAL ФСТЭК в папку service
    $ovalDestDir = Join-Path $ProjectDir "service"
    $ovalDestFile = Join-Path $ovalDestDir "oval.zip"
    Write-Host "Скачивание базы OVAL ФСТЭК..." -ForegroundColor Gray
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $webClient = New-Object System.Net.WebClient
        $webClient.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
        $webClient.DownloadFile($ovalUrl, $ovalDestFile)
        Write-Host "База OVAL ФСТЭК успешно скачана и сохранена в: $ovalDestFile" -ForegroundColor Green
        
        # Распаковываем базу в service
        Expand-Archive -Path $ovalDestFile -DestinationPath $ovalDestDir -Force
        Write-Host "База OVAL распакована." -ForegroundColor Green
    } catch {
        Write-Host "Не удалось скачать базу OVAL напрямую с ФСТЭК: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "ПРИМЕЧАНИЕ: БДУ ФСТЭК требует авторизации на портале или блокирует запросы из-за пределов РФ." -ForegroundColor Yellow
        Write-Host "Пожалуйста, скачайте архив базы вручную (после авторизации) с https://bdu.fstec.ru/scanoval" -ForegroundColor Yellow
        Write-Host "и сохраните полученный архив (.zip) или XML-файл в папку проекта 'service/'." -ForegroundColor Yellow
    }
    
    # Удаляем временную папку
    if (Test-Path $tempDir) { Remove-Item -Path $tempDir -Recurse -Force | Out-Null }
}

# Функция отображения статуса утилит
function Show-Status {
    Write-Host "`n=== СТАТУС ДИАГНОСТИЧЕСКИХ УТИЛИТ ===" -ForegroundColor Cyan
    foreach ($tool in $toolsList) {
        $path1 = Join-Path $ToolsDir $tool.Name
        $path2 = Join-Path (Join-Path $ToolsDir $tool.SubFolder) $tool.Name
        
        $status = "ОТСУТСТВУЕТ"
        $color = "Red"
        $realPath = ""
        
        if (Test-Path $path1) {
            $status = "НАЙДЕН (в корне tools)"
            $color = "Green"
            $realPath = $path1
        } elseif (Test-Path $path2) {
            $status = "НАЙДЕН (в подпапке)"
            $color = "Green"
            $realPath = $path2
        }
        
        Write-Host "- $($tool.Descr) [$($tool.Name)] : " -NoNewline -ForegroundColor Gray
        Write-Host $status -ForegroundColor $color
        if ($realPath) {
            Write-Host "  Путь: $realPath" -ForegroundColor DarkGray
        }
    }
    
    # Проверка OVAL-базы ФСТЭК
    $ovalXml = Get-ChildItem -Path (Join-Path $ProjectDir "service") -Filter "*.xml" | Where-Object { $_.Name -like "*oval*" -or $_.Name -like "*vulnerabilities*" }
    Write-Host "- OVAL-база ФСТЭК (service\*.xml) : " -NoNewline -ForegroundColor Gray
    if ($ovalXml) {
        Write-Host "НАЙДЕНА ($($ovalXml.Count) файлов)" -ForegroundColor Green
        foreach ($ox in $ovalXml) { Write-Host "  Файл: $($ox.Name)" -ForegroundColor DarkGray }
    } else {
        Write-Host "ОТСУТСТВУЕТ (требуется для ScanOval)" -ForegroundColor Red
    }
}

# Подгрузка TUI модуля
$tuiHelper = Join-Path $ProjectDir "service\tui_helper.ps1"
if (Test-Path $tuiHelper) { . $tuiHelper }

function Get-TuiStatusString {
    $statusStr = ""
    foreach ($tool in $toolsList) {
        $path1 = Join-Path $ToolsDir $tool.Name
        $path2 = Join-Path (Join-Path $ToolsDir $tool.SubFolder) $tool.Name
        
        $status = "ОТСУТСТВУЕТ"
        if (Test-Path $path1) {
            $status = "НАЙДЕН"
        } elseif (Test-Path $path2) {
            $status = "НАЙДЕН"
        }
        $statusStr += "  • $($tool.Descr) : $status`n"
    }
    
    $ovalXml = Get-ChildItem -Path (Join-Path $ProjectDir "service") -Filter "*.xml" | Where-Object { $_.Name -like "*oval*" -or $_.Name -like "*vulnerabilities*" }
    $ovalStatus = If ($ovalXml) { "НАЙДЕНА" } else { "ОТСУТСТВУЕТ" }
    $statusStr += "  • OVAL-база ФСТЭК : $ovalStatus"
    
    return $statusStr
}

# Меню менеджера утилит
while ($true) {
    $subtitle = "Статус диагностических утилит:`n" + (Get-TuiStatusString)
    
    $options = @(
        "Сканировать съемные диски (поиск локальных копий)",
        "Автоматически скачать утилиты из интернета",
        "Назад в главное меню"
    )
    
    $choice = Show-TuiMenu -Title "МЕНЕДЖЕР ЗАВИСИМОСТЕЙ И РЕПОЗИТОРИЕВ" -Subtitle $subtitle -Options $options
    
    if ($choice -eq 0) {
        Scan-RemovableDrives
        Read-Host "`nНажмите Enter для продолжения..."
    } elseif ($choice -eq 1) {
        Download-Utilities
        Read-Host "`nНажмите Enter для продолжения..."
    } elseif ($choice -eq 2 -or $choice -eq -1) {
        break
    }
}





