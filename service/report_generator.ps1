# ============================================================
#               ГЕНЕРАТОР HTML-ОТЧЕТОВ БЕЗОПАСНОСТИ
# ============================================================
# Компилирует все собранные данные аудита в единый красивый
# интерактивный HTML-файл с поддержкой переключения тем.

param(
    [string]$targetClass,
    [int]$score,
    [int]$totalChecks,
    [int]$cur_len,
    [int]$cur_hist,
    [int]$cur_max_days,
    [int]$cur_deny,
    [int]$cur_unlock_time,
    [int]$cur_tmout,
    [string]$cur_swap,
    [string]$cur_ptrace,
    [string]$cur_interpreters,
    [string]$cur_console,
    [string]$cur_audit,
    [hashtable]$sziStatus,
    [array]$usbDevices,
    [int]$installedSoftwareCount,
    [string]$compReportTxtPath
)

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectDir = Split-Path -Parent $ScriptDir
$ReportDir = Join-Path $ProjectDir "report"
$ReportFile = Join-Path $ReportDir "security_report.html"

# Вспомогательная функция кодирования HTML
function Get-HtmlEncoded {
    param([string]$str)
    if (-not $str) { return "" }
    return $str.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;").Replace('"', "&quot;").Replace("'", "&#39;")
}

# Чтение INI-файла стандартов для отображения требований в таблице
function Get-ComplianceStandardsForReport {
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
            $value = $value -replace "^['`"]|['`"]$"
            $standards[$key] = $value
        }
    }
    return $standards
}

$StandardsFile = Join-Path $ScriptDir "compliance_standards.conf"
$std = Get-ComplianceStandardsForReport $StandardsFile $targetClass

# ------------------------------------------------------------
# Вычисление переменных для HTML шаблона
# ------------------------------------------------------------

# 1. Длина пароля
$class_len = If ($cur_len -ge $std.req_len) { "status-ok" } else { "status-fail" }
$status_len = If ($cur_len -ge $std.req_len) { "OK" } else { "FAIL" }
$rec_len = If ($cur_len -ge $std.req_len) { "" } else { "<div class='recommendation'>Настройте минимальную длину пароля в secpol.msc или GPO.</div>" }

# 2. История паролей
$class_hist = If ($cur_hist -ge $std.req_hist) { "status-ok" } else { "status-fail" }
$status_hist = If ($cur_hist -ge $std.req_hist) { "OK" } else { "FAIL" }
$rec_hist = If ($cur_hist -ge $std.req_hist) { "" } else { "<div class='recommendation'>Включите хранение истории паролей (повторяемость).</div>" }

# 3. Срок действия пароля
$class_max_days = If ($cur_max_days -le $std.req_max_days) { "status-ok" } else { "status-fail" }
$status_max_days = If ($cur_max_days -le $std.req_max_days) { "OK" } else { "FAIL" }
$rec_max_days = If ($cur_max_days -le $std.req_max_days) { "" } else { "<div class='recommendation'>Ограничьте максимальный срок действия паролей.</div>" }

# 4. Порог блокировки
$class_deny = If ($std.req_deny -eq 0 -or ($cur_deny -gt 0 -and $cur_deny -le $std.req_deny)) { "status-ok" } else { "status-fail" }
$status_deny = If ($std.req_deny -eq 0 -or ($cur_deny -gt 0 -and $cur_deny -le $std.req_deny)) { "OK" } else { "FAIL" }
$rec_deny = If ($std.req_deny -eq 0 -or ($cur_deny -gt 0 -and $cur_deny -le $std.req_deny)) { "" } else { "<div class='recommendation'>Настройте порог блокировки учетных записей.</div>" }

# 5. Время блокировки
$class_unlock = If ($std.req_unlock_time -eq 0 -or ($cur_unlock_time -ge $std.req_unlock_time)) { "status-ok" } else { "status-fail" }
$status_unlock = If ($std.req_unlock_time -eq 0 -or ($cur_unlock_time -ge $std.req_unlock_time)) { "OK" } else { "FAIL" }
$rec_unlock = If ($std.req_unlock_time -eq 0 -or ($cur_unlock_time -ge $std.req_unlock_time)) { "" } else { "<div class='recommendation'>Настройте время автоматической разблокировки.</div>" }

# 6. Таймаут сессии
$class_tmout = If ($std.req_tmout -eq 0 -or ($cur_tmout -gt 0 -and $cur_tmout -le $std.req_tmout)) { "status-ok" } else { "status-fail" }
$status_tmout = If ($std.req_tmout -eq 0 -or ($cur_tmout -gt 0 -and $cur_tmout -le $std.req_tmout)) { "OK" } else { "FAIL" }
$rec_tmout = If ($std.req_tmout -eq 0 -or ($cur_tmout -gt 0 -and $cur_tmout -le $std.req_tmout)) { "" } else { "<div class='recommendation'>Настройте ограничение неактивности сессии или заставки.</div>" }

# 7. Очистка файла подкачки
$class_swap = If ($std.req_swap -eq "optional" -or $cur_swap -eq $std.req_swap) { "status-ok" } else { "status-fail" }
$status_swap = If ($std.req_swap -eq "optional" -or $cur_swap -eq $std.req_swap) { "OK" } else { "FAIL" }
$rec_swap = If ($std.req_swap -eq "optional" -or $cur_swap -eq $std.req_swap) { "" } else { "<div class='recommendation'>Включите ClearPageFileAtShutdown в реестре Windows.</div>" }

# 8. Защита процессов LSA
$class_ptrace = If ($std.req_ptrace -eq "optional" -or $cur_ptrace -eq $std.req_ptrace) { "status-ok" } else { "status-fail" }
$status_ptrace = If ($std.req_ptrace -eq "optional" -or $cur_ptrace -eq $std.req_ptrace) { "OK" } else { "FAIL" }
$rec_ptrace = If ($std.req_ptrace -eq "optional" -or $cur_ptrace -eq $std.req_ptrace) { "" } else { "<div class='recommendation'>Включите дополнительную защиту процессов LSA.</div>" }

# 9. Консоль / Блокировка экрана
$class_console = If ($std.req_console -eq "optional" -or $cur_console -eq $std.req_console) { "status-ok" } else { "status-fail" }
$status_console = If ($std.req_console -eq "optional" -or $cur_console -eq $std.req_console) { "OK" } else { "FAIL" }
$rec_console = If ($std.req_console -eq "optional" -or $cur_console -eq $std.req_console) { "" } else { "<div class='recommendation'>Настройте обязательный ввод пароля при возврате из сна/заставки.</div>" }

# 10. Системный аудит
$class_audit = If ($std.req_audit -eq "optional" -or $cur_audit -eq "Включен" -or $cur_audit -like "*строгие*") { "status-ok" } else { "status-fail" }
$status_audit = If ($std.req_audit -eq "optional" -or $cur_audit -eq "Включен" -or $cur_audit -like "*строгие*") { "OK" } else { "FAIL" }
$rec_audit = If ($std.req_audit -eq "optional" -or $cur_audit -eq "Включен" -or $cur_audit -like "*строгие*") { "" } else { "<div class='recommendation'>Включите политики аудита безопасности (auditpol.exe).</div>" }

# Переменные для плашек СЗИ
$class_szi_badge = If ($sziStatus.Active) { "badge-active" } else { "badge-inactive" }
$text_szi_badge = If ($sziStatus.Active) { "Службы Активны" } else { "Отключено / Недоступно" }
$text_szi_installed = If ($sziStatus.Installed) { "Установлено" } else { "Не найдено" }

# Вычисление процентов соответствия
$percent = [Math]::Round($score * 100 / $totalChecks)
$dashStroke = [Math]::Round(2 * [Math]::PI * 50) # Длина окружности для gauge (r=50) -> ~314
$dashOffset = [Math]::Round($dashStroke - ($percent / 100 * $dashStroke))

# Определение модели процессора и ОЗУ для хедера
$cpu = (Get-CimInstance Win32_Processor).Name
$ram = [Math]::Round((Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum / 1GB)
$os = (Get-CimInstance Win32_OperatingSystem).Caption
$sn = (Get-CimInstance Win32_Bios).SerialNumber
if (-not $sn -or $sn -eq "System Serial Number" -or $sn -eq "To be filled by O.E.M.") {
    $sn = (Get-CimInstance Win32_ComputerSystemProduct).IdentifyingNumber
}
$sn = If ($sn) { $sn } else { "Не определен" }

# Сбор строк программного обеспечения
$softwareRows = ""
$softwareFile = Join-Path $ReportDir "installed_software.txt"
if (Test-Path $softwareFile) {
    $swLines = Get-Content $softwareFile
    foreach ($line in $swLines) {
        $parts = $line -split ' \| '
        if ($parts.Count -ge 1) {
            $name = Get-HtmlEncoded $parts[0].Trim()
            $ver = If ($parts.Count -ge 2) { Get-HtmlEncoded $parts[1].Trim() } else { "" }
            $pub = If ($parts.Count -ge 3) { Get-HtmlEncoded $parts[2].Trim() } else { "" }
            $date = If ($parts.Count -ge 4) { Get-HtmlEncoded $parts[3].Trim() } else { "" }
            $softwareRows += "<tr><td>$name</td><td>$ver</td><td>$pub</td><td>$date</td></tr>`n"
        }
    }
}

# Сбор строк USB-устройств
$usbRows = ""
foreach ($dev in $usbDevices) {
    $dName = Get-HtmlEncoded $dev.Device
    $dFriendly = Get-HtmlEncoded $dev.FriendlyName
    $dDesc = Get-HtmlEncoded $dev.Description
    $dSerial = Get-HtmlEncoded $dev.Serial
    $usbRows += "<tr><td><b>$dFriendly</b></td><td>$dName</td><td><code>$dSerial</code></td><td>$dDesc</td></tr>`n"
}

# Сбор внешних файлов отчетов
$winauditExists = Test-Path (Join-Path $ReportDir "winaudit_report.html")
$usbdeviewExists = Test-Path (Join-Path $ReportDir "usbdeview_report.html")
$hwinfoExists = Test-Path (Join-Path $ReportDir "hwinfo_report.txt")
$scanovalExists = Test-Path (Join-Path $ReportDir "scanoval_report.html")

# Кнопки отчетов внешних утилит
$html_winaudit = If ($winauditExists) { "<a href='winaudit_report.html' class='action-btn' target='_blank' style='border-color: var(--status-pass); color: var(--status-pass);'>Открыть HTML</a>" } else { "<span style='color: var(--text-muted); font-size: 0.85rem;'>Отчет отсутствует (утилита не запускалась)</span>" }
$html_usbdeview = If ($usbdeviewExists) { "<a href='usbdeview_report.html' class='action-btn' target='_blank' style='border-color: var(--status-pass); color: var(--status-pass);'>Открыть HTML</a>" } else { "<span style='color: var(--text-muted); font-size: 0.85rem;'>Отчет отсутствует (утилита не запускалась)</span>" }
$html_hwinfo = If ($hwinfoExists) { "<a href='hwinfo_report.txt' class='action-btn' target='_blank' style='border-color: var(--status-pass); color: var(--status-pass);'>Открыть TXT</a>" } else { "<span style='color: var(--text-muted); font-size: 0.85rem;'>Отчет отсутствует (утилита не запускалась)</span>" }
$html_scanoval = If ($scanovalExists) { "<a href='scanoval_report.html' class='action-btn' target='_blank' style='border-color: var(--status-pass); color: var(--status-pass);'>Открыть HTML</a>" } else { "<span style='color: var(--text-muted); font-size: 0.85rem;'>Отчет отсутствует (утилита не запускалась)</span>" }

# Запись шаблона HTML-отчета
$html = @"
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Отчет о защищенности АРМ Windows - $env:COMPUTERNAME</title>
    <style>
        :root {
            --bg-main: #0f172a;
            --bg-card: #1e293b;
            --border: #334155;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --primary: #0ea5e9;
            --primary-hover: #38bdf8;
            
            --status-pass: #10b981;
            --status-warn: #f59e0b;
            --status-crit: #ef4444;
            --status-info: #3b82f6;
            
            --status-pass-bg: rgba(16, 185, 129, 0.1);
            --status-warn-bg: rgba(245, 158, 11, 0.1);
            --status-crit-bg: rgba(239, 68, 68, 0.1);
            --status-info-bg: rgba(59, 130, 246, 0.1);
        }

        .light-theme {
            --bg-main: #f8fafc;
            --bg-card: #ffffff;
            --border: #e2e8f0;
            --text-main: #0f172a;
            --text-muted: #64748b;
            --primary: #0284c7;
            --primary-hover: #0369a1;
            
            --status-pass: #059669;
            --status-warn: #d97706;
            --status-crit: #dc2626;
            --status-info: #2563eb;
            
            --status-pass-bg: rgba(5, 150, 105, 0.08);
            --status-warn-bg: rgba(217, 119, 6, 0.08);
            --status-crit-bg: rgba(220, 38, 38, 0.08);
            --status-info-bg: rgba(37, 99, 235, 0.08);
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg-main);
            color: var(--text-main);
            line-height: 1.5;
            transition: background-color 0.3s, color 0.3s;
            padding: 2rem 1rem;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
        }

        header {
            background-color: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 2rem;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
        }

        .header-top {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1rem;
        }

        h1 {
            font-size: 1.75rem;
            font-weight: 700;
        }

        .btn-group {
            display: flex;
            gap: 0.5rem;
        }

        .theme-toggle, .print-btn, .action-btn {
            background-color: var(--bg-main);
            border: 1px solid var(--border);
            color: var(--text-main);
            padding: 0.5rem 1rem;
            border-radius: 6px;
            cursor: pointer;
            font-size: 0.875rem;
            font-weight: 500;
            transition: border-color 0.2s, background-color 0.2s;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            justify-content: center;
        }

        .theme-toggle:hover, .print-btn:hover, .action-btn:hover {
            border-color: var(--primary);
            background-color: var(--border);
        }

        .meta-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 1rem;
            font-size: 0.875rem;
            border-top: 1px solid var(--border);
            padding-top: 1rem;
            margin-top: 1rem;
        }

        .meta-item span {
            color: var(--text-muted);
            display: block;
            margin-bottom: 0.25rem;
        }

        .meta-item strong {
            font-weight: 600;
        }

        /* Dashboard Score */
        .dashboard-grid {
            display: grid;
            grid-template-columns: 1fr 2fr;
            gap: 2rem;
            margin-bottom: 2rem;
        }

        @media (max-width: 768px) {
            .dashboard-grid {
                grid-template-columns: 1fr;
            }
        }

        .score-card {
            background-color: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1.5rem;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
        }

        .gauge-container {
            position: relative;
            width: 150px;
            height: 150px;
            margin-bottom: 1rem;
        }

        .gauge-circle-bg {
            fill: none;
            stroke: var(--border);
            stroke-width: 10;
        }

        .gauge-circle-fill {
            fill: none;
            stroke: var(--status-pass);
            stroke-width: 10;
            stroke-linecap: round;
            transform: rotate(-90deg);
            transform-origin: 50% 50%;
            transition: stroke-dasharray 0.5s ease;
        }

        .gauge-text {
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            font-size: 2rem;
            font-weight: 700;
        }

        .score-label {
            font-size: 1rem;
            color: var(--text-muted);
            font-weight: 500;
            margin-top: 0.5rem;
        }

        .szi-card {
            background-color: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1.5rem;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
        }

        .szi-title {
            font-size: 1.25rem;
            font-weight: 600;
            margin-bottom: 1rem;
            border-bottom: 1px solid var(--border);
            padding-bottom: 0.5rem;
        }

        .szi-status-badge {
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.875rem;
            font-weight: 600;
            margin-bottom: 1rem;
        }

        .badge-active {
            background-color: var(--status-pass-bg);
            color: var(--status-pass);
            border: 1px solid var(--status-pass);
        }

        .badge-inactive {
            background-color: var(--status-crit-bg);
            color: var(--status-crit);
            border: 1px solid var(--status-crit);
        }

        /* Section panels */
        .section-panel {
            background-color: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 2rem;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
        }

        .section-title {
            font-size: 1.25rem;
            font-weight: 600;
            margin-bottom: 1.5rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        /* Tables */
        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 1rem;
            font-size: 0.875rem;
        }

        th, td {
            padding: 0.75rem 1rem;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }

        th {
            background-color: rgba(0, 0, 0, 0.15);
            font-weight: 600;
            color: var(--text-muted);
        }

        tr:hover {
            background-color: rgba(255, 255, 255, 0.02);
        }

        .status-cell {
            font-weight: 700;
            text-align: center;
            width: 80px;
        }

        .status-ok {
            color: var(--status-pass);
            background-color: var(--status-pass-bg);
            border-radius: 4px;
        }

        .status-fail {
            color: var(--status-crit);
            background-color: var(--status-crit-bg);
            border-radius: 4px;
        }

        .recommendation {
            font-size: 0.8rem;
            color: var(--text-muted);
            margin-top: 0.25rem;
            padding-left: 0.5rem;
            border-left: 2px solid var(--primary);
        }

        .search-box {
            width: 100%;
            background-color: var(--bg-main);
            border: 1px solid var(--border);
            color: var(--text-main);
            padding: 0.5rem 1rem;
            border-radius: 6px;
            font-size: 0.875rem;
            margin-bottom: 1rem;
        }

        .search-box:focus {
            outline: none;
            border-color: var(--primary);
        }

        .table-container {
            max-height: 400px;
            overflow-y: auto;
            border: 1px solid var(--border);
            border-radius: 6px;
        }

        .tool-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
            gap: 1rem;
        }

        .tool-card {
            background-color: var(--bg-main);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 1rem;
            display: flex;
            flex-direction: column;
            justify-content: space-between;
        }

        .tool-name {
            font-size: 1rem;
            font-weight: 600;
            margin-bottom: 0.5rem;
        }

        .tool-status {
            font-size: 0.8rem;
            color: var(--text-muted);
            margin-bottom: 1rem;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="header-top">
                <div>
                    <h1>Отчет о защищенности АРМ Windows</h1>
                    <p style="color: var(--text-muted); font-size: 0.9rem; margin-top: 0.25rem;">АО НИИ «РУБИН» • Внутренний контроль защищенности АС</p>
                </div>
                <div class="btn-group">
                    <button class="theme-toggle" onclick="toggleTheme()">☀️ Тема</button>
                    <button class="print-btn" onclick="window.print()">🖨️ Печать</button>
                </div>
            </div>
            
            <div class="meta-grid">
                <div class="meta-item">
                    <span>Имя компьютера</span>
                    <strong>$env:COMPUTERNAME</strong>
                </div>
                <div class="meta-item">
                    <span>Операционная система</span>
                    <strong>$os</strong>
                </div>
                <div class="meta-item">
                    <span>Серийный номер</span>
                    <strong>$sn</strong>
                </div>
                <div class="meta-item">
                    <span>Процессор и ОЗУ</span>
                    <strong>$cpu, $ram ГБ</strong>
                </div>
                <div class="meta-item">
                    <span>Дата проверки</span>
                    <strong>$(Get-Date -Format 'dd.MM.yyyy HH:mm:ss')</strong>
                </div>
            </div>
        </header>

        <div class="dashboard-grid">
            <div class="score-card">
                <div class="gauge-container">
                    <svg width="150" height="150" viewBox="0 0 120 120">
                        <circle class="gauge-circle-bg" cx="60" cy="60" r="50"></circle>
                        <circle class="gauge-circle-fill" cx="60" cy="60" r="50" 
                                stroke-dasharray="$dashStroke" stroke-dashoffset="$dashOffset"></circle>
                    </svg>
                    <div class="gauge-text">$percent%</div>
                </div>
                <div class="score-label">Класс защищенности: $targetClass</div>
                <p style="font-size: 0.8rem; color: var(--text-muted); margin-top: 0.25rem;">Пройдено тестов: $score из $totalChecks</p>
            </div>

            <div class="szi-card">
                <div class="szi-title">Специализированное СЗИ от НСД</div>
                <div>
                    <strong>Целевое СЗИ:</strong> $($sziStatus.Name)<br>
                    <strong>Статус установки:</strong> $text_szi_installed<br>
                    <strong>Состояние защиты:</strong>
                    <div class="szi-status-badge $class_szi_badge" style="margin-top: 0.5rem;">
                        $text_szi_badge
                    </div>
                    <p style="font-size: 0.85rem; color: var(--text-muted);">$($sziStatus.Details)</p>
                </div>
            </div>
        </div>

        <!-- Compliance Checks Section -->
        <div class="section-panel">
            <div class="section-title">Контроль соответствия требованиям безопасности ФСТЭК</div>
            <table>
                <thead>
                    <tr>
                        <th style="width: 80px; text-align: center;">Статус</th>
                        <th>Требование безопасности</th>
                        <th>Фактическое значение</th>
                        <th>Эталон для класса $targetClass</th>
                    </tr>
                </thead>
                <tbody>
                    <!-- Длина пароля -->
                    <tr>
                        <td class="status-cell $class_len">$status_len</td>
                        <td>Минимальная длина пароля $rec_len</td>
                        <td>$cur_len</td>
                        <td>&gt;= $($std.req_len)</td>
                    </tr>
                    <!-- История паролей -->
                    <tr>
                        <td class="status-cell $class_hist">$status_hist</td>
                        <td>Хранение истории паролей $rec_hist</td>
                        <td>$cur_hist</td>
                        <td>&gt;= $($std.req_hist)</td>
                    </tr>
                    <!-- Макс срок действия -->
                    <tr>
                        <td class="status-cell $class_max_days">$status_max_days</td>
                        <td>Максимальный срок действия пароля (дн.) $rec_max_days</td>
                        <td>$cur_max_days</td>
                        <td>&lt;= $($std.req_max_days)</td>
                    </tr>
                    <!-- Число попыток до блокировки -->
                    <tr>
                        <td class="status-cell $class_deny">$status_deny</td>
                        <td>Число попыток входа до блокировки $rec_deny</td>
                        <td>$cur_deny</td>
                        <td>&lt;= $($std.req_deny)</td>
                    </tr>
                    <!-- Время блокировки -->
                    <tr>
                        <td class="status-cell $class_unlock">$status_unlock</td>
                        <td>Время авторазблокировки аккаунта (сек) $rec_unlock</td>
                        <td>$cur_unlock_time</td>
                        <td>&gt;= $($std.req_unlock_time)</td>
                    </tr>
                    <!-- Таймаут сессии -->
                    <tr>
                        <td class="status-cell $class_tmout">$status_tmout</td>
                        <td>Таймаут неактивности сессии (сек) $rec_tmout</td>
                        <td>$cur_tmout</td>
                        <td>&lt;= $($std.req_tmout)</td>
                    </tr>
                    <!-- Очистка файла подкачки -->
                    <tr>
                        <td class="status-cell $class_swap">$status_swap</td>
                        <td>Очистка виртуальной памяти (Pagefile) $rec_swap</td>
                        <td>$cur_swap</td>
                        <td>$($std.req_swap)</td>
                    </tr>
                    <!-- Защита LSA -->
                    <tr>
                        <td class="status-cell $class_ptrace">$status_ptrace</td>
                        <td>Защита подсистемы LSA (RunAsPPL) $rec_ptrace</td>
                        <td>$cur_ptrace</td>
                        <td>$($std.req_ptrace)</td>
                    </tr>
                    <!-- Блокировка консоли -->
                    <tr>
                        <td class="status-cell $class_console">$status_console</td>
                        <td>Блокировка экрана паролем при заставке $rec_console</td>
                        <td>$cur_console</td>
                        <td>$($std.req_console)</td>
                    </tr>
                    <!-- Системный аудит -->
                    <tr>
                        <td class="status-cell $class_audit">$status_audit</td>
                        <td>Режим системного аудита $rec_audit</td>
                        <td>$cur_audit</td>
                        <td>$($std.req_audit)</td>
                    </tr>
                </tbody>
            </table>
        </div>

        <!-- USB History Section -->
        <div class="section-panel">
            <div class="section-title">История подключенных USB-устройств хранения (Реестр USBSTOR)</div>
            <input type="text" id="usbSearch" class="search-box" placeholder="Поиск по имени, серийному номеру или описанию..." onkeyup="filterUsbTable()">
            <div class="table-container">
                <table id="usbTable">
                    <thead>
                        <tr>
                            <th>Имя (Friendly Name)</th>
                            <th>Имя устройства</th>
                            <th>Серийный номер</th>
                            <th>Описание реестра</th>
                        </tr>
                    </thead>
                    <tbody>
                        $usbRows
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Software Inventory Section -->
        <div class="section-panel">
            <div class="section-title">
                <span>Состав установленного ПО ($installedSoftwareCount позиций)</span>
                <a href="installed_software.txt" class="action-btn" target="_blank" style="font-size: 0.75rem; padding: 0.25rem 0.5rem;">Открыть TXT</a>
            </div>
            <input type="text" id="softwareSearch" class="search-box" placeholder="Поиск ПО по названию, версии или издателю..." onkeyup="filterSoftwareTable()">
            <div class="table-container">
                <table id="softwareTable">
                    <thead>
                        <tr>
                            <th>Название программного обеспечения</th>
                            <th>Версия</th>
                            <th>Издатель</th>
                            <th>Дата установки</th>
                        </tr>
                    </thead>
                    <tbody>
                        $softwareRows
                    </tbody>
                </table>
            </div>
        </div>

        <!-- External Tool Reports Section -->
        <div class="section-panel">
            <div class="section-title">Отчеты внешних диагностических утилит</div>
            <div class="tool-grid">
                <!-- WinAudit -->
                <div class="tool-card">
                    <div>
                        <div class="tool-name">WinAudit System Report</div>
                        <div class="tool-status">Содержит полный снимок ОС, ПО и аппаратуры АРМ.</div>
                    </div>
                    $html_winaudit
                </div>
                <!-- USBDeview -->
                <div class="tool-card">
                    <div>
                        <div class="tool-name">USBDeview NirSoft Report</div>
                        <div class="tool-status">Официальный отчет детального состояния портов и флешек.</div>
                    </div>
                    $html_usbdeview
                </div>
                <!-- HWInfo -->
                <div class="tool-card">
                    <div>
                        <div class="tool-name">HWInfo Hardware Report</div>
                        <div class="tool-status">Технические характеристики процессора, ОЗУ, плат и накопителей.</div>
                    </div>
                    $html_hwinfo
                </div>
                <!-- ScanOval -->
                <div class="tool-card">
                    <div>
                        <div class="tool-name">ScanOval FSTEC Report</div>
                        <div class="tool-status">Отчет сканера уязвимостей ФСТЭК России на базе OVAL.</div>
                    </div>
                    $html_scanoval
                </div>
            </div>
        </div>
    </div>

    <script>
        function toggleTheme() {
            document.body.classList.toggle('light-theme');
        }

        function filterSoftwareTable() {
            var input = document.getElementById("softwareSearch");
            var filter = input.value.toLowerCase();
            var table = document.getElementById("softwareTable");
            var tr = table.getElementsByTagName("tr");
            
            for (var i = 1; i < tr.length; i++) {
                var show = false;
                var tds = tr[i].getElementsByTagName("td");
                for (var j = 0; j < tds.length; j++) {
                    if (tds[j]) {
                        var textValue = tds[j].textContent || tds[j].innerText;
                        if (textValue.toLowerCase().indexOf(filter) > -1) {
                            show = true;
                            break;
                        }
                    }
                }
                tr[i].style.display = show ? "" : "none";
            }
        }

        function filterUsbTable() {
            var input = document.getElementById("usbSearch");
            var filter = input.value.toLowerCase();
            var table = document.getElementById("usbTable");
            var tr = table.getElementsByTagName("tr");
            
            for (var i = 1; i < tr.length; i++) {
                var show = false;
                var tds = tr[i].getElementsByTagName("td");
                for (var j = 0; j < tds.length; j++) {
                    if (tds[j]) {
                        var textValue = tds[j].textContent || tds[j].innerText;
                        if (textValue.toLowerCase().indexOf(filter) > -1) {
                            show = true;
                            break;
                        }
                    }
                }
                tr[i].style.display = show ? "" : "none";
            }
        }
    </script>
</body>
</html>
"@

# Запись отчета в файл
$html | Out-File $ReportFile -Encoding utf8

