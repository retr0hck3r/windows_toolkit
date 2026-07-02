# ============================================================
#               Р“Р•РќР•Р РђРўРћР  HTML-РћРўР§Р•РўРћР’ Р‘Р•Р—РћРџРђРЎРќРћРЎРўР
# ============================================================
# РљРѕРјРїРёР»РёСЂСѓРµС‚ РІСЃРµ СЃРѕР±СЂР°РЅРЅС‹Рµ РґР°РЅРЅС‹Рµ Р°СѓРґРёС‚Р° РІ РµРґРёРЅС‹Р№ РєСЂР°СЃРёРІС‹Р№
# РёРЅС‚РµСЂР°РєС‚РёРІРЅС‹Р№ HTML-С„Р°Р№Р» СЃ РїРѕРґРґРµСЂР¶РєРѕР№ РїРµСЂРµРєР»СЋС‡РµРЅРёСЏ С‚РµРј.

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

# Р’СЃРїРѕРјРѕРіР°С‚РµР»СЊРЅР°СЏ С„СѓРЅРєС†РёСЏ РєРѕРґРёСЂРѕРІР°РЅРёСЏ HTML
function Get-HtmlEncoded {
    param([string]$str)
    if (-not $str) { return "" }
    return $str.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;").Replace('"', "&quot;").Replace("'", "&#39;")
}

# Р’С‹С‡РёСЃР»РµРЅРёРµ РїСЂРѕС†РµРЅС‚РѕРІ СЃРѕРѕС‚РІРµС‚СЃС‚РІРёСЏ
$percent = [Math]::Round($score * 100 / $totalChecks)
$dashStroke = [Math]::Round(2 * [Math]::PI * 50) # Р”Р»РёРЅР° РѕРєСЂСѓР¶РЅРѕСЃС‚Рё РґР»СЏ gauge (r=50) -> ~314
$dashOffset = [Math]::Round($dashStroke - ($percent / 100 * $dashStroke))

# РћРїСЂРµРґРµР»РµРЅРёРµ РјРѕРґРµР»Рё РїСЂРѕС†РµСЃСЃРѕСЂР° Рё РћР—РЈ РґР»СЏ С…РµРґРµСЂР°
$cpu = (Get-CimInstance Win32_Processor).Name
$ram = [Math]::Round((Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum / 1GB)
$os = (Get-CimInstance Win32_OperatingSystem).Caption
$sn = (Get-CimInstance Win32_Bios).SerialNumber
if (-not $sn -or $sn -eq "System Serial Number" -or $sn -eq "To be filled by O.E.M.") {
    $sn = (Get-CimInstance Win32_ComputerSystemProduct).IdentifyingNumber
}
$sn = If ($sn) { $sn } else { "РќРµ РѕРїСЂРµРґРµР»РµРЅ" }

# РЎР±РѕСЂ СЃС‚СЂРѕРє РїСЂРѕРіСЂР°РјРјРЅРѕРіРѕ РѕР±РµСЃРїРµС‡РµРЅРёСЏ
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

# РЎР±РѕСЂ СЃС‚СЂРѕРє USB-СѓСЃС‚СЂРѕР№СЃС‚РІ
$usbRows = ""
foreach ($dev in $usbDevices) {
    $dName = Get-HtmlEncoded $dev.Device
    $dFriendly = Get-HtmlEncoded $dev.FriendlyName
    $dDesc = Get-HtmlEncoded $dev.Description
    $dSerial = Get-HtmlEncoded $dev.Serial
    $usbRows += "<tr><td><b>$dFriendly</b></td><td>$dName</td><td><code>$dSerial</code></td><td>$dDesc</td></tr>`n"
}

# РЎР±РѕСЂ РІРЅРµС€РЅРёС… С„Р°Р№Р»РѕРІ РѕС‚С‡РµС‚РѕРІ
$winauditExists = Test-Path (Join-Path $ReportDir "winaudit_report.html")
$usbdeviewExists = Test-Path (Join-Path $ReportDir "usbdeview_report.html")
$hwinfoExists = Test-Path (Join-Path $ReportDir "hwinfo_report.txt")
$scanovalExists = Test-Path (Join-Path $ReportDir "scanoval_report.html")

# Р—Р°РїРёСЃСЊ С€Р°Р±Р»РѕРЅР° HTML-РѕС‚С‡РµС‚Р°
$html = @"
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>РћС‚С‡РµС‚ Рѕ Р·Р°С‰РёС‰РµРЅРЅРѕСЃС‚Рё РђР Рњ Windows - $env:COMPUTERNAME</title>
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
                    <h1>РћС‚С‡РµС‚ Рѕ Р·Р°С‰РёС‰РµРЅРЅРѕСЃС‚Рё РђР Рњ Windows</h1>
                    <p style="color: var(--text-muted); font-size: 0.9rem; margin-top: 0.25rem;">РђРћ РќРР В«Р РЈР‘РРќВ» вЂў Р’РЅСѓС‚СЂРµРЅРЅРёР№ РєРѕРЅС‚СЂРѕР»СЊ Р·Р°С‰РёС‰РµРЅРЅРѕСЃС‚Рё РђРЎ</p>
                </div>
                <div class="btn-group">
                    <button class="theme-toggle" onclick="toggleTheme()">вЂпёЏ РўРµРјР°</button>
                    <button class="print-btn" onclick="window.print()">рџ–ЁпёЏ РџРµС‡Р°С‚СЊ</button>
                </div>
            </div>
            
            <div class="meta-grid">
                <div class="meta-item">
                    <span>РРјСЏ РєРѕРјРїСЊСЋС‚РµСЂР°</span>
                    <strong>$env:COMPUTERNAME</strong>
                </div>
                <div class="meta-item">
                    <span>РћРїРµСЂР°С†РёРѕРЅРЅР°СЏ СЃРёСЃС‚РµРјР°</span>
                    <strong>$os</strong>
                </div>
                <div class="meta-item">
                    <span>РЎРµСЂРёР№РЅС‹Р№ РЅРѕРјРµСЂ</span>
                    <strong>$sn</strong>
                </div>
                <div class="meta-item">
                    <span>РџСЂРѕС†РµСЃСЃРѕСЂ Рё РћР—РЈ</span>
                    <strong>$cpu, $ram Р“Р‘</strong>
                </div>
                <div class="meta-item">
                    <span>Р”Р°С‚Р° РїСЂРѕРІРµСЂРєРё</span>
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
                <div class="score-label">РљР»Р°СЃСЃ Р·Р°С‰РёС‰РµРЅРЅРѕСЃС‚Рё: $targetClass</div>
                <p style="font-size: 0.8rem; color: var(--text-muted); margin-top: 0.25rem;">РџСЂРѕР№РґРµРЅРѕ С‚РµСЃС‚РѕРІ: $score РёР· $totalChecks</p>
            </div>

            <div class="szi-card">
                <div class="szi-title">РЎРїРµС†РёР°Р»РёР·РёСЂРѕРІР°РЅРЅРѕРµ РЎР—Р РѕС‚ РќРЎР”</div>
                <div>
                    <strong>Р¦РµР»РµРІРѕРµ РЎР—Р:</strong> $($sziStatus.Name)<br>
                    <strong>РЎС‚Р°С‚СѓСЃ СѓСЃС‚Р°РЅРѕРІРєРё:</strong> $((If ($sziStatus.Installed) { "РЈСЃС‚Р°РЅРѕРІР»РµРЅРѕ" } else { "РќРµ РЅР°Р№РґРµРЅРѕ" }))<br>
                    <strong>РЎРѕСЃС‚РѕСЏРЅРёРµ Р·Р°С‰РёС‚С‹:</strong>
                    <div class="szi-status-badge $((If ($sziStatus.Active) { "badge-active" } else { "badge-inactive" }))" style="margin-top: 0.5rem;">
                        $((If ($sziStatus.Active) { "РЎР»СѓР¶Р±С‹ РђРєС‚РёРІРЅС‹" } else { "РћС‚РєР»СЋС‡РµРЅРѕ / РќРµРґРѕСЃС‚СѓРїРЅРѕ" }))
                    </div>
                    <p style="font-size: 0.85rem; color: var(--text-muted);">$($sziStatus.Details)</p>
                </div>
            </div>
        </div>

        <!-- Compliance Checks Section -->
        <div class="section-panel">
            <div class="section-title">РљРѕРЅС‚СЂРѕР»СЊ СЃРѕРѕС‚РІРµС‚СЃС‚РІРёСЏ С‚СЂРµР±РѕРІР°РЅРёСЏРј Р±РµР·РѕРїР°СЃРЅРѕСЃС‚Рё Р¤РЎРўР­Рљ</div>
            <table>
                <thead>
                    <tr>
                        <th style="width: 80px; text-align: center;">РЎС‚Р°С‚СѓСЃ</th>
                        <th>РўСЂРµР±РѕРІР°РЅРёРµ Р±РµР·РѕРїР°СЃРЅРѕСЃС‚Рё</th>
                        <th>Р¤Р°РєС‚РёС‡РµСЃРєРѕРµ Р·РЅР°С‡РµРЅРёРµ</th>
                        <th>Р­С‚Р°Р»РѕРЅ РґР»СЏ РєР»Р°СЃСЃР° $targetClass</th>
                    </tr>
                </thead>
                <tbody>
                    <!-- Р”Р»РёРЅР° РїР°СЂРѕР»СЏ -->
                    <tr>
                        <td class="status-cell $((If ($cur_len -ge $std.req_len) { "status-ok" } else { "status-fail" }))">$((If ($cur_len -ge $std.req_len) { "OK" } else { "FAIL" }))</td>
                        <td>РњРёРЅРёРјР°Р»СЊРЅР°СЏ РґР»РёРЅР° РїР°СЂРѕР»СЏ
                            $((If ($cur_len -ge $std.req_len) { "" } else { "<div class='recommendation'>РќР°СЃС‚СЂРѕР№С‚Рµ РјРёРЅРёРјР°Р»СЊРЅСѓСЋ РґР»РёРЅСѓ РїР°СЂРѕР»СЏ РІ secpol.msc РёР»Рё GPO.</div>" }))
                        </td>
                        <td>$cur_len</td>
                        <td>&gt;= $($std.req_len)</td>
                    </tr>
                    <!-- РСЃС‚РѕСЂРёСЏ РїР°СЂРѕР»РµР№ -->
                    <tr>
                        <td class="status-cell $((If ($cur_hist -ge $std.req_hist) { "status-ok" } else { "status-fail" }))">$((If ($cur_hist -ge $std.req_hist) { "OK" } else { "FAIL" }))</td>
                        <td>РҐСЂР°РЅРµРЅРёРµ РёСЃС‚РѕСЂРёРё РїР°СЂРѕР»РµР№
                            $((If ($cur_hist -ge $std.req_hist) { "" } else { "<div class='recommendation'>Р’РєР»СЋС‡РёС‚Рµ С…СЂР°РЅРµРЅРёРµ РёСЃС‚РѕСЂРёРё РїР°СЂРѕР»РµР№ (РїРѕРІС‚РѕСЂСЏРµРјРѕСЃС‚СЊ).</div>" }))
                        </td>
                        <td>$cur_hist</td>
                        <td>&gt;= $($std.req_hist)</td>
                    </tr>
                    <!-- РњР°РєСЃ СЃСЂРѕРє РґРµР№СЃС‚РІРёСЏ -->
                    <tr>
                        <td class="status-cell $((If ($cur_max_days -le $std.req_max_days) { "status-ok" } else { "status-fail" }))">$((If ($cur_max_days -le $std.req_max_days) { "OK" } else { "FAIL" }))</td>
                        <td>РњР°РєСЃРёРјР°Р»СЊРЅС‹Р№ СЃСЂРѕРє РґРµР№СЃС‚РІРёСЏ РїР°СЂРѕР»СЏ (РґРЅ.)
                            $((If ($cur_max_days -le $std.req_max_days) { "" } else { "<div class='recommendation'>РћРіСЂР°РЅРёС‡СЊС‚Рµ РјР°РєСЃРёРјР°Р»СЊРЅС‹Р№ СЃСЂРѕРє РґРµР№СЃС‚РІРёСЏ РїР°СЂРѕР»РµР№.</div>" }))
                        </td>
                        <td>$cur_max_days</td>
                        <td>&lt;= $($std.req_max_days)</td>
                    </tr>
                    <!-- Р§РёСЃР»Рѕ РїРѕРїС‹С‚РѕРє РґРѕ Р±Р»РѕРєРёСЂРѕРІРєРё -->
                    <tr>
                        <td class="status-cell $((If ($std.req_deny -eq 0 -or ($cur_deny -gt 0 -and $cur_deny -le $std.req_deny)) { "status-ok" } else { "status-fail" }))">$((If ($std.req_deny -eq 0 -or ($cur_deny -gt 0 -and $cur_deny -le $std.req_deny)) { "OK" } else { "FAIL" }))</td>
                        <td>Р§РёСЃР»Рѕ РїРѕРїС‹С‚РѕРє РІС…РѕРґР° РґРѕ Р±Р»РѕРєРёСЂРѕРІРєРё
                            $((If ($std.req_deny -eq 0 -or ($cur_deny -gt 0 -and $cur_deny -le $std.req_deny)) { "" } else { "<div class='recommendation'>РќР°СЃС‚СЂРѕР№С‚Рµ РїРѕСЂРѕРі Р±Р»РѕРєРёСЂРѕРІРєРё СѓС‡РµС‚РЅС‹С… Р·Р°РїРёСЃРµР№.</div>" }))
                        </td>
                        <td>$cur_deny</td>
                        <td>&lt;= $($std.req_deny)</td>
                    </tr>
                    <!-- Р’СЂРµРјСЏ Р±Р»РѕРєРёСЂРѕРІРєРё -->
                    <tr>
                        <td class="status-cell $((If ($std.req_unlock_time -eq 0 -or ($cur_unlock_time -ge $std.req_unlock_time)) { "status-ok" } else { "status-fail" }))">$((If ($std.req_unlock_time -eq 0 -or ($cur_unlock_time -ge $std.req_unlock_time)) { "OK" } else { "FAIL" }))</td>
                        <td>Р’СЂРµРјСЏ Р°РІС‚РѕСЂР°Р·Р±Р»РѕРєРёСЂРѕРІРєРё Р°РєРєР°СѓРЅС‚Р° (СЃРµРє)
                            $((If ($std.req_unlock_time -eq 0 -or ($cur_unlock_time -ge $std.req_unlock_time)) { "" } else { "<div class='recommendation'>РќР°СЃС‚СЂРѕР№С‚Рµ РІСЂРµРјСЏ Р°РІС‚РѕРјР°С‚РёС‡РµСЃРєРѕР№ СЂР°Р·Р±Р»РѕРєРёСЂРѕРІРєРё.</div>" }))
                        </td>
                        <td>$cur_unlock_time</td>
                        <td>&gt;= $($std.req_unlock_time)</td>
                    </tr>
                    <!-- РўР°Р№РјР°СѓС‚ СЃРµСЃСЃРёРё -->
                    <tr>
                        <td class="status-cell $((If ($std.req_tmout -eq 0 -or ($cur_tmout -gt 0 -and $cur_tmout -le $std.req_tmout)) { "status-ok" } else { "status-fail" }))">$((If ($std.req_tmout -eq 0 -or ($cur_tmout -gt 0 -and $cur_tmout -le $std.req_tmout)) { "OK" } else { "FAIL" }))</td>
                        <td>РўР°Р№РјР°СѓС‚ РЅРµР°РєС‚РёРІРЅРѕСЃС‚Рё СЃРµСЃСЃРёРё (СЃРµРє)
                            $((If ($std.req_tmout -eq 0 -or ($cur_tmout -gt 0 -and $cur_tmout -le $std.req_tmout)) { "" } else { "<div class='recommendation'>РќР°СЃС‚СЂРѕР№С‚Рµ РѕРіСЂР°РЅРёС‡РµРЅРёРµ РЅРµР°РєС‚РёРІРЅРѕСЃС‚Рё СЃРµСЃСЃРёРё РёР»Рё Р·Р°СЃС‚Р°РІРєРё.</div>" }))
                        </td>
                        <td>$cur_tmout</td>
                        <td>&lt;= $($std.req_tmout)</td>
                    </tr>
                    <!-- РћС‡РёСЃС‚РєР° С„Р°Р№Р»Р° РїРѕРґРєР°С‡РєРё -->
                    <tr>
                        <td class="status-cell $((If ($std.req_swap -eq "optional" -or $cur_swap -eq $std.req_swap) { "status-ok" } else { "status-fail" }))">$((If ($std.req_swap -eq "optional" -or $cur_swap -eq $std.req_swap) { "OK" } else { "FAIL" }))</td>
                        <td>РћС‡РёСЃС‚РєР° РІРёСЂС‚СѓР°Р»СЊРЅРѕР№ РїР°РјСЏС‚Рё (Pagefile)
                            $((If ($std.req_swap -eq "optional" -or $cur_swap -eq $std.req_swap) { "" } else { "<div class='recommendation'>Р’РєР»СЋС‡РёС‚Рµ ClearPageFileAtShutdown РІ СЂРµРµСЃС‚СЂРµ Windows.</div>" }))
                        </td>
                        <td>$cur_swap</td>
                        <td>$($std.req_swap)</td>
                    </tr>
                    <!-- Р—Р°С‰РёС‚Р° LSA -->
                    <tr>
                        <td class="status-cell $((If ($std.req_ptrace -eq "optional" -or $cur_ptrace -eq $std.req_ptrace) { "status-ok" } else { "status-fail" }))">$((If ($std.req_ptrace -eq "optional" -or $cur_ptrace -eq $std.req_ptrace) { "OK" } else { "FAIL" }))</td>
                        <td>Р—Р°С‰РёС‚Р° РїРѕРґСЃРёСЃС‚РµРјС‹ LSA (RunAsPPL)
                            $((If ($std.req_ptrace -eq "optional" -or $cur_ptrace -eq $std.req_ptrace) { "" } else { "<div class='recommendation'>Р’РєР»СЋС‡РёС‚Рµ РґРѕРїРѕР»РЅРёС‚РµР»СЊРЅСѓСЋ Р·Р°С‰РёС‚Сѓ РїСЂРѕС†РµСЃСЃРѕРІ LSA.</div>" }))
                        </td>
                        <td>$cur_ptrace</td>
                        <td>$($std.req_ptrace)</td>
                    </tr>
                    <!-- Р‘Р»РѕРєРёСЂРѕРІРєР° РєРѕРЅСЃРѕР»Рё -->
                    <tr>
                        <td class="status-cell $((If ($std.req_console -eq "optional" -or $cur_console -eq $std.req_console) { "status-ok" } else { "status-fail" }))">$((If ($std.req_console -eq "optional" -or $cur_console -eq $std.req_console) { "OK" } else { "FAIL" }))</td>
                        <td>Р‘Р»РѕРєРёСЂРѕРІРєР° СЌРєСЂР°РЅР° РїР°СЂРѕР»РµРј РїСЂРё Р·Р°СЃС‚Р°РІРєРµ
                            $((If ($std.req_console -eq "optional" -or $cur_console -eq $std.req_console) { "" } else { "<div class='recommendation'>РќР°СЃС‚СЂРѕР№С‚Рµ РѕР±СЏР·Р°С‚РµР»СЊРЅС‹Р№ РІРІРѕРґ РїР°СЂРѕР»СЏ РїСЂРё РІРѕР·РІСЂР°С‚Рµ РёР· СЃРЅР°/Р·Р°СЃС‚Р°РІРєРё.</div>" }))
                        </td>
                        <td>$cur_console</td>
                        <td>$($std.req_console)</td>
                    </tr>
                    <!-- РЎРёСЃС‚РµРјРЅС‹Р№ Р°СѓРґРёС‚ -->
                    <tr>
                        <td class="status-cell $((If ($std.req_audit -eq "optional" -or $cur_audit -eq "Р’РєР»СЋС‡РµРЅ" -or $cur_audit -like "*СЃС‚СЂРѕРіРёРµ*") { "status-ok" } else { "status-fail" }))">$((If ($std.req_audit -eq "optional" -or $cur_audit -eq "Р’РєР»СЋС‡РµРЅ" -or $cur_audit -like "*СЃС‚СЂРѕРіРёРµ*") { "OK" } else { "FAIL" }))</td>
                        <td>Р РµР¶РёРј СЃРёСЃС‚РµРјРЅРѕРіРѕ Р°СѓРґРёС‚Р°
                            $((If ($std.req_audit -eq "optional" -or $cur_audit -eq "Р’РєР»СЋС‡РµРЅ" -or $cur_audit -like "*СЃС‚СЂРѕРіРёРµ*") { "" } else { "<div class='recommendation'>Р’РєР»СЋС‡РёС‚Рµ РїРѕР»РёС‚РёРєРё Р°СѓРґРёС‚Р° Р±РµР·РѕРїР°СЃРЅРѕСЃС‚Рё (auditpol.exe).</div>" }))
                        </td>
                        <td>$cur_audit</td>
                        <td>$($std.req_audit)</td>
                    </tr>
                </tbody>
            </table>
        </div>

        <!-- USB History Section -->
        <div class="section-panel">
            <div class="section-title">РСЃС‚РѕСЂРёСЏ РїРѕРґРєР»СЋС‡РµРЅРЅС‹С… USB-СѓСЃС‚СЂРѕР№СЃС‚РІ С…СЂР°РЅРµРЅРёСЏ (Р РµРµСЃС‚СЂ USBSTOR)</div>
            <input type="text" id="usbSearch" class="search-box" placeholder="РџРѕРёСЃРє РїРѕ РёРјРµРЅРё, СЃРµСЂРёР№РЅРѕРјСѓ РЅРѕРјРµСЂСѓ РёР»Рё РѕРїРёСЃР°РЅРёСЋ..." onkeyup="filterUsbTable()">
            <div class="table-container">
                <table id="usbTable">
                    <thead>
                        <tr>
                            <th>РРјСЏ (Friendly Name)</th>
                            <th>РРјСЏ СѓСЃС‚СЂРѕР№СЃС‚РІР°</th>
                            <th>РЎРµСЂРёР№РЅС‹Р№ РЅРѕРјРµСЂ</th>
                            <th>РћРїРёСЃР°РЅРёРµ СЂРµРµСЃС‚СЂР°</th>
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
                <span>РЎРѕСЃС‚Р°РІ СѓСЃС‚Р°РЅРѕРІР»РµРЅРЅРѕРіРѕ РџРћ ($installedSoftwareCount РїРѕР·РёС†РёР№)</span>
                <a href="installed_software.txt" class="action-btn" target="_blank" style="font-size: 0.75rem; padding: 0.25rem 0.5rem;">РћС‚РєСЂС‹С‚СЊ TXT</a>
            </div>
            <input type="text" id="softwareSearch" class="search-box" placeholder="РџРѕРёСЃРє РџРћ РїРѕ РЅР°Р·РІР°РЅРёСЋ, РІРµСЂСЃРёРё РёР»Рё РёР·РґР°С‚РµР»СЋ..." onkeyup="filterSoftwareTable()">
            <div class="table-container">
                <table id="softwareTable">
                    <thead>
                        <tr>
                            <th>РќР°Р·РІР°РЅРёРµ РїСЂРѕРіСЂР°РјРјРЅРѕРіРѕ РѕР±РµСЃРїРµС‡РµРЅРёСЏ</th>
                            <th>Р’РµСЂСЃРёСЏ</th>
                            <th>РР·РґР°С‚РµР»СЊ</th>
                            <th>Р”Р°С‚Р° СѓСЃС‚Р°РЅРѕРІРєРё</th>
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
            <div class="section-title">РћС‚С‡РµС‚С‹ РІРЅРµС€РЅРёС… РґРёР°РіРЅРѕСЃС‚РёС‡РµСЃРєРёС… СѓС‚РёР»РёС‚</div>
            <div class="tool-grid">
                <!-- WinAudit -->
                <div class="tool-card">
                    <div>
                        <div class="tool-name">WinAudit System Report</div>
                        <div class="tool-status">РЎРѕРґРµСЂР¶РёС‚ РїРѕР»РЅС‹Р№ СЃРЅРёРјРѕРє РћРЎ, РџРћ Рё Р°РїРїР°СЂР°С‚СѓСЂС‹ РђР Рњ.</div>
                    </div>
                    $((If ($winauditExists) { "<a href='winaudit_report.html' class='action-btn' target='_blank' style='border-color: var(--status-pass); color: var(--status-pass);'>РћС‚РєСЂС‹С‚СЊ HTML</a>" } else { "<span style='color: var(--text-muted); font-size: 0.85rem;'>РћС‚С‡РµС‚ РѕС‚СЃСѓС‚СЃС‚РІСѓРµС‚ (СѓС‚РёР»РёС‚Р° РЅРµ Р·Р°РїСѓСЃРєР°Р»Р°СЃСЊ)</span>" }))
                </div>
                <!-- USBDeview -->
                <div class="tool-card">
                    <div>
                        <div class="tool-name">USBDeview NirSoft Report</div>
                        <div class="tool-status">РћС„РёС†РёР°Р»СЊРЅС‹Р№ РѕС‚С‡РµС‚ РґРµС‚Р°Р»СЊРЅРѕРіРѕ СЃРѕСЃС‚РѕСЏРЅРёСЏ РїРѕСЂС‚РѕРІ Рё С„Р»РµС€РµРє.</div>
                    </div>
                    $((If ($usbdeviewExists) { "<a href='usbdeview_report.html' class='action-btn' target='_blank' style='border-color: var(--status-pass); color: var(--status-pass);'>РћС‚РєСЂС‹С‚СЊ HTML</a>" } else { "<span style='color: var(--text-muted); font-size: 0.85rem;'>РћС‚С‡РµС‚ РѕС‚СЃСѓС‚СЃС‚РІСѓРµС‚ (СѓС‚РёР»РёС‚Р° РЅРµ Р·Р°РїСѓСЃРєР°Р»Р°СЃСЊ)</span>" }))
                </div>
                <!-- HWInfo -->
                <div class="tool-card">
                    <div>
                        <div class="tool-name">HWInfo Hardware Report</div>
                        <div class="tool-status">РўРµС…РЅРёС‡РµСЃРєРёРµ С…Р°СЂР°РєС‚РµСЂРёСЃС‚РёРєРё РїСЂРѕС†РµСЃСЃРѕСЂР°, РћР—РЈ, РїР»Р°С‚ Рё РЅР°РєРѕРїРёС‚РµР»РµР№.</div>
                    </div>
                    $((If ($hwinfoExists) { "<a href='hwinfo_report.txt' class='action-btn' target='_blank' style='border-color: var(--status-pass); color: var(--status-pass);'>РћС‚РєСЂС‹С‚СЊ TXT</a>" } else { "<span style='color: var(--text-muted); font-size: 0.85rem;'>РћС‚С‡РµС‚ РѕС‚СЃСѓС‚СЃС‚РІСѓРµС‚ (СѓС‚РёР»РёС‚Р° РЅРµ Р·Р°РїСѓСЃРєР°Р»Р°СЃСЊ)</span>" }))
                </div>
                <!-- ScanOval -->
                <div class="tool-card">
                    <div>
                        <div class="tool-name">ScanOval FSTEC Report</div>
                        <div class="tool-status">РћС‚С‡РµС‚ СЃРєР°РЅРµСЂР° СѓСЏР·РІРёРјРѕСЃС‚РµР№ Р¤РЎРўР­Рљ Р РѕСЃСЃРёРё РЅР° Р±Р°Р·Рµ OVAL.</div>
                    </div>
                    $((If ($scanovalExists) { "<a href='scanoval_report.html' class='action-btn' target='_blank' style='border-color: var(--status-pass); color: var(--status-pass);'>РћС‚РєСЂС‹С‚СЊ HTML</a>" } else { "<span style='color: var(--text-muted); font-size: 0.85rem;'>РћС‚С‡РµС‚ РѕС‚СЃСѓС‚СЃС‚РІСѓРµС‚ (СѓС‚РёР»РёС‚Р° РЅРµ Р·Р°РїСѓСЃРєР°Р»Р°СЃСЊ)</span>" }))
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

# Р—Р°РїРёСЃСЊ РѕС‚С‡РµС‚Р° РІ С„Р°Р№Р»
$html | Out-File $ReportFile -Encoding utf8


