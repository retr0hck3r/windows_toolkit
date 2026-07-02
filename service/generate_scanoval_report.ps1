# ============================================================
#    НАТИВНЫЙ OVAL-СКАНЕР ДЛЯ WINDOWS
#    Парсит базу ФСТЭК OVAL через XmlDocument + SelectNodes,
#    сравнивает с реестром Windows, генерирует HTML 1:1 ScanOVAL
# ============================================================
param(
    [string]$OvalXmlPath,
    [string]$OutputHtmlPath,
    [string]$OutputXmlPath = ""
)

$ErrorActionPreference = "Continue"
if (-not $OvalXmlPath -or -not (Test-Path $OvalXmlPath)) {
    Write-Error "OVAL-база не найдена: $OvalXmlPath"; exit 1
}
$startTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

# ── 1. РЕЕСТР WINDOWS: СПИСОК УСТАНОВЛЕННОГО ПО ──────────────
Write-Host "Сбор установленного ПО из реестра Windows..." -ForegroundColor Cyan
$regPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
)
$sw = @{}
foreach ($rp in $regPaths) {
    try {
        Get-ItemProperty -Path $rp -ErrorAction SilentlyContinue |
          Where-Object { $_.DisplayName -and $_.DisplayName.Trim() } |
          ForEach-Object {
              $n = ($_.DisplayName -replace '\s+',' ').Trim().ToLower()
              $v = if ($_.DisplayVersion) { ($_.DisplayVersion).Trim() } else { "" }
              if (-not $sw[$n]) { $sw[$n] = $v }
          }
    } catch {}
}
Write-Host "  Найдено $($sw.Count) записей." -ForegroundColor Gray

# ── 2. ПАРСИНГ OVAL XML (XmlDocument) ────────────────────────
Write-Host "Загрузка OVAL-базы: $(Split-Path $OvalXmlPath -Leaf)  ($([Math]::Round((Get-Item $OvalXmlPath).Length/1MB,1)) МБ)..." -ForegroundColor Cyan
$doc = New-Object System.Xml.XmlDocument
$doc.Load($OvalXmlPath)
$ns = New-Object System.Xml.XmlNamespaceManager($doc.NameTable)
$ns.AddNamespace("def","http://oval.mitre.org/XMLSchema/oval-definitions-5")

$defNodes = $doc.SelectNodes("//def:definition[@class='vulnerability']", $ns)
Write-Host "  Загружено $($defNodes.Count) определений уязвимостей." -ForegroundColor Gray

# ── 3. СОПОСТАВЛЕНИЕ ─────────────────────────────────────────
Write-Host "Сопоставление с реестром Windows..." -ForegroundColor Cyan
$sT = [ordered]@{ "Критический"=0;"Высокий"=0;"Средний"=0;"Низкий"=0;"Не определено"=0 }
$sF = [ordered]@{ "Критический"=0;"Высокий"=0;"Средний"=0;"Низкий"=0;"Не определено"=0 }
$found = [System.Collections.Generic.List[PSObject]]::new()

foreach ($def in $defNodes) {
    # Уровень опасности
    $sevNode = $def.SelectSingleNode("def:metadata/def:bdu/def:severity",$ns)
    $sev = if ($sevNode) { $sevNode.InnerText.Trim() } else { "Не определено" }
    if ($sev -eq "Нет") { $sev = "Низкий" }
    if (-not $sT.Contains($sev)) { $sev = "Не определено" }
    $sT[$sev]++

    # BDU-идентификатор
    $bduId = ""
    foreach ($ref in $def.SelectNodes("def:metadata/def:reference",$ns)) {
        $src = $ref.GetAttribute("source"); $rid = $ref.GetAttribute("ref_id")
        if ($src -eq "FSTEC" -or $rid -like "BDU:*") { $bduId = $rid; break }
    }
    if (-not $bduId) { $bduId = $def.GetAttribute("id") }

    # Название
    $titleNode = $def.SelectSingleNode("def:metadata/def:title",$ns)
    $title = if ($titleNode) { $titleNode.InnerText.Trim() } else { $bduId }

    # Платформы/продукты
    $platforms = $def.SelectNodes("def:metadata/def:affected/*",$ns) | ForEach-Object { $_.InnerText.Trim().ToLower() }

    # Поиск совпадения с установленным ПО
    $hit = ""; $matched = $false
    foreach ($plat in $platforms) {
        $kws = ($plat -split '[\s:]+') | Where-Object { $_.Length -ge 4 }
        foreach ($kw in $kws) {
            $kwc = ($kw -replace '[^a-zA-Zа-яёА-ЯЁ0-9]','').ToLower()
            if ($kwc.Length -lt 4) { continue }
            $h = $sw.Keys | Where-Object { $_ -like "*$kwc*" } | Select-Object -First 1
            if ($h) { $hit = "$h (v$($sw[$h]))"; $matched = $true; break }
        }
        if ($matched) { break }
    }

    if ($matched) {
        $sF[$sev]++
        $found.Add([PSCustomObject]@{ bdu_id=$bduId; severity=$sev; title=$title; package=$hit })
    }
}

$totalFound = $found.Count
$totalDefs  = $defNodes.Count
Write-Host "Найдено $totalFound уязвимостей из $totalDefs." -ForegroundColor Green

# ── 4. HTML-ОТЧЁТ В СТИЛЕ ScanOVAL ──────────────────────────
Write-Host "Генерация HTML-отчёта..." -ForegroundColor Cyan
$rTime  = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$rUuid  = [guid]::NewGuid().ToString()
$sUuid  = [guid]::NewGuid().ToString()
$host_  = $env:COMPUTERNAME

$css = @{
    "Критический"="risk-4"; "Высокий"="risk-3"; "Средний"="risk-2";
    "Низкий"="risk-1"; "Не определено"="risk-0"
}

$summaryRows = ""
foreach ($sv in @("Критический","Высокий","Средний","Низкий","Не определено")) {
    $c=$css[$sv]; $f=$sF[$sv]; $t=$sT[$sv]
    $summaryRows += "<tr><td><span class='$c'>$sv</span></td><td>$f</td><td>$t</td></tr>`n"
}
$summaryRows += "<tr><td><b>Всего</b></td><td><b>$totalFound</b></td><td><b>$totalDefs</b></td></tr>"

$vulnRows = ""
if ($totalFound -eq 0) {
    $vulnRows = "<tr><td colspan='4' style='text-align:center;color:#00705C;padding:16px;font-weight:bold;'>Уязвимости не обнаружены на данном хосте.</td></tr>"
} else {
    $ord = @{"Критический"=0;"Высокий"=1;"Средний"=2;"Низкий"=3;"Не определено"=4}
    foreach ($v in ($found | Sort-Object { $ord[$_.severity] })) {
        $c   = $css[$v.severity]
        $bid = [System.Net.WebUtility]::HtmlEncode($v.bdu_id)
        $tit = [System.Net.WebUtility]::HtmlEncode($v.title)
        $pkg = [System.Net.WebUtility]::HtmlEncode($v.package)
        $vulnRows += "<tr><td>$bid</td><td><span class='$c'>$($v.severity)</span></td><td>$tit</td><td>$pkg</td></tr>`n"
    }
}

$html = @"
<!doctype html><html lang='ru'><head><meta charset='utf-8'>
<title>Отчёт OVAL — $host_</title>
<style>
*{padding:0;margin:0;border:0;font:inherit;background:transparent;text-decoration:none;box-sizing:border-box}
html{background:#fafafa;display:flex;flex-direction:column;align-items:center}
body{flex:1 0 0;width:210mm;min-height:297mm;background:white;font:12px/16px Arial;padding:20px}
table{width:100%;border-collapse:collapse;margin-bottom:16px}
th{background:#f0f0f0;text-align:left;vertical-align:top;padding:6px 10px;border:1px solid #ddd;font-weight:bold}
td{text-align:left;vertical-align:top;padding:6px 10px;border:1px solid #ddd}
.risk-0{background:#777;color:#fff;padding:2px 7px;border-radius:3px;white-space:nowrap}
.risk-1{background:#00705C;color:#fff;padding:2px 7px;border-radius:3px;white-space:nowrap}
.risk-2{background:#F5770F;color:#fff;padding:2px 7px;border-radius:3px;white-space:nowrap}
.risk-3{background:#CC0000;color:#fff;padding:2px 7px;border-radius:3px;white-space:nowrap}
.risk-4{background:#89171A;color:#fff;padding:2px 7px;border-radius:3px;white-space:nowrap}
.header{display:flex;flex-direction:row;justify-content:space-between;align-items:center;background:#fafafa;padding:10px;border:1px solid #ddd;margin-bottom:18px}
.header-title{font-size:14px;font-weight:bold;text-transform:uppercase}
.report td{background:#EFF4FB}
.summary th,.summary td{text-align:center}
.summary tr:last-child td{background:#EFF4FB;font-weight:bold}
.vuln td:nth-child(2){text-align:center}
h3{font-size:13px;font-weight:bold;margin:16px 0 8px}
</style></head><body>
<div class='header'>
  <div class='header-title'>ФСТЭК России — Сканирование уязвимостей</div>
  <div>$host_</div>
</div>
<div class='report'><table>
<tr><th>№ отчёта</th><td>$rUuid</td></tr>
<tr><th>№ сканирования</th><td>$sUuid</td></tr>
<tr><th>Профиль</th><td>Уязвимости (База данных угроз ФСТЭК России)</td></tr>
<tr><th>Имя хоста</th><td>$host_</td></tr>
<tr><th>Начало сканирования</th><td>$startTime</td></tr>
<tr><th>Формирование отчёта</th><td>$rTime</td></tr>
<tr><th>Установленных программ</th><td>$($sw.Count)</td></tr>
</table></div>
<h3>Сводка по уровням опасности:</h3>
<div class='summary'><table>
<thead><tr><th>Уровень опасности</th><th>Найдено</th><th>Всего в базе</th></tr></thead>
<tbody>$summaryRows</tbody></table></div>
<h3>Обнаруженные уязвимости ($totalFound шт.):</h3>
<div class='vuln'><table>
<thead><tr>
  <th style='width:135px'>Идентификатор</th>
  <th style='width:110px'>Опасность</th>
  <th>Название уязвимости</th>
  <th style='width:220px'>Затронутое ПО</th>
</tr></thead>
<tbody>$vulnRows</tbody></table></div>
</body></html>
"@

$html | Out-File -FilePath $OutputHtmlPath -Encoding utf8
Write-Host "[OK] HTML: $OutputHtmlPath" -ForegroundColor Green

# ── 5. XML-РЕЗУЛЬТАТЫ (опционально) ──────────────────────────
if ($OutputXmlPath) {
    $xLines = @('<?xml version="1.0" encoding="UTF-8"?>')
    $xLines += '<oval_results xmlns="http://oval.mitre.org/XMLSchema/oval-results-5">'
    $xLines += "  <generator><product_name>Windows Security Checker</product_name><timestamp>$rTime</timestamp></generator>"
    $xLines += "  <results><system><primary_host_name>$host_</primary_host_name><definitions>"
    foreach ($v in $found) {
        $xLines += "    <definition definition_id=""$($v.bdu_id)"" result=""true"" severity=""$($v.severity)""/>"
    }
    $xLines += "  </definitions></system></results></oval_results>"
    $xLines -join "`r`n" | Out-File -FilePath $OutputXmlPath -Encoding utf8
    Write-Host "[OK] XML: $OutputXmlPath" -ForegroundColor Green
}
