# ============================================================
#               TUI ВСПОРМОГАТЕЛЬНЫЕ ФУНКЦИИ (CONSOLE UI)
# ============================================================
# Предоставляет интерактивные меню с управлением стрелками клавиатуры.

# Функция отрисовки меню с навигацией стрелками вверх/вниз
function Show-TuiMenu {
    param(
        [string]$Title,
        [string]$Subtitle,
        [array]$Options,
        [int]$DefaultIndex = 0
    )
    
    $index = $DefaultIndex
    $running = $true
    
    # Скрытие курсора
    $oldCursorVisible = [Console]::CursorVisible
    [Console]::CursorVisible = $false
    
    while ($running) {
        Clear-Host
        Write-Host "========================================================================" -ForegroundColor Cyan
        Write-Host "  $Title" -ForegroundColor Green
        Write-Host "========================================================================" -ForegroundColor Cyan
        if ($Subtitle) {
            Write-Host "  $Subtitle" -ForegroundColor Gray
            Write-Host "------------------------------------------------------------------------" -ForegroundColor Cyan
        }
        Write-Host "  Управление: ↑/↓ - переход, Enter - выбор.`n" -ForegroundColor DarkGray
        
        for ($i = 0; $i -lt $Options.Count; $i++) {
            if ($i -eq $index) {
                # Подсвеченный пункт
                Write-Host "  > $($Options[$i])  " -BackgroundColor Green -ForegroundColor Black
            } else {
                # Обычный пункт
                Write-Host "    $($Options[$i])  " -ForegroundColor Gray
            }
        }
        Write-Host "`n------------------------------------------------------------------------" -ForegroundColor Cyan
        
        $key = [Console]::ReadKey($true)
        switch ($key.Key) {
            "UpArrow" {
                $index = ($index - 1 + $Options.Count) % $Options.Count
            }
            "DownArrow" {
                $index = ($index + 1) % $Options.Count
            }
            "Enter" {
                $running = $false
            }
            "Escape" {
                $index = -1
                $running = $false
            }
        }
    }
    
    [Console]::CursorVisible = $oldCursorVisible
    return $index
}

# Функция вывода интерактивного окна подтверждения [ Да ] / [ Нет ] с навигацией влево/вправо
function Show-TuiConfirm {
    param(
        [string]$Title,
        [string]$Message
    )
    
    $index = 0 # 0 = Да, 1 = Нет
    $running = $true
    
    $oldCursorVisible = [Console]::CursorVisible
    [Console]::CursorVisible = $false
    
    while ($running) {
        Clear-Host
        Write-Host "========================================================================" -ForegroundColor Cyan
        Write-Host "  $Title" -ForegroundColor Green
        Write-Host "========================================================================" -ForegroundColor Cyan
        Write-Host "  $Message`n" -ForegroundColor White
        
        Write-Host "  " -NoNewline
        if ($index -eq 0) {
            Write-Host " [ Да ] " -BackgroundColor Green -ForegroundColor Black -NoNewline
            Write-Host "    [ Нет ]" -ForegroundColor Gray
        } else {
            Write-Host "   [ Да ]" -ForegroundColor Gray -NoNewline
            Write-Host "    [ Нет ] " -BackgroundColor Green -ForegroundColor Black
        }
        Write-Host "`n------------------------------------------------------------------------" -ForegroundColor Cyan
        Write-Host "  Управление: ←/→ - переход, Enter - подтверждение." -ForegroundColor DarkGray
        
        $key = [Console]::ReadKey($true)
        switch ($key.Key) {
            "LeftArrow" { $index = 0 }
            "RightArrow" { $index = 1 }
            "Enter" { $running = $false }
            "Escape" { $index = 1; $running = $false }
        }
    }
    
    [Console]::CursorVisible = $oldCursorVisible
    return ($index -eq 0)
}

# Информационное окно-сообщение
function Show-TuiMessage {
    param(
        [string]$Title,
        [string]$Message
    )
    
    Clear-Host
    Write-Host "========================================================================" -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Green
    Write-Host "========================================================================" -ForegroundColor Cyan
    Write-Host "  $Message`n" -ForegroundColor White
    Write-Host "------------------------------------------------------------------------" -ForegroundColor Cyan
    Read-Host "  Нажмите Enter для продолжения..."
}

