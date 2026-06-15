$ErrorActionPreference = 'Stop'

Add-Type -AssemblyName System.Drawing

$iconPath = Join-Path $PSScriptRoot '..\src-tauri\icons\icon.ico'
$pngPath = Join-Path $PSScriptRoot '..\src-tauri\icons\icon.png'

function Draw-PortKillIcon([int]$size, [string]$path) {
    $bitmap = New-Object System.Drawing.Bitmap $size, $size
    $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
    $graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $graphics.Clear([System.Drawing.Color]::FromArgb(247, 212, 74))

    $ink = New-Object System.Drawing.Pen ([System.Drawing.Color]::FromArgb(23, 32, 28)), ([Math]::Max(3, $size / 14))
    $danger = New-Object System.Drawing.Pen ([System.Drawing.Color]::FromArgb(180, 35, 24)), ([Math]::Max(3, $size / 15))
    $fill = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(239, 241, 236))

    $bodyX = [int]($size * 0.25)
    $bodyY = [int]($size * 0.38)
    $bodyW = [int]($size * 0.30)
    $bodyH = [int]($size * 0.26)
    $radius = [int]($size * 0.04)
    $body = New-Object System.Drawing.Rectangle $bodyX, $bodyY, $bodyW, $bodyH
    $graphics.FillRectangle($fill, $body)
    $graphics.DrawRectangle($ink, $body)

    $pinX = $bodyX + $bodyW
    $pinY1 = $bodyY + [int]($bodyH * 0.28)
    $pinY2 = $bodyY + [int]($bodyH * 0.72)
    $pinLen = [int]($size * 0.18)
    $graphics.DrawLine($ink, $pinX, $pinY1, $pinX + $pinLen, $pinY1)
    $graphics.DrawLine($ink, $pinX, $pinY2, $pinX + $pinLen, $pinY2)

    $graphics.DrawLine($danger, [int]($size * 0.28), [int]($size * 0.76), [int]($size * 0.72), [int]($size * 0.32))
    $graphics.DrawLine($danger, [int]($size * 0.72), [int]($size * 0.76), [int]($size * 0.28), [int]($size * 0.32))

    $bitmap.Save($path, [System.Drawing.Imaging.ImageFormat]::Png)
    $graphics.Dispose()
    $bitmap.Dispose()
}

Draw-PortKillIcon 256 $pngPath

$bitmap = [System.Drawing.Bitmap]::FromFile($pngPath)
$handle = $bitmap.GetHicon()
$icon = [System.Drawing.Icon]::FromHandle($handle)
$stream = [System.IO.File]::Open($iconPath, [System.IO.FileMode]::Create)
$icon.Save($stream)
$stream.Close()
$icon.Dispose()
$bitmap.Dispose()

Write-Host "Generated $iconPath"

