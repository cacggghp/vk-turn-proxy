# Получаем default gateway (IPv4)
$gateway = Get-NetRoute `
    -DestinationPrefix "0.0.0.0/0" `
    | Sort-Object RouteMetric `
    | Select-Object -First 1 -ExpandProperty NextHop

if (-not $gateway) {
    Write-Error "Не удалось определить default gateway"
    exit 1
}

Write-Host "Default gateway: $gateway"

# Читаем адреса из stdin
$input | ForEach-Object {
    $addr = $_.Trim()
    if ($addr -eq "") { return }

    if ($addr -notmatch '^\d{1,3}(\.\d{1,3}){3}$') {
        Write-Warning "Пропускаем неожиданный ввод: $addr"
        return
    }

    $prefix = "$addr/32"
    $existingRoutes = @(Get-NetRoute `
        -DestinationPrefix $prefix `
        -PolicyStore ActiveStore `
        -ErrorAction SilentlyContinue)

    if ($existingRoutes | Where-Object { $_.NextHop -eq $gateway }) {
        Write-Host "Маршрут к $addr через $gateway уже существует"
        return
    }

    if ($existingRoutes.Count -gt 0) {
        Write-Host "Обновляем маршрут к $addr через $gateway"
        $existingRoutes | Remove-NetRoute -Confirm:$false -ErrorAction Stop
    } else {
        Write-Host "Добавляем маршрут к $addr через $gateway"
    }

    New-NetRoute `
        -DestinationPrefix $prefix `
        -NextHop $gateway `
        -PolicyStore ActiveStore `
        -ErrorAction Stop | Out-Null
}

