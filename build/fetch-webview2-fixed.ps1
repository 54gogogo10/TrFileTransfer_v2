# 获取 WebView2 固定版运行时 → build\WebView2FixedRuntime\（离线便携版打包源，见 build.bat）。
#
# 两条路径：
#   1) -CabPath <下载的固定版 cab>   —— 许可最干净：官方 Fixed Version 面向第三方再分发授权，
#      下载页 https://developer.microsoft.com/microsoft-edge/webview2/ → 「固定版本」→ x64。
#   2) 无参                          —— 快照本机已安装的 Evergreen 运行时（目录布局与固定版一致，
#      含 msedgewebview2.exe）。自用/内网分发足够；对外再分发建议走路径 1。
#
# 用法：powershell -NoProfile -ExecutionPolicy Bypass -File build\fetch-webview2-fixed.ps1 [-CabPath xxx.cab]

param([string]$CabPath = "")

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot          # 仓库根
$dest = Join-Path $root "build\WebView2FixedRuntime"

function Find-WebviewExe([string]$dir) {
  Get-ChildItem $dir -Recurse -Filter msedgewebview2.exe -ErrorAction SilentlyContinue |
    Select-Object -First 1
}

# 清掉旧快照，保证版本唯一
if (Test-Path $dest) { Remove-Item $dest -Recurse -Force }

if ($CabPath -ne "") {
  if (!(Test-Path $CabPath)) { throw "cab 不存在: $CabPath" }
  Write-Host "[1/2] 解压固定版 cab ..."
  $tmp = Join-Path $env:TEMP ("trft-fixed-" + [guid]::NewGuid().ToString("N"))
  expand.exe -R $CabPath -F:* $tmp | Out-Null
  $exe = Find-WebviewExe $tmp
  if (!$exe) { throw "cab 中未找到 msedgewebview2.exe（确认下载的是 Fixed Version x64）" }
  New-Item -ItemType Directory -Force -Path $dest | Out-Null
  # cab 解出为 <版本号>\msedgewebview2.exe —— 取该版本目录内容为运行时根
  $src = $exe.Directory.FullName
  if ((Split-Path $src -Leaf) -match '^\d') { $src = Split-Path $src -Parent }
  Copy-Item (Join-Path $src "*") $dest -Recurse -Force
  Remove-Item $tmp -Recurse -Force
} else {
  Write-Host "[1/2] 从本机已安装 Evergreen 快照 ..."
  $cands = @(
    "${env:ProgramFiles(x86)}\Microsoft\EdgeWebView\Application",
    "$env:ProgramFiles\Microsoft\EdgeWebView\Application"
  ) | Where-Object { Test-Path $_ }
  # @() 必须包住管道结果：否则单元素时 $cands 被解包成字符串、[0] 取到首字母。
  $cands = @($cands)
  if (!$cands) { throw "未找到已安装的 WebView2 运行时；请用 -CabPath 提供官方固定版 cab" }
  $ver = Get-ChildItem $cands[0] -Directory |
    Where-Object { $_.Name -match '^\d' } |
    Sort-Object { [version]$_.Name } -Descending | Select-Object -First 1
  if (!$ver -or !(Test-Path (Join-Path $ver.FullName "msedgewebview2.exe"))) { throw "未定位到运行时版本目录" }
  Write-Host ("      源: {0} ({1})" -f $ver.FullName, $ver.Name)
  New-Item -ItemType Directory -Force -Path $dest | Out-Null
  Copy-Item (Join-Path $ver.FullName "*") $dest -Recurse -Force
}

if (!(Test-Path (Join-Path $dest "msedgewebview2.exe"))) { throw "产物校验失败：缺 msedgewebview2.exe" }
$size = [math]::Round((Get-ChildItem $dest -Recurse | Measure-Object Length -Sum).Sum / 1MB)
Write-Host "[2/2] 就绪: $dest (${size} MB)"
Write-Host "      现在 build.bat 会自动打出离线便携版 zip。"
