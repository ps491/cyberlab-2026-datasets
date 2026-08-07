# 從主教材 repo（private）同步各週 dataset/ 到這個 public dataset-only repo。
#
# 用途：teaching-assets-cloud/ 裡每一週的 dataset/ 資料夾是唯一的內容來源（source of truth）。
# 這個 repo 只放同步出來的成品，不要在這裡手動編輯任何檔案——否則下次同步會被覆蓋，
# 也會製造出「哪一份才是最新版」的問題（教訓見主 repo 的
# feedback-worktree-divergence-cloud-materials 記憶）。
#
# 用法：
#   .\scripts\sync-from-main-repo.ps1
#   .\scripts\sync-from-main-repo.ps1 -MainRepoPath "D:\other\path\網路攻防"

param(
    [string]$MainRepoPath = "C:\Users\beshine\Documents\網路攻防"
)

$SourceRoot = Join-Path $MainRepoPath "teaching-assets-cloud"
$DestRoot = Split-Path -Parent $PSScriptRoot

if (-not (Test-Path $SourceRoot)) {
    Write-Error "找不到來源目錄：$SourceRoot"
    exit 1
}

$weekDirs = Get-ChildItem -Path $SourceRoot -Directory | Where-Object {
    Test-Path (Join-Path $_.FullName "dataset")
}

Write-Host "=== 同步 $($weekDirs.Count) 週的 dataset/ ==="

foreach ($week in $weekDirs) {
    $src = Join-Path $week.FullName "dataset"
    $dst = Join-Path $DestRoot "$($week.Name)\dataset"

    Write-Host "  $($week.Name) ..."
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $dst) | Out-Null

    # /MIR：destination 與 source 完全鏡像（含刪除 dest 多出的檔案），確保不會留下已從主 repo 移除的舊檔
    # robocopy 的 exit code 0-7 都代表成功（1 = 有檔案被複製），只有 >=8 才是真正失敗
    robocopy $src $dst /MIR /NFL /NDL /NJH /NJS | Out-Null
    if ($LASTEXITCODE -ge 8) {
        Write-Error "  同步 $($week.Name) 失敗（robocopy exit code $LASTEXITCODE）"
    }
}
$global:LASTEXITCODE = 0

Write-Host ""
Write-Host "=== 同步完成 ==="
Write-Host "接下來請自行檢查 git status、確認差異合理後再 commit + push。"
