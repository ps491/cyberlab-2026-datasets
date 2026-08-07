# cyberlab-2026 — 課程實驗資料集（Datasets）

本 repo 是「資安攻防」課程各週實驗用資料集的**公開下載鏡像**，供學生下載使用。

**這裡只有資料集檔案（PCAP、log、範例資料等），不含教師手冊、答案鍵、評分標準——這些內容留在課程的私有 repo 中，不對外公開。**

## 目錄結構

每個資料夾對應課程的一個週次，內容與私有 repo `teaching-assets-cloud/<week>/dataset/` 完全一致：

```
week01_linux/dataset/
week03_pcap/dataset/
week07_sqli/dataset/
week09_password/dataset/
week10_midterm/dataset/
week11_logs/dataset/
week12_incident_response/dataset/
week13_forensics/dataset/
week14_soc/dataset/
```

## 下載方式

- 單一檔案：進入該檔案的頁面，點選右上角 **Download raw file** 按鈕
- 整週打包：見本 repo 的 [Releases](../../releases) 頁面（若有發布）

## 授權

僅供教學使用（internal-education）。內容為課程自製或改編自公開的教學範例資料，若有版權疑慮請與課程維護者聯絡。

## 維護說明（給課程維護者，非學生）

**不要在這個 repo 裡手動編輯檔案。** 唯一內容來源是私有教材 repo 的 `teaching-assets-cloud/<week>/dataset/`，任何更新請在私有 repo 改好後，執行：

```powershell
.\scripts\sync-from-main-repo.ps1
```

同步後檢查 `git status`，確認差異合理再 commit + push。
