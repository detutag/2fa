# 2FA 驗證器

[English](./README_EN.md)

雲端 2FA 驗證器，支援 Cloudflare Workers 與 Docker 兩種部署方式。
端對端加密、離線可用、跨裝置同步，並可從其他驗證器一鍵遷移。

## 功能特性

- **TOTP / HOTP 生成**：相容 Google Authenticator、Authy 等標準協議；支援自訂位數（6/7/8）、週期（秒）、演算法（SHA-1/256/512）與 HOTP 計數器
- **萬用匯入**：支援 Aegis、2FAS、Ente Auth、Bitwarden、FreeOTP、Raivo、OTP Auth (iOS)、Google Authenticator 遷移資料（`otpauth-migration://`）、`otpauth://` URI 清單與本應用 JSON 備份；匯入前顯示預覽清單，可勾選、自動標記重複與無效項目
- **匯出**：JSON 備份（保留全部參數）或通用 `otpauth://` URI 清單（.txt），方便遷移到其他驗證器
- **雲端同步**：資料儲存於 Cloudflare KV（或 Docker 版 SQLite），跨裝置存取
- **端到端加密**：AES-256-GCM 加密，伺服器只儲存密文
- **零註冊**：無需信箱／手機號，用主密碼即可建立帳戶
- **記住登入狀態**：預設記住登入（可關閉），並提供「閒置自動鎖定」（15 分鐘～7 天／永不，預設 24 小時）
- **PWA 支援**：可安裝到桌面／主畫面，享受原生應用體驗
- **離線使用**：首次登入後支援完全離線存取，資料自動快取 7 天
- **QR code 掃描**：支援相機掃描、圖片上傳、剪貼簿貼上辨識
- **主題**：淺色／深色／跟隨系統，手動切換並記憶偏好
- **隱私模式**：遮蔽畫面上的驗證碼，點擊眼睛圖示可單顆顯示
- **剪貼簿自動清除**：複製驗證碼 60 秒後自動從剪貼簿清除（可開啟）
- **拖曳排序**：桌面版可拖曳金鑰卡片調整順序
- **安全強化**：嚴格 CSP（無 inline script）、登入失敗節流、API 金鑰格式驗證與大小上限、可選 Rate Limiting、完整安全標頭

## 技術架構

支援兩種部署方式：

**Cloudflare Workers 部署**：

```
瀏覽器 <--HTTPS--> Cloudflare Worker <--KV API--> KV 儲存
```

**Docker 部署**：

```
瀏覽器 <--HTTP/HTTPS--> Express Server <--SQLite--> 本機資料庫
```

**安全設計**：

| 面向 | 措施 |
|------|------|
| 資料加密 | AES-256-GCM，客戶端加密後傳輸 |
| 金鑰派生 | PBKDF2-SHA256，600,000 次迭代 |
| 使用者識別 | 密碼雜湊（PBKDF2） |
| 前端安全 | 嚴格 CSP（`script-src 'self'` + hash）、無 inline event handler |
| API 防護 | key 格式驗證（64 位十六進位）、請求大小上限、可選 Rate Limiting binding |
| 跨域 | 僅允許同源（可用 `ALLOWED_ORIGIN` 開放指定來源） |
| 登入防護 | 連續失敗 5 次後指數退避鎖定（30 秒起，上限 5 分鐘） |
| 標頭 | CSP、X-Frame-Options: DENY、X-Content-Type-Options: nosniff、Referrer-Policy、Permissions-Policy |

## 命令速覽

| 目標 | Build 命令 | Deploy / 啟動命令 | 備註 |
|------|-----------|------------------|------|
| Cloudflare Workers（Wrangler） | 無需 build（純靜態 + Worker） | `wrangler deploy` | 本機測試：`wrangler dev` |
| Cloudflare 面板（連接 Git） | 留空（選填欄位） | Deploy command 預設 `npx wrangler deploy` | 見方式三；push 後自動重新部署 |
| Docker | `docker build -t 2fa .` | `docker compose up -d` 或 `docker run …` | 亦可直接拉取現成映像 `l981244680/2fa` |
| 本機 Node（Docker 版後端） | `npm install` | `npm start` | 開發熱重載：`npm run dev` |
| 回歸測試 | — | `npm test` | Node ≥ 18 |

## 部署教學

### 方式一：Docker 部署（推薦）

前置條件：安裝 [Docker](https://docs.docker.com/get-docker/)

#### 使用 Docker Run

```bash
docker run -d \
  --name 2fa-auth \
  -p 3000:3000 \
  -v 2fa-data:/app/data \
  l981244680/2fa:latest

# 瀏覽 http://localhost:3000
```

#### 使用 Docker Compose

建立 `docker-compose.yml` 檔案：

```yaml
services:
  2fa:
    image: l981244680/2fa:latest
    container_name: 2fa-authenticator
    ports:
      - "3000:3000"
    volumes:
      - ./data:/app/data
    restart: unless-stopped
```

然後執行：

```bash
docker compose up -d
```

#### 從原始碼建置

```bash
# build 命令
docker build -t 2fa .

# deploy / 啟動命令
docker run -d \
  --name 2fa-auth \
  -p 3000:3000 \
  -v 2fa-data:/app/data \
  2fa
```

#### 環境變數

| 變數 | 預設值 | 說明 |
|------|--------|------|
| `PORT` | 3000 | HTTP 服務連接埠 |
| `DB_PATH` | `/app/data/2fa.db` | SQLite 資料庫路徑 |
| `ALLOWED_ORIGIN` | （空） | 允許的跨域來源（逗號分隔）；未設定時僅允許同源 |
| `RATE_LIMIT_READS` | 300 | 每 IP 每分鐘讀取請求上限 |
| `RATE_LIMIT_WRITES` | 60 | 每 IP 每分鐘寫入請求上限 |

### 方式二：Cloudflare Workers 部署

#### 前置條件

- [Node.js](https://nodejs.org/) 18+
- [Cloudflare 帳戶](https://dash.cloudflare.com/sign-up)

#### 步驟 1：安裝 Wrangler CLI

```bash
npm install -g wrangler
```

#### 步驟 2：登入 Cloudflare

```bash
wrangler login
```

#### 步驟 3：KV 命名空間（可選）

當 `wrangler.toml` 裡只設定 `binding`（不填 `id`）時，wrangler 會在首次 `wrangler deploy` 時自動建立（或複用）KV 命名空間，重複部署也會綁定到同一個 KV。因此本儲存庫預設可以跳過本步驟。

如果你想手動建立（例如明確指定／複用已有 KV），執行：

```bash
# 進入專案目錄
cd 2fa

# 建立生產環境 KV
wrangler kv namespace create DATA_KV
# 輸出類似：{ binding = "DATA_KV", id = "xxxxxxxxxxxx" }

# 建立預覽環境 KV（可選）
wrangler kv namespace create DATA_KV --preview
# 輸出類似：{ binding = "DATA_KV", preview_id = "yyyyyyyyyyyy" }
```

#### 步驟 4：設定 wrangler.toml

- 自動建立方式：保持 `wrangler.toml` 裡 `[[kv_namespaces]]` 僅包含 `binding`，直接執行 `wrangler deploy`；Wrangler 會自動建立／複用 KV（不會修改 `wrangler.toml`）。
- 手動方式：將上一步輸出的 `id`／`preview_id` 填入 `wrangler.toml`。

`wrangler.toml` 中的 `assets` 設定使用 `run_worker_first = true`，讓 Worker 先處理所有請求，以便為靜態資源附加安全標頭；`[[unsafe.bindings]]` 的 `API_RATE_LIMITER`（ratelimit）為可選的 API 速率限制，若你的環境不支援，註解掉該段即可（worker.js 會自動偵測）。

#### 步驟 5：本機測試

```bash
wrangler dev
# 瀏覽 http://localhost:8787
```

#### 步驟 6：部署

```bash
wrangler deploy
# 輸出類似：Published 2fa-sync (https://2fa-sync.xxx.workers.dev)
```

部署完成後，瀏覽輸出的 URL 即可使用。

### 方式三：Cloudflare 面板部署（連接 Git，免本機 Wrangler）

適合不想在本機安裝 Wrangler 或自架 CI 的情境，全程在 Cloudflare 面板完成：

1. 登入 [Cloudflare 面板](https://dash.cloudflare.com/) → **Workers & Pages** → **Create application**
2. 選擇 **Import an existing Git repository**（連接 GitHub／GitLab），選取本儲存庫
3. 填寫 build 設定（位於 Worker 的 **Settings → Build**）：
   - **Branch**：`main`
   - **Root directory**：留空（儲存庫根目錄，即 `wrangler.toml` 所在位置）
   - **Build command**：**留空**。此欄為選填，僅需要編譯步驟的框架（Next.js、Astro 等）才需填寫；本專案為純靜態檔案 + 純 JS Worker，無任何編譯步驟。若面板預留了預設值（如 `npm run build`），請清空——或保留也無妨：package.json 的 `build` script 為 no-op echo，不會失敗
   - **Deploy command**：保持預設 `npx wrangler deploy` 即可。真正完成部署的是這一步：wrangler 讀取 `wrangler.toml`，上傳 `public/` 靜態資源與 Worker 腳本；Wrangler 版本跟隨 package.json 的 `devDependencies`（已釘 `^4.59.1`）
   - 面板會自動讀取儲存庫中的 `wrangler.toml`：靜態資源目錄（`public/`）、KV binding 等；未填 `id` 的 KV 會在首次部署時自動建立並綁定（Builds 自動產生的 API token 已含 KV 編輯權限）
4. 點擊 **Deploy**，等待 build 完成後瀏覽分配的 `*.workers.dev` 域名
5. 之後每次 push 到 `main`，面板會自動觸發新的 build 與部署（此為 Cloudflare 自家 CI，與 GitHub Actions 相互獨立）
6. 可選設定：
   - **自訂域名**：Worker 頁面 → Settings → Domains & Routes
   - **手動指定 KV**：Workers & Pages → KV → 建立 namespace → 將 ID 填入 `wrangler.toml` 的 `[[kv_namespaces]] id`（不填則自動建立）
   - **速率限制**：`wrangler.toml` 的 `[[ratelimits]]`（`API_RATE_LIMITER`，`namespace_id = "1001"`、每 IP 每 60 秒 100 次）預設啟用；若部署環境不支援 Rate Limiting API，註解掉該段即可（其餘防護仍在）
   - **Worker 名稱**：面板 Builds 會部署到以專案名（repo 名 `2fa`）建立的 Worker；`wrangler.toml` 的 `name` 已設為 `2fa`，使本機 CLI、GitHub Actions 與面板都部署同一個 Worker
   - **沿用舊 KV 資料**：若你之前已有部署過的 Worker 且想保留其中的加密資料，到面板 Workers & Pages → 舊 Worker → Settings → Bindings（或 KV 頁面）複製 namespace ID，填入 `wrangler.toml` 的 `[[kv_namespaces]] id`；留空則會自動建立全新 KV（舊資料不會跟過來）

> 注意：若同時啟用本儲存庫的 GitHub Actions（`deploy-worker.yml`），兩條部署路徑會部署同一個 Worker（名稱 `2fa-sync`）、互相覆蓋，建議只保留一條。

### GitHub Actions 自動部署（可選）

本儲存庫包含一個用於自動部署 Cloudflare Worker 的工作流：

- Deploy Cloudflare Worker：`.github/workflows/deploy-worker.yml` — 在 push 到 `main` 或手動觸發時部署 Worker。需要在儲存庫 Secrets 中設定：`CLOUDFLARE_API_TOKEN` 與 `CLOUDFLARE_ACCOUNT_ID`。

## 使用說明

### 首次使用（建立帳戶）

1. 瀏覽部署後的 URL
2. 點擊「首次使用？建立帳戶」
3. 設定主密碼（至少 8 個字元，需包含字母與數字；畫面會顯示強度計）
4. 確認密碼後點擊「設定密碼」

> ⚠ 密碼即帳戶且無法找回，請務必牢記。

### 登入與記住登入狀態

1. 輸入主密碼
2. 勾選「記住登入狀態」（預設開啟）後點擊「解鎖」
3. 記住登入後，關閉瀏覽器再開啟不需重新輸入密碼；超過「閒置自動鎖定」時間（設定中調整，預設 24 小時）才會要求重新解鎖
4. 連續輸入錯誤 5 次將暫時鎖定（指數退避，最長 5 分鐘）

### 新增 2FA 金鑰

點擊右上角「＋」按鈕，支援三種方式：

**手動輸入**：

1. 輸入名稱（如：GitHub）
2. 輸入 Base32 格式的金鑰
3. 需要時展開「進階選項」：類型（TOTP/HOTP）、位數、週期、演算法、計數器
4. 點擊「新增」

**掃描 QR code**：

1. 切換到「掃描」分頁
2. 點擊「啟動相機」
3. 將 QR code 對準相機，辨識成功後自動填入（支援批量遷移 QR code，會開啟匯入預覽）

**上傳圖片**：

1. 切換到「上傳」分頁
2. 點擊選擇圖片、拖曳圖片或直接貼上截圖
3. 辨識成功後自動填入

### 使用驗證碼

- 點擊卡片任意區域即可複製驗證碼
- 右側圓環顯示剩餘有效時間（預設 30 秒週期）
- HOTP 金鑰顯示計數器與「下一個」按鈕
- 桌面版可拖曳卡片左側的把手圖示重新排序
- 快捷鍵：`/` 聚焦搜尋、`Esc` 關閉對話框

### 匯入其他驗證器的資料

點擊「匯入」並選擇備份檔案（.json 或 .txt），支援：

| 來源應用 | 格式 |
|----------|------|
| 本應用 | JSON v1/v2 |
| Aegis Authenticator | 未加密 JSON 備份 |
| 2FAS Authenticator | 未加密 JSON 備份 |
| Ente Auth | JSON 備份 |
| Bitwarden | JSON 匯出（含 TOTP 欄位） |
| FreeOTP / FreeOTP+ | JSON 備份 |
| Raivo OTP | JSON 備份 |
| OTP Auth (iOS) | JSON 備份 |
| Google Authenticator | 遷移資料（`otpauth-migration://`，含 QR code 掃描） |
| 通用 | `otpauth://` URI 清單（每行一個） |

> 已加密的備份（Aegis/2FAS 加密匯出）無法直接匯入，請先在來源應用選擇「未加密／明文」匯出。

匯入前會顯示預覽清單：可勾選要匯入的項目，重複與無效項目會自動標記並停用。

### 匯出備份

點擊「匯出」，可選擇四種格式：

| 格式 | 相容對象 |
|------|----------|
| **JSON 備份（本應用 v2）** | 本應用來回匯入，保留全部參數（位數、週期、演算法、HOTP 計數器等） |
| **otpauth URI 清單（.txt）** | 通用標準：Aegis／Ente 的 Plain text 匯入、其他支援 URI 的工具；也可逐條轉成 QR code |
| **Aegis 相容 JSON** | Aegis Authenticator「匯入 → Aegis」直接原檔匯入（未加密格式） |
| **2FAS 相容 JSON** | 2FAS Authenticator「從其他應用匯入 → 2FAS」直接原檔匯入 |

> ⚠ 匯出檔案皆為明文，請妥善保管，使用後建議刪除。

### 設定

點擊左上角齒輪圖示：

- **外觀**：跟隨系統／淺色／深色
- **閒置自動鎖定**：15 分鐘／1 小時／4 小時／12 小時／24 小時／3 天／7 天／永不
- **隱私模式**：遮蔽畫面上的驗證碼
- **自動清除剪貼簿**：複製 60 秒後自動清除
- **資料管理**：清除本機離線快取、刪除雲端資料（需輸入「刪除」確認，不可復原）

### 登出

點擊左上角登出按鈕，清除目前工作階段並返回登入畫面。

## 注意事項

1. **密碼不可找回**：忘記密碼將無法恢復資料，請牢記主密碼
2. **密碼即帳戶**：相同密碼 = 相同帳戶，不同裝置用相同密碼登入可同步資料
3. **工作階段**：勾選「記住登入狀態」後關閉瀏覽器不需重新登入；閒置超過自動鎖定時間（預設 24 小時）需重新輸入密碼
4. **離線模式**：首次需連線登入，之後可離線使用（快取有效期 7 天）
5. **資料同步**：離線期間的修改會在連線後自動同步，如有衝突會提示選擇保留哪一份

## 專案結構

```
2fa/
├── .github/
│   └── workflows/
│       ├── deploy-worker.yml   # Worker 自動部署
│       └── docker-publish.yml  # Docker 映像發布
├── public/
│   ├── icons/
│   │   └── icon.svg            # PWA 圖示
│   ├── vendor/
│   │   └── jsQR.js             # 自託管 QR code 辨識函式庫（無外部 CDN 依賴）
│   ├── app.js                  # 前端核心邏輯
│   ├── index.html              # 前端頁面
│   ├── manifest.json           # PWA 清單
│   └── service-worker.js       # Service Worker（離線快取）
├── src/
│   └── server.js               # Docker 版本的 Express 伺服器
├── worker.js                   # Cloudflare Worker
├── wrangler.toml               # Wrangler 設定檔
├── Dockerfile                  # Docker 映像定義
├── docker-compose.yml          # Docker Compose 設定
├── package.json                # npm 依賴設定
└── README.md                   # 本文件
```

## License

MIT
