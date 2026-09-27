# Shadowrocket Rules

專供 **Shadowrocket（iOS／iPadOS）** 使用的規則集與完整分流設定，衍生自 [Loyalsoldier/surge-rules](https://github.com/Loyalsoldier/surge-rules)。

完整保留上游 **12 個規則分類及檔名**，僅適配 Shadowrocket。所有發布規則均為 Shadowrocket `RULE-SET` 格式，不提供 Surge DOMAIN-SET。原有 [kofttlcc/surge-rules](https://github.com/kofttlcc/surge-rules) 獨立供 Surge 使用。

## 每週更新

GitHub Actions **每週一 09:30（UTC+8；UTC 01:30）** 更新一次，亦支援手動 `Run workflow` 及相關程式／文件變更觸發。

[查看工作流程與執行結果](https://github.com/kofttlcc/shadowrocket-rules/actions/workflows/run.yml)

每次取得上游 `release` 的單一 commit 快照，轉換及驗證成功後發布至本庫 `release`。下載失敗、清單缺失／為空或出現未知格式時停止發布，保留上一版。GitHub 排程可能延遲；公開庫長時間無活動也可能被平台停用排程，以最近成功紀錄為準。

手機端不會隨 GitHub 更新立即刷新；請在 Shadowrocket 啟用規則集自動更新，或重新「使用配置／編譯配置」並檢查結果。

## 完整規則分類

清單不包含策略名稱；在配置的 `RULE-SET` 行指定 `DIRECT`、`PROXY` 或 `REJECT`。分類與檔名沿用上游，沒有合併或省略。

| 分類 | 檔名與下載 | 用途 |
| --- | --- | --- |
| 直連域名 | [direct.txt](https://raw.githubusercontent.com/kofttlcc/shadowrocket-rules/release/ruleset/direct.txt) | 上游直連域名 |
| 代理域名 | [proxy.txt](https://raw.githubusercontent.com/kofttlcc/shadowrocket-rules/release/ruleset/proxy.txt) | 上游代理域名 |
| 廣告域名 | [reject.txt](https://raw.githubusercontent.com/kofttlcc/shadowrocket-rules/release/ruleset/reject.txt) | 廣告封鎖 |
| 私有網路域名 | [private.txt](https://raw.githubusercontent.com/kofttlcc/shadowrocket-rules/release/ruleset/private.txt) | 私有／區域網路域名 |
| Apple | [apple.txt](https://raw.githubusercontent.com/kofttlcc/shadowrocket-rules/release/ruleset/apple.txt) | Apple 中國大陸可直連域名 |
| iCloud | [icloud.txt](https://raw.githubusercontent.com/kofttlcc/shadowrocket-rules/release/ruleset/icloud.txt) | iCloud 域名 |
| Google（慎用） | [google.txt](https://raw.githubusercontent.com/kofttlcc/shadowrocket-rules/release/ruleset/google.txt) | 部分在中國大陸可直連的 Google 域名 |
| GFWList | [gfw.txt](https://raw.githubusercontent.com/kofttlcc/shadowrocket-rules/release/ruleset/gfw.txt) | GFWList 域名 |
| GreatFire | [greatfire.txt](https://raw.githubusercontent.com/kofttlcc/shadowrocket-rules/release/ruleset/greatfire.txt) | 上游已有的 GreatFire 分類 |
| 非中國大陸頂級域名 | [tld-not-cn.txt](https://raw.githubusercontent.com/kofttlcc/shadowrocket-rules/release/ruleset/tld-not-cn.txt) | 非中國大陸使用的頂級域名 |
| Telegram IP | [telegramcidr.txt](https://raw.githubusercontent.com/kofttlcc/shadowrocket-rules/release/ruleset/telegramcidr.txt) | Telegram IPv4／IPv6 |
| 中國大陸 IP | [cncidr.txt](https://raw.githubusercontent.com/kofttlcc/shadowrocket-rules/release/ruleset/cncidr.txt) | 中國大陸 IPv4／IPv6 |

沿用原有目錄模式，同時提供 `release/<檔名>.txt` 與 `release/ruleset/<檔名>.txt`。**兩個位置的內容完全相同，均為 Shadowrocket RULE-SET**；根目錄不再提供 Surge DOMAIN-SET。引用範例：

```ini
[Rule]
RULE-SET,https://raw.githubusercontent.com/kofttlcc/shadowrocket-rules/release/ruleset/proxy.txt,PROXY
```

## 在 iPhone／iPad 匯入完整配置

先在 Shadowrocket 首頁加入自己的節點或訂閱並選擇可用節點。本庫不提供代理伺服器或節點憑證。

| 模式 | 配置下載 | 未命中流量 |
| --- | --- | --- |
| 白名單（沿用上游推薦模式） | [shadowrocket.conf](https://raw.githubusercontent.com/kofttlcc/shadowrocket-rules/release/shadowrocket.conf) | 代理 |
| 黑名單 | [shadowrocket-blacklist.conf](https://raw.githubusercontent.com/kofttlcc/shadowrocket-rules/release/shadowrocket-blacklist.conf) | 直連 |

1. Shadowrocket「配置」→ 右上角「＋」，貼上上表配置網址。
2. 下載後選「使用配置」，完成編譯與遠端清單下載。
3. 首頁「全局路由」選「配置」，選擇可用節點後連線。

`PROXY` 是內建策略，使用首頁選中的節點，無須另建同名策略組。完整配置不會自動合併原有 DNS、重寫或規則，請保留原配置方便切回；已啟用的模組可能覆蓋此配置。

### 白名單模式

沿用上游策略：私有域名直連、廣告拒絕、iCloud／Apple／Google 指定清單直連、代理清單走代理、直連清單直連、Telegram IP 走代理、中國大陸 IP 直連、區域網路直連、其餘走代理。

**Google 清單沿用上游「慎用」標記**，它不是所有 Google 服務的直連清單。為保留原版策略，範例仍設為 `DIRECT`；若所在網路無法直連，可將該行改為 `PROXY`。Apple／iCloud 直連效果亦取決於網路環境。

### 黑名單模式

沿用上游策略：私有域名直連、廣告拒絕、`tld-not-cn`／`gfw` 走代理、Telegram IP 走代理，未命中流量直連。兩種配置均不影響完整 12 個分類的發布；未引用的清單不表示被刪除。

## 僅做客戶端適配

- 保留 `DOMAIN` 與 `DOMAIN-SUFFIX` 的精確／後綴語意，驗證域名並依原序去重。
- IPv6 將 Surge `IP-CIDR6` 轉為 Shadowrocket `IP-CIDR`；IPv4 亦使用 `IP-CIDR`。
- 不為上游 CIDR 任意新增 `no-resolve`，避免改變 IP 分流；來源已有則保留。
- 移除不適用的 `PROCESS-NAME`、Surge `RULE-SET,SYSTEM`／`RULE-SET,LAN`、`force-remote-dns`、`dns-failed`。LAN 用明確網段規則表達；Surge 的系統內建清單沒有逐條等價複製。
- DNS 跟隨系統，啟用 IPv6。不加入解密證書、腳本、重寫或節點資訊。

格式參考：[Shadowrocket 社群維護手冊及範例](https://github.com/LOWERTOP/Shadowrocket)、[Shadowrocket Telegram IP 規則](https://github.com/blackmatrix7/ios_rule_script/blob/master/rule/Shadowrocket/Telegram/Telegram.list)。社群文件並非官方規格。

## 來源追溯與本機建置

`release/metadata.json` 記錄上游 commit、輸入輸出 SHA-256 及規則數量。格式驗證不保證上游每條分類均正確，亦不等同已在你的 iPhone 上實測；匯入後可在日誌檢查命中策略。

主分支保存程式、工作流程與本說明；`release` 保存 12 個分類（根目錄與 ruleset 各一份）、兩種完整配置、README、LICENSE 及 metadata。不要手動修改生成分支。

Python 3.10+，僅使用標準函式庫：

```sh
git clone --depth 1 --branch release https://github.com/Loyalsoldier/surge-rules.git upstream-release
python3 -m unittest discover -s tests -v
python3 scripts/build_shadowrocket.py \
  --source-dir upstream-release \
  --output-dir output \
  --upstream-sha "$(git -C upstream-release rev-parse HEAD)" \
  --repository kofttlcc/shadowrocket-rules
```

## 來源與授權

衍生自 [Loyalsoldier/surge-rules](https://github.com/Loyalsoldier/surge-rules)，保留 [GPL-3.0](LICENSE) 授權。上游資料主要來自 [Loyalsoldier/v2ray-rules-dat](https://github.com/Loyalsoldier/v2ray-rules-dat)、[v2fly/domain-list-community](https://github.com/v2fly/domain-list-community)、[Loyalsoldier/domain-list-custom](https://github.com/Loyalsoldier/domain-list-custom)、[felixonmars/dnsmasq-china-list](https://github.com/felixonmars/dnsmasq-china-list) 與 [Loyalsoldier/geoip](https://github.com/Loyalsoldier/geoip)。本庫每週同步上游已發布快照，不另行更改分類邏輯。
