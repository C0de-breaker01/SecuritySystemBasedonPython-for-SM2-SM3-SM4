# 基于国密算法（SM2/SM3/SM4）的综合安全系统

> **开发语言**：Python 3.11+  
> **依赖库**：gmssl 3.2, pycryptodomex 3.23, PyInstaller 6.21

---

## 功能模块

| 模块 | 文件 | 功能 |
|------|------|------|
| SM3 哈希 | `sm3_hash.py` | 字符串/文件哈希、HMAC-SM3、完整性校验 |
| SM4 加解密 | `sm4_crypto.py` | ECB/CBC/CTR 模式、字符串/文件加解密 |
| SM2 非对称密码 | `sm2_crypto.py` | 密钥对生成、加解密、数字签名、PKCS#8 PEM |
| SM2+SM4 混合加密 | `hybrid_crypto.py` | 安全信封、先签后加密、文件加解密 |
| 密钥管理 | `key_manager.py` | 密钥创建/存储/加载/删除（APPDATA 持久化） |
| 图形界面 | `gui.py` | Tkinter 5 标签页交互界面 |
| 命令行界面 | `main.py` | 交互式菜单 + 快速演示 |

---

## 快速开始

### 方式一：直接运行可执行文件

```
dist/国密安全系统.exe
```

密钥存储位置：`%APPDATA%\国密安全系统\keys\`

### 方式二：源码运行

```bash
# 安装依赖
pip install -r requirements.txt

# 启动图形界面
python gui.py

# 启动命令行界面
python main.py

# 快速功能演示
python -c "from main import demo_all; demo_all()"
```

### 方式三：编译可执行文件

```bash
pip install pyinstaller
pyinstaller --onefile --windowed --name 国密安全系统 gui.py
```

---

## 项目结构

```
coursedesign/crypto/
├── gui.py                   # Tkinter 图形界面（5 标签页）
├── main.py                  # 命令行菜单界面
├── sm3_hash.py              # SM3 哈希模块
├── sm4_crypto.py            # SM4 加解密模块
├── sm2_crypto.py            # SM2 非对称密码模块
├── hybrid_crypto.py         # SM2+SM4 混合加密模块
├── key_manager.py           # 密钥管理模块
├── requirements.txt         # Python 依赖清单
└── dist/
    └── 国密安全系统.exe     # 编译好的可执行文件
```

---

## 架构设计

```
┌───────────────────────────────────────────────────┐
│  gui.py (Tkinter)        main.py (CLI)            │  ← 用户界面层
├───────────────────────────────────────────────────┤
│  sm3_hash.py  sm4_crypto.py  sm2_crypto.py        │  ← 算法功能层
│  hybrid_crypto.py  key_manager.py                 │
├───────────────────────────────────────────────────┤
│  gmssl (SM2/SM3/SM4)  pycryptodomex (ASN.1 DER)   │  ← 密码库层
└───────────────────────────────────────────────────┘
```

---

## 安全声明

### 合规声明

本系统底层使用 **PyPI gmssl 库**，该库**未通过**国家密码管理局商用密码产品认证。  
在金融、政务、涉密等需要通过商用密码测评的场景中，请替换为国密局核准的 SDK

### ECB 模式警告

SM4 **ECB 模式**是密码学反模式——相同明文块生成相同密文块，完全丧失语义安全性。
本系统保留 ECB 模式仅用于**学习对比**，调用时会输出 stderr 警告：
```
⚠️ ECB 模式不具备语义安全性，禁止用于生产环境！
```

### 混合加密文件限制

混合加密（SM2+SM4）需要对文件进行全量 Base64 编码后加密，内存峰值约为文件大小的 3 倍。
文件加密功能限制为 **50 MB 以内**。超大文件建议仅用 SM4 加密，混合加密仅保护 SM4 密钥。

---

## 免责声明

本系统为**密码学课程设计作品**，仅供学习、研究和教学目的使用。

1. **不提供安全性保证**：本系统未经过独立安全审计，可能存在未知漏洞。请勿用于保护真实敏感数据。
2. **不承担任何责任**：作者不对因使用本系统导致的任何直接或间接损失承担责任，包括但不限于数据泄露、数据丢失、系统损坏等。
3. **无商业适用性**：本系统不保证适用于任何特定用途，不提供任何明示或暗示的担保。
4. **第三方依赖**：本系统依赖的第三方库（gmssl、pycryptodomex 等）。
5. **国密合规**：本系统未通过国家密码管理局商用密码产品认证，不得用于等保/密评合规场景。

---

## 参考文献

1. 国家密码管理局. GM/T 0002-2012 SM4 分组密码算法[S]. 2012.
2. 国家密码管理局. GM/T 0003-2012 SM2 椭圆曲线公钥密码算法[S]. 2012.
3. 国家密码管理局. GM/T 0004-2012 SM3 密码杂凑算法[S]. 2012.
4. 王小云, 于红波. SM3 密码杂凑算法[J]. 信息安全研究, 2016.
5. 吕述望, 苏波展, 王鹏, 等. SM4 分组密码算法综述[J]. 信息安全研究, 2016.
6. 汪朝晖, 张振峰. SM2 椭圆曲线公钥密码算法综述[J]. 信息安全研究, 2016.
7. gmssl 库文档. https://github.com/duanhongyi/gmssl
8. Krawczyk H, Bellare M, Canetti R. HMAC: Keyed-Hashing for Message Authentication. RFC 2104, 1997.

---

## 许可

本项目仅用于教学目的。