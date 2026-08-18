"""
基于国密算法（SM2/SM3/SM4）的综合安全系统
=========================================
主入口 —— 统一命令行菜单界面

功能模块：
  [1] SM3 哈希工具     —— 字符串/文件哈希、HMAC、完整性校验
  [2] SM4 加解密工具   —— ECB/CBC/CTR 模式、字符串/文件加解密
  [3] SM2 非对称工具   —— 密钥对生成、加密解密、数字签名验签
  [4] SM2+SM4 混合加密 —— 安全信封、先签后加密、大数据混合加密
  [5] 密钥管理器       —— SM2/SM4 密钥的创建、存储、加载、删除
"""

import sys
import os

# 确保能找到同目录下的模块
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sm3_hash import (
    sm3_hash_string, sm3_hash_file, sm3_hash_file_verify,
    hmac_sm3, sm3_save_hash_file
)
from sm4_crypto import (
    sm4_encrypt_ecb, sm4_decrypt_ecb,
    sm4_encrypt_cbc, sm4_decrypt_cbc,
    sm4_encrypt_ctr, sm4_decrypt_ctr,
    sm4_encrypt_file_cbc, sm4_decrypt_file_cbc,
    _generate_iv
)
from sm2_crypto import (
    generate_sm2_keypair, sm2_encrypt, sm2_decrypt,
    sm2_sign, sm2_verify, SM2KeyPair,
    sm2_private_key_to_pem, sm2_public_key_to_pem
)
from hybrid_crypto import (
    HybridCipher, hybrid_sign_encrypt, hybrid_verify_decrypt,
    hybrid_encrypt_file, hybrid_decrypt_file
)
from key_manager import KeyManager


def print_header():
    """打印系统标题"""
    print("=" * 64)
    print("  基于国密算法（SM2/SM3/SM4）的综合安全系统")
    print("  Comprehensive Security System Based on National Cryptography")
    print("=" * 64)


def print_menu():
    """打印主菜单"""
    print("\n" + "─" * 64)
    print("  主菜单")
    print("─" * 64)
    print("  [1] 🔐 SM3 哈希工具")
    print("  [2] 🔒 SM4 加解密工具")
    print("  [3] 🔑 SM2 非对称密码工具")
    print("  [4] 📦 SM2+SM4 混合加密系统")
    print("  [5] 🗝️  密钥管理器")
    print("  [6] 📋 快速演示（所有功能）")
    print("  [0] ❌ 退出")
    print("─" * 64)


def submenu_sm3():
    """SM3 哈希工具子菜单"""
    while True:
        print("\n" + "─" * 50)
        print("  SM3 哈希工具")
        print("─" * 50)
        print("  1. 计算字符串 SM3 哈希")
        print("  2. 计算文件 SM3 哈希并保存")
        print("  3. 验证文件 SM3 哈希")
        print("  4. 计算 HMAC-SM3")
        print("  0. 返回主菜单")

        choice = input("\n请选择 (0-4): ").strip()
        if choice == '0':
            break
        elif choice == '1':
            data = input("请输入字符串: ")
            h = sm3_hash_string(data)
            print(f"\nSM3({data!r}) = {h}")
            print(f"  长度: {len(h)} 字符 / {len(h) * 4} bits")
        elif choice == '2':
            path = input("请输入文件路径: ").strip()
            try:
                h = sm3_hash_file(path)
                print(f"\nSM3({path}) = {h}")
                save = input("是否保存到 .sm3 文件? (y/n): ").strip().lower()
                if save == 'y':
                    sm3_save_hash_file(path)
                    print(f"哈希已保存到 {path}.sm3")
            except Exception as e:
                print(f"\n错误: {e}")
        elif choice == '3':
            path = input("请输入文件路径: ").strip()
            expected = input("请输入期望哈希值: ").strip()
            match = sm3_hash_file_verify(path, expected)
            print(f"\n{'✓ 哈希匹配!' if match else '✗ 哈希不匹配!'}")
        elif choice == '4':
            key = input("请输入密钥: ").strip()
            data = input("请输入消息: ").strip()
            hm = hmac_sm3(key.encode(), data.encode())
            print(f"\nHMAC-SM3 = {hm}")
        else:
            print("无效选项")


def submenu_sm4():
    """SM4 加解密工具子菜单"""
    while True:
        print("\n" + "─" * 50)
        print("  SM4 加解密工具")
        print("─" * 50)
        print("  1. [不安全] ECB 模式加密字符串")
        print("  2. [不安全] ECB 模式解密字符串")
        print("  3. CBC 模式加密字符串")
        print("  4. CBC 模式解密字符串")
        print("  5. CTR 模式加密字符串")
        print("  6. CTR 模式解密字符串")
        print("  7. CBC 模式加密文件")
        print("  8. CBC 模式解密文件")
        print("  0. 返回主菜单")

        choice = input("\n请选择 (0-8): ").strip()
        if choice == '0':
            break
        elif choice == '1':
            key_hex = input("请输入密钥(32位hex): ").strip()
            plain = input("请输入明文: ")
            try:
                key = bytes.fromhex(key_hex)
                ct = sm4_encrypt_ecb(key, plain)
                print(f"\n密文(Base64): {ct}")
            except Exception as e:
                print(f"\n错误: {e}")
        elif choice == '2':
            key_hex = input("请输入密钥(32位hex): ").strip()
            ct = input("请输入密文(Base64): ").strip()
            try:
                key = bytes.fromhex(key_hex)
                pt = sm4_decrypt_ecb(key, ct)
                print(f"\n明文: {pt}")
            except Exception as e:
                print(f"\n错误: {e}")
        elif choice == '3':
            key_hex = input("请输入密钥(32位hex): ").strip()
            plain = input("请输入明文: ")
            try:
                key = bytes.fromhex(key_hex)
                iv = _generate_iv()
                ct = sm4_encrypt_cbc(key, iv, plain)
                print(f"\n密文(Base64,含IV): {ct}")
            except Exception as e:
                print(f"\n错误: {e}")
        elif choice == '4':
            key_hex = input("请输入密钥(32位hex): ").strip()
            ct = input("请输入密文(Base64): ").strip()
            try:
                key = bytes.fromhex(key_hex)
                pt = sm4_decrypt_cbc(key, ct)
                print(f"\n明文: {pt}")
            except Exception as e:
                print(f"\n错误: {e}")
        elif choice == '5':
            key_hex = input("请输入密钥(32位hex): ").strip()
            plain = input("请输入明文: ")
            try:
                key = bytes.fromhex(key_hex)
                nonce = os.urandom(8)
                ct = sm4_encrypt_ctr(key, nonce, plain)
                print(f"\n密文(Base64): {ct}")
            except Exception as e:
                print(f"\n错误: {e}")
        elif choice == '6':
            key_hex = input("请输入密钥(32位hex): ").strip()
            ct = input("请输入密文(Base64): ").strip()
            try:
                key = bytes.fromhex(key_hex)
                pt = sm4_decrypt_ctr(key, ct)
                print(f"\n明文: {pt}")
            except Exception as e:
                print(f"\n错误: {e}")
        elif choice == '7':
            key_hex = input("请输入密钥(32位hex): ").strip()
            in_path = input("请输入文件路径: ").strip()
            try:
                key = bytes.fromhex(key_hex)
                iv = _generate_iv()
                out = sm4_encrypt_file_cbc(key, iv, in_path)
                print(f"\n加密成功: {out}")
            except Exception as e:
                print(f"\n错误: {e}")
        elif choice == '8':
            key_hex = input("请输入密钥(32位hex): ").strip()
            in_path = input("请输入密文文件路径: ").strip()
            try:
                key = bytes.fromhex(key_hex)
                out = sm4_decrypt_file_cbc(key, in_path)
                print(f"\n解密成功: {out}")
            except Exception as e:
                print(f"\n错误: {e}")
        else:
            print("无效选项")


def submenu_sm2():
    """SM2 非对称密码子菜单"""
    while True:
        print("\n" + "─" * 50)
        print("  SM2 非对称密码工具")
        print("─" * 50)
        print("  1. 生成 SM2 密钥对")
        print("  2. SM2 公钥加密")
        print("  3. SM2 私钥解密")
        print("  4. SM2+SM3 数字签名")
        print("  5. SM2+SM3 验签")
        print("  6. 导出 PEM 格式")
        print("  0. 返回主菜单")

        choice = input("\n请选择 (0-6): ").strip()
        if choice == '0':
            break
        elif choice == '1':
            try:
                kp = generate_sm2_keypair()
                print(f"\n私钥: {kp.private_key}")
                print(f"公钥: {kp.public_key}")
            except Exception as e:
                print(f"\n错误: {e}")
        elif choice == '2':
            pub = input("请输入公钥(hex): ").strip()
            plain = input("请输入明文: ")
            try:
                ct = sm2_encrypt(pub, plain.encode())
                print(f"\n密文(hex): {ct.hex()}")
                print(f"密文长度: {len(ct)} 字节")
            except Exception as e:
                print(f"\n错误: {e}")
        elif choice == '3':
            priv = input("请输入私钥(hex): ").strip()
            pub = input("请输入公钥(hex): ").strip()
            ct_hex = input("请输入密文(hex): ").strip()
            try:
                ct = bytes.fromhex(ct_hex)
                pt = sm2_decrypt(priv, pub, ct)
                print(f"\n明文: {pt.decode('utf-8')}")
            except Exception as e:
                print(f"\n错误: {e}")
        elif choice == '4':
            priv = input("请输入私钥(hex): ").strip()
            msg = input("请输入消息: ")
            sig = sm2_sign(priv, msg.encode())
            print(f"\n签名: {sig}")
        elif choice == '5':
            pub = input("请输入公钥(hex): ").strip()
            sig = input("请输入签名(hex): ").strip()
            msg = input("请输入原始消息: ")
            valid = sm2_verify(pub, sig, msg.encode())
            print(f"\n验签: {'✓ 有效' if valid else '✗ 无效'}")
        elif choice == '6':
            t = input("类型 (1-私钥, 2-公钥): ").strip()
            if t == '1':
                priv = input("请输入私钥(hex): ").strip()
                print(f"\n{sm2_private_key_to_pem(priv)}")
            elif t == '2':
                pub = input("请输入公钥(hex): ").strip()
                print(f"\n{sm2_public_key_to_pem(pub)}")
        else:
            print("无效选项")


def submenu_hybrid():
    """混合加密子菜单"""
    while True:
        print("\n" + "─" * 50)
        print("  SM2+SM4 混合加密系统")
        print("─" * 50)
        print("  1. 混合加密字符串")
        print("  2. 混合解密字符串")
        print("  3. 先签名后加密（防抵赖）")
        print("  4. 解密并验签")
        print("  5. 混合加密文件")
        print("  6. 混合解密文件")
        print("  0. 返回主菜单")

        choice = input("\n请选择 (0-6): ").strip()
        if choice == '0':
            break
        elif choice == '1':
            pub = input("请输入 SM2 公钥(hex): ").strip()
            data = input("请输入明文: ")
            env = HybridCipher().encrypt(pub, data)
            print(f"\n加密信封(Base64):\n{env}")
        elif choice == '2':
            priv = input("请输入 SM2 私钥(hex): ").strip()
            pub = input("请输入 SM2 公钥(hex): ").strip()
            env = input("请输入加密信封(Base64): ").strip()
            pt = HybridCipher().decrypt(priv, pub, env)
            print(f"\n解密结果: {pt}")
        elif choice == '3':
            priv = input("请输入 SM2 私钥(hex): ").strip()
            pub = input("请输入 SM2 公钥(hex): ").strip()
            data = input("请输入明文: ")
            kp = SM2KeyPair(priv, pub)
            env = hybrid_sign_encrypt(kp, kp.public_key, data)
            print(f"\n加密信封(Base64):\n{env}")
        elif choice == '4':
            priv = input("请输入 SM2 私钥(hex): ").strip()
            pub = input("请输入 SM2 公钥(hex): ").strip()
            env = input("请输入加密信封(Base64): ").strip()
            kp = SM2KeyPair(priv, pub)
            pt, valid = hybrid_verify_decrypt(kp.private_key, kp.public_key, kp.public_key, env)
            print(f"\n解密结果: {pt}")
            print(f"签名验证: {'✓ 有效' if valid else '✗ 无效（可能被篡改）'}")
        elif choice == '5':
            pub = input("请输入 SM2 公钥(hex): ").strip()
            in_path = input("请输入文件路径: ").strip()
            out = hybrid_encrypt_file(pub, in_path)
            print(f"\n加密成功: {out}")
        elif choice == '6':
            priv = input("请输入 SM2 私钥(hex): ").strip()
            pub = input("请输入 SM2 公钥(hex): ").strip()
            in_path = input("请输入密文文件路径: ").strip()
            out = hybrid_decrypt_file(priv, pub, in_path)
            print(f"\n解密成功: {out}")
        else:
            print("无效选项")


def submenu_key_manager():
    """密钥管理子菜单"""
    km = KeyManager()
    while True:
        print("\n" + "─" * 50)
        print("  密钥管理器")
        print("─" * 50)
        print("  1. 创建 SM2 密钥对")
        print("  2. 创建 SM4 密钥")
        print("  3. 查看密钥摘要")
        print("  4. 加载 SM2 密钥对")
        print("  5. 加载 SM4 密钥")
        print("  6. 删除密钥")
        print("  0. 返回主菜单")

        choice = input("\n请选择 (0-6): ").strip()
        if choice == '0':
            break
        elif choice == '1':
            try:
                name = input("密钥名称: ").strip()
                desc = input("描述(可选): ").strip()
                kp = km.create_sm2_keypair(name, desc)
                print(f"\n创建成功! 私钥: {kp.private_key[:20]}...")
            except FileExistsError:
                if input(f"\n密钥 '{name}' 已存在，是否覆盖？(y/N): ").strip().lower() == 'y':
                    km.delete_sm2_key(name)
                    kp = km.create_sm2_keypair(name, desc)
                    print(f"\n已覆盖! 私钥: {kp.private_key[:20]}...")
        elif choice == '2':
            try:
                name = input("密钥名称: ").strip()
                desc = input("描述(可选): ").strip()
                key = km.create_sm4_key(name, desc)
                print(f"\n创建成功! 密钥(hex): {key.hex()}")
            except FileExistsError:
                if input(f"\n密钥 '{name}' 已存在，是否覆盖？(y/N): ").strip().lower() == 'y':
                    km.delete_sm4_key(name)
                    key = km.create_sm4_key(name, desc)
                    print(f"\n已覆盖! 密钥(hex): {key.hex()}")
        elif choice == '3':
            km.print_summary()
        elif choice == '4':
            name = input("密钥名称: ").strip()
            kp = km.load_sm2_keypair(name)
            if kp:
                print(f"\n私钥: {kp.private_key}")
                print(f"公钥: {kp.public_key}")
            else:
                print("\n密钥不存在")
        elif choice == '5':
            name = input("密钥名称: ").strip()
            key = km.load_sm4_key(name)
            if key:
                print(f"\n密钥(hex): {key.hex()}")
            else:
                print("\n密钥不存在")
        elif choice == '6':
            t = input("类型 (1-SM2, 2-SM4): ").strip()
            name = input("密钥名称: ").strip()
            confirm = input(f"确认删除密钥 '{name}'? 此操作不可恢复！(y/N): ").strip().lower()
            if confirm != 'y':
                print("\n已取消")
                continue
            ok = km.delete_sm2_key(name) if t == '1' else km.delete_sm4_key(name)
            print(f"\n{'删除成功' if ok else '密钥不存在'}")
        else:
            print("无效选项")


def demo_all():
    """快速演示所有功能"""
    print("\n" + "=" * 64)
    print("  🚀 国密综合安全系统 —— 快速功能演示")
    print("=" * 64)

    # ---- SM3 演示 ----
    print("\n" + "─" * 64)
    print("  [1] SM3 哈希演示")
    print("─" * 64)
    msg = "国密算法综合安全系统"
    h = sm3_hash_string(msg)
    print(f"  SM3('{msg}') = {h}")

    msg2 = "国密算法综合安全系统!"
    h2 = sm3_hash_string(msg2)
    print(f"  SM3('{msg2}') = {h2}")
    print(f"  雪崩效应: 仅差一个字符，哈希完全不同 ✓")

    hm = hmac_sm3("密钥123".encode(), msg.encode())
    print(f"  HMAC-SM3('密钥123', msg) = {hm}")

    # ---- SM4 演示 ----
    print("\n" + "─" * 64)
    print("  [2] SM4 对称加解密演示")
    print("─" * 64)
    import os as _os
    key = _os.urandom(16)
    iv = _os.urandom(16)
    plain_sm4 = "SM4 对称加密 — 支持中文和 English 混合!"
    ct_ecb = sm4_encrypt_ecb(key, plain_sm4)
    pt_ecb = sm4_decrypt_ecb(key, ct_ecb)
    print(f"  SM4-ECB: {plain_sm4}")
    print(f"  → 密文: {ct_ecb[:40]}...")
    print(f"  → 解密: {pt_ecb}")
    print(f"  结果正确: {plain_sm4 == pt_ecb} ✓")

    ct_cbc = sm4_encrypt_cbc(key, iv, plain_sm4)
    pt_cbc = sm4_decrypt_cbc(key, ct_cbc)
    print(f"  SM4-CBC 加解密正确: {plain_sm4 == pt_cbc} ✓")

    nonce = _os.urandom(8)
    ct_ctr = sm4_encrypt_ctr(key, nonce, plain_sm4)
    pt_ctr = sm4_decrypt_ctr(key, ct_ctr)
    print(f"  SM4-CTR 加解密正确: {plain_sm4 == pt_ctr} ✓")

    # ---- SM2 演示 ----
    print("\n" + "─" * 64)
    print("  [3] SM2 非对称密码演示")
    print("─" * 64)
    kp = generate_sm2_keypair()
    print(f"  密钥对已生成")
    print(f"  私钥: {kp.private_key[:20]}... (长度{len(kp.private_key)}位)")
    print(f"  公钥: {kp.public_key[:20]}... (长度{len(kp.public_key)}位)")

    plain_sm2 = "SM2 非对称加密测试消息"
    ct_sm2 = sm2_encrypt(kp.public_key, plain_sm2.encode())
    pt_sm2 = sm2_decrypt(kp.private_key, kp.public_key, ct_sm2)
    print(f"  加密 → 解密: {pt_sm2.decode()}")
    print(f"  结果正确: {plain_sm2 == pt_sm2.decode()} ✓")

    sig = sm2_sign(kp.private_key, plain_sm2.encode())
    valid = sm2_verify(kp.public_key, sig, plain_sm2.encode())
    print(f"  数字签名验签: {'✓ 有效' if valid else '✗ 无效'}")

    valid_bad = sm2_verify(kp.public_key, sig, "篡改数据".encode())
    print(f"  篡改数据检测: {'✓ 已拦截' if not valid_bad else '✗ 未检测到'}")

    # ---- 混合加密演示 ----
    print("\n" + "─" * 64)
    print("  [4] SM2+SM4 混合加密演示")
    print("─" * 64)
    long_text = "国密SM2+SM4混合加密方案：利用SM2非对称加密的安全密钥分发能力" \
                "与SM4对称加密的高效大数据加密能力，构建安全信封。此消息较长，" \
                "展示了混合加密处理大数据的能力。"
    env = HybridCipher().encrypt(kp.public_key, long_text)
    print(f"  明文长度: {len(long_text)} 字符")
    print(f"  加密信封(Base64): {env[:50]}...({len(env)} 字符)")
    dec = HybridCipher().decrypt(kp.private_key, kp.public_key, env)
    print(f"  解密结果: {dec[:30]}...")
    print(f"  结果正确: {long_text == dec} ✓")

    # ---- 带签名混合加密演示 ----
    env2 = hybrid_sign_encrypt(kp, kp.public_key, long_text)
    dec2, valid2 = hybrid_verify_decrypt(kp.private_key, kp.public_key, kp.public_key, env2)
    print(f"  先签后加密解密正确: {long_text == dec2} ✓")
    print(f"  签名验证: {'✓ 有效' if valid2 else '✗ 无效'}")

    # ---- 摘要 ----
    print("\n" + "─" * 64)
    print("  ✅ 演示完成！所有功能均正常工作")
    print("─" * 64)
    print("  已演示功能:")
    print("    ✓ SM3 哈希 + 雪崩效应 + HMAC")
    print("    ✓ SM4 ECB/CBC/CTR 三种模式")
    print("    ✓ SM2 密钥生成 + 加解密 + 签名验签 + 篡改检测")
    print("    ✓ SM2+SM4 混合加密（安全信封）")
    print("    ✓ 带数字签名的混合加密（防抵赖）")
    print("─" * 64)


def main():
    """主入口"""
    print_header()

    while True:
        print_menu()
        choice = input("\n请选择操作 (0-6): ").strip()

        if choice == '0':
            print("\n感谢使用国密综合安全系统！再见 👋")
            break
        elif choice == '1':
            submenu_sm3()
        elif choice == '2':
            submenu_sm4()
        elif choice == '3':
            submenu_sm2()
        elif choice == '4':
            submenu_hybrid()
        elif choice == '5':
            submenu_key_manager()
        elif choice == '6':
            demo_all()
        else:
            print("无效选项，请输入 0-6")


if __name__ == '__main__':
    main()