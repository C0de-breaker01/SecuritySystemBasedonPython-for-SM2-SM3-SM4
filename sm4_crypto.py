"""
SM4 加解密模块
==============
功能：基于国密 SM4 算法的对称加解密
"""

import os, sys, base64, warnings
from gmssl.sm4 import CryptSM4, SM4_ENCRYPT, SM4_DECRYPT, PKCS7

# ── 算法常量 ──
SM4_BLOCK_SIZE = 16       # 128 位分组 / IV 长度
SM4_KEY_SIZE = 16          # 128 位密钥
CTR_NONCE_SIZE = 8         # CTR 模式 Nonce 长度（8 字节）
_MAX_FILE_SIZE = 512 * 1024**2  # 文件加解密上限 512 MB（R-11: 可根据实际内存调整）


def _generate_iv() -> bytes:
    """生成 16 字节随机 IV"""
    return os.urandom(SM4_BLOCK_SIZE)


def _generate_sm4_key() -> bytes:
    """生成 16 字节 SM4 密钥"""
    return os.urandom(SM4_KEY_SIZE)


def _parse_hex_input(label: str, raw: str, expected_bytes: int) -> bytes:
    """通用十六进制输入校验 (先清空格、再验长度、再 fromhex)"""
    raw = raw.strip().replace(' ', '').replace('\n', '').replace('\r', '')
    if not raw:
        raise ValueError(f'{label} 不能为空')
    if len(raw) != expected_bytes * 2:
        raise ValueError(f'{label} 长度应为 {expected_bytes*2} 位十六进制（{expected_bytes} 字节），实际输入 {len(raw)} 位')
    try:
        return bytes.fromhex(raw)
    except ValueError as e:
        raise ValueError(f'{label} 包含非法十六进制字符: {e}')


def sm4_encrypt_ecb(key: bytes, plaintext: str) -> str:
    """SM4-ECB 模式加密字符串 — [不安全]

    Args:
        key: 16 字节密钥
        plaintext: 明文字符串

    Returns:
        Base64 编码的密文
    """
    print('! ECB 模式不具备语义安全性！', file=sys.stderr)
    cipher = CryptSM4(mode=SM4_ENCRYPT, padding_mode=PKCS7)
    cipher.set_key(key, SM4_ENCRYPT)
    encrypted = cipher.crypt_ecb(plaintext.encode('utf-8'))
    return base64.b64encode(encrypted).decode('utf-8')


def sm4_decrypt_ecb(key: bytes, ciphertext_b64: str) -> str:
    """SM4-ECB 模式解密字符串 — [不安全]"""
    print('! ECB 模式不具备语义安全性！', file=sys.stderr)
    cipher = CryptSM4(mode=SM4_DECRYPT, padding_mode=PKCS7)
    cipher.set_key(key, SM4_DECRYPT)
    encrypted = base64.b64decode(ciphertext_b64)
    decrypted = cipher.crypt_ecb(encrypted)
    return decrypted.decode('utf-8')


def sm4_encrypt_file_ecb(key: bytes, input_path: str, output_path: str = None):
    """SM4-ECB 模式加密文件 — [不安全]"""
    print('! ECB 模式不具备语义安全性！', file=sys.stderr)
    if output_path is None:
        output_path = input_path + '.enc'
    fsize = os.path.getsize(input_path)
    if fsize > _MAX_FILE_SIZE:
        raise ValueError(f'文件过大 ({fsize/1024**2:.0f} MB)')
    cipher = CryptSM4(mode=SM4_ENCRYPT, padding_mode=PKCS7)
    cipher.set_key(key, SM4_ENCRYPT)
    with open(input_path, 'rb') as f:
        plaintext = f.read()
    encrypted = cipher.crypt_ecb(plaintext)
    with open(output_path, 'wb') as f:
        f.write(encrypted)
    return output_path


def sm4_decrypt_file_ecb(key: bytes, input_path: str, output_path: str = None):
    """SM4-ECB 模式解密文件 — [不安全]"""
    print('! ECB 模式不具备语义安全性！', file=sys.stderr)
    if output_path is None:
        output_path = (input_path[:-4] if input_path.endswith('.enc')
                       else input_path + '.dec')
    fsize = os.path.getsize(input_path)
    if fsize > _MAX_FILE_SIZE:
        raise ValueError(f'文件过大 ({fsize/1024**2:.0f} MB)')
    cipher = CryptSM4(mode=SM4_DECRYPT, padding_mode=PKCS7)
    cipher.set_key(key, SM4_DECRYPT)
    with open(input_path, 'rb') as f:
        encrypted = f.read()
    decrypted = cipher.crypt_ecb(encrypted)
    with open(output_path, 'wb') as f:
        f.write(decrypted)
    return output_path


def sm4_encrypt_cbc(key: bytes, iv: bytes, plaintext: str) -> str:
    """SM4-CBC 模式加密字符串

    使用 PKCS7 填充，符合 GM/T 0002-2012 要求。

    Args:
        key: 16 字节密钥
        iv: 16 字节初始化向量
        plaintext: 明文字符串

    Returns:
        Base64 编码（IV + 密文）。可用 sm4_split_cbc 分离 IV 和密文。
    """
    cipher = CryptSM4(mode=SM4_ENCRYPT, padding_mode=PKCS7)
    cipher.set_key(key, SM4_ENCRYPT)
    encrypted = cipher.crypt_cbc(iv, plaintext.encode('utf-8'))
    return base64.b64encode(iv + encrypted).decode('utf-8')


def sm4_decrypt_cbc(key: bytes, ciphertext_b64: str) -> str:
    """SM4-CBC 模式解密字符串
    此接口按 UTF-8 文本解密。

    Args:
        key: 16 字节密钥
        ciphertext_b64: Base64 编码（IV + 密文）

    Returns:
        明文字符串
    """
    data = base64.b64decode(ciphertext_b64)
    if len(data) < SM4_BLOCK_SIZE:
        raise ValueError('密文格式错误：长度不足（CBC 需至少 16 字节）')
    iv = data[:SM4_BLOCK_SIZE]
    encrypted = data[SM4_BLOCK_SIZE:]
    cipher = CryptSM4(mode=SM4_DECRYPT, padding_mode=PKCS7)
    cipher.set_key(key, SM4_DECRYPT)
    decrypted = cipher.crypt_cbc(iv, encrypted)
    return decrypted.decode('utf-8')


def sm4_split_cbc(combined_b64: str) -> tuple:
    """分离 SM4-CBC 组合格式为 IV 和密文"""
    data = base64.b64decode(combined_b64)
    if len(data) < SM4_BLOCK_SIZE:
        raise ValueError('密文格式错误：长度不足')
    return data[:SM4_BLOCK_SIZE].hex(), base64.b64encode(data[SM4_BLOCK_SIZE:]).decode('utf-8')


def sm4_encrypt_file_cbc(key: bytes, iv: bytes, input_path: str, output_path: str = None):
    """SM4-CBC 模式加密文件（将 IV 写入文件头）

    缺点：gmssl.crypt_cbc 不支持流式处理，全量加载到内存。
         超过 _MAX_FILE_SIZE (512 MB) 的文件将抛 ValueError。

    Args:
        key: 16 字节密钥
        iv: 16 字节初始化向量
        input_path: 输入文件路径
        output_path: 输出文件路径
    """
    if output_path is None:
        output_path = input_path + '.enc'
    fsize = os.path.getsize(input_path)
    if fsize > _MAX_FILE_SIZE:
        raise ValueError(f'文件过大 ({fsize/1024**2:.0f} MB)，超过限制 {_MAX_FILE_SIZE/1024**2:.0f} MB')
    # 流式读取
    buf = bytearray()
    with open(input_path, 'rb') as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            buf.extend(chunk)
    cipher = CryptSM4(mode=SM4_ENCRYPT, padding_mode=PKCS7)
    cipher.set_key(key, SM4_ENCRYPT)
    encrypted = cipher.crypt_cbc(iv, bytes(buf))
    with open(output_path, 'wb') as f:
        f.write(iv + encrypted)
    return output_path


def sm4_decrypt_file_cbc(key: bytes, input_path: str, output_path: str = None):
    """SM4-CBC 模式解密文件（从文件头读取 IV）"""
    if output_path is None:
        output_path = (input_path[:-4] if input_path.lower().endswith('.enc')
                       else input_path + '.dec')
    fsize = os.path.getsize(input_path)
    if fsize > _MAX_FILE_SIZE + SM4_BLOCK_SIZE:
        raise ValueError(f'文件过大 ({fsize/1024**2:.0f} MB)')
    # 流式读取
    buf = bytearray()
    with open(input_path, 'rb') as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            buf.extend(chunk)
    data = bytes(buf)
    iv = data[:SM4_BLOCK_SIZE]
    encrypted = data[SM4_BLOCK_SIZE:]
    cipher = CryptSM4(mode=SM4_DECRYPT, padding_mode=PKCS7)
    cipher.set_key(key, SM4_DECRYPT)
    decrypted = cipher.crypt_cbc(iv, encrypted)
    with open(output_path, 'wb') as f:
        f.write(decrypted)
    return output_path


def sm4_encrypt_ctr(key: bytes, nonce: bytes, plaintext: str) -> str:
    """SM4-CTR 模式加密字符串
    同一密钥下必须保证 Nonce 唯一！Nonce 复用会导致密钥流重用，加密数据完全不安全！

    Counter = nonce(8B) || counter(8B)

    Args:
        key: 16 字节密钥
        nonce: 8 字节随机数
        plaintext: 明文字符串

    Returns:
        Base64 编码（nonce + 密文）
    """
    if len(nonce) != CTR_NONCE_SIZE:
        raise ValueError(f'Nonce 必须为 {CTR_NONCE_SIZE} 字节')

    plain_bytes = plaintext.encode('utf-8')
    result = bytearray()
    cipher = CryptSM4(mode=SM4_ENCRYPT)
    cipher.set_key(key, SM4_ENCRYPT)

    for block_idx in range(0, len(plain_bytes), SM4_BLOCK_SIZE):
        counter_bytes = (block_idx // SM4_BLOCK_SIZE & ((1 << 64) - 1)).to_bytes(8, 'big')
        keystream = cipher.crypt_ecb(bytes(nonce + counter_bytes))
        chunk = plain_bytes[block_idx:block_idx + SM4_BLOCK_SIZE]
        for j in range(len(chunk)):
            result.append(chunk[j] ^ keystream[j])

    return base64.b64encode(nonce + bytes(result)).decode('utf-8')


def sm4_decrypt_ctr(key: bytes, ciphertext_b64: str) -> str:
    """SM4-CTR 模式解密字符串
    此接口按 UTF-8 文本解密。

    Args:
        key: 16 字节密钥
        ciphertext_b64: Base64 编码（nonce + 密文）

    Returns:
        明文字符串
    """
    data = base64.b64decode(ciphertext_b64)
    if len(data) < CTR_NONCE_SIZE + 1:
        raise ValueError('密文格式错误：长度不足（CTR 需至少 9 字节）')
    nonce = data[:CTR_NONCE_SIZE]
    encrypted = data[CTR_NONCE_SIZE:]

    plain_bytes = bytearray()
    # CTR 模式下加解密都是异或 Keystream，统一使用 SM4_ENCRYPT
    cipher = CryptSM4(mode=SM4_ENCRYPT)
    cipher.set_key(key, SM4_ENCRYPT)

    for block_idx in range(0, len(encrypted), SM4_BLOCK_SIZE):
        counter_bytes = (block_idx // SM4_BLOCK_SIZE & ((1 << 64) - 1)).to_bytes(8, 'big')
        keystream = cipher.crypt_ecb(bytes(nonce + counter_bytes))
        chunk = encrypted[block_idx:block_idx + SM4_BLOCK_SIZE]
        for j in range(len(chunk)):
            plain_bytes.append(chunk[j] ^ keystream[j])

    return plain_bytes.decode('utf-8')


def sm4_decrypt_ctr_bytes(key: bytes, ciphertext_b64: str) -> bytes:
    """SM4-CTR 模式解密，返回原始字节"""
    data = base64.b64decode(ciphertext_b64)
    if len(data) < CTR_NONCE_SIZE + 1:
        raise ValueError('密文格式错误：长度不足')
    nonce = data[:CTR_NONCE_SIZE]
    encrypted = data[CTR_NONCE_SIZE:]

    result = bytearray()
    # CTR 模式下加解密相同，用 SM4_ENCRYPT
    cipher = CryptSM4(mode=SM4_ENCRYPT)
    cipher.set_key(key, SM4_ENCRYPT)

    for block_idx in range(0, len(encrypted), SM4_BLOCK_SIZE):
        counter_bytes = (block_idx // SM4_BLOCK_SIZE & ((1 << 64) - 1)).to_bytes(8, 'big')
        keystream = cipher.crypt_ecb(bytes(nonce + counter_bytes))
        chunk = encrypted[block_idx:block_idx + SM4_BLOCK_SIZE]
        for j in range(len(chunk)):
            result.append(chunk[j] ^ keystream[j])

    return bytes(result)


if __name__ == '__main__':
    print("=" * 60)
    print("SM4 加解密工具")
    print("=" * 60)

    while True:
        print("\n请选择操作：")
        print("1. [不安全] SM4-ECB 加密字符串")
        print("2. [不安全] SM4-ECB 解密字符串")
        print("3. SM4-CBC 加密字符串")
        print("4. SM4-CBC 解密字符串")
        print("5. SM4-CTR 加密字符串")
        print("6. SM4-CTR 解密字符串")
        print("7. SM4-CBC 加密文件")
        print("8. SM4-CBC 解密文件")
        print("0. 返回")

        choice = input("\n请输入选项 (0-8): ").strip()

        if choice == '0':
            break
        elif choice == '1':
            key = _parse_hex_input('密钥', input('密钥(32hex): '), SM4_KEY_SIZE)
            plain = input("明文: ")
            print(f"\n密文 (Base64): {sm4_encrypt_ecb(key, plain)}")
        elif choice == '2':
            key = _parse_hex_input('密钥', input('密钥(32hex): '), SM4_KEY_SIZE)
            ct = input("密文 (Base64): ").strip()
            print(f"\n明文: {sm4_decrypt_ecb(key, ct)}")
        elif choice == '3':
            key = _parse_hex_input('密钥', input('密钥(32hex): '), SM4_KEY_SIZE)
            iv_hex = input("IV (32hex, 回车随机): ").strip()
            iv = _parse_hex_input('IV', iv_hex, SM4_BLOCK_SIZE) if iv_hex else _generate_iv()
            plain = input("明文: ")
            ct = sm4_encrypt_cbc(key, iv, plain)
            print(f"\n密文 (Base64): {ct}")
        elif choice == '4':
            key = _parse_hex_input('密钥', input('密钥(32hex): '), SM4_KEY_SIZE)
            ct = input("密文 (Base64): ").strip()
            print(f"\n明文: {sm4_decrypt_cbc(key, ct)}")
        elif choice == '5':
            key = _parse_hex_input('密钥', input('密钥(32hex): '), SM4_KEY_SIZE)
            n_hex = input("Nonce (16hex, 回车随机): ").strip()
            nonce = _parse_hex_input('Nonce', n_hex, CTR_NONCE_SIZE) if n_hex else os.urandom(CTR_NONCE_SIZE)
            plain = input("明文: ")
            ct = sm4_encrypt_ctr(key, nonce, plain)
            print(f"\n密文 (Base64): {ct}")
        elif choice == '6':
            key = _parse_hex_input('密钥', input('密钥(32hex): '), SM4_KEY_SIZE)
            ct = input("密文 (Base64): ").strip()
            print(f"\n明文: {sm4_decrypt_ctr(key, ct)}")
        elif choice == '7':
            key = _parse_hex_input('密钥', input('密钥(32hex): '), SM4_KEY_SIZE)
            in_path = input("文件路径: ").strip()
            iv = _generate_iv()
            out = sm4_encrypt_file_cbc(key, iv, in_path)
            print(f"\n文件加密成功: {out}")
            print(f"IV (hex): {iv.hex()}  ← 请妥善保存")
        elif choice == '8':
            key = _parse_hex_input('密钥', input('密钥(32hex): '), SM4_KEY_SIZE)
            in_path = input("密文文件路径: ").strip()
            out = sm4_decrypt_file_cbc(key, in_path)
            print(f"\n文件解密成功: {out}")
        else:
            print("无效选项，请重新输入")