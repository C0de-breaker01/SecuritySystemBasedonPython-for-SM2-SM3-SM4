"""
SM3 哈希模块
============
功能：基于国密 SM3 算法的哈希计算与完整性校验
"""

import os
import hmac as _hmac
from gmssl import sm3, func

# ── SM3 算法常量 ──
_SM3_BLOCK_SIZE = 64   # 512 bits
_SM3_DIGEST_SIZE = 32  # 256 bits

# 文件哈希限制：gmssl 不支持流式更新，需全量读入内存再计算
_MAX_FILE_SIZE = 1 * 1024**3  # 1 GB


class _SM3Hash:
    """SM3 算法的 hashlib 兼容包装，供标准库 hmac.new() 使用"""
    digest_size = _SM3_DIGEST_SIZE
    block_size = _SM3_BLOCK_SIZE
    name = 'sm3'

    def __init__(self, data=b''):
        self._buf = bytearray()
        if data:
            self.update(data)

    def update(self, data: bytes):
        self._buf.extend(data)

    def digest(self) -> bytes:
        return bytes.fromhex(sm3.sm3_hash(list(self._buf)))

    def hexdigest(self) -> str:
        return sm3.sm3_hash(list(self._buf))

    def copy(self):
        c = _SM3Hash()
        c._buf = bytearray(self._buf)
        return c

    @classmethod
    def new(cls, data=b''):
        return cls(data)


def sm3_hash_string(data: str) -> str:
    """计算字符串的 SM3 哈希值"""
    return sm3.sm3_hash(func.bytes_to_list(data.encode('utf-8')))


def sm3_hash_bytes(data: bytes) -> str:
    """计算字节数据的 SM3 哈希值，返回 64 位十六进制字符串"""
    return sm3.sm3_hash(func.bytes_to_list(data))


def sm3_hash_file(file_path: str) -> str:
    """计算文件的 SM3 哈希值（全量读入内存后计算）

    缺点：
    - gmssl 库不支持流式 update，因此需将整个文件读入内存
    - 文件大小超过 _MAX_FILE_SIZE (1 GB) 时会抛出 ValueError
    - 超大文件需改用支持流式 SM3 的库（如 GmSSL EVP 接口）

    Args:
        file_path: 文件路径

    Returns:
        64 位十六进制哈希值

    Raises:
        FileNotFoundError: 文件不存在
        ValueError: 文件超过大小限制
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"文件不存在: {file_path}")

    fsize = os.path.getsize(file_path)
    if fsize > _MAX_FILE_SIZE:
        raise ValueError(
            f"文件过大 ({fsize / 1024**3:.1f} GB)，超过限制 {_MAX_FILE_SIZE / 1024**3:.0f} GB。"
            f"需改用支持流式 SM3 的库。")

    buf = bytearray()
    with open(file_path, 'rb') as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            buf.extend(chunk)
    return sm3.sm3_hash(list(buf))


def sm3_hash_file_verify(file_path: str, expected_hash: str) -> bool:
    """常量时间验证文件的 SM3 哈希值"""
    actual_hash = sm3_hash_file(file_path)
    return _hmac.compare_digest(actual_hash.lower(), expected_hash.lower())


def hmac_sm3(key: bytes, data: bytes) -> str:
    """计算 HMAC-SM3 消息认证码，返回 64 位十六进制字符串

    使用 Python 标准库 hmac.new()，以 _SM3Hash 作为底层哈希函数，
    遵循 RFC 2104 标准。

    Args:
        key:  密钥（bytes）
        data: 消息（bytes）

    Returns:
        64 位十六进制 HMAC 值
    """
    return _hmac.new(key, data, digestmod=_SM3Hash).hexdigest()


def hmac_sm3_verify(key: bytes, data: bytes, expected: str) -> bool:
    """验证 HMAC-SM3 消息认证码（常量时间比较）

    Args:
        key:      密钥
        data:     消息
        expected: 期望的 HMAC 值（64 位十六进制字符串）

    Returns:
        True 如果匹配，否则 False
    """
    actual = hmac_sm3(key, data)
    return _hmac.compare_digest(actual, expected)


def sm3_file_integrity_check(file_path: str, hash_file_path: str = None) -> dict:
    """文件完整性校验

    计算或验证文件的 SM3 哈希值。

    Args:
        file_path: 待检查的文件路径
        hash_file_path: 哈希文件路径。如果提供，会读取并与计算值比对。
                        如果为 None，仅计算并返回哈希值。

    Returns:
        dict: {
            'file': 文件名,
            'hash': 计算得到的 SM3 哈希值,
            'expected': 期望的哈希值（如果提供了 hash_file_path）,
            'match': 是否匹配（如果提供了 hash_file_path）
        }
    """
    result = {
        'file': os.path.basename(file_path),
        'hash': sm3_hash_file(file_path),
        'expected': None,
        'match': None
    }

    if hash_file_path and os.path.exists(hash_file_path):
        with open(hash_file_path, 'r') as f:
            result['expected'] = f.read().strip()
        result['match'] = _hmac.compare_digest(
            result['hash'].lower(), result['expected'].lower())

    return result


def sm3_save_hash_file(file_path: str, hash_file_path: str = None) -> str:
    """计算文件哈希并保存到 .sm3 文件

    Args:
        file_path: 目标文件路径
        hash_file_path: 哈希文件保存路径。为 None 时自动在同目录生成 .sm3 文件

    Returns:
        保存的哈希文件路径
    """
    if hash_file_path is None:
        hash_file_path = file_path + '.sm3'

    file_hash = sm3_hash_file(file_path)
    with open(hash_file_path, 'w') as f:
        f.write(file_hash)

    return hash_file_path


if __name__ == '__main__':
    import sys

    print("=" * 60)
    print("SM3 哈希工具")
    print("=" * 60)

    while True:
        print("\n请选择操作：")
        print("1. 计算字符串 SM3 哈希")
        print("2. 计算文件 SM3 哈希")
        print("3. 验证文件 SM3 哈希")
        print("4. 计算 HMAC-SM3")
        print("5. 生成并保存文件哈希")
        print("0. 返回")

        choice = input("\n请输入选项 (0-5): ").strip()

        if choice == '0':
            break
        elif choice == '1':
            data = input("请输入字符串: ")
            result = sm3_hash_string(data)
            print(f"\nSM3 哈希值: {result}")
            print(f"长度: {len(result)} 位十六进制 | {len(result) * 4} bits")
        elif choice == '2':
            path = input("请输入文件路径: ").strip()
            try:
                result = sm3_hash_file(path)
                print(f"\n文件 SM3 哈希值: {result}")
            except Exception as e:
                print(f"\n错误: {e}")
        elif choice == '3':
            path = input("请输入文件路径: ").strip()
            expected = input("请输入期望的哈希值: ").strip()
            match = sm3_hash_file_verify(path, expected)
            print(f"\n哈希验证: {'✓ 匹配' if match else '✗ 不匹配'}")
        elif choice == '4':
            key = input("请输入密钥: ").strip()
            data = input("请输入消息: ").strip()
            result = hmac_sm3(key.encode(), data.encode())
            print(f"\nHMAC-SM3: {result}")
        elif choice == '5':
            path = input("请输入文件路径: ").strip()
            try:
                hash_path = sm3_save_hash_file(path)
                print(f"\n哈希已保存到: {hash_path}")
            except Exception as e:
                print(f"\n错误: {e}")
        else:
            print("无效选项，请重新输入")