"""
SM2 + SM4 混合加密模块
======================
功能：SM2 非对称 + SM4 对称混合密码系统
"""

import os, json, base64
from typing import Tuple
from gmssl.sm4 import CryptSM4, SM4_ENCRYPT, SM4_DECRYPT, PKCS7

from sm2_crypto import generate_sm2_keypair, sm2_encrypt, sm2_decrypt, sm2_sign, sm2_verify, SM2KeyPair
from sm4_crypto import _generate_iv, _generate_sm4_key, sm4_decrypt_cbc
from sm3_hash import hmac_sm3


class IntegrityError(ValueError):
    """完整性校验失败"""

class DecryptError(ValueError):
    """解密过程出错"""

# 小文件专用，大文件建议仅 SM4 加密密钥用混合保护
_MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB


class HybridCipher:
    """混合加密器 —— SM2 + SM4"""

    def __init__(self, mode: int = 1):
        self.mode = mode

    def encrypt(self, public_key_hex: str, plaintext: str) -> str:
        """混合加密

        流程：
        1. 生成随机 SM4 会话密钥 + IV
        2. SM4-CBC 加密明文 → raw bytes
        3. SM2 加密密钥材料 (session_key + iv)
        4. HMAC = hmac_sm3(session_key, encrypted_key_b64 + encrypted_data_b64)
           session_key 只有收发双方知晓，攻击者无法伪造 HMAC
        5. 打包 JSON → Base64

        安全信封结构：
        { version, algorithm, encrypted_key_b64, encrypted_data_b64,
          integrity(hmac), mode }
        """
        if len(public_key_hex) < 128:  # 简单格式校验
            raise ValueError('公钥格式错误')

        sk = _generate_sm4_key()
        iv = _generate_iv()

        # SM2 加密密钥材料
        key_payload = json.dumps(
            {'session_key': sk.hex()},
            separators=(',', ':')).encode('utf-8')
        encrypted_key = sm2_encrypt(public_key_hex, key_payload, mode=self.mode)
        encrypted_key_b64 = base64.b64encode(encrypted_key).decode('utf-8')

        # 直接用 gmssl 取 raw bytes，一次 Base64
        cipher = CryptSM4(mode=SM4_ENCRYPT, padding_mode=PKCS7)
        cipher.set_key(sk, SM4_ENCRYPT)
        raw_ct = cipher.crypt_cbc(iv, plaintext.encode('utf-8'))
        encrypted_data_b64 = base64.b64encode(iv + raw_ct).decode('utf-8')

        # HMAC：session_key 为共享秘密，仅收发双方可计算
        integrity = hmac_sm3(sk, (encrypted_key_b64 + encrypted_data_b64).encode('utf-8'))

        envelope = {
            'version': '1.0',
            'algorithm': 'SM2+SM4-CBC',
            'encrypted_key_b64': encrypted_key_b64,
            'encrypted_data_b64': encrypted_data_b64,
            'integrity': integrity,
            'mode': self.mode,
        }
        return base64.b64encode(
            json.dumps(envelope, ensure_ascii=False).encode('utf-8')).decode('utf-8')

    def decrypt(self, private_key_hex: str, public_key_hex: str,
                envelope_b64: str) -> str:
        """混合解密

        流程：
        1. 解析信封
        2. SM2 解密密钥材料 → 获取 session_key + iv
        3. 用 session_key 验证 HMAC
        4. SM4-CBC 解密数据

           先解密密钥材料（32B 短数据），再用 session_key 验完整性
        """
        raw = base64.b64decode(envelope_b64).decode('utf-8')
        env = json.loads(raw)
        if env.get('version', '0.9') != '1.0':
            raise ValueError(f'不支持的版本: {env.get("version")}')

        # SM2 解密密钥材料（短数据，风险可控）
        ek = base64.b64decode(env['encrypted_key_b64'])
        mode = env.get('mode', 1)
        key_payload = sm2_decrypt(private_key_hex, public_key_hex, ek, mode=mode)
        if key_payload is None:
            raise DecryptError('SM2 解密密钥材料失败')
        kd = json.loads(key_payload.decode('utf-8'))
        sk = bytes.fromhex(kd['session_key'])

        # 用 session_key 验证 HMAC
        ed_b64 = env['encrypted_data_b64']
        actual = hmac_sm3(sk, (env['encrypted_key_b64'] + ed_b64).encode('utf-8'))
        if actual.lower() != env['integrity'].lower():
            raise IntegrityError('完整性校验失败：数据已被篡改！')

        # SM4 解密
        return sm4_decrypt_cbc(sk, ed_b64)


def hybrid_sign_encrypt(sender_keypair: SM2KeyPair, receiver_pubkey: str,
                        plaintext: str) -> str:
    """发送方：签名后用接收方公钥加密

    Args:
        sender_keypair:  发送方密钥对（用于签名）
        receiver_pubkey: 接收方公钥（用于加密）
        plaintext:       明文字符串
    """
    msg_bytes = plaintext.encode('utf-8')
    signature = sm2_sign(sender_keypair.private_key, msg_bytes)
    signed = json.dumps({
        'data': plaintext,
        'signature': signature,
    }, ensure_ascii=False)
    return HybridCipher().encrypt(receiver_pubkey, signed)


def hybrid_verify_decrypt(receiver_privkey: str, receiver_pubkey: str,
                          sender_pubkey: str,
                          envelope_b64: str) -> Tuple[str, bool]:
    """接收方：用自己私钥解密，用发送方公钥验签

    Args:
        receiver_privkey: 接收方私钥
        receiver_pubkey:  接收方公钥（用于 HMAC）
        sender_pubkey:    发送方公钥（用于验签）
        envelope_b64:     Base64 安全信封

    Returns:
        (明文, 签名是否有效)
    """
    decrypted = HybridCipher().decrypt(receiver_privkey, receiver_pubkey, envelope_b64)
    sm = json.loads(decrypted)
    plaintext = sm['data']
    signature = sm['signature']
    valid = sm2_verify(sender_pubkey, signature, plaintext.encode('utf-8'))
    return plaintext, valid


def hybrid_encrypt_file(public_key_hex: str, input_path: str,
                        output_path: str = None) -> str:
    """混合加密文件（仅限 50MB 以内小文件）

    缺点：混合加密需全量 Base64 后加密，内存峰值约为文件 3 倍。
    超大文件建议仅用 SM4 加密，混合加密仅保护 SM4 密钥。
    """
    if output_path is None:
        output_path = input_path + '.hEnc'
    fsize = os.path.getsize(input_path)
    if fsize > _MAX_FILE_SIZE:
        raise ValueError(f'文件过大 ({fsize/1024**2:.0f} MB)，小文件混合加密限制 {_MAX_FILE_SIZE/1024**2:.0f} MB')
    buf = bytearray()
    with open(input_path, 'rb') as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            buf.extend(chunk)
    b64 = base64.b64encode(bytes(buf)).decode('utf-8')
    envelope = HybridCipher().encrypt(public_key_hex, b64)
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(envelope)
    return output_path


def hybrid_decrypt_file(private_key_hex: str, public_key_hex: str,
                        input_path: str, output_path: str = None) -> str:
    if output_path is None:
        output_path = input_path[:-5] if input_path.lower().endswith('.henc') else input_path + '.decrypted'
    with open(input_path, 'r', encoding='utf-8') as f:
        envelope = f.read().strip()
    b64 = HybridCipher().decrypt(private_key_hex, public_key_hex, envelope)
    with open(output_path, 'wb') as f:
        f.write(base64.b64decode(b64))
    return output_path


if __name__ == '__main__':
    from sm2_crypto import generate_sm2_keypair
    from sm4_crypto import _parse_hex_input

    print("=" * 60)
    print("SM2 + SM4 混合加密工具")
    print("=" * 60)

    while True:
        print("\n请选择操作：")
        print("1. 生成 SM2 密钥对")
        print("2. 混合加密字符串")
        print("3. 混合解密字符串")
        print("4. [Demo] 先签名后加密")
        print("5. [Demo] 解密并验签")
        print("6. 混合加密文件 (≤50MB)")
        print("7. 混合解密文件")
        print("0. 返回")

        choice = input("\n请输入选项 (0-7): ").strip()

        if choice == '0':
            break
        elif choice == '1':
            kp = generate_sm2_keypair()
            print(f"\n私钥: {kp.private_key}\n公钥: {kp.public_key}")
        elif choice == '2':
            try:
                pub = input("SM2 公钥: ").strip()
                data = input("明文: ")
                print(f"\n{HybridCipher().encrypt(pub, data)}")
            except IntegrityError as e:
                print(f"\n❌ 完整性校验失败: {e}")
            except Exception as e:
                print(f"\n错误: {e}")
        elif choice == '3':
            try:
                priv = _parse_hex_input('私钥', input("SM2 私钥: "), 32)
                pub = _parse_hex_input('公钥', input("SM2 公钥: "), 64)
                env = input("信封 (Base64): ").strip()
                print(f"\n{HybridCipher().decrypt(priv.hex(), pub.hex(), env)}")
            except IntegrityError as e:
                print(f"\n❌ {e}")
            except Exception as e:
                print(f"\n错误: {e}")
        elif choice == '4':
            try:
                sp = _parse_hex_input('发送方私钥', input("发送方私钥: "), 32)
                rp = _parse_hex_input('接收方公钥', input("接收方公钥: "), 64)
                data = input("明文: ")
                # 从私钥计算公钥，保证 SM2KeyPair 完整
                from sm2_crypto import _sm2_point_mul, DEFAULT_ECC_TABLE
                pub = _sm2_point_mul(sp.hex(), DEFAULT_ECC_TABLE['g'])
                skp = SM2KeyPair(sp.hex(), pub)
                env = hybrid_sign_encrypt(skp, rp.hex(), data)
                print(f"\n{env}")
            except Exception as e:
                print(f"\n错误: {e}")
        elif choice == '5':
            try:
                rp = _parse_hex_input('接收方私钥', input("接收方私钥: "), 32)
                rpub = _parse_hex_input('接收方公钥', input("接收方公钥: "), 64)
                sp = _parse_hex_input('发送方公钥', input("发送方公钥: "), 64)
                env = input("信封 (Base64): ").strip()
                pt, ok = hybrid_verify_decrypt(rp.hex(), rpub.hex(), sp.hex(), env)
                print(f"\n{pt}\n验签: {'✓ 有效' if ok else '✗ 无效'}")
            except IntegrityError as e:
                print(f"\n❌ {e}")
            except Exception as e:
                print(f"\n错误: {e}")
        elif choice == '6':
            try:
                pub = input("SM2 公钥: ").strip()
                in_path = input("文件路径: ").strip()
                print(f"\n{hybrid_encrypt_file(pub, in_path)}")
            except Exception as e:
                print(f"\n错误: {e}")
        elif choice == '7':
            try:
                priv = _parse_hex_input('私钥', input("SM2 私钥: "), 32)
                pub = _parse_hex_input('公钥', input("SM2 公钥: "), 64)
                in_path = input("密文文件路径: ").strip()
                print(f"\n{hybrid_decrypt_file(priv.hex(), pub.hex(), in_path)}")
            except IntegrityError as e:
                print(f"\n❌ {e}")
            except Exception as e:
                print(f"\n错误: {e}")
        else:
            print("无效选项")
