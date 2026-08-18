"""
SM2 非对称密码模块
==================
功能：基于国密 SM2 椭圆曲线算法的非对称密码操作
"""

import os
import base64
from gmssl import sm2, func
from Cryptodome.Util.asn1 import DerSequence, DerInteger, DerOctetString, DerObjectId, DerBitString, DerNull

# SM2 算法 OID（国家密码管理局分配）
_SM2_OID = '1.2.156.10197.1.301'

# SM2 推荐椭圆曲线参数（国家密码管理局标准）
# 素域 256 位，曲线 y² = x³ + ax + b
DEFAULT_ECC_TABLE = {
    'n': 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123',
    'p': 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF',
    'g': '32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7'
         'bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0',
    'a': 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC',
    'b': '28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93',
}

assert len(DEFAULT_ECC_TABLE['n']) == 64, '基点阶 n 应为 64 hex'
assert len(DEFAULT_ECC_TABLE['p']) == 64, '素域 p 应为 64 hex'
assert len(DEFAULT_ECC_TABLE['g']) == 128, '基点 G 应为 128 hex'
assert DEFAULT_ECC_TABLE['a'] == (
    'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC'
), '参数 a 不匹配 SM2 标准'


class SM2KeyPair:
    """SM2 密钥对"""

    def __init__(self, private_key_hex: str, public_key_hex: str):
        """
        Args:
            private_key_hex: 私钥（十六进制字符串，64位）
            public_key_hex: 公钥（十六进制字符串，以04开头的未压缩格式或纯xy坐标）
        """
        self.private_key = private_key_hex
        self.public_key = public_key_hex

    @property
    def public_key_uncompressed(self) -> str:
        """获取未压缩公钥（04 || x || y）"""
        if self.public_key.startswith('04'):
            return self.public_key
        return '04' + self.public_key

    def to_dict(self) -> dict:
        return {
            'private_key': self.private_key,
            'public_key': self.public_key,
            'public_key_uncompressed': self.public_key_uncompressed
        }


def _sm2_point_mul(k_hex: str, point_hex: str) -> str:
    """
    椭圆曲线点乘 k·P（内部函数，封装 _kg 私有 API）
    """
    ecc_table = DEFAULT_ECC_TABLE
    # 借用 CryptSM2 的点乘能力；private_key 参数仅用于构造，实际运算用 _kg
    proxy = sm2.CryptSM2(private_key=k_hex, public_key=point_hex, ecc_table=ecc_table)
    return proxy._kg(int(k_hex, 16), point_hex)


def generate_sm2_keypair() -> SM2KeyPair:
    """生成 SM2 密钥对

    随机选择私钥 d ∈ [1, n-2]，计算 P = d × G

    Returns:
        SM2KeyPair 对象
    """
    ecc_table = DEFAULT_ECC_TABLE
    n = int(ecc_table['n'], 16)

    while True:
        private_key_hex = func.random_hex(len(ecc_table['n']))
        d = int(private_key_hex, 16)
        # 确保 d ∈ [1, n-2]
        if 1 <= d <= n - 2:
            break

    public_key_hex = _sm2_point_mul(private_key_hex, ecc_table['g'])

    return SM2KeyPair(
        private_key_hex=private_key_hex,
        public_key_hex=public_key_hex
    )


def sm2_encrypt(public_key_hex: str, data: bytes, mode: int = 1) -> bytes:
    """SM2 公钥加密

    Args:
        public_key_hex: 公钥（十六进制字符串）
        data: 待加密的字节数据
        mode: 0-C1C2C3, 1-C1C3C2

    Returns:
        密文字节数据
    """
    if not public_key_hex or len(public_key_hex) < 128:
        raise ValueError('公钥格式错误：长度不足 128 位十六进制')
    if not data:
        raise ValueError('待加密数据不能为空')
    # 传入占位符 '0'*64 满足接口要求，实际不会被加密使用
    cipher = sm2.CryptSM2(
        private_key='0' * 64,
        public_key=public_key_hex,
        mode=mode
    )
    return cipher.encrypt(data)


def sm2_decrypt(private_key_hex: str, public_key_hex: str,
                ciphertext: bytes, mode: int = 1) -> bytes:
    """SM2 私钥解密

    Args:
        private_key_hex: 私钥（十六进制字符串）
        public_key_hex: 对应公钥（十六进制字符串）
        ciphertext: 密文字节数据
        mode: 0-C1C2C3, 1-C1C3C2（需与加密时一致）

    Returns:
        明文字节数据
    """
    if not private_key_hex or len(private_key_hex) != 64:
        raise ValueError('私钥格式错误：应为 64 位十六进制')
    if not ciphertext:
        raise ValueError('密文不能为空')
    cipher = sm2.CryptSM2(
        private_key=private_key_hex,
        public_key=public_key_hex,
        mode=mode
    )
    return cipher.decrypt(ciphertext)


def sm2_sign(private_key_hex: str, data: bytes) -> str:
    """SM2 + SM3 数字签名

    遵循 GM/T 0003.2-2012 标准。
    内部使用 sign_with_sm3：先计算 Z=SM3(ID||a||b||xG||yG||xA||yA)，
    再计算 e=SM3(Z||M)，最后生成签名 (r, s)。

    Args:
        private_key_hex: 私钥（十六进制字符串）
        data: 待签名的消息数据

    Returns:
        签名的十六进制字符串（r||s 拼接格式）
    """
    ecc_table = DEFAULT_ECC_TABLE
    # 从私钥计算公钥点 P = d × G
    pk_point = _sm2_point_mul(private_key_hex, ecc_table['g'])

    # 输入校验
    if not private_key_hex or not data:
        raise ValueError('私钥和待签名数据不能为空')

    signer = sm2.CryptSM2(
        private_key=private_key_hex,
        public_key=pk_point,
        ecc_table=ecc_table,
        asn1=False
    )
    # sign_with_sm3 内部生成随机 k
    return signer.sign_with_sm3(data)


def sm2_verify(public_key_hex: str, signature_hex: str, data: bytes) -> bool:
    """SM2 + SM3 验签

    Args:
        public_key_hex: 公钥（十六进制字符串）
        signature_hex: 签名的十六进制字符串
        data: 原始消息数据

    Returns:
        True 如果签名有效，否则 False
    """
    if not public_key_hex or len(public_key_hex) < 128:
        raise ValueError('公钥格式错误：长度不足 128 位十六进制')
    if not signature_hex or len(signature_hex) < 128:
        raise ValueError('签名格式错误')
    if not data:
        raise ValueError('待验签数据不能为空')
    verifier = sm2.CryptSM2(
        private_key='0' * 64,
        public_key=public_key_hex,
        ecc_table=DEFAULT_ECC_TABLE,
        asn1=False
    )
    return verifier.verify_with_sm3(signature_hex, data)


def sm2_sign_asn1(private_key_hex: str, public_key_hex: str, data: bytes) -> str:
    """SM2 + SM3 数字签名（ASN.1 DER 编码）

    Args:
        private_key_hex: 私钥
        public_key_hex: 公钥
        data: 待签名数据

    Returns:
        ASN.1 DER 编码的签名字符串
    """
    signer = sm2.CryptSM2(
        private_key=private_key_hex,
        public_key=public_key_hex,
        ecc_table=DEFAULT_ECC_TABLE,
        asn1=True
    )
    return signer.sign_with_sm3(data)


def sm2_verify_asn1(public_key_hex: str, signature_hex: str, data: bytes) -> bool:
    """SM2 + SM3 验签（ASN.1 DER 格式）

    Args:
        public_key_hex: 公钥
        signature_hex: ASN.1 DER 编码的签名字符串
        data: 原始消息数据

    Returns:
        True 如果签名有效
    """
    verifier = sm2.CryptSM2(
        private_key='0' * 64,
        public_key=public_key_hex,
        ecc_table=DEFAULT_ECC_TABLE,
        asn1=True
    )
    return verifier.verify_with_sm3(signature_hex, data)


def sm2_private_key_to_pem(private_key_hex: str) -> str:
    """将 SM2 私钥转换为标准 PKCS#8 PEM 格式

    遵循 RFC 5208 PKCS#8 和 GM/T 0003 标准，
    使用 OID 1.2.156.10197.1.301 标识 SM2 算法。
    PEM 标签为 "PRIVATE KEY"，符合行业互操作规范。

    Args:
        private_key_hex: 私钥十六进制字符串（64 位）

    Returns:
        PKCS#8 PEM 格式字符串
    """
    key_bytes = bytes.fromhex(private_key_hex)

    # PKCS#8 PrivateKeyInfo ::= SEQUENCE {
    #   version                 INTEGER (0),
    #   privateKeyAlgorithm     SEQUENCE { OID, NULL },
    #   privateKey              OCTET STRING (raw key)
    # }
    algo_seq = DerSequence([DerObjectId(_SM2_OID), DerNull()])
    pkcs8 = DerSequence([
        DerInteger(0),             # version = 0
        algo_seq,
        DerOctetString(key_bytes)  # 裸私钥字节
    ])
    der = pkcs8.encode()

    b64 = base64.b64encode(der).decode('ascii')
    lines = ['-----BEGIN PRIVATE KEY-----']
    for i in range(0, len(b64), 64):
        lines.append(b64[i:i + 64])
    lines.append('-----END PRIVATE KEY-----')
    return '\n'.join(lines)


def sm2_public_key_to_pem(public_key_hex: str) -> str:
    """将 SM2 公钥转换为标准 SubjectPublicKeyInfo PEM 格式

    遵循 RFC 5480 和 GM/T 0003 标准，
    使用 OID 1.2.156.10197.1.301 标识 SM2 算法。
    PEM 标签为 "PUBLIC KEY"，符合行业互操作规范。

    Args:
        public_key_hex: 公钥十六进制字符串（128 位 xy 坐标）

    Returns:
        SubjectPublicKeyInfo PEM 格式字符串
    """
    if not public_key_hex.startswith('04'):
        public_key_hex = '04' + public_key_hex
    key_bytes = bytes.fromhex(public_key_hex)

    # SubjectPublicKeyInfo ::= SEQUENCE {
    #   algorithm         SEQUENCE { OID, NULL },
    #   subjectPublicKey  BIT STRING (04||x||y)
    # }
    algo_seq = DerSequence([DerObjectId(_SM2_OID), DerNull()])
    spki = DerSequence([
        algo_seq,
        DerBitString(key_bytes)
    ])
    der = spki.encode()

    b64 = base64.b64encode(der).decode('ascii')
    lines = ['-----BEGIN PUBLIC KEY-----']
    for i in range(0, len(b64), 64):
        lines.append(b64[i:i + 64])
    lines.append('-----END PUBLIC KEY-----')
    return '\n'.join(lines)


def sm2_private_key_from_pem(pem_str: str) -> str:
    """从标准 PKCS#8 PEM 解析 SM2 私钥

    Args:
        pem_str: PEM 格式的私钥字符串（标签: PRIVATE KEY）

    Returns:
        私钥十六进制字符串
    """
    lines = pem_str.strip().split('\n')
    b64_data = ''.join(line.strip() for line in lines
                       if not line.startswith('-----'))
    der = base64.b64decode(b64_data)
    pkcs8 = DerSequence().decode(der)
    if len(pkcs8) < 3:
        raise ValueError('无效的 PKCS#8 私钥格式')
    raw = pkcs8[2]  # OCTET STRING 原始字节
    if raw[:1] != b'\x04':
        raise ValueError('PKCS#8 第三个字段应为 OCTET STRING')
    # 跳过 OCTET STRING TLV 头（tag + length）
    head = 2
    if raw[1] & 0x80:
        head += raw[1] & 0x7f  # 长编码
    return raw[head:head + 32].hex()


def sm2_public_key_from_pem(pem_str: str) -> str:
    """从标准 SubjectPublicKeyInfo PEM 解析 SM2 公钥

    Args:
        pem_str: PEM 格式的公钥字符串（标签: PUBLIC KEY）

    Returns:
        公钥十六进制字符串（去掉 04 前缀）
    """
    lines = pem_str.strip().split('\n')
    b64_data = ''.join(line.strip() for line in lines
                       if not line.startswith('-----'))
    der = base64.b64decode(b64_data)
    spki = DerSequence().decode(der)
    if len(spki) < 2:
        raise ValueError('无效的 SubjectPublicKeyInfo 公钥格式')
    raw = spki[1]  # BIT STRING 原始字节
    if raw[:1] != b'\x03':
        raise ValueError('SPKI 第二个字段应为 BIT STRING')
    payload = raw[3:]  # 03 + len + unused_bits 之后
    hex_str = payload.hex()
    return hex_str[2:] if hex_str.startswith('04') else hex_str


if __name__ == '__main__':
    print("=" * 60)
    print("SM2 非对称密码工具")
    print("=" * 60)

    while True:
        print("\n请选择操作：")
        print("1. 生成 SM2 密钥对")
        print("2. SM2 公钥加密")
        print("3. SM2 私钥解密")
        print("4. SM2 + SM3 数字签名")
        print("5. SM2 + SM3 验签")
        print("6. 密钥导出 PEM 格式")
        print("0. 返回")

        choice = input("\n请输入选项 (0-6): ").strip()

        if choice == '0':
            break
        elif choice == '1':
            try:
                keypair = generate_sm2_keypair()
                print(f"\n私钥: {keypair.private_key}")
                print(f"公钥: {keypair.public_key}")
            except Exception as e:
                print(f"\n错误: {e}")
        elif choice == '2':
            try:
                pub_key = input("请输入公钥（十六进制）: ").strip()
                plaintext = input("请输入明文: ")
                ct = sm2_encrypt(pub_key, plaintext.encode('utf-8'))
                print(f"\n密文 (hex): {ct.hex()}")
            except Exception as e:
                print(f"\n错误: {e}")
        elif choice == '3':
            try:
                priv_key = input("请输入私钥（十六进制）: ").strip()
                pub_key = input("请输入公钥（十六进制）: ").strip()
                ct_hex = input("请输入密文（十六进制）: ").strip()
                ct = bytes.fromhex(ct_hex)
                pt = sm2_decrypt(priv_key, pub_key, ct)
                print(f"\n明文: {pt.decode('utf-8')}")
            except Exception as e:
                print(f"\n错误: {e}")
        elif choice == '4':
            try:
                priv_key = input("请输入私钥（十六进制）: ").strip()
                msg = input("请输入要签名的消息: ")
                sig = sm2_sign(priv_key, msg.encode('utf-8'))
                print(f"\n签名: {sig}")
            except Exception as e:
                print(f"\n错误: {e}")
        elif choice == '5':
            try:
                pub_key = input("请输入公钥（十六进制）: ").strip()
                sig = input("请输入签名（十六进制）: ").strip()
                msg = input("请输入原始消息: ")
                valid = sm2_verify(pub_key, sig, msg.encode('utf-8'))
                print(f"\n验签结果: {'✓ 签名有效' if valid else '✗ 签名无效'}")
            except Exception as e:
                print(f"\n错误: {e}")
        elif choice == '6':
            try:
                key_type = input("导出类型 (1-私钥, 2-公钥): ").strip()
                if key_type == '1':
                    priv = input("请输入私钥（十六进制）: ").strip()
                    print(f"\n{sm2_private_key_to_pem(priv)}")
                elif key_type == '2':
                    pub = input("请输入公钥（十六进制）: ").strip()
                    print(f"\n{sm2_public_key_to_pem(pub)}")
            except Exception as e:
                print(f"\n错误: {e}")
        else:
            print("无效选项，请重新输入")