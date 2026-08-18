"""
密钥管理模块
============
功能：SM2/SM4 密钥的管理（创建、存储、加载、删除）
"""

import os, sys, re, json, platform
from datetime import datetime
from typing import Optional, List, Dict
from sm2_crypto import (
    generate_sm2_keypair, sm2_private_key_to_pem, sm2_public_key_to_pem,
    sm2_private_key_from_pem, sm2_public_key_from_pem, SM2KeyPair
)
from sm4_crypto import _generate_sm4_key

_VALID_NAME = re.compile(r'^[a-zA-Z0-9_-]+$')

if getattr(sys, 'frozen', False):
    _BASE = os.path.join(os.environ.get('APPDATA', os.path.expanduser('~')), '国密安全系统')
else:
    _BASE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_KEY_DIR = os.path.join(_BASE, 'keys')


def _sanitize_name(name: str) -> str:
    name = name.strip()
    if not name:
        raise ValueError('密钥名称不能为空')
    if not _VALID_NAME.match(name):
        raise ValueError('密钥名称只能包含字母、数字、下划线、连字符，当前输入包含非法字符')
    return name


def _resolve_safe_path(base_dir: str, relative_path: str) -> str:
    """R-02: 解析并校验路径在 base_dir 下，防止路径穿越"""
    real_base = os.path.realpath(base_dir)
    real_file = os.path.realpath(os.path.join(real_base, relative_path))
    if not real_file.startswith(real_base + os.sep) and real_file != real_base:
        raise ValueError(f'非法路径: {relative_path}')
    return real_file


def _repair_permissions(directory: str):
    """修复被 icacls 损坏权限的旧文件"""
    if platform.system() != 'Windows' or not os.path.exists(directory):
        return
    import subprocess
    user = os.environ.get('USERNAME', '')
    if not user:
        return
    for fname in os.listdir(directory):
        fpath = os.path.join(directory, fname)
        try:
            with open(fpath, 'r'):
                pass
        except PermissionError:
            subprocess.run(['takeown', '/f', fpath], capture_output=True, timeout=5)
            subprocess.run(['icacls', fpath, '/grant', f'{user}:(F)'],
                           capture_output=True, timeout=5)


def _set_private_permission(path: str):
    """设置文件权限为仅所有者可读写 (Windows 单用户环境跳过)"""
    try:
        if platform.system() != 'Windows':
            os.chmod(path, 0o600)
    except Exception:
        print(f'! 无法设置文件权限: {path}', file=sys.stderr)


def _set_private_dir_permission(path: str):
    """设置目录权限为仅所有者可访问 (Windows 单用户环境跳过)"""
    try:
        if platform.system() != 'Windows':
            os.chmod(path, 0o700)
    except Exception:
        print(f'! 无法设置目录权限: {path}', file=sys.stderr)


def _secure_delete(path: str):
    """安全删除——随机覆盖后删除"""
    if not os.path.exists(path):
        return
    size = os.path.getsize(path)
    if size > 0:
        with open(path, 'wb') as f:
            for _ in range(3):
                f.seek(0)
                f.write(os.urandom(size))
                f.flush()
                os.fsync(f.fileno())
    os.remove(path)


class KeyManager:

    def __init__(self, key_dir: str = None):
        self.key_dir = key_dir or DEFAULT_KEY_DIR
        os.makedirs(self.key_dir, exist_ok=True)
        _set_private_dir_permission(self.key_dir)
        self.sm2_dir = os.path.join(self.key_dir, 'sm2')
        self.sm4_dir = os.path.join(self.key_dir, 'sm4')
        os.makedirs(self.sm2_dir, exist_ok=True)
        _set_private_dir_permission(self.sm2_dir)
        os.makedirs(self.sm4_dir, exist_ok=True)
        _set_private_dir_permission(self.sm4_dir)
        # 修复被 icacls 损坏权限的旧文件
        _repair_permissions(self.sm2_dir)
        _repair_permissions(self.sm4_dir)


    def _check_exists(self, name: str):
        """设置文件权限为仅所有者可读写"""
        for ext in ['_meta.json', '_priv.pem', '_pub.pem']:
            if os.path.exists(os.path.join(self.sm2_dir, name + ext)):
                return True
        if os.path.exists(os.path.join(self.sm4_dir, f'{name}_meta.json')):
            return True
        return False

    def create_sm2_keypair(self, name: str, description: str = "") -> SM2KeyPair:
        name = _sanitize_name(name)
        if self._check_exists(name):
            raise FileExistsError(f'密钥 "{name}" 已存在，请先删除或使用其他名称')
        keypair = generate_sm2_keypair()
        self._save_sm2_keypair(name, keypair, description)
        return keypair

    def _save_sm2_keypair(self, name: str, keypair: SM2KeyPair, description: str = ""):
        priv_path = os.path.join(self.sm2_dir, f'{name}_priv.pem')
        with open(priv_path, 'w') as f:
            f.write(sm2_private_key_to_pem(keypair.private_key))
        _set_private_permission(priv_path)
        pub_path = os.path.join(self.sm2_dir, f'{name}_pub.pem')
        with open(pub_path, 'w') as f:
            f.write(sm2_public_key_to_pem(keypair.public_key))
        _set_private_permission(pub_path)
        meta = {
            'name': name, 'type': 'SM2', 'description': description,
            'created_at': datetime.now().isoformat(),
            'private_key_file': f'{name}_priv.pem',
            'public_key_file': f'{name}_pub.pem',
        }
        meta_path = os.path.join(self.sm2_dir, f'{name}_meta.json')
        with open(meta_path, 'w', encoding='utf-8') as f:
            json.dump(meta, f, ensure_ascii=False, indent=2)
        _set_private_permission(meta_path)

    def load_sm2_keypair(self, name: str) -> Optional[SM2KeyPair]:
        meta_path = os.path.join(self.sm2_dir, f'{name}_meta.json')
        if not os.path.exists(meta_path):
            return None
        try:
            with open(meta_path, 'r', encoding='utf-8') as f:
                meta = json.load(f)
        except json.JSONDecodeError:
            raise ValueError(f'元数据文件损坏: {meta_path}')
        priv_rel = meta.get('private_key_file', '')
        pub_rel = meta.get('public_key_file', '')
        if not priv_rel or not pub_rel:
            raise ValueError('元数据缺少密钥文件路径')
        # 安全路径解析
        priv_path = _resolve_safe_path(self.sm2_dir, priv_rel)
        pub_path = _resolve_safe_path(self.sm2_dir, pub_rel)
        if not os.path.exists(priv_path):
            raise FileNotFoundError(f'私钥文件不存在: {priv_path}')
        if not os.path.exists(pub_path):
            raise FileNotFoundError(f'公钥文件不存在: {pub_path}')
        with open(priv_path, 'r') as f:
            priv_pem = f.read()
        with open(pub_path, 'r') as f:
            pub_pem = f.read()
        if 'BEGIN PRIVATE KEY' not in priv_pem:
            raise ValueError('私钥 PEM 格式无效')
        if 'BEGIN PUBLIC KEY' not in pub_pem:
            raise ValueError('公钥 PEM 格式无效')
        try:
            priv_hex = sm2_private_key_from_pem(priv_pem)
            pub_hex = sm2_public_key_from_pem(pub_pem)
        except (ValueError, IndexError) as e:
            raise ValueError(f'PEM 解析失败: {e}')
        if len(priv_hex) != 64 or len(pub_hex) != 128:
            raise ValueError('密钥长度异常')
        return SM2KeyPair(private_key_hex=priv_hex, public_key_hex=pub_hex)

    def list_sm2_keys(self) -> List[Dict]:
        keys = []
        try:
            for fname in os.listdir(self.sm2_dir):
                if fname.endswith('_meta.json'):
                    with open(os.path.join(self.sm2_dir, fname), 'r', encoding='utf-8') as f:
                        keys.append(json.load(f))
        except FileNotFoundError:
            pass
        return keys

    def delete_sm2_key(self, name: str) -> bool:
        files = [f'{name}_priv.pem', f'{name}_pub.pem', f'{name}_meta.json']
        success = 0
        failed = []
        for fn in files:
            path = os.path.join(self.sm2_dir, fn)
            if os.path.exists(path):
                try:
                    _secure_delete(path)
                    success += 1
                except Exception as e:
                    failed.append(f'{fn}: {e}')
        if failed:
            raise OSError(f'部分文件删除失败: {"; ".join(failed)}')
        return success > 0


    def create_sm4_key(self, name: str, description: str = "") -> bytes:
        name = _sanitize_name(name)
        if self._check_exists(name):
            raise FileExistsError(f'密钥 "{name}" 已存在，请先删除或使用其他名称')
        key = _generate_sm4_key()
        self._save_sm4_key(name, key, description)
        return key

    def _save_sm4_key(self, name: str, key: bytes, description: str = ""):
        key_path = os.path.join(self.sm4_dir, f'{name}.key')
        with open(key_path, 'wb') as f:
            f.write(key)
        _set_private_permission(key_path)
        meta = {
            'name': name, 'type': 'SM4', 'description': description,
            'created_at': datetime.now().isoformat(),
            'key_file': f'{name}.key',
        }
        meta_path = os.path.join(self.sm4_dir, f'{name}_meta.json')
        with open(meta_path, 'w', encoding='utf-8') as f:
            json.dump(meta, f, ensure_ascii=False, indent=2)
        _set_private_permission(meta_path)

    def load_sm4_key(self, name: str) -> Optional[bytes]:
        meta_path = os.path.join(self.sm4_dir, f'{name}_meta.json')
        if not os.path.exists(meta_path):
            return None
        with open(meta_path, 'r', encoding='utf-8') as f:
            meta = json.load(f)
        key_rel = meta.get('key_file', '')
        if not key_rel:
            raise ValueError('元数据缺少密钥文件路径')
        key_path = _resolve_safe_path(self.sm4_dir, key_rel)
        if not os.path.exists(key_path):
            return None
        with open(key_path, 'rb') as f:
            key = f.read()
        if len(key) != 16:
            raise ValueError(f'SM4 密钥长度异常: {len(key)} 字节（应为 16）')
        return key

    def list_sm4_keys(self) -> List[Dict]:
        keys = []
        try:
            for fname in os.listdir(self.sm4_dir):
                if fname.endswith('_meta.json'):
                    with open(os.path.join(self.sm4_dir, fname), 'r', encoding='utf-8') as f:
                        keys.append(json.load(f))
        except FileNotFoundError:
            pass
        return keys

    def delete_sm4_key(self, name: str) -> bool:
        meta_path = os.path.join(self.sm4_dir, f'{name}_meta.json')
        if not os.path.exists(meta_path):
            return False
        with open(meta_path, 'r', encoding='utf-8') as f:
            meta = json.load(f)
        key_rel = meta.get('key_file', f'{name}.key')
        key_path = _resolve_safe_path(self.sm4_dir, key_rel)
        success = 0
        failed = []
        for p in [meta_path, key_path]:
            if os.path.exists(p):
                try:
                    _secure_delete(p)
                    success += 1
                except Exception as e:
                    failed.append(f'{os.path.basename(p)}: {e}')
        if failed:
            raise OSError(f'部分文件删除失败: {"; ".join(failed)}')
        return success > 0

    def get_key_dir(self) -> str:
        return self.key_dir

    def print_summary(self):
        sm2 = self.list_sm2_keys()
        sm4 = self.list_sm4_keys()
        print(f"\n密钥存储目录: {self.key_dir}")
        print(f"SM2 密钥对: {len(sm2)} 个")
        for k in sm2:
            print(f"  [{k['name']}]")
        print(f"SM4 密钥: {len(sm4)} 个")
        for k in sm4:
            print(f"  [{k['name']}]")


if __name__ == '__main__':
    km = KeyManager()
    print("=" * 60)
    print("国密密钥管理器")
    print("=" * 60)
    while True:
        print("\n请选择操作：")
        print("1. 创建 SM2 密钥对")
        print("2. 创建 SM4 密钥")
        print("3. 查看 SM2 密钥列表")
        print("4. 查看 SM4 密钥列表")
        print("5. 查看摘要")
        print("6. 删除密钥")
        print("0. 返回")
        c = input("\n选项 (0-6): ").strip()
        if c == '0':
            break
        elif c == '1':
            try:
                name = input("名称: ").strip()
                desc = input("描述(可选): ").strip()
                kp = km.create_sm2_keypair(name, desc)
                print(f"\n✓ SM2 '{name}' 创建成功")
            except FileExistsError as e:
                print(f"\n⚠ {e}")
                if input("是否覆盖？(y/N): ").strip().lower() == 'y':
                    km.delete_sm2_key(name)
                    kp = km.create_sm2_keypair(name, desc)
                    print(f"\n✓ 已覆盖 SM2 '{name}'")
            except Exception as e:
                print(f"\n错误: {e}")
        elif c == '2':
            try:
                name = input("名称: ").strip()
                desc = input("描述(可选): ").strip()
                key = km.create_sm4_key(name, desc)
                print(f"\n✓ SM4 '{name}' 创建成功")
            except FileExistsError as e:
                print(f"\n⚠ {e}")
                if input("是否覆盖？(y/N): ").strip().lower() == 'y':
                    km.delete_sm4_key(name)
                    key = km.create_sm4_key(name, desc)
                    print(f"\n✓ 已覆盖 SM4 '{name}'")
            except Exception as e:
                print(f"\n错误: {e}")
        elif c == '3':
            for k in km.list_sm2_keys():
                print(f"  [{k['name']}]")
        elif c == '4':
            for k in km.list_sm4_keys():
                print(f"  [{k['name']}]")
        elif c == '5':
            km.print_summary()
        elif c == '6':
            try:
                t = input("类型 (1-SM2, 2-SM4): ").strip()
                name = input("名称: ").strip()
                confirm = input(f"确认删除密钥 '{name}'? 此操作不可恢复！(y/N): ").strip().lower()
                if confirm != 'y':
                    print("\n已取消")
                    continue
                ok = km.delete_sm2_key(name) if t == '1' else km.delete_sm4_key(name)
                print(f"\n{'✓ 已删除' if ok else '密钥不存在'}")
            except OSError as e:
                print(f"\n⚠ 删除部分失败: {e}")
            except Exception as e:
                print(f"\n错误: {e}")
        else:
            print("无效选项")