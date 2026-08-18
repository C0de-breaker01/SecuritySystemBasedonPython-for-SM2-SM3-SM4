#!/usr/bin/env python3
"""
基于国密算法（SM2/SM3/SM4）的综合安全系统 —— 图形界面版
========================================================
使用 Tkinter ttk 构建的多标签页交互式 GUI。
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import sys, os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sm3_hash import sm3_hash_string, sm3_hash_file, sm3_hash_file_verify, hmac_sm3, hmac_sm3_verify, sm3_save_hash_file
from sm4_crypto import (sm4_encrypt_ecb, sm4_decrypt_ecb, sm4_encrypt_cbc, sm4_decrypt_cbc,
                        sm4_encrypt_ctr, sm4_decrypt_ctr, sm4_encrypt_file_cbc, sm4_decrypt_file_cbc,
                        sm4_split_cbc, _generate_iv, _generate_sm4_key)
from sm2_crypto import (generate_sm2_keypair, sm2_encrypt, sm2_decrypt, sm2_sign, sm2_verify, SM2KeyPair)
from hybrid_crypto import HybridCipher, hybrid_sign_encrypt, hybrid_verify_decrypt, hybrid_encrypt_file, hybrid_decrypt_file
from key_manager import KeyManager

FONT = ('微软雅黑', 10)
FONT_BOLD = ('微软雅黑', 10, 'bold')
FONT_MONO = ('Consolas', 10)

# ============================================================
# 工具函数
# ============================================================
def _make_text_box(parent, height=6, width=60):
    """创建一个带滚动条的文本框"""
    txt = scrolledtext.ScrolledText(parent, height=height, width=width,
                                    font=FONT_MONO, wrap=tk.WORD, relief=tk.FLAT, borderwidth=1)
    return txt

def _clip(text):
    """剪短长文本用于展示"""
    return text if len(text) <= 50 else text[:22] + '...' + text[-25:]

def _make_copy_btn(parent, textbox):
    """创建一个复制按钮，优先取 textbox._copy_value（手动设置的值），否则取最后一行"""
    def _copy():
        # 优先使用预先设置的值
        value = getattr(textbox, '_copy_value', None)
        if not value:
            content = textbox.get(1.0, tk.END).strip()
            if not content:
                messagebox.showwarning('提示', '没有可复制的内容')
                return
            lines = content.rsplit('\n', 1)
            value = lines[-1].strip() if len(lines) > 1 else content
        root = textbox.winfo_toplevel()
        root.clipboard_clear()
        root.clipboard_append(value)
        root.update()
        preview = value if len(value) <= 40 else value[:18] + '...' + value[-18:]
        messagebox.showinfo('✅ 已复制', f'已复制到剪贴板:\n{preview}')
    return ttk.Button(parent, text='📋 复制', command=_copy)

# ============================================================
# 主界面
# ============================================================
class CryptoApp:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title('国密综合安全系统 SM2/SM3/SM4')
        self.root.geometry('880x820')
        self.root.minsize(880, 800)
        self.root.configure(bg='#f0f4f8')

        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TNotebook.Tab', font=('微软雅黑', 10, 'bold'), padding=[10, 4])
        style.configure('TLabelframe.Label', font=('微软雅黑', 10, 'bold'))
        style.configure('TButton', font=FONT, padding=[6, 3])
        style.configure('TEntry', fieldbackground='white')

        self.km = KeyManager()
        self._build_ui()
        self.root.mainloop()

    def _build_ui(self):
        hdr = tk.Frame(self.root, bg='#2c3e50', height=56)
        hdr.pack(fill='x')
        tk.Label(hdr, text='国密综合安全系统', fg='white', bg='#2c3e50',
                 font=('微软雅黑', 16, 'bold')).pack(side='left', padx=20, pady=12)
        tk.Label(hdr, text='SM2 · SM3 · SM4', fg='#95a5a6', bg='#2c3e50',
                 font=('微软雅黑', 10)).pack(side='right', padx=20)

        self.nb = nb = ttk.Notebook(self.root)
        nb.pack(fill='both', expand=True, padx=8, pady=8)

        self._tab_sm3(nb)
        self._tab_sm4(nb)
        self._tab_sm2(nb)
        self._tab_hybrid(nb)
        self._tab_keymgr(nb)

    # ==================== SM3 标签页 ====================
    def _tab_sm3(self, nb):
        f = ttk.Frame(nb, padding=10)
        nb.add(f, text=' SM3 哈希 ')

        left = ttk.LabelFrame(f, text='操作', padding=8)
        left.pack(side='left', fill='y', padx=(0,5))

        # ── 哈希计算 ──
        ttk.Label(left, text='字符串 / 文件路径:', font=FONT_BOLD).pack(anchor='w')
        self.sm3_input = ttk.Entry(left, width=50, font=FONT_MONO)
        self.sm3_input.pack(fill='x', pady=(2,4))

        ttk.Button(left, text='📂 选择文件', command=lambda: self._sm3_pick_file()).pack(fill='x', pady=1)
        btn_f = ttk.Frame(left)
        btn_f.pack(fill='x', pady=4)
        ttk.Button(btn_f, text='计算哈希', command=lambda: self._sm3_calc()).pack(side='left', padx=2)
        ttk.Button(btn_f, text='保存哈希', command=lambda: self._sm3_save()).pack(side='left', padx=2)

        # ── 哈希验证 ──
        ttk.Separator(left).pack(fill='x', pady=6)
        ttk.Label(left, text='验证文件哈希:', font=FONT_BOLD).pack(anchor='w')
        ttk.Label(left, text='期望哈希值:').pack(anchor='w')
        self.sm3_verify_hash = ttk.Entry(left, font=FONT_MONO)
        self.sm3_verify_hash.pack(fill='x', pady=(0,4))
        ttk.Button(left, text='🔍 验证', command=lambda: self._sm3_verify()).pack(anchor='w', pady=2)

        # ── HMAC ──
        ttk.Separator(left).pack(fill='x', pady=6)
        ttk.Label(left, text='HMAC-SM3 消息认证码:', font=FONT_BOLD).pack(anchor='w')
        ttk.Label(left, text='密钥:').pack(anchor='w')
        self.sm3_hmac_key = ttk.Entry(left, font=FONT_MONO)
        self.sm3_hmac_key.pack(fill='x', pady=(0,2))
        ttk.Button(left, text='计算 HMAC', command=lambda: self._sm3_hmac()).pack(anchor='w', pady=1)

        ttk.Label(left, text='验证 HMAC:').pack(anchor='w', pady=(6,0))
        self.sm3_hmac_expect = ttk.Entry(left, font=FONT_MONO)
        self.sm3_hmac_expect.pack(fill='x', pady=(0,4))
        ttk.Button(left, text='🔍 验证 HMAC', command=lambda: self._sm3_hmac_verify()).pack(anchor='w')

        # ── 输出 ──
        right = ttk.LabelFrame(f, text='输出', padding=8)
        right.pack(side='right', fill='both', expand=True, padx=(5,0))

        self.sm3_result = _make_text_box(right, height=20)
        self.sm3_result.pack(fill='both', expand=True)
        _make_copy_btn(right, self.sm3_result).pack(anchor='e', pady=2)

    def _sm3_pick_file(self):
        p = filedialog.askopenfilename()
        if p:
            self.sm3_input.delete(0, tk.END)
            self.sm3_input.insert(0, p)

    def _sm3_calc(self):
        txt = self.sm3_input.get().strip()
        if not txt:
            messagebox.showwarning('提示', '请输入字符串或选择文件')
            return
        self.sm3_result.delete(1.0, tk.END)
        try:
            if os.path.isfile(txt):
                h = sm3_hash_file(txt)
                self.sm3_result._copy_value = h
                self.sm3_result.insert(tk.END,
                    f'📄 文件哈希\n文件: {os.path.basename(txt)}\n'
                    f'SM3: {h}\n状态: ✅ 计算完成')
            else:
                h = sm3_hash_string(txt)
                self.sm3_result._copy_value = h
                self.sm3_result.insert(tk.END,
                    f'📝 字符串哈希\n输入: {txt}\n'
                    f'SM3: {h}\n长度: {len(h)} 字符 / {len(h)*4} bits')
        except Exception as e:
            self.sm3_result._copy_value = None
            self.sm3_result.insert(tk.END, f'错误: {e}')

    def _sm3_verify(self):
        path = self.sm3_input.get().strip()
        expected = self.sm3_verify_hash.get().strip()
        if not path or not os.path.isfile(path):
            messagebox.showwarning('提示', '请先选择文件')
            return
        if not expected:
            messagebox.showwarning('提示', '请输入期望的哈希值')
            return
        if len(expected) != 64:
            messagebox.showwarning('提示', '哈希值长度应为64位十六进制字符')
            return
        self.sm3_result.delete(1.0, tk.END)
        try:
            match = sm3_hash_file_verify(path, expected)
            if match:
                self.sm3_result._copy_value = expected
                self.sm3_result.insert(tk.END,
                    f'✅ 验证通过\n文件: {os.path.basename(path)}\n'
                    f'哈希匹配: {expected[:20]}... ✓')
            else:
                h = sm3_hash_file(path)
                self.sm3_result._copy_value = h
                self.sm3_result.insert(tk.END,
                    f'❌ 验证失败\n文件: {os.path.basename(path)}\n'
                    f'期望: {expected}\n实际: {h}')
        except Exception as e:
            self.sm3_result._copy_value = None
            self.sm3_result.insert(tk.END, f'错误: {e}')

    def _sm3_save(self):
        txt = self.sm3_input.get().strip()
        if not txt or not os.path.isfile(txt):
            messagebox.showwarning('提示', '请先选择一个文件')
            return
        try:
            p = sm3_save_hash_file(txt)
            self.sm3_result.delete(1.0, tk.END)
            self.sm3_result.insert(tk.END, f'✅ 哈希已保存到: {p}')
        except Exception as e:
            messagebox.showerror('错误', str(e))

    def _sm3_hmac(self):
        msg = self.sm3_input.get().strip()
        key = self.sm3_hmac_key.get().strip()
        if not msg or not key:
            messagebox.showwarning('提示', '请输入消息和密钥')
            return
        h = hmac_sm3(key.encode(), msg.encode())
        self.sm3_result.delete(1.0, tk.END)
        self.sm3_result._copy_value = h
        self.sm3_result.insert(tk.END, f'HMAC-SM3:\n  密钥: {key}\n  消息: {_clip(msg)}\n  结果: {h}')

    def _sm3_hmac_verify(self):
        msg = self.sm3_input.get().strip()
        key = self.sm3_hmac_key.get().strip()
        expected = self.sm3_hmac_expect.get().strip()
        if not msg or not key or not expected:
            messagebox.showwarning('提示', '请输入消息、密钥和期望的 HMAC 值')
            return
        self.sm3_result.delete(1.0, tk.END)
        match = hmac_sm3_verify(key.encode(), msg.encode(), expected)
        if match:
            self.sm3_result._copy_value = expected
            self.sm3_result.insert(tk.END,
                f'✅ HMAC 验证通过\n密钥: {_clip(key)}\n消息: {_clip(msg)}\n'
                f'HMAC 匹配: {expected[:20]}... ✓')
        else:
            actual = hmac_sm3(key.encode(), msg.encode())
            self.sm3_result._copy_value = actual
            self.sm3_result.insert(tk.END,
                f'❌ HMAC 验证失败\n密钥: {_clip(key)}\n消息: {_clip(msg)}\n'
                f'期望: {expected}\n实际: {actual}')

    # ==================== SM4 标签页 ====================
    def _tab_sm4(self, nb):
        f = ttk.Frame(nb, padding=10)
        nb.add(f, text=' SM4 加解密 ')

        # 顶部：密钥区
        top = ttk.LabelFrame(f, text='密钥设置', padding=6)
        top.pack(fill='x')
        ttk.Label(top, text='密钥 (32位hex, 16字节):').pack(side='left')
        self.sm4_key = ttk.Entry(top, width=35, font=FONT_MONO)
        self.sm4_key.pack(side='left', padx=5)
        ttk.Button(top, text='生成密钥', command=lambda: self._sm4_gen_key()).pack(side='left')

        # 中间：模式 + 内容
        mid = ttk.Frame(f)
        mid.pack(fill='both', expand=True, pady=8)

        left = ttk.LabelFrame(mid, text='加解密操作', padding=8)
        left.pack(side='left', fill='both', expand=True, padx=(0,4))

        ttk.Label(left, text='工作模式:').grid(row=0, column=0, sticky='w')
        self.sm4_mode = ttk.Combobox(left, values=['CBC', 'ECB', 'CTR'], state='readonly', width=8)
        self.sm4_mode.current(0)
        self.sm4_mode.grid(row=0, column=1, sticky='w', pady=4)

        ttk.Label(left, text='操作:').grid(row=1, column=0, sticky='w')
        opf = ttk.Frame(left)
        opf.grid(row=1, column=1, sticky='w', pady=4)
        self.sm4_action = tk.StringVar(value='encrypt')
        ttk.Radiobutton(opf, text='加密', variable=self.sm4_action, value='encrypt').pack(side='left')
        ttk.Radiobutton(opf, text='解密', variable=self.sm4_action, value='decrypt').pack(side='left', padx=10)

        ivf = ttk.Frame(left)
        ivf.grid(row=2, column=0, columnspan=2, sticky='ew', pady=4)
        ttk.Label(ivf, text='IV / Nonce (hex, 留空自动生成):').pack(side='left')
        self.sm4_iv = ttk.Entry(ivf, width=34, font=FONT_MONO)
        self.sm4_iv.pack(side='left', padx=4, fill='x', expand=True)
        ttk.Button(ivf, text='🎲 随机', command=lambda: self._sm4_gen_iv()).pack(side='left')

        ttk.Label(left, text='输入数据:').grid(row=3, column=0, sticky='nw', pady=(8,0))
        self.sm4_input = _make_text_box(left, height=5)
        self.sm4_input.grid(row=3, column=1, sticky='ew', pady=(8,0))
        left.columnconfigure(1, weight=1)

        btn_f = ttk.Frame(left)
        btn_f.grid(row=4, column=1, sticky='w', pady=8)
        ttk.Button(btn_f, text='▶ 执行', command=lambda: self._sm4_run()).pack(side='left', padx=2)
        ttk.Button(btn_f, text='📁 选择文件', command=lambda: self._sm4_pick_src()).pack(side='left', padx=2)

        right = ttk.LabelFrame(mid, text='输出结果', padding=8)
        right.pack(side='right', fill='both', expand=True, padx=(4,0))

        self.sm4_result = _make_text_box(right, height=10)
        self.sm4_result.pack(fill='both', expand=True)
        _make_copy_btn(right, self.sm4_result).pack(anchor='e', pady=2)

        bot = ttk.LabelFrame(f, text='文件加解密', padding=6)
        bot.pack(fill='x')
        ttk.Label(bot, text='源文件:').pack(side='left')
        self.sm4_fsrc = ttk.Entry(bot, width=40, font=FONT_MONO)
        self.sm4_fsrc.pack(side='left', padx=4)
        ttk.Button(bot, text='选择', command=lambda: self._sm4_pick_src()).pack(side='left', padx=2)
        ttk.Button(bot, text='加密文件 ▶', command=lambda: self._sm4_file_enc()).pack(side='left', padx=2)
        ttk.Button(bot, text='解密文件 ▶', command=lambda: self._sm4_file_dec()).pack(side='left', padx=2)

    def _sm4_gen_key(self):
        k = _generate_sm4_key()
        self.sm4_key.delete(0, tk.END)
        self.sm4_key.insert(0, k.hex())

    def _sm4_gen_iv(self):
        mode = self.sm4_mode.get()
        if mode == 'CTR':
            iv = os.urandom(8)
        else:
            iv = _generate_iv()
        self.sm4_iv.delete(0, tk.END)
        self.sm4_iv.insert(0, iv.hex())

    def _sm4_pick_src(self):
        p = filedialog.askopenfilename()
        if p:
            self.sm4_fsrc.delete(0, tk.END)
            self.sm4_fsrc.insert(0, p)

    def _sm4_run(self):
        key_hex = self.sm4_key.get().strip()
        if len(key_hex) != 32:
            messagebox.showwarning('提示', '密钥需32位十六进制字符（16字节）')
            return
        key = bytes.fromhex(key_hex)
        mode = self.sm4_mode.get()
        action = self.sm4_action.get()
        data = self.sm4_input.get(1.0, tk.END).strip()

        if not data:
            messagebox.showwarning('提示', '请输入数据')
            return

        self.sm4_result.delete(1.0, tk.END)
        try:
            if action == 'encrypt':
                if mode == 'ECB':
                    r = sm4_encrypt_ecb(key, data)
                    self.sm4_result._copy_value = r
                    self.sm4_result.insert(tk.END, f'加密成功 (SM4-ECB):\n\n{r}')
                elif mode == 'CBC':
                    iv_hex = self.sm4_iv.get().strip()
                    if iv_hex:
                        if len(iv_hex) != 32:
                            messagebox.showwarning('提示', 'CBC 模式的 IV 需 32 位十六进制（16 字节）')
                            return
                        iv = bytes.fromhex(iv_hex)
                    else:
                        iv = _generate_iv()
                        self.sm4_iv.delete(0, tk.END)
                        self.sm4_iv.insert(0, iv.hex())
                    r = sm4_encrypt_cbc(key, iv, data)
                    iv_hex, ct_b64 = sm4_split_cbc(r)
                    self.sm4_result._copy_value = r
                    self.sm4_result.insert(tk.END,
                        f'加密成功 (SM4-CBC)\n\n'
                        f'IV (hex, 16 字节):\n{iv_hex}\n\n'
                        f'密文 (Base64):\n{ct_b64}\n\n'
                        f'—— 组合格式（解密时可直接粘贴）——\n{r}')
                else:  # CTR
                    nonce_hex = self.sm4_iv.get().strip()
                    if nonce_hex:
                        if len(nonce_hex) != 16:
                            messagebox.showwarning('提示', 'CTR 模式的 Nonce 需 16 位十六进制（8 字节）')
                            return
                        nonce = bytes.fromhex(nonce_hex)
                    else:
                        nonce = os.urandom(8)
                        self.sm4_iv.delete(0, tk.END)
                        self.sm4_iv.insert(0, nonce.hex())
                    r = sm4_encrypt_ctr(key, nonce, data)
                    self.sm4_result._copy_value = r
                    self.sm4_result.insert(tk.END, f'加密成功 (SM4-{mode}):\n\n{r}')
            else:
                if mode == 'ECB':
                    r = sm4_decrypt_ecb(key, data)
                elif mode == 'CBC':
                    r = sm4_decrypt_cbc(key, data)
                else:
                    r = sm4_decrypt_ctr(key, data)
                self.sm4_result._copy_value = r
                self.sm4_result.insert(tk.END, f'解密成功 (SM4-{mode}):\n\n{r}')
        except Exception as e:
            self.sm4_result._copy_value = None
            self.sm4_result.insert(tk.END, f'错误: {e}')

    def _sm4_file_enc(self):
        src = self.sm4_fsrc.get().strip()
        key_hex = self.sm4_key.get().strip()
        if not src or not os.path.isfile(src):
            messagebox.showwarning('提示', '请选择源文件')
            return
        if len(key_hex) != 32:
            messagebox.showwarning('提示', '密钥需32位十六进制字符')
            return
        try:
            iv = _generate_iv()
            out = sm4_encrypt_file_cbc(bytes.fromhex(key_hex), iv, src)
            self.sm4_result.insert(tk.END, f'文件加密成功:\n{out}')
        except PermissionError:
            messagebox.showerror('权限错误', '无法读取源文件或写入目标文件，请检查文件权限')
        except Exception as e:
            messagebox.showerror('错误', f'文件加密失败: {e}')

    def _sm4_file_dec(self):
        src = self.sm4_fsrc.get().strip()
        key_hex = self.sm4_key.get().strip()
        if not src or not os.path.isfile(src):
            messagebox.showwarning('提示', '请选择密文文件')
            return
        if len(key_hex) != 32:
            messagebox.showwarning('提示', '密钥需32位十六进制字符')
            return
        # 预检查文件大小是否合法（SM4-CBC至少16字节头+16字节数据）
        try:
            fsize = os.path.getsize(src)
            if fsize < 32:
                messagebox.showerror('文件格式错误',
                    '文件太小（不足32字节），不是有效的 SM4 加密文件。\n'
                    '请确认选择了正确的 .enc 加密文件。')
                return
            if fsize % 16 != 0:
                # SM4 CBC密文应为16的倍数
                pass  # 只是提示性检查，不阻断
        except Exception:
            pass
        try:
            out = sm4_decrypt_file_cbc(bytes.fromhex(key_hex), src)
            self.sm4_result.insert(tk.END, f'文件解密成功:\n{out}')
        except (ValueError, IndexError, UnicodeDecodeError):
            messagebox.showerror('解密失败',
                '文件解密失败，可能原因：\n'
                '1. 密钥不正确\n'
                '2. 文件不是 SM4 加密文件或已损坏\n'
                '3. 文件格式不匹配（请选择 .enc 文件）')
        except PermissionError:
            messagebox.showerror('权限错误', '无法读取文件，请检查文件权限')
        except Exception as e:
            messagebox.showerror('错误', f'文件解密失败: {e}')

    # ==================== SM2 标签页 ====================
    def _tab_sm2(self, nb):
        f = ttk.Frame(nb, padding=10)
        nb.add(f, text=' SM2 非对称 ')

        kg = ttk.LabelFrame(f, text='密钥对生成', padding=6)
        kg.pack(fill='x')
        ttk.Button(kg, text='🎲 生成密钥对', command=lambda: self._sm2_gen()).pack(side='left', padx=2)
        ttk.Label(kg, text='私钥:').pack(side='left', padx=(10,0))
        self.sm2_priv_lb = ttk.Entry(kg, width=22, font=FONT_MONO)
        self.sm2_priv_lb.pack(side='left', padx=2, fill='x', expand=True)
        ttk.Label(kg, text='公钥:').pack(side='left')
        self.sm2_pub_lb = ttk.Entry(kg, width=22, font=FONT_MONO)
        self.sm2_pub_lb.pack(side='left', padx=2, fill='x', expand=True)

        mid = ttk.Frame(f)
        mid.pack(fill='both', expand=True, pady=8)

        left_col = ttk.Frame(mid)
        left_col.pack(side='left', fill='both', expand=True, padx=(0,4))

        enc_g = ttk.LabelFrame(left_col, text='🔒 加密', padding=6)
        enc_g.pack(fill='both', expand=True, pady=(0,4))
        ttk.Label(enc_g, text='公钥:').grid(row=0, column=0, sticky='w', pady=2)
        self.sm2_enc_pub = ttk.Entry(enc_g, font=FONT_MONO)
        self.sm2_enc_pub.grid(row=0, column=1, sticky='ew', padx=4, pady=2)
        ttk.Label(enc_g, text='明文:').grid(row=1, column=0, sticky='nw', pady=2)
        self.sm2_enc_pt = _make_text_box(enc_g, height=3)
        self.sm2_enc_pt.grid(row=1, column=1, sticky='ew', pady=2)
        enc_g.columnconfigure(1, weight=1)
        mf = ttk.Frame(enc_g)
        mf.grid(row=2, column=1, sticky='w', pady=4)
        ttk.Label(mf, text='模式:').pack(side='left')
        self.sm2_mode = ttk.Combobox(mf, values=['C1C3C2 (默认)', 'C1C2C3'],
                                      state='readonly', width=12)
        self.sm2_mode.current(0)
        self.sm2_mode.pack(side='left', padx=4)
        ttk.Button(mf, text='加密', command=lambda: self._sm2_enc()).pack(side='left', padx=4)
        self.sm2_res_enc = _make_text_box(enc_g, height=3)
        self.sm2_res_enc.grid(row=3, column=0, columnspan=2, sticky='ew', pady=2)
        _make_copy_btn(enc_g, self.sm2_res_enc).grid(row=4, column=1, sticky='e', pady=(0,2))

        dec_g = ttk.LabelFrame(left_col, text='🔓 解密', padding=6)
        dec_g.pack(fill='both', expand=True, pady=(4,0))
        ttk.Label(dec_g, text='私钥:').grid(row=0, column=0, sticky='w', pady=2)
        self.sm2_dec_priv = ttk.Entry(dec_g, font=FONT_MONO)
        self.sm2_dec_priv.grid(row=0, column=1, sticky='ew', padx=4, pady=2)
        ttk.Label(dec_g, text='密文 (hex):').grid(row=1, column=0, sticky='nw', pady=2)
        self.sm2_dec_ct = _make_text_box(dec_g, height=3)
        self.sm2_dec_ct.grid(row=1, column=1, sticky='ew', pady=2)
        dec_g.columnconfigure(1, weight=1)
        ttk.Button(dec_g, text='解密', command=lambda: self._sm2_dec()) \
            .grid(row=2, column=1, sticky='w', pady=4)
        self.sm2_res_dec = _make_text_box(dec_g, height=3)
        self.sm2_res_dec.grid(row=3, column=0, columnspan=2, sticky='ew', pady=2)
        _make_copy_btn(dec_g, self.sm2_res_dec).grid(row=4, column=1, sticky='e', pady=(0,2))

        right_col = ttk.Frame(mid)
        right_col.pack(side='right', fill='both', expand=True, padx=(4,0))

        sig_g = ttk.LabelFrame(right_col, text='✍ 签名', padding=6)
        sig_g.pack(fill='both', expand=True, pady=(0,4))
        ttk.Label(sig_g, text='私钥:').grid(row=0, column=0, sticky='w', pady=2)
        self.sm2_sig_priv = ttk.Entry(sig_g, font=FONT_MONO)
        self.sm2_sig_priv.grid(row=0, column=1, sticky='ew', padx=4, pady=2)
        ttk.Label(sig_g, text='消息:').grid(row=1, column=0, sticky='nw', pady=2)
        self.sm2_sig_msg = _make_text_box(sig_g, height=3)
        self.sm2_sig_msg.grid(row=1, column=1, sticky='ew', pady=2)
        sig_g.columnconfigure(1, weight=1)
        ttk.Button(sig_g, text='签名', command=lambda: self._sm2_sign()) \
            .grid(row=2, column=1, sticky='w', pady=4)
        self.sm2_res_sig = _make_text_box(sig_g, height=3)
        self.sm2_res_sig.grid(row=3, column=0, columnspan=2, sticky='ew', pady=2)
        _make_copy_btn(sig_g, self.sm2_res_sig).grid(row=4, column=1, sticky='e', pady=(0,2))

        ver_g = ttk.LabelFrame(right_col, text='✓ 验签', padding=6)
        ver_g.pack(fill='both', expand=True, pady=(4,0))
        ttk.Label(ver_g, text='公钥:').grid(row=0, column=0, sticky='w', pady=2)
        self.sm2_ver_pub = ttk.Entry(ver_g, font=FONT_MONO)
        self.sm2_ver_pub.grid(row=0, column=1, sticky='ew', padx=4, pady=2)
        ttk.Label(ver_g, text='签名:').grid(row=1, column=0, sticky='w', pady=2)
        self.sm2_ver_sig = ttk.Entry(ver_g, font=FONT_MONO)
        self.sm2_ver_sig.grid(row=1, column=1, sticky='ew', padx=4, pady=2)
        ttk.Label(ver_g, text='原始消息:').grid(row=2, column=0, sticky='nw', pady=2)
        self.sm2_ver_msg = _make_text_box(ver_g, height=2)
        self.sm2_ver_msg.grid(row=2, column=1, sticky='ew', pady=2)
        ver_g.columnconfigure(1, weight=1)
        ttk.Button(ver_g, text='验签', command=lambda: self._sm2_verify()) \
            .grid(row=3, column=1, sticky='w', pady=4)
        self.sm2_res_ver = _make_text_box(ver_g, height=3)
        self.sm2_res_ver.grid(row=4, column=0, columnspan=2, sticky='ew', pady=2)
        _make_copy_btn(ver_g, self.sm2_res_ver).grid(row=5, column=1, sticky='e', pady=(0,2))

    def _sm2_gen(self):
        kp = generate_sm2_keypair()
        self.sm2_priv_lb.delete(0, tk.END); self.sm2_priv_lb.insert(0, kp.private_key)
        self.sm2_pub_lb.delete(0, tk.END); self.sm2_pub_lb.insert(0, kp.public_key)
        self.sm2_enc_pub.delete(0, tk.END); self.sm2_enc_pub.insert(0, kp.public_key)
        self.sm2_dec_priv.delete(0, tk.END); self.sm2_dec_priv.insert(0, kp.private_key)
        self.sm2_sig_priv.delete(0, tk.END); self.sm2_sig_priv.insert(0, kp.private_key)
        self.sm2_ver_pub.delete(0, tk.END); self.sm2_ver_pub.insert(0, kp.public_key)
        messagebox.showinfo('成功', 'SM2 密钥对已生成并自动填入各输入框')

    def _sm2_mode_val(self) -> int:
        """获取 SM2 密文排列模式：1=C1C3C2, 0=C1C2C3"""
        return 0 if self.sm2_mode.get().startswith('C1C2C3') else 1

    def _sm2_enc(self):
        pub = self.sm2_enc_pub.get().strip()
        data = self.sm2_enc_pt.get(1.0, tk.END).strip()
        mode = self._sm2_mode_val()
        if not pub or not data:
            messagebox.showwarning('提示', '请填入公钥和明文')
            return
        if len(pub) < 128:
            messagebox.showwarning('输入错误', '公钥长度不足（应为128位十六进制字符），请检查输入')
            return
        try:
            ct = sm2_encrypt(pub, data.encode(), mode=mode)
            if ct is None:
                self.sm2_res_enc.delete(1.0, tk.END)
                self.sm2_res_enc.insert(tk.END, '加密失败: 请检查公钥是否正确')
                return
            self.sm2_res_enc.delete(1.0, tk.END)
            self.sm2_res_enc._copy_value = ct.hex()
            label = 'C1C3C2' if mode else 'C1C2C3'
            self.sm2_res_enc.insert(tk.END, f'密文 ({label}, {len(ct)} 字节):\n{ct.hex()}')
        except Exception as e:
            self.sm2_res_enc.delete(1.0, tk.END)
            err_msg = str(e)
            if 'public key' in err_msg.lower() or 'point' in err_msg.lower():
                self.sm2_res_enc.insert(tk.END, '公钥格式错误: 请检查公钥是否为有效的SM2椭圆曲线点')
            else:
                self.sm2_res_enc.insert(tk.END, f'加密出错: {err_msg}')

    def _sm2_dec(self):
        priv = self.sm2_dec_priv.get().strip()
        data = self.sm2_dec_ct.get(1.0, tk.END).strip()
        mode = self._sm2_mode_val()
        if not priv or not data:
            messagebox.showwarning('提示', '请填入私钥和密文')
            return
        data_clean = data.replace('\n', '').replace(' ', '').replace('\r', '')
        if not data_clean:
            messagebox.showwarning('提示', '密文不能为空')
            return
        try:
            bytes.fromhex(data_clean)
        except ValueError:
            messagebox.showwarning('输入错误', '密文格式错误：请输入合法的十六进制字符串（0-9, a-f）')
            return
        try:
            ct = bytes.fromhex(data_clean)
            pt = sm2_decrypt(priv, '', ct, mode=mode)
            if pt is None:
                self.sm2_res_dec.delete(1.0, tk.END)
                self.sm2_res_dec.insert(tk.END, '错误: 解密失败，请检查私钥是否正确')
                return
            self.sm2_res_dec.delete(1.0, tk.END)
            try:
                pt_str = pt.decode('utf-8')
            except UnicodeDecodeError:
                other_mode = 'C1C2C3' if mode else 'C1C3C2'
                self.sm2_res_dec.insert(tk.END,
                    f'解密得到的数据不是有效文本，可能原因：\n'
                    f'1. 密文排列模式不匹配（当前: {self.sm2_mode.get()}，试试 {other_mode}）\n'
                    f'2. 私钥不正确\n'
                    f'3. 密文数据已损坏')
                return
            self.sm2_res_dec._copy_value = pt_str
            self.sm2_res_dec.insert(tk.END, f'明文: {pt_str}')
        except Exception as e:
            self.sm2_res_dec.delete(1.0, tk.END)
            err_msg = str(e)
            other_mode = 'C1C2C3' if mode else 'C1C3C2'
            if 'decrypt' in err_msg.lower() or 'cipher' in err_msg.lower():
                self.sm2_res_dec.insert(tk.END, '解密失败: 请检查私钥是否正确，或密文是否被篡改')
            elif 'key' in err_msg.lower():
                self.sm2_res_dec.insert(tk.END, '密钥错误: 私钥格式不正确')
            elif 'mac' in err_msg.lower() or 'check' in err_msg.lower() or 'hash' in err_msg.lower():
                self.sm2_res_dec.insert(tk.END,
                    f'密文排列模式可能不匹配。\\n当前: {self.sm2_mode.get()}\\n'
                    f'请尝试切换到: {other_mode}')
            else:
                self.sm2_res_dec.insert(tk.END,
                    f'解密出错，可能原因：\\n'
                    f'1. 密文排列模式不匹配（当前: {self.sm2_mode.get()}，试试 {other_mode}）\\n'
                    f'2. 私钥不正确\\n'
                    f'3. 密文数据已损坏')

    def _sm2_sign(self):
        priv = self.sm2_sig_priv.get().strip()
        msg = self.sm2_sig_msg.get(1.0, tk.END).strip()
        if not priv or not msg:
            messagebox.showwarning('提示', '请填入私钥和消息')
            return
        try:
            sig = sm2_sign(priv, msg.encode())
            self.sm2_res_sig.delete(1.0, tk.END)
            self.sm2_res_sig.insert(tk.END, f'签名成功:\n{sig}')
        except Exception as e:
            self.sm2_res_sig.delete(1.0, tk.END)
            self.sm2_res_sig.insert(tk.END, f'签名错误: {e}')

    def _sm2_verify(self):
        pub = self.sm2_ver_pub.get().strip()
        sig = self.sm2_ver_sig.get().strip()
        msg = self.sm2_ver_msg.get(1.0, tk.END).strip()
        if not pub or not sig or not msg:
            messagebox.showwarning('提示', '请填入公钥、签名和原始消息')
            return
        try:
            valid = sm2_verify(pub, sig, msg.encode())
            self.sm2_res_ver.delete(1.0, tk.END)
            self.sm2_res_ver.insert(tk.END, f'验签: {"✓ 签名有效!" if valid else "✗ 签名无效!"}')
        except Exception as e:
            self.sm2_res_ver.delete(1.0, tk.END)
            self.sm2_res_ver.insert(tk.END, f'验签错误: {e}')

    # ==================== 混合加密标签页 ====================
    def _tab_hybrid(self, nb):
        f = ttk.Frame(nb, padding=10)
        nb.add(f, text=' SM2+SM4 混合 ')

        top = ttk.LabelFrame(f, text='密钥', padding=6)
        top.pack(fill='x')
        ttk.Label(top, text='私钥:').pack(side='left')
        self.hyb_priv = ttk.Entry(top, width=35, font=FONT_MONO)
        self.hyb_priv.pack(side='left', padx=4)
        ttk.Label(top, text='公钥:').pack(side='left')
        self.hyb_pub = ttk.Entry(top, width=35, font=FONT_MONO)
        self.hyb_pub.pack(side='left', padx=4)
        ttk.Button(top, text='生成密钥对', command=lambda: self._hyb_gen()).pack(side='left')

        # ─── 底部文件加密（先 pack 到底部，保证始终可见）───
        bot = ttk.LabelFrame(f, text='文件混合加解密', padding=6)
        bot.pack(fill='x', side='bottom')
        ttk.Label(bot, text='文件:').pack(side='left')
        self.hyb_file = ttk.Entry(bot, width=50, font=FONT_MONO)
        self.hyb_file.pack(side='left', padx=4)
        ttk.Button(bot, text='选择', command=lambda: self._hyb_pick()).pack(side='left', padx=2)
        ttk.Button(bot, text='🔒 加密文件', command=lambda: self._hyb_fenc()).pack(side='left', padx=2)
        ttk.Button(bot, text='🔓 解密文件', command=lambda: self._hyb_fdec()).pack(side='left', padx=2)

        # ─── 中间区域：两行两列 ───
        mid = ttk.Frame(f)
        mid.pack(fill='both', expand=True, pady=6)

        row1 = ttk.Frame(mid)
        row1.pack(fill='both', expand=True, pady=(0,4))

        enc_g = ttk.LabelFrame(row1, text='📦 混合加密', padding=6)
        enc_g.pack(side='left', fill='both', expand=True, padx=(0,4))
        ttk.Label(enc_g, text='公钥:').grid(row=0, column=0, sticky='w', pady=2)
        self.hyb_enc_pub = ttk.Entry(enc_g, font=FONT_MONO)
        self.hyb_enc_pub.grid(row=0, column=1, sticky='ew', padx=4, pady=2)
        ttk.Label(enc_g, text='明文:').grid(row=1, column=0, sticky='nw', pady=2)
        self.hyb_enc_pt = _make_text_box(enc_g, height=2)
        self.hyb_enc_pt.grid(row=1, column=1, sticky='ew', pady=2)
        enc_g.columnconfigure(1, weight=1)
        ttk.Button(enc_g, text='加密', command=lambda: self._hyb_enc()) \
            .grid(row=2, column=1, sticky='w', pady=4)
        self.hyb_res_enc = _make_text_box(enc_g, height=2)
        self.hyb_res_enc.grid(row=3, column=0, columnspan=2, sticky='ew', pady=2)
        _make_copy_btn(enc_g, self.hyb_res_enc).grid(row=4, column=1, sticky='e', pady=(0,2))

        seng_g = ttk.LabelFrame(row1, text='✍ 先签名后加密', padding=6)
        seng_g.pack(side='right', fill='both', expand=True, padx=(4,0))
        ttk.Label(seng_g, text='私钥:').grid(row=0, column=0, sticky='w', pady=2)
        self.hyb_seng_priv = ttk.Entry(seng_g, font=FONT_MONO)
        self.hyb_seng_priv.grid(row=0, column=1, sticky='ew', padx=4, pady=2)
        ttk.Label(seng_g, text='消息:').grid(row=1, column=0, sticky='nw', pady=2)
        self.hyb_seng_msg = _make_text_box(seng_g, height=2)
        self.hyb_seng_msg.grid(row=1, column=1, sticky='ew', pady=2)
        seng_g.columnconfigure(1, weight=1)
        ttk.Button(seng_g, text='签名+加密', command=lambda: self._hyb_sign_enc()) \
            .grid(row=2, column=1, sticky='w', pady=4)
        self.hyb_res_seng = _make_text_box(seng_g, height=2)
        self.hyb_res_seng.grid(row=3, column=0, columnspan=2, sticky='ew', pady=2)
        _make_copy_btn(seng_g, self.hyb_res_seng).grid(row=4, column=1, sticky='e', pady=(0,2))

        row2 = ttk.Frame(mid)
        row2.pack(fill='both', expand=True, pady=(4,0))

        dec_g = ttk.LabelFrame(row2, text='📂 混合解密', padding=6)
        dec_g.pack(side='left', fill='both', expand=True, padx=(0,4))
        ttk.Label(dec_g, text='私钥:').grid(row=0, column=0, sticky='w', pady=2)
        self.hyb_dec_priv = ttk.Entry(dec_g, font=FONT_MONO)
        self.hyb_dec_priv.grid(row=0, column=1, sticky='ew', padx=4, pady=2)
        ttk.Label(dec_g, text='密文信封:').grid(row=1, column=0, sticky='nw', pady=2)
        self.hyb_dec_env = _make_text_box(dec_g, height=2)
        self.hyb_dec_env.grid(row=1, column=1, sticky='ew', pady=2)
        dec_g.columnconfigure(1, weight=1)
        ttk.Button(dec_g, text='解密', command=lambda: self._hyb_dec()) \
            .grid(row=2, column=1, sticky='w', pady=4)
        self.hyb_res_dec = _make_text_box(dec_g, height=2)
        self.hyb_res_dec.grid(row=3, column=0, columnspan=2, sticky='ew', pady=2)
        _make_copy_btn(dec_g, self.hyb_res_dec).grid(row=4, column=1, sticky='e', pady=(0,2))

        vdec_g = ttk.LabelFrame(row2, text='✓ 解密并验签', padding=6)
        vdec_g.pack(side='right', fill='both', expand=True, padx=(4,0))
        ttk.Label(vdec_g, text='私钥:').grid(row=0, column=0, sticky='w', pady=2)
        self.hyb_vdec_priv = ttk.Entry(vdec_g, font=FONT_MONO)
        self.hyb_vdec_priv.grid(row=0, column=1, sticky='ew', padx=4, pady=2)
        ttk.Label(vdec_g, text='公钥:').grid(row=1, column=0, sticky='w', pady=2)
        self.hyb_vdec_pub = ttk.Entry(vdec_g, font=FONT_MONO)
        self.hyb_vdec_pub.grid(row=1, column=1, sticky='ew', padx=4, pady=2)
        ttk.Label(vdec_g, text='密文信封:').grid(row=2, column=0, sticky='nw', pady=2)
        self.hyb_vdec_env = _make_text_box(vdec_g, height=1)
        self.hyb_vdec_env.grid(row=2, column=1, sticky='ew', pady=2)
        vdec_g.columnconfigure(1, weight=1)
        ttk.Button(vdec_g, text='解密+验签', command=lambda: self._hyb_ver_dec()) \
            .grid(row=3, column=1, sticky='w', pady=4)
        self.hyb_res_vdec = _make_text_box(vdec_g, height=2)
        self.hyb_res_vdec.grid(row=4, column=0, columnspan=2, sticky='ew', pady=2)
        _make_copy_btn(vdec_g, self.hyb_res_vdec).grid(row=5, column=1, sticky='e', pady=(0,2))

    def _hyb_gen(self):
        kp = generate_sm2_keypair()
        self.hyb_priv.delete(0, tk.END); self.hyb_priv.insert(0, kp.private_key)
        self.hyb_pub.delete(0, tk.END); self.hyb_pub.insert(0, kp.public_key)
        self.hyb_enc_pub.delete(0, tk.END); self.hyb_enc_pub.insert(0, kp.public_key)
        self.hyb_dec_priv.delete(0, tk.END); self.hyb_dec_priv.insert(0, kp.private_key)
        self.hyb_seng_priv.delete(0, tk.END); self.hyb_seng_priv.insert(0, kp.private_key)
        self.hyb_vdec_priv.delete(0, tk.END); self.hyb_vdec_priv.insert(0, kp.private_key)
        self.hyb_vdec_pub.delete(0, tk.END); self.hyb_vdec_pub.insert(0, kp.public_key)
        messagebox.showinfo('成功', '密钥对已生成并自动填入各输入框')

    def _hyb_pick(self):
        p = filedialog.askopenfilename()
        if p:
            self.hyb_file.delete(0, tk.END)
            self.hyb_file.insert(0, p)

    def _hyb_enc(self):
        pub = self.hyb_enc_pub.get().strip()
        data = self.hyb_enc_pt.get(1.0, tk.END).strip()
        if not pub or not data:
            messagebox.showwarning('提示', '请填入公钥和明文')
            return
        try:
            env = HybridCipher().encrypt(pub, data)
            self.hyb_res_enc.delete(1.0, tk.END)
            self.hyb_res_enc.insert(tk.END, f'加密信封 (Base64):\n{env}')
        except Exception as e:
            self.hyb_res_enc.delete(1.0, tk.END)
            self.hyb_res_enc.insert(tk.END, f'错误: {e}')

    def _hyb_dec(self):
        priv = self.hyb_dec_priv.get().strip()
        data = self.hyb_dec_env.get(1.0, tk.END).strip()
        if not priv or not data:
            messagebox.showwarning('提示', '请填入私钥和密文信封')
            return
        try:
            # 解密时需要公钥（从密文信封中提取），传入空字符串由库处理
            kp = SM2KeyPair(priv, '')
            pt = HybridCipher().decrypt(priv, '', data)
            self.hyb_res_dec.delete(1.0, tk.END)
            self.hyb_res_dec.insert(tk.END, f'解密结果:\n{pt}')
        except ValueError as e:
            self.hyb_res_dec.delete(1.0, tk.END)
            self.hyb_res_dec.insert(tk.END, f'⚠ {e}')
        except Exception as e:
            self.hyb_res_dec.delete(1.0, tk.END)
            self.hyb_res_dec.insert(tk.END, f'错误: {e}')

    def _hyb_sign_enc(self):
        priv = self.hyb_seng_priv.get().strip()
        pub = self.hyb_pub.get().strip()
        data = self.hyb_seng_msg.get(1.0, tk.END).strip()
        if not priv or not data:
            messagebox.showwarning('提示', '请填入私钥和消息')
            return
        try:
            kp = SM2KeyPair(priv, pub)
            env = hybrid_sign_encrypt(kp, kp.public_key, data)
            self.hyb_res_seng.delete(1.0, tk.END)
            self.hyb_res_seng.insert(tk.END, f'签名+加密信封:\n{env}')
        except Exception as e:
            self.hyb_res_seng.delete(1.0, tk.END)
            self.hyb_res_seng.insert(tk.END, f'错误: {e}')

    def _hyb_ver_dec(self):
        priv = self.hyb_vdec_priv.get().strip()
        pub = self.hyb_vdec_pub.get().strip()
        data = self.hyb_vdec_env.get(1.0, tk.END).strip()
        if not priv or not data:
            messagebox.showwarning('提示', '请填入私钥和密文信封')
            return
        try:
            kp = SM2KeyPair(priv, pub)
            pt, valid = hybrid_verify_decrypt(kp.private_key, kp.public_key, kp.public_key, data)
            self.hyb_res_vdec.delete(1.0, tk.END)
            self.hyb_res_vdec.insert(tk.END, f'解密: {pt}\n验签: {"✓ 来源可信" if valid else "✗ 来源不可信"}')
        except ValueError as e:
            self.hyb_res_vdec.delete(1.0, tk.END)
            self.hyb_res_vdec.insert(tk.END, f'⚠ {e}')
        except Exception as e:
            self.hyb_res_vdec.delete(1.0, tk.END)
            self.hyb_res_vdec.insert(tk.END, f'错误: {e}')

    def _hyb_fenc(self):
        src = self.hyb_file.get().strip()
        pub = self.hyb_pub.get().strip()
        if not src or not os.path.isfile(src):
            messagebox.showwarning('提示', '请选择文件')
            return
        try:
            out = hybrid_encrypt_file(pub, src)
            messagebox.showinfo('成功', f'文件混合加密成功:\n{out}')
        except Exception as e:
            messagebox.showerror('错误', str(e))

    def _hyb_fdec(self):
        src = self.hyb_file.get().strip()
        priv = self.hyb_priv.get().strip()
        pub = self.hyb_pub.get().strip()
        if not src or not os.path.isfile(src):
            messagebox.showwarning('提示', '请选择文件')
            return
        # 预检查文件是否为文本格式
        try:
            with open(src, 'rb') as f:
                header = f.read(64)
            header.decode('utf-8')
        except UnicodeDecodeError:
            messagebox.showerror('文件格式错误',
                '无法读取该文件：混合加密文件应为 Base64 文本格式。\n'
                '请确认选择了正确的加密文件（.hEnc 后缀），而不是其他格式的文件。')
            return
        try:
            out = hybrid_decrypt_file(priv, pub, src)
            messagebox.showinfo('成功', f'文件混合解密成功:\n{out}')
        except UnicodeDecodeError:
            messagebox.showerror('文件格式错误',
                '该文件不是有效的混合加密文件或已损坏。\n请确认选择了正确的 .hEnc 文件。')
        except Exception as e:
            messagebox.showerror('错误', str(e))

    # ==================== 密钥管理标签页 ====================
    def _tab_keymgr(self, nb):
        f = ttk.Frame(nb, padding=10)
        nb.add(f, text=' 密钥管理 ')

        top = ttk.Frame(f)
        top.pack(fill='x', pady=(0,8))

        gm = ttk.LabelFrame(top, text='新建密钥', padding=6)
        gm.pack(side='left', fill='x', expand=True, padx=(0,4))

        ttk.Label(gm, text='名称:').grid(row=0, column=0, sticky='w')
        self.km_name = ttk.Entry(gm, width=20)
        self.km_name.grid(row=0, column=1, sticky='ew', padx=4)
        ttk.Label(gm, text='描述:').grid(row=0, column=2, sticky='w', padx=(10,0))
        self.km_desc = ttk.Entry(gm, width=30)
        self.km_desc.grid(row=0, column=3, sticky='ew', padx=4)
        gm.columnconfigure(1, weight=1)
        gm.columnconfigure(3, weight=1)

        bf = ttk.Frame(gm)
        bf.grid(row=1, column=0, columnspan=4, sticky='w', pady=6)
        ttk.Button(bf, text='创建 SM2 密钥对', command=lambda: self._km_create_sm2()).pack(side='left', padx=2)
        ttk.Button(bf, text='创建 SM4 密钥', command=lambda: self._km_create_sm4()).pack(side='left', padx=2)
        ttk.Button(bf, text='🔄 刷新列表', command=lambda: self._km_refresh()).pack(side='left', padx=20)

        # 密钥列表 + 详情
        mid = ttk.Frame(f)
        mid.pack(fill='both', expand=True)

        lf = ttk.LabelFrame(mid, text='已保存的密钥', padding=6)
        lf.pack(side='left', fill='both', expand=True, padx=(0,4))

        self.km_tree = ttk.Treeview(lf, columns=('type', 'desc', 'time'), show='headings', height=12)
        self.km_tree.heading('#1', text='类型')
        self.km_tree.heading('#2', text='描述')
        self.km_tree.heading('#3', text='创建时间')
        self.km_tree.column('#1', width=60)
        self.km_tree.column('#2', width=140)
        self.km_tree.column('#3', width=140)
        self.km_tree.pack(fill='both', expand=True)
        self.km_tree.bind('<<TreeviewSelect>>', lambda e: self._km_show_detail())

        rf = ttk.LabelFrame(mid, text='密钥详情', padding=6)
        rf.pack(side='right', fill='both', expand=True, padx=(4,0))

        self.km_detail = _make_text_box(rf, height=12)
        self.km_detail.pack(fill='both', expand=True)

        act = ttk.Frame(rf)
        act.pack(fill='x', pady=4)
        r1 = ttk.Frame(act); r1.pack(fill='x')
        r2 = ttk.Frame(act); r2.pack(fill='x')
        ttk.Button(r1, text='📋 复制私钥', command=lambda: self._km_copy_priv()).pack(side='left', padx=2)
        ttk.Button(r1, text='📋 复制公钥', command=lambda: self._km_copy_pub()).pack(side='left', padx=2)
        ttk.Button(r2, text='▶ 导入 SM2', command=lambda: self._km_import_sm2()).pack(side='left', padx=2)
        ttk.Button(r2, text='▶ 导入 混合', command=lambda: self._km_import_hybrid()).pack(side='left', padx=2)
        ttk.Button(r2, text='▶ 导入 SM4', command=lambda: self._km_import_sm4()).pack(side='left', padx=2)
        ttk.Button(r2, text='🗑 删除', command=lambda: self._km_delete()).pack(side='left', padx=6)

        self.km_selected = None
        self._km_refresh()

    def _km_refresh(self):
        for row in self.km_tree.get_children():
            self.km_tree.delete(row)
        for k in self.km.list_sm2_keys():
            self.km_tree.insert('', tk.END, values=('SM2', k.get('description',''), k['created_at'][:16]),
                                tags=(k['name'], 'sm2'))
        for k in self.km.list_sm4_keys():
            self.km_tree.insert('', tk.END, values=('SM4', k.get('description',''), k['created_at'][:16]),
                                tags=(k['name'], 'sm4'))

    def _km_create_sm2(self):
        name = self.km_name.get().strip()
        desc = self.km_desc.get().strip()
        if not name:
            messagebox.showwarning('提示', '请输入密钥名称')
            return
        try:
            kp = self.km.create_sm2_keypair(name, desc)
            self.km_detail.delete(1.0, tk.END)
            self.km_detail.insert(tk.END, f'SM2 密钥对 "{name}" 创建成功!\n\n私钥: {kp.private_key}\n\n公钥: {kp.public_key}')
            self._km_refresh()
        except Exception as e:
            messagebox.showerror('错误', str(e))

    def _km_create_sm4(self):
        name = self.km_name.get().strip()
        desc = self.km_desc.get().strip()
        if not name:
            messagebox.showwarning('提示', '请输入密钥名称')
            return
        try:
            key = self.km.create_sm4_key(name, desc)
            self.km_detail.delete(1.0, tk.END)
            self.km_detail.insert(tk.END, f'SM4 密钥 "{name}" 创建成功!\n\n密钥 (hex): {key.hex()}')
            self._km_refresh()
        except Exception as e:
            messagebox.showerror('错误', str(e))

    def _km_show_detail(self):
        sel = self.km_tree.selection()
        if not sel:
            return
        item = self.km_tree.item(sel[0])
        tags = item.get('tags', [])
        if len(tags) < 2:
            return
        name, ktype = tags
        self.km_selected = (name, ktype)
        self.km_detail.delete(1.0, tk.END)

        if ktype == 'sm2':
            kp = self.km.load_sm2_keypair(name)
            if kp:
                self.km_detail.insert(tk.END, f'密钥名称: {name} (SM2)\n\n私钥:\n{kp.private_key}\n\n公钥:\n{kp.public_key}')
        else:
            key = self.km.load_sm4_key(name)
            if key:
                self.km_detail.insert(tk.END, f'密钥名称: {name} (SM4)\n\n密钥 (hex):\n{key.hex()}')

    def _km_copy_priv(self):
        if not self.km_selected:
            messagebox.showwarning('提示', '请先在左侧列表中选择一个密钥')
            return
        name, ktype = self.km_selected
        if ktype != 'sm2':
            messagebox.showwarning('提示', 'SM4 密钥没有私钥/公钥之分，请使用复制密钥')
            return
        kp = self.km.load_sm2_keypair(name)
        if kp:
            self.root.clipboard_clear()
            self.root.clipboard_append(kp.private_key)
            self.root.update()  # 确保剪贴板内容持久化
            messagebox.showinfo('✅ 已复制', f'私钥已复制到剪贴板\n{_clip(kp.private_key)}')

    def _km_copy_pub(self):
        if not self.km_selected:
            messagebox.showwarning('提示', '请先在左侧列表中选择一个密钥')
            return
        name, ktype = self.km_selected
        if ktype != 'sm2':
            messagebox.showwarning('提示', 'SM4 密钥没有私钥/公钥之分')
            return
        kp = self.km.load_sm2_keypair(name)
        if kp:
            self.root.clipboard_clear()
            self.root.clipboard_append(kp.public_key)
            self.root.update()  # 确保剪贴板内容持久化
            messagebox.showinfo('✅ 已复制', f'公钥已复制到剪贴板\n{_clip(kp.public_key)}')

    def _km_import_sm2(self):
        if not self.km_selected or self.km_selected[1] != 'sm2':
            messagebox.showwarning('提示', '请先选择一个 SM2 密钥')
            return
        name = self.km_selected[0]
        kp = self.km.load_sm2_keypair(name)
        if not kp:
            messagebox.showerror('错误', '密钥加载失败')
            return
        # 填入 SM2 标签页各字段
        self.sm2_enc_pub.delete(0, tk.END); self.sm2_enc_pub.insert(0, kp.public_key)
        self.sm2_dec_priv.delete(0, tk.END); self.sm2_dec_priv.insert(0, kp.private_key)
        self.sm2_sig_priv.delete(0, tk.END); self.sm2_sig_priv.insert(0, kp.private_key)
        self.sm2_ver_pub.delete(0, tk.END); self.sm2_ver_pub.insert(0, kp.public_key)
        self.sm2_priv_lb.delete(0, tk.END); self.sm2_priv_lb.insert(0, kp.private_key)
        self.sm2_pub_lb.delete(0, tk.END); self.sm2_pub_lb.insert(0, kp.public_key)
        # 切换到 SM2 标签页 (index 2)
        self.nb.select(2)
        messagebox.showinfo('✅ 已导入', f'SM2 密钥 "{name}" 已填入 SM2 标签页')

    def _km_import_hybrid(self):
        if not self.km_selected or self.km_selected[1] != 'sm2':
            messagebox.showwarning('提示', '请先选择一个 SM2 密钥')
            return
        name = self.km_selected[0]
        kp = self.km.load_sm2_keypair(name)
        if not kp:
            messagebox.showerror('错误', '密钥加载失败')
            return
        self.hyb_priv.delete(0, tk.END); self.hyb_priv.insert(0, kp.private_key)
        self.hyb_pub.delete(0, tk.END); self.hyb_pub.insert(0, kp.public_key)
        self.hyb_enc_pub.delete(0, tk.END); self.hyb_enc_pub.insert(0, kp.public_key)
        self.hyb_dec_priv.delete(0, tk.END); self.hyb_dec_priv.insert(0, kp.private_key)
        self.hyb_seng_priv.delete(0, tk.END); self.hyb_seng_priv.insert(0, kp.private_key)
        self.hyb_vdec_priv.delete(0, tk.END); self.hyb_vdec_priv.insert(0, kp.private_key)
        self.hyb_vdec_pub.delete(0, tk.END); self.hyb_vdec_pub.insert(0, kp.public_key)
        self.nb.select(3)
        messagebox.showinfo('✅ 已导入', f'SM2 密钥 "{name}" 已填入混合加密标签页')

    def _km_import_sm4(self):
        if not self.km_selected or self.km_selected[1] != 'sm4':
            messagebox.showwarning('提示', '请先选择一个 SM4 密钥')
            return
        name = self.km_selected[0]
        key = self.km.load_sm4_key(name)
        if not key:
            messagebox.showerror('错误', '密钥加载失败')
            return
        self.sm4_key.delete(0, tk.END); self.sm4_key.insert(0, key.hex())
        self.nb.select(1)
        messagebox.showinfo('✅ 已导入', f'SM4 密钥 "{name}" 已填入 SM4 标签页')

    def _km_delete(self):
        if not self.km_selected:
            messagebox.showwarning('提示', '请先在列表中选择一个密钥')
            return
        name, ktype = self.km_selected
        if not messagebox.askyesno('确认删除', f'确定要删除密钥 "{name}" 吗？'):
            return
        if ktype == 'sm2':
            self.km.delete_sm2_key(name)
        else:
            self.km.delete_sm4_key(name)
        self.km_detail.delete(1.0, tk.END)
        self.km_selected = None
        self._km_refresh()


if __name__ == '__main__':
    CryptoApp()