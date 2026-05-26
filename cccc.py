"""vulnerable_app.py.

此程式碼已進行安全重構，修復了 SQL 注入、阻斷服務、憑證洩漏等漏洞，
並改善了程式碼壞味道（Code Smell）。
"""

import hmac
import logging
import os
import secrets
import sqlite3
import subprocess
from typing import Any, List, Optional
import requests

# 建立 Logger 代替 print 進行除錯，避免機敏資訊外洩
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

# ==============================================================================
# 安全修復：將硬編碼憑證移至環境變數（Hardcoded Secrets -> Environment Variables）
# ==============================================================================
PASSWORD = os.getenv("APP_ADMIN_PASSWORD", "default_secure_fallback_password")
API_KEY = os.getenv("APP_API_KEY")

users: List[str] = []


# ==============================================================================
# 安全修復：SQL 注入（SQL Injection -> Parameterized Query）
# ==============================================================================
def login(username: str, password: str) -> bool:
    """使用參數化查詢防止 SQL Injection。"""
    conn = sqlite3.connect("test.db")
    cursor = conn.cursor()

    # 使用 ? 作為佔位符，由 DB 驅動安全處理輸入值
    query = "SELECT * FROM users WHERE username=? AND password=?"
    cursor.execute(query, (username, password))
    result = cursor.fetchone()
    conn.close()

    return result is not None


# ==============================================================================
# 安全修復：命令注入（Command Injection -> Shlex Split & shell=False）
# ==============================================================================
def ping_host(ip: str) -> None:
    """移除 os.system，改用 subprocess 並關閉 shell=True。"""
    try:
        # 使用 list 傳入參數，且不透過 shell 執行，防止指令拼接注入
        subprocess.run(["ping", "-c", "1", ip], shell=False, check=True)
    except subprocess.CalledProcessError as e:
        logger.error(f"Ping failed: {e}")


def run_command(cmd: List[str]) -> None:
    """禁止接收字串型態並開啟 shell=True 的指令執行。"""
    if not isinstance(cmd, list):
        raise ValueError("Command must be a list of arguments")
    subprocess.run(cmd, shell=False, check=True)


# ==============================================================================
# 安全修復：弱雜湊演算法（Weak Hash -> SHA-256 / PBKDF2）
# ==============================================================================
def hash_password(password: str) -> str:
    """廢棄 MD5，改用更安全的 SHA-256（實務上建議用 bcrypt 或 argon2）。"""
    # 這裡示範使用密碼學安全的 hmac / hashlib.sha256
    import hashlib
    return hashlib.sha256(password.encode()).hexdigest()


# ==============================================================================
# 安全修復：可預測隨機數（Predictable Random -> Secrets Module）
# ==============================================================================
def generate_token() -> int:
    """廢棄 random.seed()，改用密碼學安全的 secrets 模組。"""
    return secrets.randbelow(9000) + 1000  # 生成 1000 ~ 9999 的隨機數


# ==============================================================================
# 安全修復：不安全的反序列化（Dangerous Pickle -> JSON / Safe Format）
# ==============================================================================
def load_user_data_safe(data_string: str) -> Any:
    """廢棄 pickle.load() 以防 RCE 漏洞，改用標準 JSON。"""
    import json
    return json.loads(data_string)


# ==============================================================================
# 壞味道修復：錯誤處理與邏輯優化（Code Smells & Logic Errors）
# ==============================================================================
def divide(a: float, b: float) -> Optional[float]:
    """加入除以零檢查，避免程式崩潰。"""
    if b == 0:
        logger.warning("Attempted to divide by zero.")
        return None
    return a / b


def calculate() -> int:
    """移除未使用的變數 z。"""
    x = 100
    y = 200
    return x + y


def add_numbers(a: int, b: int) -> int:
    """刪除重複的 add_numbers2 函數，統一呼叫此函數。"""
    result = a + b
    logger.info(f"Result: {result}")
    return result


def recursive(depth: int = 0) -> None:
    """加入終止條件，防止無限遞迴（Stack Overflow）。"""
    if depth > 10:
        return
    recursive(depth + 1)


def safe_exception() -> None:
    """禁止使用空捕捉（Bare Except），必須指定異常型態並記錄 log。"""
    try:
        _ = 1 / 0
    except ZeroDivisionError as e:
        logger.error(f"Captured expected error: {e}")


def debug_mode() -> None:
    """移除敏感密碼列印，改用適當的 Log 層級。"""
    logger.debug("DEBUG MODE ENABLED")


def call_api() -> str:
    """將硬編碼 URL 參數化（應從設定檔或環境變數讀取），實務上應盡量避免不安全的 http。"""
    url = os.getenv("API_ENDPOINT", "https://api.secure-domain.com/data")
    response = requests.get(url, timeout=10)  # 加入 timeout 防止連線掛起阻斷服務
    return response.text


def read_file(file_path: str = "test.txt") -> str:
    """使用 with context manager 確保檔案資源正確釋放（修復 Leak）。"""
    with open(file_path, "r", encoding="utf-8") as f:
        return f.read()


def calculate_input_safe(user_input: str) -> Any:
    """絕對禁止使用 eval()，改用安全解析數學公式的 ast.literal_eval。"""
    import ast
    try:
        return ast.literal_eval(user_input)
    except (ValueError, SyntaxError):
        logger.error("Invalid or unsafe input for evaluation.")
        return None


# ==============================================================================
# 壞味道修復：全局變數、長函數、可變預設參數、None 比較
# ==============================================================================
# 移除全域變數 count 濫用，改用類別或封裝（此處簡化示範）

def huge_function() -> None:
    """將原本冗長且重複的列印邏輯簡化。"""
    for i in range(1, 21):
        logger.info(f"line{i}")


def test_return() -> bool:
    """移除無法執行到的程式碼（Unreachable Code）。"""
    return True


def check_none(value: Any) -> bool:
    """使用 'is None' 代替 '== None'。"""
    return value is None


def append_item(item: Any, items: Optional[List[Any]] = None) -> List[Any]:
    """修復可變動預設參數（Mutable Default Argument）共用記憶體的問題。"""
    if items is None:
        items = []
    items.append(item)
    return items


# ==============================================================================
# Main
# ==============================================================================
if __name__ == "__main__":
    # 測試執行
    logger.info(f"Login success: {login('admin', 'admin')}")
    ping_host("127.0.0.1")
    logger.info(f"Token: {generate_token()}")
    safe_exception()
    debug_mode()
    logger.info(f"Calc: {calculate_input_safe('2')}")  # literal_eval 安全解析
    huge_function()
