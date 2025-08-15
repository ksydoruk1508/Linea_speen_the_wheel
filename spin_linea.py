# spin_linea.py
# -*- coding: utf-8 -*-

# ===== Настройки паузы между кошельками =====
DELAY_MIN = 15   # сек
DELAY_MAX = 45   # сек

# ===== Ретраи для прокси =====
PROXY_RETRIES = 3
PROXY_RETRY_DELAY = 5  # сек между попытками

import time
import random
import requests
from datetime import datetime, timezone
from loguru import logger
from tabulate import tabulate

from web3 import Web3, HTTPProvider
from web3.middleware import geth_poa_middleware
from eth_utils import to_checksum_address
from eth_account.messages import encode_defunct
from eth_account import Account

# ===== Контракт и ABI (участие через participate) =====
CONTRACT_ADDRESS = to_checksum_address("0xDb3a3929269281F157A58D91289185F21E30A1e0")
CONTRACT_ABI = [
    {
        "inputs": [
            {"internalType": "uint64",  "name": "_nonce",                "type": "uint64"},
            {"internalType": "uint256", "name": "_expirationTimestamp",  "type": "uint256"},
            {"internalType": "uint64",  "name": "_boost",                "type": "uint64"},
            {
                "components": [
                    {"internalType": "bytes32", "name": "r", "type": "bytes32"},
                    {"internalType": "bytes32", "name": "s", "type": "bytes32"},
                    {"internalType": "uint8",   "name": "v", "type": "uint8"},
                ],
                "internalType": "struct Signature",
                "name": "_signature",
                "type": "tuple",
            },
        ],
        "name": "participate",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    }
]

# ===== Эндпоинты =====
LINEA_RPC       = "https://rpc.linea.build"
NONCE_URL       = "https://app.dynamicauth.com/api/v0/sdk/ae98b9b4-daaf-4bb3-b5e0-3f07175906ed/nonce"
VERIFY_URL      = "https://app.dynamicauth.com/api/v0/sdk/ae98b9b4-daaf-4bb3-b5e0-3f07175906ed/verify"
HUB_AUTH_URL    = "https://hub-api.linea.build/auth"
USERS_ME_URL    = "https://hub-api.linea.build/users/me"
SPINS_URL       = "https://hub-api.linea.build/spins"
SPINS_TODAY_URL = "https://hub-api.linea.build/spins/today"
PRIZES_URL      = "https://hub-api.linea.build/prizes/user"
REQUEST_ID      = "ae98b9b4-daaf-4bb3-b5e0-3f07175906ed"

# ===== Данные =====
def read_lines(fname):
    with open(fname, encoding="utf-8") as f:
        return [x.strip() for x in f if x.strip()]

private_keys = read_lines("private_keys.txt")
proxies      = read_lines("proxies.txt")

# ===== Вспомогательные =====
def make_web3(proxy):
    url = f"http://{proxy}"
    provider = HTTPProvider(LINEA_RPC, request_kwargs={"proxies": {"http": url, "https": url}})
    w3 = Web3(provider)
    w3.middleware_onion.inject(geth_poa_middleware, layer=0)
    return w3

def test_proxy_once(proxy):
    r = requests.get("https://httpbin.org/ip",
                     proxies={"http": f"http://{proxy}", "https": f"http://{proxy}"},
                     timeout=10)
    ip = r.json().get("origin")
    logger.info(f"Прокси {proxy} работает. IP: {ip}")

def test_proxy_with_retries(proxy, retries=PROXY_RETRIES, delay=PROXY_RETRY_DELAY):
    for attempt in range(1, retries+1):
        try:
            test_proxy_once(proxy)
            return True
        except Exception as e:
            if attempt < retries:
                logger.warning(f"Прокси {proxy} не ответил (попытка {attempt}/{retries}): {e}. Повтор через {delay}с")
                time.sleep(delay)
            else:
                logger.error(f"Прокси {proxy} не работает после {retries} попыток: {e}")
                return False

def build_message(address, nonce, issued_at):
    return (
        f"linea.build wants you to sign in with your Ethereum account:\n"
        f"{address}\n\n"
        "Welcome to Linea Hub. Signing is the only way we can truly know that you are the owner of the wallet you are connecting. Signing is a safe, gas-less transaction that does not in any way give Linea Hub permission to perform any transactions with your wallet.\n\n"
        f"URI: https://linea.build/hub/rewards\n"
        f"Version: 1\n"
        f"Chain ID: 1\n"
        f"Nonce: {nonce}\n"
        f"Issued At: {issued_at}\n"
        f"Request ID: {REQUEST_ID}"
    )

def get_nonce(session):
    r = session.get(NONCE_URL,
                    headers={"Referer": "https://linea.build/", "Origin": "https://linea.build"},
                    timeout=15)
    r.raise_for_status()
    js = r.json()
    logger.info(f"/nonce: {js}")
    return js

def get_dynamic_tokens(session, address, signature, message):
    payload = {
        "publicWalletAddress": address,
        "messageToSign": message,
        "signedMessage": signature,
        "chain": "EVM",
        "network": "1",
        "walletName": "rabby",
        "walletProvider": "browserExtension",
    }
    r = session.post(VERIFY_URL, json=payload,
                     headers={"Content-Type": "application/json",
                              "Referer": "https://linea.build/",
                              "Origin": "https://linea.build"},
                     timeout=15)
    logger.info(f"/verify: {r.status_code}")
    r.raise_for_status()
    js = r.json()
    tokens = {"jwt": js.get("jwt") or js.get("token"),
              "minifiedJwt": js.get("minifiedJwt") or js.get("jwt") or js.get("token")}
    return tokens

def get_bearer_tokens(session, address, pk):
    n = get_nonce(session)
    issued_at = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    msg = build_message(address, n["nonce"], issued_at)
    signature = Account.sign_message(encode_defunct(text=msg), private_key=pk).signature.hex()
    tokens = get_dynamic_tokens(session, address, signature, msg)
    if not (tokens.get("jwt") or tokens.get("minifiedJwt")):
        raise RuntimeError("DynamicAuth не вернул jwt/minifiedJwt")
    logger.info("Токены готовы (jwt/minified).")
    return tokens

def activate_user(session, jwt_token):
    headers = {"Authorization": f"Bearer {jwt_token}",
               "Origin": "https://linea.build",
               "Referer": "https://linea.build/"}
    r = session.post(HUB_AUTH_URL, headers=headers, data=b"", timeout=15)
    logger.info(f"/auth (Bearer jwt; пусто): {r.status_code} {r.text[:200]}")
    return 200 <= r.status_code < 300

def wait_user_ready(session, bearer, attempts=10, delay=1.5):
    headers = {"Authorization": f"Bearer {bearer}",
               "Origin": "https://linea.build",
               "Referer": "https://linea.build/"}
    for _ in range(attempts):
        r = session.get(USERS_ME_URL, headers=headers, timeout=10)
        logger.info(f"/users/me: {r.status_code} {r.text[:160]}")
        if r.status_code == 200:
            return True
        time.sleep(delay)
    return False

def read_spins_today(session, bearer):
    r = session.get(SPINS_TODAY_URL,
                    headers={"Authorization": f"Bearer {bearer}",
                             "Origin": "https://linea.build",
                             "Referer": "https://linea.build/"},
                    timeout=10)
    try:
        js = r.json()
    except Exception:
        js = {}
    logger.info(f"/spins/today: {r.status_code} {str(js)[:200]}")
    return r.status_code, js

def wait_counters_update(session, bearer, timeout_sec=180, interval_sec=6):
    status0, js0 = read_spins_today(session, bearer)
    plays0, today0 = js0.get("plays"), js0.get("todaySpins")
    t0 = time.time()
    last = js0
    while time.time() - t0 < timeout_sec:
        time.sleep(interval_sec)
        _, js = read_spins_today(session, bearer)
        last = js
        plays, today = js.get("plays"), js.get("todaySpins")
        if (isinstance(plays0, int) and isinstance(plays, int) and plays > plays0) or \
           (isinstance(today0, int) and isinstance(today, int) and today < today0):
            logger.success(f"Счётчики обновились: plays {plays0}->{plays}, todaySpins {today0}->{today}")
            return True, js0, js
    logger.warning("Счётчики не обновились за отведённое время.")
    return False, js0, last

def ensure_hex32(x):
    if not isinstance(x, str):
        raise ValueError("ожидалась hex-строка")
    if not x.startswith("0x"):
        x = "0x" + x
    return "0x" + x[2:].rjust(64, "0")

def parse_signature(sig):
    if isinstance(sig, dict):
        r = ensure_hex32(sig["r"]); s = ensure_hex32(sig["s"]); v = int(sig["v"])
    elif isinstance(sig, (list, tuple)) and len(sig) >= 3:
        r = ensure_hex32(sig[0]); s = ensure_hex32(sig[1]); v = int(sig[2])
    else:
        raise ValueError(f"Неизвестный формат сигнатуры: {sig}")
    if v in (0, 1):
        v += 27
    return r, s, v

def get_spin_signature(session, bearer):
    headers = {"Authorization": f"Bearer {bearer}",
               "Origin": "https://linea.build",
               "Referer": "https://linea.build/"}
    r = session.post(SPINS_URL, headers=headers, timeout=15)
    text = r.text[:200]
    logger.info(f"/spins: {r.status_code} {text}")
    if r.status_code == 403 and "exhausted your spins" in r.text:
        return {"status": "no_spins"}
    if r.status_code == 404 and ("not found" in r.text.lower() or "not found" in text.lower()):
        return {"status": "not_activated"}
    r.raise_for_status()
    return {"status": "ok", "data": r.json()}

def maybe_activate_and_retry(session, tokens):
    jwt = tokens.get("jwt") or tokens.get("minifiedJwt")
    if not jwt:
        return False
    if not activate_user(session, jwt):
        return False
    if not wait_user_ready(session, jwt, attempts=10, delay=1.0):
        return False
    logger.success("Кошелёк активирован автоматически.")
    return True

def get_streak(session, bearer):
    r = session.get(USERS_ME_URL, headers={"Authorization": f"Bearer {bearer}",
                                           "Origin": "https://linea.build",
                                           "Referer": "https://linea.build/"},
                    timeout=10)
    if r.status_code == 200:
        try:
            return int(r.json().get("streak", 0))
        except Exception:
            return None
    return None

def check_extra_spin_available(session, bearer):
    status, js = read_spins_today(session, bearer)
    if status == 200 and int(js.get("todaySpins", 0)) > 0:
        logger.info("Доступен дополнительный спин — повторим вращение.")
        return True
    return False

# ===== Работа с призами (факт) =====
def prize_to_str(p):
    if not isinstance(p, dict):
        return str(p)
    title = p.get("title") or p.get("name") or p.get("type") or p.get("reward") or ""
    amount = p.get("amount") or p.get("value") or p.get("points")
    token  = p.get("token") or p.get("symbol") or ""
    if isinstance(amount, (int, float, str)) and str(amount) != "":
        main = f"{amount} {token}".strip()
        return f"{title}: {main}" if title else main
    desc = p.get("description") or p.get("note") or ""
    return (f"{title} — {desc}".strip(" —")) if (title or desc) else "prize"

def fetch_prizes_page(session, bearer, skip=0, take=30):
    headers = {"Authorization": f"Bearer {bearer}",
               "Origin": "https://linea.build",
               "Referer": "https://linea.build/"}
    params = {"skip": skip, "take": take}
    r = session.get(PRIZES_URL, headers=headers, params=params, timeout=12)
    try:
        js = r.json()
    except Exception:
        js = {}
    logger.info(f"/prizes/user: {r.status_code} (skip={skip}, take={take}) size={len(js.get('data', []) or [])}, total={js.get('total')}")
    if r.status_code != 200:
        return {"data": [], "total": 0, "skip": skip, "take": take}
    return js

def fetch_all_prizes(session, bearer, page_size=50, max_pages=20):
    all_items = []
    skip = 0
    for _ in range(max_pages):
        page = fetch_prizes_page(session, bearer, skip=skip, take=page_size)
        items = page.get("data") or []
        all_items.extend(items)
        total = int(page.get("total") or 0)
        skip += page_size
        if len(all_items) >= total or not items:
            return all_items, total
    return all_items, len(all_items)

def prizes_set_signature(prizes):
    s = set()
    for p in prizes or []:
        pid = p.get("id") or p.get("_id") or p.get("uuid")
        if pid:
            s.add(("id", str(pid)))
        else:
            s.add(("txt", prize_to_str(p)))
    return s

def diff_new_prizes(before_list, after_list):
    before = prizes_set_signature(before_list)
    new_items = []
    for p in after_list or []:
        pid = p.get("id") or p.get("_id") or p.get("uuid")
        key = ("id", str(pid)) if pid else ("txt", prize_to_str(p))
        if key not in before:
            new_items.append(p)
    return new_items

# ===== Основной спин =====
def perform_spin(w3, session, bearer, address, pk, prizes_before):
    """Возвращает (status, extra_info, reward_list[str])."""
    sig_resp = get_spin_signature(session, bearer)
    status = sig_resp["status"]

    if status == "no_spins":
        logger.warning(f"({address}) Спинов на сегодня нет — пропуск.")
        return "no_spins", None, []

    if status == "not_activated":
        logger.warning(f"({address}) Пользователь не активирован — пробуем автоактивацию.")
        if maybe_activate_and_retry(session, {"jwt": bearer}):
            sig_resp = get_spin_signature(session, bearer)
            status = sig_resp["status"]
            if status == "not_activated":
                logger.error(f"({address}) Не удалось активировать кошелёк — пропуск.")
                return "not_activated", None, []
            if status == "no_spins":
                logger.warning(f"({address}) После активации спинов нет — пропуск.")
                return "no_spins", None, []
        else:
            logger.error(f"({address}) Активация не удалась — пропуск.")
            return "not_activated", None, []

    if status != "ok":
        logger.error(f"({address}) Неожиданный статус {status} при запросе /spins.")
        return "error", None, []

    spin_data = sig_resp["data"]
    logger.info(f"({address}) Данные спина: {spin_data}")

    try:
        nonce   = int(spin_data["nonce"])
        exp_ts  = int(spin_data["expirationTimestamp"])
        boost   = int(spin_data.get("boost", 0))
        r_, s_, v_ = parse_signature(spin_data["signature"])
    except Exception as e:
        logger.error(f"({address}) Ошибка разбора сигнатуры: {e}")
        return "error", None, []

    contract = w3.eth.contract(address=CONTRACT_ADDRESS, abi=CONTRACT_ABI)
    gas_price = w3.eth.gas_price

    try:
        est_gas = contract.functions.participate(nonce, exp_ts, boost, (r_, s_, v_)) \
            .estimate_gas({"from": address})
        logger.info(f"({address}) Оценка газа: {est_gas}, gasPrice: {gas_price}")
    except Exception as e:
        logger.error(f"({address}) Не удалось оценить газ: {e} — использую дефолт.")
        est_gas = 250_000

    need_wei = int(est_gas * gas_price * 1.15)
    balance  = w3.eth.get_balance(address)
    if balance < need_wei:
        logger.warning(
            f"({address}) Недостаточно средств: {Web3.from_wei(balance,'ether')} ETH, "
            f"нужно ~{Web3.from_wei(need_wei,'ether')} ETH."
        )
        return "error", "Недостаточно средств", []

    nonce_on_chain = w3.eth.get_transaction_count(address)
    tx = contract.functions.participate(nonce, exp_ts, boost, (r_, s_, v_)).build_transaction({
        "from": address,
        "gas": int(est_gas * 1.10),
        "gasPrice": gas_price,
        "nonce": nonce_on_chain,
    })

    signed = w3.eth.account.sign_transaction(tx, pk)
    tx_hash = w3.eth.send_raw_transaction(signed.rawTransaction)
    tx_hash_hex = tx_hash.hex()
    logger.info(f"({address}) Tx отправлен: {tx_hash_hex}")

    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=180)
    if receipt.status != 1:
        logger.error(f"({address}) Транзакция не прошла: {tx_hash_hex}")
        return "error", "tx failed", []

    logger.success(f"({address}) Успешно! Tx: {tx_hash_hex} | Gas used: {receipt.gasUsed}")

    ok, before, after = wait_counters_update(session, bearer, timeout_sec=180, interval_sec=6)
    if ok:
        logger.info(f"({address}) Счётчики обновились: {before} -> {after}")
    else:
        logger.warning(f"({address}) Индексация запаздывает (но транза успешна).")

    prizes_after, total_after = fetch_all_prizes(session, bearer, page_size=50)
    new_prizes = diff_new_prizes(prizes_before, prizes_after)
    if new_prizes:
        display = [prize_to_str(p) for p in new_prizes]
        logger.success(f"({address}) Новые призы: {', '.join(display)}")
    else:
        logger.info(f"({address}) Новых призов не появилось (total={total_after}).")

    return "done", None, [prize_to_str(p) for p in new_prizes]

def spin_wallet(pk, proxy, idx, total):
    session = requests.Session()
    session.proxies = {"http": f"http://{proxy}", "https": f"http://{proxy}"}
    session.headers.update({
        "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                       "AppleWebKit/537.36 (KHTML, like Gecko) "
                       "Chrome/118.0.0.0 Safari/537.36")
    })

    if not test_proxy_with_retries(proxy):
        return {"address": "-", "streak": None, "status": "Прокси ошибка", "reward": "—"}

    w3 = make_web3(proxy)
    address = w3.eth.account.from_key(pk).address
    logger.info(f"({idx+1}/{total}) Кошелёк: {address} | Прокси: {proxy}")

    # Токены
    try:
        tokens = get_bearer_tokens(session, address, pk)
    except Exception as e:
        logger.error(f"({address}) Не удалось получить токены: {e}")
        return {"address": address, "streak": None, "status": "Токен ошибка", "reward": "—"}

    bearer = tokens.get("jwt") or tokens.get("minifiedJwt")
    if not bearer:
        return {"address": address, "streak": None, "status": "Нет Bearer", "reward": "—"}

    # BEFORE: призы до
    prizes_before, total_before = fetch_all_prizes(session, bearer, page_size=50)
    logger.info(f"({address}) Призов до спина: {total_before}")

    any_spin_done = False
    all_new_prizes = []
    last_status = "Ошибка"

    while True:
        status, _, new_list = perform_spin(w3, session, bearer, address, pk, prizes_before)
        last_status = status
        if status == "done":
            any_spin_done = True
            all_new_prizes.extend([x for x in new_list if x])
            prizes_before, _ = fetch_all_prizes(session, bearer, page_size=50)
            if check_extra_spin_available(session, bearer):
                continue
            break
        elif status in ("no_spins", "not_activated"):
            break
        else:
            break

    streak = get_streak(session, bearer)

    if any_spin_done:
        status_label = "Вращено"
        reward_label = ", ".join(all_new_prizes) if all_new_prizes else "Без приза"
    else:
        status_label = {"no_spins": "Нет спинов",
                        "not_activated": "Не активирован"}.get(last_status, "Ошибка")
        reward_label = "—"

    return {"address": address, "streak": streak, "status": status_label, "reward": reward_label}

# ======== MAIN ========
if __name__ == "__main__":
    logger.add("spin_linea.log", rotation="1 week", backtrace=False, diagnose=False)

    results = []
    total = len(private_keys)

    for idx, pk in enumerate(private_keys):
        proxy = proxies[idx % len(proxies)]
        try:
            res = spin_wallet(pk, proxy, idx, total)
        except Exception as e:
            logger.exception(f"(idx={idx}) Непойманная ошибка: {e}")
            res = {"address": "-", "streak": None, "status": "Критическая ошибка", "reward": "—"}
        results.append(res)

        if idx < total - 1:
            delay = random.randint(DELAY_MIN, DELAY_MAX)
            logger.info(f"Пауза {delay} сек до следующего кошелька...")
            time.sleep(delay)

    # Таблица итогов
    rows = []
    for r in results:
        addr = r["address"]
        streak = r["streak"]
        streak_str = (f"{streak} дн." if isinstance(streak, int) else "-")
        rows.append([addr, streak_str, r["status"], r["reward"]])

    print("\nИТОГИ:")
    print(tabulate(rows, headers=["Кошелёк", "Streak", "Статус", "Награды"], tablefmt="fancy_grid"))

    # (опционально) Сохранить CSV
    try:
        import csv
        with open("results.csv", "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["address", "streak", "status", "reward"])
            for r in results:
                w.writerow([r["address"],
                            r["streak"] if r["streak"] is not None else "",
                            r["status"], r["reward"]])
        logger.info("Итог сохранён в results.csv")
    except Exception as e:
        logger.warning(f"Не удалось сохранить results.csv: {e}")
