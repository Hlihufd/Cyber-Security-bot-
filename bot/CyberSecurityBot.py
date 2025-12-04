import sqlite3
import re
import ssl
import logging
import socket
import asyncio
import httpx
import platform
import os
import time
import subprocess
from datetime import datetime
from urllib.parse import urlparse
from typing import List, Tuple, Optional
from contextlib import closing
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    CallbackQueryHandler,
    ContextTypes,
    filters
)
from telegram.error import NetworkError

# Настройка логирования
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# Конфигурация
TOKEN = "7939158021:AAHjDg8aFRokZpvGyP5m1Wxv1h8zYkcMwM0"
DB_NAME = "security_recommendations.db"
SAFE_PORTS = [80, 443, 8080]
MAX_RETRIES = 3
DB_TIMEOUT = 15
DB_LOCK = asyncio.Lock()

# Настройка SSL
ssl_context = ssl.create_default_context()
ssl_context.set_ciphers('DEFAULT@SECLEVEL=1')

class DatabaseManager:
    def __init__(self):
        self.connection_pool = []
        self.lock = asyncio.Lock()
        
    async def get_connection(self):
        async with self.lock:
            if not self.connection_pool:
                conn = await asyncio.to_thread(
                    sqlite3.connect,
                    DB_NAME,
                    timeout=DB_TIMEOUT,
                    check_same_thread=False
                )
                conn.execute("PRAGMA journal_mode=WAL")
                return conn
            return self.connection_pool.pop()
            
    async def release_connection(self, conn):
        async with self.lock:
            self.connection_pool.append(conn)

db_manager = DatabaseManager()

async def self_heal_database():
    max_retries = 5
    for attempt in range(max_retries):
        try:
            async with DB_LOCK:
                if os.path.exists(DB_NAME):
                    try:
                        conn = await db_manager.get_connection()
                        await asyncio.to_thread(conn.execute, "PRAGMA wal_checkpoint(TRUNCATE)")
                        await asyncio.to_thread(conn.close)
                    except Exception as e:
                        logger.warning(f"Checkpoint error: {e}")
                    backup_name = f"{DB_NAME}.backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                    os.replace(DB_NAME, backup_name)
                    logger.info(f"Database backed up as {backup_name}")
                    return True
                return False
        except Exception as e:
            logger.warning(f"Self-heal attempt {attempt+1} failed: {e}")
            if attempt < max_retries - 1:
                await asyncio.sleep(0.5 * (attempt + 1))
            else:
                try:
                    if os.path.exists(DB_NAME):
                        os.remove(DB_NAME)
                        logger.warning("Database file forcibly removed")
                        return True
                except Exception as e_remove:
                    logger.error(f"Final removal failed: {e_remove}")
                    return False

async def init_db():
    for attempt in range(3):
        try:
            if os.path.exists(DB_NAME):
                try:
                    conn = await db_manager.get_connection()
                    cursor = await asyncio.to_thread(conn.execute, "PRAGMA integrity_check")
                    result = await asyncio.to_thread(cursor.fetchone)
                    if result[0] != "ok":
                        raise sqlite3.DatabaseError("Database corruption detected")
                except sqlite3.DatabaseError as e:
                    logger.warning(f"Database corrupted: {e}")
                    if not await self_heal_database():
                        raise
            conn = await db_manager.get_connection()
            await asyncio.to_thread(conn.execute, '''
                CREATE TABLE IF NOT EXISTS recommendations (
                    id INTEGER PRIMARY KEY,
                    target TEXT UNIQUE,
                    issue TEXT,
                    recommendation TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )''')
            await asyncio.to_thread(conn.commit)
            logger.info("Database initialized successfully")
            return True
        except Exception as e:
            logger.error(f"Init DB attempt {attempt+1} failed: {e}")
            if attempt == 2:
                logger.critical("Failed to initialize database after 3 attempts")
                raise
            await asyncio.sleep(1)

async def check_internet_connection() -> bool:
    """Проверяет интернет-соединение через несколько точек (IP и домены)"""
    test_urls = [
        "https://8.8.8.8",  # Google DNS
        "https://1.1.1.1",  # Cloudflare DNS
        "https://api.telegram.org "
    ]
    
    for url in test_urls:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                await client.get(url)
                return True
        except Exception as e:
            logger.debug(f"Connection failed to {url}: {str(e)}")
            continue
    
    # Резервная проверка через ping
    if platform.system().lower() == "windows":
        try:
            result = await safe_execute(["ping", "-n", "1", "8.8.8.8"], "")
            return "TTL=" in result[0]
        except Exception as e:
            logger.warning(f"Ping check failed: {str(e)}")
    
    return False

def is_valid_ip(target: str) -> bool:
    pattern = r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    return re.fullmatch(pattern, target) is not None

def normalize_url(url: str) -> str:
    parsed = urlparse(url)
    if not parsed.scheme:
        return f"http://{url}"
    return url

def is_valid_url(url: str) -> bool:
    try:
        parsed = urlparse(normalize_url(url))
        return all([parsed.scheme in {'http', 'https'}, parsed.netloc])
    except ValueError:
        return False

async def safe_execute(command: List[str], target: str) -> Tuple[str, bool]:
    try:
        full_command = command + [target]
        result = await asyncio.to_thread(
            subprocess.run,
            full_command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding='utf-8',
            errors='replace',
            timeout=30
        )
        output = result.stdout.strip()
        error = result.stderr.strip()
        if result.returncode != 0:
            logger.error(f"Command failed: {error}")
            return f"🔴 Ошибка выполнения:\n{error}", False
        return output, True
    except subprocess.TimeoutExpired:
        return "🔴 Таймаут выполнения команды", False
    except Exception as e:
        logger.error(f"Execution error: {str(e)}", exc_info=True)
        return f"🔴 Критическая ошибка:\n{str(e)}", False

async def nmap_scan(target: str) -> str:
    if not is_valid_ip(target):
        return "🚫 Некорректный формат IP-адреса"
    for attempt in range(MAX_RETRIES):
        result, success = await safe_execute([
            "nmap",
            "-Pn", "-sT", "-p", ",".join(map(str, SAFE_PORTS)), "-oN", "-"
        ], target)
        if success:
            clean_result = re.sub(r'<\?xml.*?\?>', '', result)
            clean_result = re.sub(r'<[^>]+>', '', clean_result)
            return "🔍 Результаты сканирования:\n" + clean_result[:4000]
        if attempt < MAX_RETRIES - 1:
            await asyncio.sleep(2)
    return "🔴 Не удалось выполнить сканирование"

async def check_ssl(url: str) -> str:
    try:
        hostname = urlparse(normalize_url(url)).hostname
        context = ssl.create_default_context()
        reader, writer = await asyncio.open_connection(
            hostname, 443, ssl=context, server_hostname=hostname
        )
        ssl_info = writer.get_extra_info('ssl_object')
        cert = ssl_info.getpeercert()
        writer.close()
        await writer.wait_closed()
        expire_date = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
        issuer = dict(x[0] for x in cert['issuer'])
        subject = dict(x[0] for x in cert['subject'])
        return (
            "🔐 Детали SSL-сертификата:\n"
            f"🛡️ Защищает: {subject.get('commonName', 'N/A')}\n"
            f"📅 Срок действия: {expire_date.strftime('%d.%m.%Y %H:%M:%S')}\n"
            f"🏢 Издатель: {issuer.get('organizationName', 'N/A')}\n"
            f"🔑 Алгоритм: {ssl_info.cipher()[0]}\n"
            f"📡 Протокол: {ssl_info.version()}"
        )
    except Exception as e:
        logger.error(f"SSL check error: {str(e)}")
        return f"🔴 Ошибка проверки SSL:\n{str(e)}"

async def test_sql_injection(url: str) -> str:
    if not is_valid_url(url):
        return "🚫 Некорректный формат URL"
    for attempt in range(MAX_RETRIES):
        try:
            connector = aiohttp.TCPConnector(ssl=ssl_context, limit_per_host=5)
            async with aiohttp.ClientSession(connector=connector) as session:
                results = []
                test_payloads = [
                    {"id": "' OR '1'='1"},
                    {"id": "1 AND 1=1"},
                    {"id": "1; SELECT pg_sleep(5)--"}
                ]
                for payload in test_payloads:
                    start_time = datetime.now()
                    try:
                        async with session.get(url, params=payload, timeout=15) as response:
                            response_time = (datetime.now() - start_time).total_seconds()
                            text = await response.text()
                            detection = any(keyword in text.lower() for keyword in ["error", "syntax", "mysql", "postgresql"])
                            results.append(
                                f"🔍 Тест {payload['id']}:\n"
                                f"⏱ Время ответа: {response_time:.2f} сек\n"
                                f"📊 Результат: {'⚠️ Уязвимость обнаружена' if detection else '✅ Безопасно'}"
                            )
                    except aiohttp.ClientTimeout:
                        results.append(
                            f"🔍 Тест {payload['id']}:\n"
                            "⏱ Таймаут запроса\n"
                            "📊 Результат: ❓ Неизвестно"
                        )
                return "📋 Результаты тестов SQLi:\n" + "\n".join(results)
        except Exception as e:
            if attempt < MAX_RETRIES - 1:
                await asyncio.sleep(2)
            else:
                logger.error(f"SQLi test error: {str(e)}")
                return f"🔴 Ошибка подключения:\n{str(e)}"
    return "🔴 Не удалось выполнить тестирование"

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    keyboard = [
        [InlineKeyboardButton("🔍 Сканировать IP", callback_data='scan_ip')],
        [InlineKeyboardButton("🌐 Проверить сайт", callback_data='check_web')]
    ]
    await update.message.reply_text(
        "🛡️ Добро пожаловать в SecurityBot!\nВыберите действие:",
        reply_markup=InlineKeyboardMarkup(keyboard)
    )

async def handle_query(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    if query.data in {'scan_ip', 'check_web'}:
        context.user_data['action'] = query.data
        await query.edit_message_text(
            text=f"📥 Введите {'IP-адрес' if query.data == 'scan_ip' else 'URL сайта'}:"
        )

async def save_to_db(target: str) -> bool:
    async with DB_LOCK:
        for retry in range(3):
            try:
                conn = await db_manager.get_connection()
                await asyncio.to_thread(
                    conn.execute,
                    "INSERT OR IGNORE INTO recommendations (target) VALUES (?)",
                    (target,)
                )
                await asyncio.to_thread(conn.commit)
                return True
            except sqlite3.OperationalError as e:
                logger.warning(f"Database busy, retry {retry+1}")
                await asyncio.sleep(0.3 * (retry + 1))
            except sqlite3.DatabaseError as e:
                logger.error(f"Database error: {e}")
                await init_db()
            finally:
                await db_manager.release_connection(conn)
        return False

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    action = context.user_data.get('action')
    text = update.message.text.strip()
    if not action:
        await update.message.reply_text("⚠️ Сначала выберите действие через меню!")
        return
    
    try:
        if action == 'scan_ip':
            if not is_valid_ip(text):
                await update.message.reply_text("🚫 Некорректный формат IP-адреса!")
                return
            result = await nmap_scan(text)
        elif action == 'check_web':
            url = normalize_url(text)
            if not is_valid_url(url):
                await update.message.reply_text("🚫 Некорректный формат URL!")
                return
            ssl_info = await check_ssl(url)
            sql_test = await test_sql_injection(url)
            result = f"{ssl_info}\n{sql_test}"
        
        if not await save_to_db(text):
            logger.warning("Failed to save to database")
            await update.message.reply_text(
                "⚠️ Не удалось сохранить результаты в базу данных, но проверка прошла успешно"
            )
        
        if len(result) > 4096:
            for i in range(0, len(result), 4096):
                await update.message.reply_text(result[i:i+4096])
        else:
            await update.message.reply_text(f"📊 Результаты проверки:\n{result}")
            
    except Exception as e:
        logger.error(f"Ошибка обработки запроса: {str(e)}", exc_info=True)
        await update.message.reply_text("🔴 Временная ошибка, попробуйте позже")
    finally:
        context.user_data.pop('action', None)

async def run_bot(application: Application):
    await application.initialize()
    await application.start()
    await application.updater.start_polling()
    try:
        while True:
            await asyncio.sleep(3600)
    except asyncio.CancelledError:
        logger.info("Получен сигнал завершения работы")
    finally:
        await application.updater.stop()
        await application.stop()
        await application.shutdown()

async def main():
    if not await check_internet_connection():
        logger.error("Нет подключения к интернету! Проверьте:")
        logger.error("1. Подключение к сети Wi-Fi/Ethernet")
        logger.error("2. Настройки прокси (если используются)")
        logger.error("3. Работу DNS (попробуйте 8.8.8.8 или 1.1.1.1)")
        await asyncio.sleep(5)
        return
    
    await init_db()
    
    application = Application.builder().token(TOKEN).connect_timeout(30).pool_timeout(30).build()
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CallbackQueryHandler(handle_query))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    
    retries = 0
    while retries < MAX_RETRIES:
        try:
            await run_bot(application)
            break
        except NetworkError as e:
            logger.error(f"Сетевая ошибка: {e}. Попытка {retries+1}/{MAX_RETRIES}")
            retries += 1
            await asyncio.sleep(5)
        except Exception as e:
            logger.error(f"Критическая ошибка: {e}")
            break

if __name__ == '__main__':
    if platform.system() == 'Windows':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Работа бота остановлена пользователем")