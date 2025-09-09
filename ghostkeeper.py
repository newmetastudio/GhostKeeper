#!/usr/bin/env python3
"""
Техническая разработка и дизайн — NewMeta Studio (https://t,me/new_metas). Условия использования GhostKeeper: https://clck.ru/3P5hmE
Technical development and design — NewMeta Studio (https://t,me/new_metas). GhostKeeper Terms of Use: https://clck.ru/3P5hmE
技术研发与设计 — NewMeta Studio (https://t,me/new_metas)。GhostKeeper 使用条款：https://clck.ru/3P5hmE
"""

import os
import asyncio
import logging
import json
import gzip
import base64
import lzma
import zlib
import brotli
import secrets
import imageio
import warnings
from datetime import datetime, timedelta, timezone
from pathlib import Path
import aiohttp

# Подавление пред-ий от imageio о pkg_resources
warnings.filterwarnings("ignore", message="pkg_resources is deprecated as an API", category=UserWarning)
from PIL import Image, ImageOps
import io
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Переменные окружения 
def load_env_file_silent():
    """Загружает переменные окружения из файла config.env"""
    env_file = Path("config.env")
    
    if not env_file.exists():
        print("❌ Файл config.env не найден!")
        return False
    
    try:
        with open(env_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    os.environ[key] = value
        
        return True
        
    except Exception as e:
        print(f"❌ Ошибка загрузки переменных окружения: {e}")
        return False

def load_env_file():
    """Загружает переменные окружения из файла config.env"""
    env_file = Path("config.env")
    
    if not env_file.exists():
        print(get_log_text('log_env_file_not_found'))
        return False
    
    try:
        with open(env_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    os.environ[key] = value
                    print(get_log_text('log_env_loaded', env_key=key))
        
        return True
        
    except Exception as e:
        print(get_log_text('log_env_load_error', error=str(e)))
        return False

print()  

# Настройки шифрования 
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY", "your-secret-key-change-this-in-production")
SALT = b'ghostkeeper_salt_2025'  # Соль 
COMPRESSION_ENABLED = True  # Вкл. сжатие
ENCRYPTION_ENABLED = True   # Пермач
COMPRESSION_ALGORITHM = "brotli"  # brotli, lzma, zlib, gzip, none
COMPRESSION_LEVEL = 11  # Ур. сжатия
ENCRYPTION_ALGORITHM = "AES256_GCM"  
KEY_DERIVATION_ITERATIONS = 1000000  # Количество итераций для генерации ключа

# Настройки сжатия файлов
FILE_COMPRESSION_ENABLED = True  # Включить сжатие медиафайлов
IMAGE_COMPRESSION_QUALITY = 85  # Качество сжатия изображений (1-100)
AUDIO_COMPRESSION_BITRATE = "128k"  # Битрейт аудио
MAX_IMAGE_SIZE = 1920  # Максимальный размер изображения

# Файл с внутренними настройками
SETTINGS_FILE = Path("bot_settings.json")

# Функции шифрования и сжатия
def generate_encryption_key(password: str, salt: bytes) -> bytes:
    """Генерирует ключ шифрования из пароля"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),  
        length=32,
        salt=salt,
        iterations=KEY_DERIVATION_ITERATIONS,  
    )
    key = kdf.derive(password.encode())
    return key

def generate_random_salt() -> bytes:
    """Генерирует криптографически стойкую случайную соль"""
    return secrets.token_bytes(32)  

def encrypt_with_aes256_gcm(data: bytes, key: bytes) -> bytes:
    """Шифрует данные с помощью AES-256-GCM"""
    nonce = secrets.token_bytes(12) 
    
    # Создаем шифр
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
    encryptor = cipher.encryptor()
    
    # Шифруем данные
    ciphertext = encryptor.update(data) + encryptor.finalize()
    
    # Получаем тег аутентификации
    tag = encryptor.tag
    
    return nonce + tag + ciphertext

def decrypt_with_aes256_gcm(encrypted_data: bytes, key: bytes) -> bytes:
    """Расшифровывает данные с помощью AES-256-GCM"""
    nonce = encrypted_data[:12]
    tag = encrypted_data[12:28]
    ciphertext = encrypted_data[28:]
    
    # Создаем шифр
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
    decryptor = cipher.decryptor()
    
    # Расшифровываем данные
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext


 

def optimize_json_data(data: dict) -> dict:
    """Оптимизирует JSON данные для максимального сжатия"""
    try:
        optimized = {}
        
        for key, value in data.items():
            # Пропускаем пустые значения
            if value is None or value == "" or value == [] or value == {}:
                continue
                
            # Оптимизация вложенныз структур
            if isinstance(value, dict):
                optimized_value = optimize_json_data(value)
                if optimized_value:  # Добавляем только если есть данные
                    optimized[key] = optimized_value
            elif isinstance(value, list):
                # Фильтруем пустые элементы
                filtered_list = [item for item in value if item is not None and item != ""]
                if filtered_list:
                    optimized[key] = filtered_list
            else:
                optimized[key] = value
        
        return optimized
    except Exception as e:
        logger.error(get_log_text("log_json_optimization_error") + f": {e}")
        return data

def compress_image(input_path: Path, output_path: Path = None) -> Path:
    """Сжимает изображение без потери качества"""
    try:
        if output_path is None:
            output_path = input_path
        
        # Открываем изображение
        with Image.open(input_path) as img:
            # Конвертируем в RGB если нужно
            if img.mode in ('RGBA', 'LA', 'P'):
                img = img.convert('RGB')
            
            # Изменяем размер если слишком большое
            if max(img.size) > MAX_IMAGE_SIZE:
                img.thumbnail((MAX_IMAGE_SIZE, MAX_IMAGE_SIZE), Image.Resampling.LANCZOS)
            
            # Оптимизируем изображение
            img = ImageOps.exif_transpose(img)  # Исправляем ориентацию
            
            # Сохраняем с максимальным сжатием
            img.save(output_path, 'JPEG', quality=IMAGE_COMPRESSION_QUALITY, optimize=True, progressive=True)
            
            original_size = input_path.stat().st_size
            compressed_size = output_path.stat().st_size
            compression_ratio = (1 - compressed_size / original_size) * 100
            
            # Убираем лог сжатия изображения
            return output_path
            
    except Exception as e:
        # Убираем лог ошибки сжатия изображения
        return input_path


def compress_audio(input_path: Path, output_path: Path = None) -> Path:
    """Сжимает аудио без потери качества"""
    try:
        if output_path is None:
            output_path = input_path.with_suffix('.mp3')
        
        # Поддерживает ли imageio этот тип файла
        file_ext = input_path.suffix.lower()
        if file_ext in ['.ogg', '.wav', '.flac']:
            # Копируем файл без сжатия
            import shutil
            shutil.copy2(input_path, output_path)
            return output_path
        
        # Сжатие файлов
        audio = imageio.get_reader(input_path)
        
        # Сохраняем с сжатием
        imageio.write(audio, str(output_path), bitrate=AUDIO_COMPRESSION_BITRATE)
        
        original_size = input_path.stat().st_size
        compressed_size = output_path.stat().st_size
        compression_ratio = (1 - compressed_size / original_size) * 100
        
        # Убираем лог сжатия аудио
        return output_path
        
    except Exception as e:
        # Убираем лог ошибки сжатия аудио
        return input_path

def compress_file(file_path: Path) -> Path:
    """Сжимает файл в зависимости от его типа"""
    try:
        if not FILE_COMPRESSION_ENABLED:
            return file_path
        
        file_extension = file_path.suffix.lower()
        
        # Изображения
        if file_extension in ['.jpg', '.jpeg', '.png', '.bmp', '.tiff', '.webp', '.gif']:
            return compress_image(file_path)
        
        # Видео - не сжимается
        elif file_extension in ['.mp4', '.avi', '.mov', '.mkv', '.wmv']:
            # Убираем лог о сжатии видео
            return file_path
        
        # Аудио
        elif file_extension in ['.mp3', '.wav', '.ogg', '.flac', '.aac']:
            return compress_audio(file_path)
        
        # Архивация док-ов
        elif file_extension in ['.pdf', '.doc', '.docx', '.txt', '.rtf']:
            # gzip сжатие
            compressed_path = file_path.with_suffix(file_path.suffix + '.gz')
            with open(file_path, 'rb') as f_in:
                with gzip.open(compressed_path, 'wb', compresslevel=9) as f_out:
                    f_out.writelines(f_in)
            
            original_size = file_path.stat().st_size
            compressed_size = compressed_path.stat().st_size
            compression_ratio = (1 - compressed_size / original_size) * 100
            
            logger.info(get_log_text("log_document_compression", original=original_size, compressed=compressed_size, ratio=compression_ratio))
            return compressed_path
        
        else:
            return file_path
            
    except Exception as e:
        logger.error(get_log_text("log_file_compression_error", file=file_path) + f": {e}")
        return file_path

def compress_and_encrypt_data(data: dict) -> bytes:
    """Сжимает и шифрует данные с максимальной оптимизацией и безопасностью"""
    try:
        # 1. Оптимизируем данные перед сжатием
        optimized_data = optimize_json_data(data)
        
        # 2. Оптимизируем JSON 
        json_data = json.dumps(optimized_data, ensure_ascii=False, separators=(',', ':'), sort_keys=True)
        original_size = len(json_data.encode('utf-8'))
        
        # 3. Сжимаем данные 
        if COMPRESSION_ENABLED:
            if COMPRESSION_ALGORITHM == "brotli":
                compressed_data = brotli.compress(json_data.encode('utf-8'), quality=COMPRESSION_LEVEL, lgwin=24)
                algorithm_name = f"Brotli (Level {COMPRESSION_LEVEL})"
            elif COMPRESSION_ALGORITHM == "lzma":
                compressed_data = lzma.compress(json_data.encode('utf-8'), preset=lzma.PRESET_EXTREME)
                algorithm_name = "LZMA (Extreme)"
            elif COMPRESSION_ALGORITHM == "zlib":
                compressed_data = zlib.compress(json_data.encode('utf-8'), level=9)
                algorithm_name = "ZLIB (Level 9)"
            elif COMPRESSION_ALGORITHM == "gzip":
                compressed_data = gzip.compress(json_data.encode('utf-8'), compresslevel=9)
                algorithm_name = "GZIP (Level 9)"
            else:
                compressed_data = json_data.encode('utf-8')
                algorithm_name = "Без сжатия"
            
            compressed_size = len(compressed_data)
            compression_ratio = (1 - compressed_size / original_size) * 100
            # Убираем лог сжатия Brotli
        else:
            compressed_data = json_data.encode('utf-8')
            logger.info(get_log_text("log_no_compression", size=len(compressed_data)))
        
        # 4. Шифруем данные
        if ENCRYPTION_ENABLED:
            key = generate_encryption_key(ENCRYPTION_KEY, SALT)
            
            if ENCRYPTION_ALGORITHM == "AES256_GCM":
                encrypted_data = encrypt_with_aes256_gcm(compressed_data, key)
                encryption_name = "AES-256-GCM"
            else:
                raise ValueError("Unsupported ENCRYPTION_ALGORITHM. Use AES256_GCM.")
            
            final_size = len(encrypted_data)
            # Убираем лог шифрования AES-256-GCM
            return encrypted_data
        else:
            logger.info(get_log_text("log_no_encryption", size=len(compressed_data)))
            return compressed_data
            
    except Exception as e:
        logger.error(get_log_text("log_compression_encryption_error") + f": {e}")
        # Исх. данные возвращаем в случае ошибки
        return json.dumps(data, ensure_ascii=False).encode('utf-8')

def decrypt_and_decompress_data(encrypted_data: bytes) -> dict:
    """Расшифровывает и распаковывает данные с максимальной безопасностью"""
    try:
        original_size = len(encrypted_data)
        
        # 1. Расшифровываем данные
        if ENCRYPTION_ENABLED:
            key = generate_encryption_key(ENCRYPTION_KEY, SALT)
            
            try:
                if ENCRYPTION_ALGORITHM == "AES256_GCM":
                    decrypted_data = decrypt_with_aes256_gcm(encrypted_data, key)
                    encryption_name = "AES-256-GCM"
                else:
                    raise ValueError("Unsupported ENCRYPTION_ALGORITHM. Use AES256_GCM.")
                
                decrypted_size = len(decrypted_data)
                from datetime import datetime, timezone, UTC, UTC
                current_time = datetime.now().strftime("%d.%m.%Y в %H:%M:%S")
                logger.info(f"{current_time} - {get_log_text('log_decryption', algorithm=encryption_name, original=original_size, decrypted=decrypted_size)}")
            except Exception as e:
                logger.error(get_log_text("log_decryption_error", algorithm=ENCRYPTION_ALGORITHM) + f": {e}")
                raise
        else:
            decrypted_data = encrypted_data
            logger.info(get_log_text("log_no_decryption", size=original_size))
        
        # 2. Если это сжатые данные - распаковываем
        try:
            if COMPRESSION_ALGORITHM == "brotli":
                decompressed_data = brotli.decompress(decrypted_data)
                algorithm_name = "Brotli"
            elif COMPRESSION_ALGORITHM == "lzma":
                decompressed_data = lzma.decompress(decrypted_data)
                algorithm_name = "LZMA"
            elif COMPRESSION_ALGORITHM == "zlib":
                decompressed_data = zlib.decompress(decrypted_data)
                algorithm_name = "ZLIB"
            elif COMPRESSION_ALGORITHM == "gzip":
                decompressed_data = gzip.decompress(decrypted_data)
                algorithm_name = "GZIP"
            else:
                decompressed_data = decrypted_data
                algorithm_name = "Без распаковки"
            
            decompressed_size = len(decompressed_data)
            from datetime import datetime, timezone, UTC
            current_time = datetime.now().strftime("%d.%m.%Y в %H:%M:%S")
            logger.info(f"{current_time} - {get_log_text('log_decompression', algorithm=algorithm_name, compressed=len(decrypted_data), decompressed=decompressed_size)}")
        except (OSError, lzma.LZMAError, zlib.error, brotli.error):
            # Если не удалось распаковать, считаем что данные не сжаты
            decompressed_data = decrypted_data
            logger.info(get_log_text("log_no_decompression", size=len(decrypted_data)))
        
        # 3. Парсим JSON
        json_data = decompressed_data.decode('utf-8')
        return json.loads(json_data)
        
    except Exception as e:
        logger.error(get_log_text("log_decryption_decompression_error") + f": {e}")
        raise ValueError(f"Не удалось расшифровать данные: {e}")

def get_file_extension() -> str:
    """Возвращает расширение файла в зависимости от настроек"""
    # Шифрование
    return ".enc"

# Локализация
TRANSLATIONS = {
    "RU": {
        "bot_active": "👻 <b>GhostKeeper NMS: Бот активен</b>",
        "saving_others": "👁‍🗨 Сохранение чужих удаленных и отредактированных сообщений",
        "saving_own": "💾 Сохранение своих удаленных и отредактированных сообщений", 
        "saving_media": "📷 Сохранение медиа файлов",
        "language": "🇷🇺 Язык",
        "auto_cleanup_period": "📁 Период автоочистки",
        "enabled": "Включено",
        "disabled": "Отключено",
        "agreement_text": "Используя бота, вы автоматически соглашаетесь с <a href=\"https://telegra.ph/Polzovatelskoe-soglashenie--GhostKeeper-NMS-09-05\">Пользовательским соглашением</a>",
        "developed_by": "Разработано студией <a href=\"https://t.me/new_metas\">NewMeta STUDIO</a>",
        "stats_title": "📊 <b>GhostKeeper — Статистика</b>",
        "saved_deleted": "💬 Сохранено удаленных сообщений",
        "saved_edited": "✏️ Сохранено отредактированных сообщений",
        "saved_files": "📁 Сохранено файлов",
        "media_breakdown": "из них:",
        "from_others": "от других пользователей",
        "my": "мои",
        "photo": "Фото",
        "video": "Видео",
        "audio": "Аудио",
        "document": "Документы",
        "voice": "Голосовые",
        "video_note": "Видео-ноты",
        "sticker": "Стикеры",
        "bytes": "Б",
        "kb": "КБ",
        "mb": "МБ",
        "gb": "ГБ",
        "tb": "ТБ",
        "updated": "📅 Обновлено",
        "settings_title": "⚙️ <b>GhostKeeper — текущие настройки</b>",
        "settings_subtitle": "Для изменения параметров просто нажмите на одну из кнопок ниже:",
        "others_messages": "👁‍🗨 Чужие сообщения",
        "own_messages": "💾 Свои сообщения", 
        "media": "📷 Медиа",
        "media_settings": "🖼️ Настройки медиа",
        "media_photos": "🖼️ Фото",
        "media_videos": "🎬 Видео",
        "media_audio": "🎵 Аудио",
        "media_voice": "🎤 Голосовые",
        "media_video_notes": "🎥 Кружки",
        "media_stickers": "🌟 Стикеры",
        "media_documents": "📄 Документы",
        "media_enabled": "Включено",
        "media_disabled": "Отключено",
        "back": "⬅️ Вернуться",
        "stats_unavailable": "📊 Статистика недоступна сейчас",
        # Уведомления об удаленных сообщениях
        "message_deleted": "🗑️ Сообщение удалено",
        "from_user": "👤 От",
        "chat": "💬 Чат",
        "id": "🆔 ID",
        "deletion_time": "📅 Время удаления",
        "send_time": "📅 Время отправки",
        "deleted_text": "Удаленный текст",
        "deleted_caption": "Удаленная подпись",
        "deleted_media_photo": "📎 Удаленное медиа (фото)",
        "deleted_media_video": "📎 Удаленное медиа (видео)",
        "deleted_media_audio": "📎 Удаленное медиа (аудио)",
        "deleted_media_document": "📎 Удаленное медиа (документ)",
        "deleted_sticker": "🎯 Удаленный стикер",
        "deleted_voice": "🎤 Удаленное голосовое",
        "deleted_video_note": "🎥 Удаленная видео-нота",
        "deleted_gif": "🎬 Удаленный GIF",
        "deleted_media": "📎 Удаленное медиа",
        "media_files": "Медифайлы",
        "replaced": "заменены",
        "caption_added": "К фотографии добавлена подпись",
        "caption_added_to_media": "📝 К медиафайлу добавлена подпись",
        "unknown": "Неизвестно",
        "no_tag": "Нет",
        "tag": "🏷 Тег",
        # Логи
        "log_json_optimization_error": "Ошибка оптимизации JSON",
        "log_document_compression": "📄 Сжатие документа: {original} → {compressed} байт ({ratio:.1f}% экономии)",
        "log_file_compression_error": "Ошибка сжатия файла {file}",
        "log_no_compression": "📦 Без сжатия: {size} байт",
        "log_no_encryption": "🔓 Без шифрования: {size} байт",
        "log_compression_encryption_error": "Ошибка сжатия и шифрования данных",
        "log_decryption": "🔓 Расшифровка {algorithm}: {original} → {decrypted} байт",
        "log_decryption_error": "Ошибка расшифровки {algorithm}",
        
        "log_fallback_error": "Ошибка fallback расшифровки",
        "log_no_decryption": "🔓 Без расшифровки: {size} байт",
        "log_decompression": "📦 Распаковка {algorithm}: {compressed} → {decompressed} байт",
        "log_no_decompression": "📦 Без распаковки: {size} байт",
        "log_decryption_decompression_error": "Ошибка расшифровки и распаковки данных",
        "log_disk_warning_sent": "⚠️ Отправлено предупреждение о заполнении диска",
        "log_disk_warning_error": "Ошибка отправки предупреждения о диске",
        "log_encryption_forced": "🔒 Шифрование принудительно включено для безопасности!",
        "log_file_load_error": "Ошибка загрузки файла {file}",
        "log_metadata_extraction_error": "Ошибка извлечения метаданных из {file}",
        "log_photo_send_error": "Ошибка отправки фото",
        "log_document_send_error": "Ошибка отправки документа",
        "log_video_send_error": "Ошибка отправки видео",
        "log_audio_send_error": "Ошибка отправки аудио",
        "log_voice_send_error": "Ошибка отправки голосового",
        "log_video_note_send_error": "Ошибка отправки видео-ноты",
        "log_animation_send_error": "Ошибка отправки анимации",
        "log_status_send_error": "Ошибка отправки статуса /start",
        "log_stats_formation_error": "Ошибка формирования статистики",
        "log_settings_navigation": "⚙️  Переход в Настройки [callback: {callback}]",
        "log_main_menu_navigation": "🏠 Переход в Главное меню [callback: {callback}]",
        "log_stats_navigation": "📊 Переход в Статистику [callback: {callback}]",
        "log_cleanup_settings_navigation": "⚙️  Переход в Параметры автоочистки [callback: {callback}]",
        "log_language_selection": "🌐 Выбор языка [callback: {callback}]",
        "log_foreign_messages_toggle": "💾 Сохранение чужих удаленных и отредактированных сообщений: {status} [callback: {callback} // Настройка save_foreign изменена: {old} → {new}]",
        "log_own_messages_toggle": "💾 Сохранение своих удаленных и отредактированных сообщений: {status} [callback: {callback} // Настройка save_own_deleted изменена: {old} → {new}]",
        "log_media_toggle": "📎Медиафайлы {status} [callback: {callback} // Настройка send_media изменена: {old} → {new}]",
        "log_language_selected": "🌐 Выбран {language} язык [callback: lang_{lang}]",
        "log_cleanup_details_shown": "Показаны подробные детали очистки [callback: {callback}]",
        "log_custom_cleanup_setup": "🛠️ Настройка кастомного режима автоочистки [callback: {callback}]",
        "log_cleanup_period_selected": "⏰Выбран период автоочистки: {period} [callback: {callback}]",
        "log_previous_message_delete_error": "Не удалось удалить предыдущее сообщение об успехе",
        "log_old_message_delete_error": "Не удалось удалить старое сообщение: {error}",
        "log_cleanup_notification_delete_error": "Не удалось удалить уведомление об автоочистке: {error}",
        "log_cleanup_notifications_toggle": "🔔 Уведомления об автоочистке архива: {status} [callback: {callback} // Настройка auto_cleanup_notifications изменена: {old} → {new}]",
        "log_cleanup_notifications_disabled": "Уведомления об автоочистке архива отключены [callback: {callback}]",
        "log_delete_all_request": "⚠️  Запрос на удаление всех сохраненных сообщений, медиафайлов и кеша [callback: {callback}]",
        "log_delete_all_confirmed": "✅ Запрос подтвержден [callback: {callback}]",
        "log_delete_all_cancelled": "❌ Запрос на удаление отклонен [callback: {callback}]",
        "log_custom_cleanup_cancelled": "❌ Отмена настройки кастомного режима автоочистки [callback: {callback}]",
        "log_cleanup_disabled": "🚫 Автоочистка отключена [callback: {callback}]",
        "log_archive_download_request": "📥 Запрос на скачивание архива [callback: {callback}]",
        "msg_no_rights_archive": "❌ У вас нет прав для скачивания архива.",
        "log_archive_sent": "📤 Архив отправлен: {filename} ({size} байт)",
        "log_archive_file_deleted": "🗑️  Файл архива удален: {filename}",
        "log_file_metadata_read_error": "Ошибка чтения метаданных {file}: {error}",
        "log_file_decryption_error": "Ошибка расшифровки {file}: {error}",
        "log_archive_file_missing": "❌ Файл архива не существует: {path}",
        "log_temp_file_delete_error": "❌ Ошибка удаления временного файла {filename}: {error}",
        "log_archive_send_error": "❌ Ошибка отправки архива: {error}",
        "unknown_error": "Неизвестная ошибка",
        "log_archive_create_error": "Ошибка создания архива: {error}",
        "log_cleanup_completed": "Автоочистка завершена. Удалено файлов: {count}",
        "log_cleanup_file_deleted": "🗑️ Автоочистка: удален файл архива {file}",
        "log_cleanup_media_deleted": "🗑️ Автоочистка: удален медиафайл {file}",
        "log_cleanup_cache_cleared": "🗑️ Кеш сообщений очищен при автоочистке",
        "log_stats_reset": "📊 Счетчики статистики сброшены (архив пуст)",
        "log_cleanup_notification_sent": "✅ Уведомление об автоочистке отправлено: удалено {count} файлов",
        "log_cleanup_notification_disabled": "🔕 Уведомления об автоочистке отключены, пропускаем отправку",
        "log_message_saved": "💾 Сообщение пользователя с ID {user_id} сохранено в архив",
        "log_media_saved": "💾 Медиа пользователя с ID {user_id} ({media_type}) сохранено в архив",
        "log_command_processed": "💬 Команда обработана: {command}",
        "log_edited_media_found": "💾 📎 Найдено отредактированное медиа ({media_type}) от пользователя с ID {user_id}. Отправка медиа отключена, медиафайлы не будут скачиваться при удалении/редактировании.",
        "log_own_edited_media_found": "💾 📎 Найдено собственное отредактированное медиа ({media_type}). Отправка медиа отключена, медиафайлы не будут скачиваться при удалении/редактировании.",
        "log_edited_media_saved": "💾 Отредактированное медиа пользователя с ID {user_id} ({media_type}) сохранено в архив",
        "log_deleted_media_found": "💾 📎 Найдено удаленное медиа ({media_type}) от пользователя с ID {user_id}. Отправка медиа отключена, медиафайлы не будут скачиваться при удалении/редактировании.",
        "log_own_deleted_media_found": "💾 📎 Найдено собственное удалённое медиа ({media_type}). Отправка медиа отключена, медиафайлы не будут скачиваться при удалении/редактировании.",
        "log_deleted_media_saved": "💾 Удаленное медиа пользователя с ID {user_id} ({media_type}) сохранено в архив",
        "log_own_edited_media_saved": "💾 Собственное отредактированное медиа ({media_types}) сохранено в архив",
        "log_own_edited_message_saved": "💾 Собственное отредактированное сообщение{media_text} сохранено в архив",
        "log_own_edited_message_saved_text_only": "💾 Собственное отредактированное сообщение сохранено в архив",
        "log_edited_media_saved_foreign": "💾 Отредактированное медиа пользователя с ID {user_id} ({media_types}) сохранено в архив",
        "log_edited_message_saved_foreign": "💾 Отредактированное сообщение пользователя с ID {user_id}{media_text} сохранено в архив",
        "log_edited_message_saved_foreign_text_only": "💾 Отредактированное сообщение пользователя с ID {user_id} сохранено в архив",
        "log_own_deleted_media_saved": "💾 Собственное удаленное медиа ({media_types}) сохранено в архив",
        "log_own_deleted_message_saved": "💾 Собственное удаленное сообщение{media_text} сохранено в архив",
        "log_own_deleted_message_saved_text_only": "💾 Собственное удаленное сообщение сохранено в архив",
        "log_deleted_media_saved_foreign": "💾 Медиа пользователя с ID {user_id} ({media_types}) сохранено в архив",
        "log_deleted_message_saved_foreign": "💾 Сообщение пользователя с ID {user_id}{media_text} сохранено в архив",
        "log_deleted_message_saved_foreign_text_only": "💾 Сообщение пользователя с ID {user_id} сохранено в архив",
        "log_media_compression": "🖼️ Сжатие изображения: {original} → {compressed} байт ({ratio:.1f}% экономии)",
        "log_media_downloaded": "Файл скачан: {file}",
        "log_media_compressed": "Файл скачан и сжат: {file}",
        "log_media_downloaded_count": "📥 Скачано медиафайлов: {count}",
        "log_skip_chat_no_messages": "⏭️ Пропускаем удаления из чата {chat_id} (нет сообщений в кеше)",
        "log_skip_message_processed": "⏭️ Сообщение {msg_id} уже было обработано глобально, пропускаем",
        "log_skip_unauthorized": "⏭️ Пропускаем команду от не-админа {user_id} (бот работает только у админа {admin_id})",
        "log_session_conflict": "Бот не может работать корректно, так как одновременно открыто более двух сессий. Пожалуйста, закройте одну из них и перезапустите бота (Ctrl + C)",
        "log_invalid_format": "❌ Введен неверный формат. Необходимо использовать корректный формат: число/единицы времени. Пример: 1 день",
        "log_media_found": "🔍 Найдено скачанных медиа: {count} файлов",
        "log_media_info": "📎 Медиа: {type} - {path}",
        "log_media_added": "✅ Добавляем к отправке: {type}",
        "log_media_sending": "Отправка медиа: {type}",
        "log_media_send_start": "Начинаем отправку медиа: {type}",
        "log_text_notification_sent": "✅ Текстовое уведомление отправлено",
        "log_media_processing": "🔍 Обрабатываем медиа...",
        "log_media_processing_detailed": "Обработка медиа: {type}",
        "log_file_check": "📁 Проверяем существование файла: {file}",
        "log_photo_sent": "✅ Фото отправлено успешно",
        "log_document_sent": "✅ Документ отправлен успешно",
        "log_video_sent": "✅ Видео отправлено успешно",
        "log_audio_sent": "✅ Аудио отправлено успешно",
        "log_voice_sent": "✅ Голосовое отправлено успешно",
        "log_video_note_sent": "✅ Видео-нота отправлена успешно",
        "log_animation_sent": "✅ Анимация отправлена успешно",
        "log_cleanup_interval_set": "🕐 Автоочистка настроена. Следующая очистка через {interval} секунд",
        "log_cleanup_completed_detailed": "✅ Автоматическая очистка завершена",
        "log_cleanup_completed_files": "Автоочистка завершена. Удалено файлов: {count}",
        "log_cleanup_file_deleted_detailed": "🗑️ Автоочистка: удален файл архива {file}",
        "log_cleanup_media_deleted_detailed": "🗑️ Автоочистка: удален медиафайл {file}",
        "log_cleanup_completed_detailed_final": "🧹 Автоочистка завершена. Удалено файлов: {count}",
        "log_cleanup_cache_cleared_detailed": "🗑️ Кеш сообщений очищен при автоочистке",
        "log_stats_reset_detailed": "📊 Счетчики статистики сброшены (архив пуст)",
        "log_cleanup_notification_sent_detailed": "✅ Уведомление об автоочистке отправлено: удалено {count} файлов",
        "log_cleanup_notification_disabled_detailed": "🔕 Уведомления об автоочистке отключены, пропускаем отправку",
        "log_archive_file_deleted_detailed": "🗑️ Удален файл архива: {file}",
        "log_cleanup_completed_final": "🧹 Очистка всех данных завершена. Удалено файлов: {count}",
        # Логи запуска бота
        "log_env_loaded": "✅ Загружено: {env_key}",
        "log_bot_starting": "🚀 Запуск GhostKeeper Bot... (попытка #{attempt})",
        "log_ghostkeeper_starting": "🚀 Запуск GhostKeeper...",
        "log_token": "🤖 Токен: {token}...",
        "log_admin": "👤 Администратор: {admin_id}",
        "log_archive_dir": "📁 Архив для хранения сообщений находится в папке: {dir}",
        "log_files_dir": "📁 Архив для хранения файлов находится в папке: {dir}",
        "log_bot_configured": "📱 Бот настроен как Business Bot в профиле",
        "log_encryption_enabled": "🔒 Все данные зашифрованы AES-256-GCM!",
        "log_foreign_saving": "💾 Сохранение чужих удаленных и отредактированных сообщений: ✅ ВКЛ",
        "log_own_saving": "💾 Сохранение своих удаленных и отредактированных сообщений: ✅ ВКЛ",
        "log_media_sending": "📎 Отправка медиа файлов: ✅ ВКЛ",
        "log_encryption_status": "🔐 Шифрование данных: ✅ ВКЛ (AES256_GCM)",
        "log_compression_status": "📦 Сжатие данных: ✅ ВКЛ (BROTLI)",
        "log_file_compression_status": "📁 Сжатие файлов: ✅ ВКЛ",
        "log_encryption_warning": "⚠️  Шифруются только текстовые сообщения, медиафайлы не шифруются для оптимизации места на диске. Видеофайлы не сжимаются для сохранения качества.",
        "log_stop_instruction": "⏹️  Для остановки нажмите Ctrl+C",
        "log_bot_stopping": "⏹️  Останавливаем бота...",
        "log_bot_stopped_by_user": "⛔ БОТ ОСТАНОВЛЕН ПОЛЬЗОВАТЕЛЕМ",
        "log_bot_info": "🤖 Бот: @{username} ({first_name})",
        "log_env_file_not_found": "❌ Файл config.env не найден!",
        "log_env_load_error": "❌ Ошибка загрузки переменных окружения: {error}",
        "log_env_vars_missing": "❌ Установите BOT_TOKEN и ADMIN_CHAT_ID в config.env",
        # Уведомления об отредактированных сообщениях
        "message_edited": "✏️ Сообщение отредактировано",
        "time": "📅 Время",
        "was": "Было",
        "became": "Стало",
        "was_caption": "Было",
        "became_caption": "Стала подпись",
        "no_text": "Нет текста",
        "mb": "МБ",
        
        # Логи настроек
        "settings_load_error": "Ошибка загрузки настроек",
        "settings_saved": "Настройки сохранены",
        "settings_save_error": "Ошибка сохранения настроек",
        # Сообщения загрузки
        "env_loaded": "✅ Переменные окружения загружены",
        "auto_cleanup": "📁 Автоочистка",
        "auto_cleanup_title": "📁 GhostKeeper — автоочистка архива",
        "auto_cleanup_status": "🔌 Состояние",
        "auto_cleanup_disk_usage": "🗄 Занято место на диске",
        "auto_cleanup_current_period": "📅 Текущий период",
        "auto_cleanup_period_not_set": "Не установлен",
        "auto_cleanup_last_cleanup": "♻️ Последняя очистка",
        "auto_cleanup_next_cleanup": "⏳ Ближайшая очистка",
        "through": "через",
        "auto_cleanup_notifications": "🔔 Уведомления",
        "auto_cleanup_notifications_enabled": "Включено",
        "auto_cleanup_notifications_disabled": "Отключено",
        "disable_notifications": "🔕 Отключить уведомления",
        "notifications_disabled_message": "✅ Уведомления отключены, чтобы включить их перейдите в /settings",
        "disk_full_warning": "⚠️ <b>Файлы в архиве занимают много места.</b>\n\nРекомендуется очистить архив. Перейдите в /settings → Автоочистка.", #1 GB
        "disk_space_freed": "🧹 Освобождено место на диске",
        "archive_period": "Архив сообщений сформирован за период",
        "archive_title": "Архив сообщений",
        "archive_header": "GhostKeeper — архив сообщений",
        "from": "с",
        "to": "по",
        "created": "Создан",
        "total_messages": "Всего сообщений",
        "deleted": "УДАЛЕНО",
        "edited": "ОТРЕДАКТИРОВАНО",
        "normal": "ОБЫЧНОЕ",
        "other": "ЧУЖОЕ",
        "no_text": "Без текста",
        
        "archive_ready": "📦⬇️ Ваш архив готов к скачиванию!",
        "tag": "Тег",
        "no_tag": "Нет",
        "time_format": "%d.%m.%Y в %H:%M:%S",
        "media_disabled_notification": "📷 📎 Найдено удалённое медиа ({media_type}).\nЧтобы получать медиа-файлы, включите соответствующую опцию в /settings.",
        "auto_cleanup_select_period": "Выберите период автоочистки",
        "auto_cleanup_1_day": "1 день",
        "auto_cleanup_7_days": "7 дней",
        "auto_cleanup_14_days": "14 дней", 
        "auto_cleanup_30_days": "30 дней",
        "auto_cleanup_custom": "🛠️ Настраиваемый период",
        "auto_cleanup_disabled": "Отключено",
        "auto_cleanup_enabled": "Включено",
        "auto_cleanup_set": "Установить период",
        "auto_cleanup_current": "Текущий период",
        "clear_all": "🗑️ Очистить все",
        "clear_all_confirm": "⚠️ ⚠️ ВНИМАНИЕ! Это действие удалит ВСЕ сохраненные данные безвозвратно!",
        "clear_all_will_be_deleted": "🗑️ Будут удалены:",
        "clear_all_messages": "• Все сохраненные сообщения",
        "clear_all_media": "• Все медиафайлы",
        "clear_all_cache": "• Кеш удаленных и отредактированных сообщений",
        "clear_all_button": "✅ Очистить все",
        "clear_all_cancel": "❌ Отмена",
        "auto_cleanup_completed": "Автоочистка завершена",
        "auto_cleanup_data_older": "Данные старше",
        "auto_cleanup_deleted": "удалены",
        "auto_cleanup_details": "Детали автоочистки",
        "total_deleted": "Всего удалено",
        "clear_all_confirm": "⚠️ <b>ВНИМАНИЕ! Это действие удалит ВСЕ сохраненные данные безвозвратно!</b>",
        "clear_all_success": "✅ Все данные успешно очищены!",
        "clear_all_cancelled": "❌ Очистка отменена",
        "cleanup_completed": "Очистка завершена!",
        "deleted_messages": "Удалено сообщений",
        "edited_messages": "Отредактированные сообщения",
        "deleted_media": "Удалено медифайлов",
        "media_files": "Медифайлы",
        "replaced": "заменены",
        "photo": "Фото",
        "video": "Видео",
        "audio": "Аудио",
        "document": "Документы",
        "voice": "Голосовые",
        "video_note": "Видео-ноты",
        "sticker": "Стикеры",
        "gif": "GIF",
        "download_archive": "📥 Скачать архив",
        "archive_wait_message": "🙏 Пожалуйста, подождите.",
        "archive_wait_description": "Формирование архива может занять некоторое время.",
        "archive_formed": "📊 Архив сформирован: с {start_date}, по {end_date}",
        "archive_formed_single": "📊 Архив сформирован: {date}",

        "command_not_recognized": "⚠️ <b>Команда не распознана.</b>\n\nПожалуйста, используйте меню для работы с ботом.\n\n/start - Главное меню\n/settings - Настройки\n/stats - Статистика",
        "disable_auto_cleanup": "🚫 Отключить автоочистку",
        "auto_cleanup_disabled_msg": "✅ Автоочистка отключена",
        "auto_cleanup_period_set": "Период автоочистки: {} успешно установлен! 🔄",
        "custom_period_title": "⏲️ Настраиваемый период",
        "custom_period_instruction": "Введите срок, через который старые сообщения будут автоматически удаляться с диска.",
        "custom_period_format": "Введите данные в формате: День, часы, минуты, секунды",
        "custom_period_example": "Пример: 0 дней, 2 часа, 15 минут, 3 секунды",
        "custom_period_input": "Введите период:",
        "custom_period_invalid": "❌ <b>Неверный формат!</b>\n\nИспользуйте формат: число/единица времени\nПример: 1 день",
        "custom_period_minimum": "⏱️ <b>Минимальный период автоочистки — 1 минута.</b>\n\nЗначение <code>{input_value}</code> отклонено.\nУстановлен период очистки: <b>1 минута</b>.",
        "custom_period_maximum": "⏱️ <b>Максимальный период автоочистки — 365 дней.</b>\n\nЗначение <code>{input_value}</code> отклонено.\nУстановлен период очистки: <b>365 дней</b>.",
        "custom_period_success": "✅ Настраиваемый период установлен: {period}",
        "custom_period_cancel": "❌ Ввод настраиваемого периода отменен"
    },
    "EN": {
        "bot_active": "👻 <b>GhostKeeper NMS: Bot is active</b>",
        "saving_others": "👁‍🗨 Saving others' deleted and edited messages",
        "saving_own": "💾 Saving your own deleted and edited messages",
        "saving_media": "📷 Saving media files", 
        "language": "🇬🇧 Language",
        "auto_cleanup_period": "📁 Auto-cleanup period",
        "enabled": "Enabled",
        "disabled": "Disabled",
        "agreement_text": "By using the bot you automatically agree to the <a href=\"https://telegra.ph/USER-AGREEMENT--GhostKeeper-NMS-09-05\">User Agreement</a>",
        "developed_by": "Developed by <a href=\"https://t.me/new_metas\">NewMeta STUDIO</a>",
        "stats_title": "📊 <b>GhostKeeper — Statistics</b>",
        "saved_deleted": "💬 Saved deleted messages",
        "saved_edited": "✏️ Saved edited messages", 
        "saved_files": "📁 Saved files",
        "media_breakdown": "of them:",
        "from_others": "from other users",
        "my": "mine",
        "photo": "Photos",
        "video": "Videos",
        "audio": "Audio",
        "document": "Documents",
        "voice": "Voice",
        "video_note": "Video notes",
        "sticker": "Stickers",
        "bytes": "B",
        "kb": "KB",
        "mb": "MB",
        "gb": "GB",
        "tb": "TB",
        "updated": "📅 Updated",
        "settings_title": "⚙️ <b>GhostKeeper — current settings</b>",
        "settings_subtitle": "To change parameters, simply click on one of the buttons below:",
        "others_messages": "👁‍🗨 Others' messages",
        "own_messages": "💾 Own messages",
        "media": "📷 Media",
        "media_settings": "🖼️ Media Settings",
        "media_photos": "🖼️ Photos",
        "media_videos": "🎬 Videos",
        "media_audio": "🎵 Audio",
        "media_voice": "🎤 Voice",
        "media_video_notes": "🎥 Video Notes",
        "media_stickers": "🌟 Stickers",
        "media_documents": "📄 Documents",
        "media_enabled": "Enabled",
        "media_disabled": "Disabled",
        "back": "⬅️ Back",
        "stats_unavailable": "📊 Statistics unavailable now",
        # Уведомления об удаленных сообщениях
        "message_deleted": "🗑️ Message deleted",
        "from_user": "👤 From",
        "chat": "💬 Chat",
        "id": "🆔 ID",
        "deletion_time": "📅 Deletion time",
        "send_time": "📅 Send time",
        "deleted_text": "Deleted text",
        "deleted_caption": "Deleted caption",
        "deleted_media_photo": "📎 Deleted media (photo)",
        "deleted_media_video": "📎 Deleted media (video)",
        "deleted_media_audio": "📎 Deleted media (audio)",
        "deleted_media_document": "📎 Deleted media (document)",
        "deleted_sticker": "🎯 Deleted sticker",
        "deleted_voice": "🎤 Deleted voice message",
        "deleted_video_note": "🎥 Deleted video note",
        "deleted_gif": "🎬 Deleted GIF",
        "deleted_media": "📎 Deleted media",
        "media_files": "Media files",
        "replaced": "replaced",
        "caption_added": "Caption added to photo",
        "caption_added_to_media": "📝 Caption added to media file",
        "unknown": "Unknown",
        "no_tag": "No tag",
        "tag": "🏷 Tag",
        # Уведомления об отредактированных сообщениях
        "message_edited": "✏️ Message edited",
        "time": "📅 Time",
        "was": "Was",
        "became": "Became",
        "was_caption": "Was",
        "became_caption": "Became caption",
        "no_text": "No text",
        "mb": "MB",
        
        # Логи настроек
        "settings_load_error": "Error loading settings",
        "settings_saved": "Settings saved",
        "settings_save_error": "Error saving settings",
        # Сообщения загрузки
        "env_loaded": "✅ Environment variables loaded",
        "auto_cleanup": "📁 Auto cleanup",
        "auto_cleanup_title": "📁 GhostKeeper — Archive Auto Cleanup",
        "auto_cleanup_status": "🔌 Status",
        "auto_cleanup_disk_usage": "🗄 Disk space used",
        "auto_cleanup_current_period": "📅 Current period",
        "auto_cleanup_period_not_set": "Not set",
        "auto_cleanup_last_cleanup": "♻️ Last cleanup",
        "auto_cleanup_next_cleanup": "⏳ Next cleanup",
        "through": "in",
        "auto_cleanup_notifications": "🔔 Notifications",
        "auto_cleanup_notifications_enabled": "Enabled",
        "auto_cleanup_notifications_disabled": "Disabled",
        "disable_notifications": "🔕 Disable notifications",
        "notifications_disabled_message": "✅ Notifications disabled, to enable them go to /settings",
        "disk_full_warning": "⚠️ <b>Archive files are taking up a lot of space.</b>\n\nIt is recommended to clean the archive. Go to /settings → Auto cleanup.",
        "disk_space_freed": "🧹 Disk space freed",
        "archive_period": "Message archive formed for period",
        "archive_title": "Message archive",
        "archive_header": "GhostKeeper — message archive",
        "from": "from",
        "to": "to",
        "created": "Created",
        "total_messages": "Total messages",
        "deleted": "DELETED",
        "edited": "EDITED",
        "normal": "NORMAL",
        "other": "OTHER",
        "no_text": "No text",
        "files": "file(s)",
        "archive_ready": "📦⬇️ Your archive is ready for download!",
        "tag": "Tag",
        "no_tag": "No",
        "time_format": "%d.%m.%Y at %H:%M:%S",
        "media_disabled_notification": "📷 📎 Found deleted media ({media_type}).\nTo receive media files, enable the corresponding option in /settings.",
        "auto_cleanup_select_period": "Select cleanup period",
        "auto_cleanup_1_day": "1 day",
        "auto_cleanup_7_days": "7 days",
        "auto_cleanup_14_days": "14 days",
        "auto_cleanup_30_days": "30 days",
        "auto_cleanup_custom": "🛠️ Custom period",
        "auto_cleanup_disabled": "Disabled",
        "auto_cleanup_enabled": "Enabled",
        "auto_cleanup_set": "Set period",
        "auto_cleanup_current": "Current period",
        "clear_all": "🗑️ Clear all",
        "clear_all_confirm": "⚠️ ⚠️ WARNING! This action will delete ALL saved data permanently!",
        "clear_all_will_be_deleted": "🗑️ Will be deleted:",
        "clear_all_messages": "• All saved messages",
        "clear_all_media": "• All media files",
        "clear_all_cache": "• Cache of deleted and edited messages",
        "clear_all_button": "✅ Clear all",
        "clear_all_cancel": "❌ Cancel",
        "auto_cleanup_completed": "Auto cleanup completed",
        "auto_cleanup_data_older": "Data older than",
        "auto_cleanup_deleted": "deleted",
        "auto_cleanup_details": "Auto cleanup details",
        "total_deleted": "Total deleted",
        "clear_all_confirm": "⚠️ <b>WARNING! This action will delete ALL saved data permanently!</b>",
        "clear_all_success": "✅ All data successfully cleared!",
        "clear_all_cancelled": "❌ Clear cancelled",
        "cleanup_completed": "Cleanup completed!",
        "deleted_messages": "Deleted messages",
        "edited_messages": "Edited messages",
        "deleted_media": "Deleted media files",
        "media_files": "Media files",
        "replaced": "replaced",
        "photo": "Photos",
        "video": "Videos",
        "audio": "Audio",
        "document": "Documents",
        "voice": "Voice",
        "video_note": "Video notes",
        "sticker": "Stickers",
        "gif": "GIF",
        "download_archive": "📥 Download archive",
        "archive_wait_message": "🙏 Please wait.",
        "archive_wait_description": "Archive generation may take some time.",
        "archive_formed": "📊 Archive formed: from {start_date} to {end_date}",
        "archive_formed_single": "📊 Archive formed: {date}",

        "command_not_recognized": "⚠️ <b>Command not recognized.</b>\n\nPlease use the menu to work with the bot.\n\n/start - Main menu\n/settings - Settings\n/stats - Statistics",
        "disable_auto_cleanup": "🚫 Disable auto-cleanup",
        "auto_cleanup_disabled_msg": "✅ Auto-cleanup disabled",
        "auto_cleanup_period_set": "Auto-cleanup period: {} successfully set! 🔄",
        "custom_period_title": "⏲️ Custom period",
        "custom_period_instruction": "Enter the period after which old messages will be automatically deleted from disk.",
        "custom_period_format": "Enter data in format: Day, hours, minutes, seconds",
        "custom_period_example": "Example: 0 days, 2 hours, 15 minutes, 3 seconds",
        "custom_period_input": "Enter period:",
        "custom_period_invalid": "❌ <b>Invalid format!</b>\n\nUse format: number/time_unit\nExample: 1 day",
        "custom_period_minimum": "⏱️ <b>Minimum auto-cleanup period is 1 minute.</b>\n\nValue <code>{input_value}</code> rejected.\nCleanup period set to: <b>1 minute</b>.",
        "custom_period_maximum": "⏱️ <b>Maximum auto-cleanup period is 365 days.</b>\n\nValue <code>{input_value}</code> rejected.\nCleanup period set to: <b>365 days</b>.",
        "custom_period_success": "✅ Custom period set: {period}",
        "custom_period_cancel": "❌ Custom period input cancelled",
        # Локализация EN
        "log_json_optimization_error": "JSON optimization error",
        "log_document_compression": "📄 Document compression: {original} → {compressed} bytes ({ratio:.1f}% savings)",
        "log_file_compression_error": "File compression error {file}",
        "log_no_compression": "📦 No compression: {size} bytes",
        "log_no_encryption": "🔓 No encryption: {size} bytes",
        "log_compression_encryption_error": "Data compression and encryption error",
        "log_decryption": "🔓 Decryption {algorithm}: {original} → {decrypted} bytes",
        "log_decryption_error": "Decryption error {algorithm}",
        
        "log_fallback_error": "Fallback decryption error",
        "log_no_decryption": "🔓 No decryption: {size} bytes",
        "log_decompression": "📦 Decompression {algorithm}: {compressed} → {decompressed} bytes",
        "log_no_decompression": "📦 No decompression: {size} bytes",
        "log_decryption_decompression_error": "Decryption and decompression error",
        "log_disk_warning_sent": "⚠️ Disk space warning sent",
        "log_disk_warning_error": "Disk warning send error",
        "log_encryption_forced": "🔒 Encryption force enabled for security!",
        "log_file_load_error": "File load error {file}",
        "log_metadata_extraction_error": "Metadata extraction error from {file}",
        "log_photo_send_error": "Photo send error",
        "log_document_send_error": "Document send error",
        "log_video_send_error": "Video send error",
        "log_audio_send_error": "Audio send error",
        "log_voice_send_error": "Voice send error",
        "log_video_note_send_error": "Video note send error",
        "log_animation_send_error": "Animation send error",
        "log_status_send_error": "Status /start send error",
        "log_stats_formation_error": "Statistics formation error",
        "log_settings_navigation": "⚙️ Settings navigation [callback: {callback}]",
        "log_main_menu_navigation": "🏠 Main menu navigation [callback: {callback}]",
        "log_stats_navigation": "📊 Statistics navigation [callback: {callback}]",
        "log_cleanup_settings_navigation": "⚙️ Auto-cleanup settings navigation [callback: {callback}]",
        "log_language_selection": "🌐 Language selection [callback: {callback}]",
        "log_foreign_messages_toggle": "💾Saving others' deleted and edited messages: {status} [callback: {callback} // Setting save_foreign changed: {old} → {new}]",
        "log_own_messages_toggle": "💾Saving own deleted and edited messages: {status} [callback: {callback} // Setting save_own_deleted changed: {old} → {new}]",
        "log_media_toggle": "📎Media files {status} [callback: {callback} // Setting send_media changed: {old} → {new}]",
        "log_language_selected": "🌐Selected {language} language [callback: lang_{lang}]",
        "log_cleanup_details_shown": "Cleanup details shown [callback: {callback}]",
        "log_custom_cleanup_setup": "🛠️ Custom auto-cleanup setup [callback: {callback}]",
        "log_cleanup_period_selected": "⏰Auto-cleanup period selected: {period} [callback: {callback}]",
        "log_previous_message_delete_error": "Failed to delete previous success message",
        "log_cleanup_notifications_toggle": "🔔Auto-cleanup archive notifications: {status} [callback: {callback} // Setting auto_cleanup_notifications changed: {old} → {new}]",
        "log_cleanup_notifications_disabled": "Auto-cleanup archive notifications disabled [callback: {callback}]",
        "log_delete_all_request": "⚠️Request to delete all saved messages, media files and cache [callback: {callback}]",
        "log_delete_all_confirmed": "✅Request confirmed [callback: {callback}]",
        "log_delete_all_cancelled": "❌Delete request rejected [callback: {callback}]",
        "log_custom_cleanup_cancelled": "❌Custom auto-cleanup setup cancelled [callback: {callback}]",
        "log_cleanup_disabled": "🚫Auto-cleanup disabled [callback: {callback}]",
        "log_archive_download_request": "📥 Archive download request [callback: {callback}]",
        "log_archive_sent": "📤 Archive sent: {filename} ({size} bytes)",
        "log_archive_file_deleted": "🗑️ Archive file deleted: {filename}",
        "log_cleanup_completed": "Auto-cleanup completed. Files deleted: {count}",
        "log_cleanup_file_deleted": "🗑️ Auto-cleanup: archive file deleted {file}",
        "log_cleanup_media_deleted": "🗑️ Auto-cleanup: media file deleted {file}",
        "log_cleanup_cache_cleared": "🗑️ Message cache cleared during auto-cleanup",
        "log_stats_reset": "📊 Statistics counters reset (archive empty)",
        "log_cleanup_notification_sent": "✅ Auto-cleanup notification sent: {count} files deleted",
        "log_cleanup_notification_disabled": "🔕 Auto-cleanup notifications disabled, skipping send",
        "log_message_saved": "💾 Message from user ID {user_id} saved to archive",
        "log_media_saved": "💾 Media from user ID {user_id} ({media_type}) saved to archive",
        "log_command_processed": "💬 Command processed: {command}",
        "log_edited_media_found": "💾 📎 Found edited media ({media_type}) from user ID {user_id}. Media sending disabled, media files will not be downloaded on deletion/editing.",
        "log_own_edited_media_found": "💾 📎 Found own edited media ({media_type}). Media sending disabled, media files will not be downloaded on deletion/editing.",
        "log_edited_media_saved": "💾 Edited media from user ID {user_id} ({media_type}) saved to archive",
        "log_deleted_media_found": "💾 📎 Found deleted media ({media_type}) from user ID {user_id}. Media sending disabled, media files will not be downloaded on deletion/editing.",
        "log_own_deleted_media_found": "💾 📎 Found own deleted media ({media_type}). Media sending disabled, media files will not be downloaded on deletion/editing.",
        "log_deleted_media_saved": "💾 Deleted media from user ID {user_id} ({media_type}) saved to archive",
        "log_own_edited_media_saved": "💾 Own edited media ({media_types}) saved to archive",
        "log_own_edited_message_saved": "💾 Own edited message{media_text} saved to archive",
        "log_own_edited_message_saved_text_only": "💾 Own edited message saved to archive",
        "log_edited_media_saved_foreign": "💾 Edited media from user ID {user_id} ({media_types}) saved to archive",
        "log_edited_message_saved_foreign": "💾 Edited message from user ID {user_id}{media_text} saved to archive",
        "log_edited_message_saved_foreign_text_only": "💾 Edited message from user ID {user_id} saved to archive",
        "log_own_deleted_media_saved": "💾 Own deleted media ({media_types}) saved to archive",
        "log_own_deleted_message_saved": "💾 Own deleted message{media_text} saved to archive",
        "log_own_deleted_message_saved_text_only": "💾 Own deleted message saved to archive",
        "log_deleted_media_saved_foreign": "💾 Media from user ID {user_id} ({media_types}) saved to archive",
        "log_deleted_message_saved_foreign": "💾 Message from user ID {user_id}{media_text} saved to archive",
        "log_deleted_message_saved_foreign_text_only": "💾 Message from user ID {user_id} saved to archive",
        "log_media_compression": "🖼️ Image compression: {original} → {compressed} bytes ({ratio:.1f}% savings)",
        "log_media_downloaded": "File downloaded: {file}",
        "log_media_compressed": "File downloaded and compressed: {file}",
        "log_media_downloaded_count": "📥 Media files downloaded: {count}",
        "log_skip_chat_no_messages": "⏭️ Skipping deletions from chat {chat_id} (no messages in cache)",
        "log_skip_message_processed": "⏭️ Message {msg_id} already processed globally, skipping",
        "log_skip_unauthorized": "⏭️ Skipping command from non-admin {user_id} (bot works only for admin {admin_id})",
        "log_session_conflict": "Bot cannot work properly as more than two sessions are open simultaneously. Please close one of them and restart the bot (Ctrl + C)",
        "log_invalid_format": "❌Invalid format entered. Must use correct format: number/time_unit. Example: 1 day",
        "log_media_found": "🔍 Found downloaded media: {count} files",
        "log_media_info": "📎 Media: {type} - {path}",
        "log_media_added": "✅ Adding to send: {type}",
        "log_media_sending": "Sending media: {type}",
        "log_media_send_start": "Starting media send: {type}",
        "log_text_notification_sent": "✅ Text notification sent",
        "log_media_processing": "🔍 Processing media...",
        "log_media_processing_detailed": "Media processing: {type}",
        "log_file_check": "📁 Checking file existence: {file}",
        "log_photo_sent": "✅ Photo sent successfully",
        "log_document_sent": "✅ Document sent successfully",
        "log_video_sent": "✅ Video sent successfully",
        "log_audio_sent": "✅ Audio sent successfully",
        "log_voice_sent": "✅ Voice sent successfully",
        "log_video_note_sent": "✅ Video note sent successfully",
        "log_animation_sent": "✅ Animation sent successfully",
        "log_cleanup_interval_set": "🕐 Auto-cleanup configured. Next cleanup in {interval} seconds",
        "log_cleanup_completed_detailed": "✅ Automatic cleanup completed",
        "log_cleanup_completed_files": "Auto-cleanup completed. Files deleted: {count}",
        "log_cleanup_file_deleted_detailed": "🗑️ Auto-cleanup: archive file deleted {file}",
        "log_cleanup_media_deleted_detailed": "🗑️ Auto-cleanup: media file deleted {file}",
        "log_cleanup_completed_detailed_final": "🧹 Auto-cleanup completed. Files deleted: {count}",
        "log_cleanup_cache_cleared_detailed": "🗑️ Message cache cleared during auto-cleanup",
        "log_stats_reset_detailed": "📊 Statistics counters reset (archive empty)",
        "log_cleanup_notification_sent_detailed": "✅ Auto-cleanup notification sent: {count} files deleted",
        "log_cleanup_notification_disabled_detailed": "🔕 Auto-cleanup notifications disabled, skipping send",
        "log_archive_file_deleted_detailed": "🗑️ Archive file deleted: {file}",
        "log_cleanup_completed_final": "🧹 All data cleanup completed. Files deleted: {count}",
        # Bot startup logs
        "log_env_loaded": "✅ Loaded: {env_key}",
        "log_bot_starting": "🚀 Starting GhostKeeper Bot... (attempt #{attempt})",
        "log_ghostkeeper_starting": "🚀 Starting GhostKeeper...",
        "log_token": "🤖 Token: {token}...",
        "log_admin": "👤 Administrator: {admin_id}",
        "log_archive_dir": "📁 Message archive is located in folder: {dir}",
        "log_files_dir": "📁 File archive is located in folder: {dir}",
        "log_bot_configured": "📱 Bot configured as Business Bot in profile",
        "log_encryption_enabled": "🔒 All data encrypted with AES-256-GCM!",
        "log_foreign_saving": "💾 Saving others' deleted and edited messages: ✅ ON",
        "log_own_saving": "💾 Saving your own deleted and edited messages: ✅ ON",
        "log_media_sending": "📎 Sending media files: ✅ ON",
        "log_encryption_status": "🔐 Data encryption: ✅ ON (AES256_GCM)",
        "log_compression_status": "📦 Data compression: ✅ ON (BROTLI)",
        "log_file_compression_status": "📁 File compression: ✅ ON",
        "log_encryption_warning": "⚠️  Only text messages are encrypted, media files are not encrypted to optimize disk space. Video files are not compressed to preserve quality.",
        "log_stop_instruction": "⏹️  Press Ctrl+C to stop",
        "log_bot_stopping": "⏹️  Stopping bot...",
        "log_bot_stopped_by_user": "⛔ BOT STOPPED BY USER",
        "log_bot_info": "🤖 Bot: @{username} ({first_name})",
        "log_env_file_not_found": "❌ File config.env not found!",
        "log_env_load_error": "❌ Error loading environment variables: {error}",
        "log_env_vars_missing": "❌ Set BOT_TOKEN and ADMIN_CHAT_ID in config.env"
    },
    "ZH": {
        "bot_active": "👻 <b>GhostKeeper NMS: 机器人已激活</b>",
        "saving_others": "👁‍🗨 保存他人的已删除和已编辑消息",
        "saving_own": "💾 保存您自己的已删除和已编辑消息",
        "saving_media": "📷 保存媒体文件",
        "language": "🇨🇳 语言",
        "auto_cleanup_period": "📁 自动清理周期",
        "enabled": "已启用",
        "disabled": "已禁用",
        "agreement_text": "使用机器人即表示您自动同意<a href=\"https://telegra.ph/%E7%94%A8%E6%88%B7%E5%8D%8F%E8%AE%AE--GhostKeeper-NMS-09-05\">用户协议</a>",
        "developed_by": "由 <a href=\"https://t.me/new_metas\">NewMeta STUDIO</a> 开发",
        "stats_title": "📊 <b>GhostKeeper — 统计</b>",
        "saved_deleted": "💬 已保存删除的消息",
        "saved_edited": "✏️ 已保存编辑的消息",
        "saved_files": "📁 已保存文件",
        "media_breakdown": "其中：",
        "from_others": "来自其他用户",
        "my": "我的",
        "photo": "照片",
        "video": "视频",
        "audio": "音频",
        "document": "文档",
        "voice": "语音",
        "video_note": "视频笔记",
        "sticker": "贴纸",
        "bytes": "字节",
        "kb": "KB",
        "mb": "MB",
        "gb": "GB",
        "tb": "TB",
        "updated": "📅 更新时间",
        "settings_title": "⚙️ <b>GhostKeeper — 当前设置</b>",
        "settings_subtitle": "要更改参数，只需点击下面的按钮之一：",
        "others_messages": "👁‍🗨 他人消息",
        "own_messages": "💾 自己的消息",
        "media": "📷 媒体",
        "media_settings": "🖼️ 媒体设置",
        "media_photos": "🖼️ 照片",
        "media_videos": "🎬 视频",
        "media_audio": "🎵 音频",
        "media_voice": "🎤 语音",
        "media_video_notes": "🎥 视频笔记",
        "media_stickers": "🌟 贴纸",
        "media_documents": "📄 文档",
        "media_enabled": "已启用",
        "media_disabled": "已禁用",
        "back": "⬅️ 返回",
        "stats_unavailable": "📊 统计信息暂时不可用",
        # Уведомления об удаленных сообщениях ZH
        "message_deleted": "🗑️ 消息已删除",
        "from_user": "👤 来自",
        "chat": "💬 聊天",
        "id": "🆔 ID",
        "deletion_time": "📅 删除时间",
        "send_time": "📅 发送时间",
        "deleted_text": "已删除的文本",
        "deleted_caption": "已删除的说明",
        "deleted_media_photo": "📎 已删除的媒体（照片）",
        "deleted_media_video": "📎 已删除的媒体（视频）",
        "deleted_media_audio": "📎 已删除的媒体（音频）",
        "deleted_media_document": "📎 已删除的媒体（文档）",
        "deleted_sticker": "🎯 已删除的贴纸",
        "deleted_voice": "🎤 已删除的语音消息",
        "deleted_video_note": "🎥 已删除的视频笔记",
        "deleted_gif": "🎬 已删除的GIF",
        "deleted_media": "📎 已删除的媒体",
        "media_files": "媒体文件",
        "replaced": "已替换",
        "caption_added": "已为照片添加说明",
        "caption_added_to_media": "📝 已为媒体文件添加说明",
        "unknown": "未知",
        "no_tag": "无标签",
        "tag": "🏷 标签",
        # Уведомления об отредактированных сообщениях
        "message_edited": "✏️ 消息已编辑",
        "time": "📅 时间",
        "was": "之前",
        "became": "之后",
        "was_caption": "之前",
        "became_caption": "之后标题",
        "no_text": "无文本",
        "mb": "MB",
        # Логи
        "business_deleted": "🗑️ 业务删除",
        "business_edited": "✏️ 业务编辑",
        "skip_own_deleted": "🗑️ 跳过自己的删除消息",
        "skip_own_edited": "✏️ 跳过自己的编辑消息",
        "message_not_found": "编辑消息在缓存中未找到",
        # Логи отправки
        "media_disabled": "📝 媒体发送已禁用，仅发送文本",
        "sending_media": "🎵 发送媒体",
        "sending_text_only": "📝 仅发送文本（无媒体可发送）",
        "files": "文件",
        # Логи обработки
        "starting_media_send": "📤 开始发送媒体",
        "processing_media": "📎 处理",
        "business_message": "💼 业务消息",
        "processing_callback": "🔘 处理回调",
        
        # Логи настроек
        "settings_load_error": "加载设置时出错",
        "settings_saved": "设置已保存",
        "settings_save_error": "保存设置时出错",
        # Сообщения загрузки
        "env_loaded": "✅ 环境变量已加载",
        "auto_cleanup": "📁 自动清理",
        "auto_cleanup_title": "📁 GhostKeeper — 档案自动清理",
        "auto_cleanup_status": "🔌 状态",
        "auto_cleanup_disk_usage": "🗄 磁盘使用空间",
        "auto_cleanup_current_period": "📅 当前周期",
        "auto_cleanup_period_not_set": "未设置",
        "auto_cleanup_last_cleanup": "♻️ 上次清理",
        "auto_cleanup_next_cleanup": "⏳ 下次清理",
        "through": "在",
        "auto_cleanup_notifications": "🔔 通知",
        "auto_cleanup_notifications_enabled": "已启用",
        "auto_cleanup_notifications_disabled": "已禁用",
        "disable_notifications": "🔕 禁用通知",
        "notifications_disabled_message": "✅ 通知已禁用，要启用它们请转到 /settings",
        "disk_full_warning": "⚠️ <b>档案文件占用大量空间。</b>\n\n建议清理档案。转到 /settings → 自动清理。",
        "disk_space_freed": "🧹 释放磁盘空间",
        "archive_period": "消息档案形成期间",
        "archive_title": "消息档案",
        "archive_header": "GhostKeeper — 消息档案",
        "from": "从",
        "to": "到",
        "created": "创建",
        "total_messages": "总消息数",
        "deleted": "已删除",
        "edited": "已编辑",
        "normal": "普通",
        "other": "其他",
        "no_text": "无文本",
        "files": "文件",
        "archive_ready": "📦⬇️ 您的档案已准备好下载！",
        "tag": "标签",
        "no_tag": "无",
        "time_format": "%d.%m.%Y 在 %H:%M:%S",
        "media_disabled_notification": "📷 📎 发现已删除的媒体 ({media_type})。\n要接收媒体文件，请在 /settings 中启用相应选项。",
        "auto_cleanup_select_period": "选择清理周期",
        "auto_cleanup_1_day": "1天",
        "auto_cleanup_7_days": "7天",
        "auto_cleanup_14_days": "14天",
        "auto_cleanup_30_days": "30天",
        "auto_cleanup_custom": "🛠️ 自定义周期",
        "auto_cleanup_disabled": "已禁用",
        "auto_cleanup_enabled": "已启用",
        "auto_cleanup_set": "设置周期",
        "auto_cleanup_current": "当前周期",
        "clear_all": "🗑️ 清除全部",
        "clear_all_confirm": "⚠️ ⚠️ 警告！此操作将永久删除所有保存的数据！",
        "clear_all_will_be_deleted": "🗑️ 将被删除：",
        "clear_all_messages": "• 所有保存的消息",
        "clear_all_media": "• 所有媒体文件",
        "clear_all_cache": "• 已删除和已编辑消息的缓存",
        "clear_all_button": "✅ 清除全部",
        "clear_all_cancel": "❌ 取消",
        "auto_cleanup_completed": "自动清理完成",
        "auto_cleanup_data_older": "早于",
        "auto_cleanup_deleted": "的数据已删除",
        "auto_cleanup_details": "自动清理详情",
        "total_deleted": "总计删除",
        "clear_all_confirm": "⚠️ <b>警告！此操作将永久删除所有保存的数据！</b>",
        "clear_all_success": "✅ 所有数据已成功清除！",
        "clear_all_cancelled": "❌ 清除已取消",
        "cleanup_completed": "清理完成！",
        "deleted_messages": "已删除消息",
        "edited_messages": "已编辑消息",
        "deleted_media": "已删除媒体文件",
        "media_files": "媒体文件",
        "replaced": "已替换",
        "photo": "照片",
        "video": "视频",
        "audio": "音频",
        "document": "文档",
        "voice": "语音",
        "video_note": "视频笔记",
        "sticker": "贴纸",
        "gif": "GIF",
        "download_archive": "📥 下载存档",
        "archive_wait_message": "🙏 请稍候。",
        "archive_wait_description": "存档生成可能需要一些时间。",
        "archive_formed": "📊 存档已形成：从 {start_date} 到 {end_date}",
        "archive_formed_single": "📊 存档已形成：{date}",

        "command_not_recognized": "⚠️ <b>命令未识别。</b>\n\n请使用菜单与机器人交互。\n\n/start - 主菜单\n/settings - 设置\n/stats - 统计",
        "disable_auto_cleanup": "🚫 禁用自动清理",
        "auto_cleanup_disabled_msg": "✅ 自动清理已禁用",
        "auto_cleanup_period_set": "自动清理周期：{} 已成功设置！🔄",
        "custom_period_title": "⏲️ 自定义周期",
        "custom_period_instruction": "输入旧消息将被自动从磁盘删除的期限。",
        "custom_period_format": "以格式输入数据：天、小时、分钟、秒",
        "custom_period_example": "示例：0天，2小时，15分钟，3秒",
        "custom_period_input": "输入周期：",
        "custom_period_invalid": "❌ <b>格式无效！</b>\n\n使用格式：数字/时间单位\n示例：1天",
        "custom_period_minimum": "⏱️ <b>自动清理最小周期为1分钟。</b>\n\n值 <code>{input_value}</code> 被拒绝。\n清理周期设置为：<b>1分钟</b>。",
        "custom_period_maximum": "⏱️ <b>自动清理最大周期为365天。</b>\n\n值 <code>{input_value}</code> 被拒绝。\n清理周期设置为：<b>365天</b>。",
        "custom_period_success": "✅ 自定义周期已设置：{period}",
        "custom_period_cancel": "❌ 自定义周期输入已取消",
        # Логи2 ZH
        "log_bot_starting": "🚀 启动 GhostKeeper 机器人... (尝试 #{attempt})",
        "log_bot_started": "🚀 启动 GhostKeeper...",
        "log_bot_token": "🤖 令牌: {token}",
        "log_bot_admin": "👤 管理员: {admin_id}",
        "log_bot_archive_dir": "📁 消息存档位于文件夹: {archive_dir}",
        "log_bot_configured": "🤖 机器人: @{bot_username} (GhostKeeper by NMS)",
        "log_bot_business": "📱 机器人配置为 Business Bot 配置文件",
        "log_bot_encryption": "🔒 所有数据使用 AES-256-GCM 加密！",
        "log_bot_settings": "💾 保存他人的已删除和已编辑消息: {foreign_status}",
        "log_bot_own_settings": "💾 保存您自己的已删除和已编辑消息: {own_status}",
        "log_bot_media_settings": "📎 发送媒体文件: {media_status}",
        "log_bot_encryption_settings": "🔐 数据加密: {encryption_status}",
        "log_bot_compression_settings": "📦 数据压缩: {compression_status}",
        "log_bot_file_compression": "📁 文件压缩: {file_compression_status}",
        "log_bot_warning": "⚠️ 只有文本消息被加密，媒体文件不加密以优化磁盘空间。视频文件不压缩以保持质量。",
        "log_bot_stop_instruction": "⏹️ 按 Ctrl+C 停止",
        "log_bot_stopped_user": "⛔ 机器人被用户停止",
        "log_bot_stopped_error": "⛔ 机器人因错误停止: {error}",
        "log_bot_restarting": "🔄 重启机器人... (尝试 #{attempt})",
        "log_bot_max_attempts": "❌ 达到最大重启尝试次数 ({max_attempts})，停止机器人",
        "log_env_loaded": "✅ 已加载: {env_key}",
        "log_archive_download_request": "📥 请求下载存档",
        "log_archive_sent": "✅ 存档已成功发送: {filename} (大小: {file_size} 字节)",
        "log_archive_file_deleted": "🗑️ 临时存档文件已删除: {filename}",
        "log_cleanup_completed": "⏳ 🔄 自动清理完成",
        "log_cleanup_completed_detailed_final": "⏳ 🔄 自动清理完成\n\n删除了 {deleted_count} 个文件。\n释放了 {freed_space} 磁盘空间。",
        "log_cleanup_interval_set": "⏰ 自动清理间隔设置为: {period}",
        "log_command_processed": "💬 命令已处理: {command}",
        "log_own_edited_media_found": "💾 📎 找到自己的已编辑媒体 ({media_type})。媒体发送已禁用，删除/编辑时不会下载媒体文件。",
        "log_edited_media_found": "💾 📎 找到用户 ID {user_id} 的已编辑媒体 ({media_type})。媒体发送已禁用，删除/编辑时不会下载媒体文件。",
        "log_own_deleted_media_found": "💾 📎 找到自己的已删除媒体 ({media_type})。媒体发送已禁用，删除/编辑时不会下载媒体文件。",
        "log_deleted_media_found": "💾 📎 找到用户 ID {user_id} 的已删除媒体 ({media_type})。媒体发送已禁用，删除/编辑时不会下载媒体文件。",
        "log_skip_chat_no_messages": "⏭️ 跳过聊天 {chat_id} 的删除 (缓存中没有消息)",
        "log_skip_message_processed": "⏭️ 消息 {msg_id} 已在全局处理，跳过",
        "log_skip_unauthorized": "⏭️ 跳过非管理员 {user_id} 的命令 (机器人仅对管理员 {admin_id} 工作)",
        "log_session_conflict": "机器人无法正常工作，因为同时打开了超过两个会话。请关闭其中一个并重启机器人 (Ctrl + C)",
        "log_invalid_format": "❌输入了无效格式。必须使用正确格式: 数字/时间单位。示例: 1 天",
        "log_media_found": "🔍 找到已下载的媒体: {count} 个文件",
        "log_media_info": "📎 媒体: {type} - {path}",
        "log_media_added": "✅ 添加到发送: {type}",
        "log_media_sending": "发送媒体: {type}",
        "log_media_send_start": "开始发送媒体: {type}",
        "log_media_send_success": "✅ 媒体发送成功: {type}",
        "log_media_send_error": "❌ 媒体发送失败: {type} - {error}",
        "log_media_downloaded": "文件已下载: {file}",
        "log_media_compressed": "文件已下载并压缩: {file}",
        "log_media_downloaded_count": "📥 已下载媒体文件: {count}",
        "log_media_compression": "🖼️ 图像压缩: {original} → {compressed} 字节 ({ratio:.1f}% 节省)",
        "log_own_edited_media_saved": "💾 自己的已编辑媒体 ({media_types}) 已保存到存档",
        "log_own_edited_message_saved": "💾 自己的已编辑消息{media_text} 已保存到存档",
        "log_own_edited_message_saved_text_only": "💾 自己的已编辑消息已保存到存档",
        "log_edited_media_saved_foreign": "💾 用户 ID {user_id} 的已编辑媒体 ({media_types}) 已保存到存档",
        "log_edited_message_saved_foreign": "💾 用户 ID {user_id} 的已编辑消息{media_text} 已保存到存档",
        "log_edited_message_saved_foreign_text_only": "💾 用户 ID {user_id} 的已编辑消息已保存到存档",
        "log_own_deleted_media_saved": "💾 自己的已删除媒体 ({media_types}) 已保存到存档",
        "log_own_deleted_message_saved": "💾 自己的已删除消息{media_text} 已保存到存档",
        "log_own_deleted_message_saved_text_only": "💾 自己的已删除消息已保存到存档",
        "log_deleted_media_saved_foreign": "💾 用户 ID {user_id} 的媒体 ({media_types}) 已保存到存档",
        "log_deleted_message_saved_foreign": "💾 用户 ID {user_id} 的消息{media_text} 已保存到存档",
        "log_deleted_message_saved_foreign_text_only": "💾 用户 ID {user_id} 的消息已保存到存档",
        "log_cleanup_details_shown": "🔍 显示清理详情 [callback: {callback}]",
        "log_cleanup_notifications_disabled": "🔕 自动清理通知已禁用 [callback: {callback}]",
        "log_delete_all_request": "🗑️ 请求删除所有数据 [callback: {callback}]",
        "log_delete_all_confirmed": "✅ 确认删除所有数据 [callback: {callback}]",
        "log_delete_all_cancelled": "❌ 取消删除所有数据 [callback: {callback}]",
        "log_foreign_messages_toggle": "👁‍🗨 他人消息: {status} [callback: {callback} // 设置 save_foreign 已更改: {old} → {new}]",
        "log_own_messages_toggle": "💾 自己的消息: {status} [callback: {callback} // 设置 save_own_deleted 已更改: {old} → {new}]",
        "log_media_toggle": "📎 媒体: {status} [callback: {callback} // 设置 send_media 已更改: {old} → {new}]",
        "log_language_selected": "🌐 已选择语言: {lang} [callback: {callback}]",
        "log_cleanup_period_selected": "⏰ 已选择自动清理周期: {period} [callback: {callback}]",
        "log_cleanup_notifications_toggle": "🔔 自动清理通知: {status} [callback: {callback} // 设置 auto_cleanup_notifications 已更改: {old} → {new}]",
        "log_cleanup_disabled": "🚫 自动清理已禁用 [callback: {callback}]"
    }
}


def get_language_name(lang_code: str) -> str:
    """Возвращает название языка"""
    names = {
        "RU": "Русский (RU)",
        "EN": "English (EN)", 
        "ZH": "中文 (ZH)"
    }
    return names.get(lang_code, "Русский (RU)")

def get_formatted_time(dt: datetime, lang: str = None) -> str:
    """Возвращает отформатированное время в зависимости от языка"""
    if lang is None:
        lang = bot_settings.get('language', 'RU')
    
    time_format = get_text('time_format', lang)
    return dt.strftime(time_format)

def parse_custom_period(text: str) -> int:
    """
    Парсит настраиваемый период из текста на любом языке
    Возвращает количество секунд или None если не удалось распарсить
    """
    import re
    
    # Словари
    time_units = {
        'день': 86400, 'дня': 86400, 'дней': 86400, 'дн': 86400,
        'час': 3600, 'часа': 3600, 'часов': 3600, 'ч': 3600,
        'минута': 60, 'минуты': 60, 'минут': 60, 'мин': 60, 'м': 60,
        'секунда': 1, 'секунды': 1, 'секунд': 1, 'сек': 1, 'с': 1,
        
        'day': 86400, 'days': 86400, 'd': 86400,
        'hour': 3600, 'hours': 3600, 'h': 3600,
        'minute': 60, 'minutes': 60, 'min': 60, 'm': 60,
        'second': 1, 'seconds': 1, 'sec': 1, 's': 1,
        
        '天': 86400, '日': 86400,
        '小时': 3600, '时': 3600,
        '分钟': 60, '分': 60,
        '秒': 1
    }
    
    # Очищаем текст и приводим к нижнему регистру
    text = text.lower().strip()
    
    # Удаляем лишние символы, оставляем только цифры, буквы, пробелы и запятые
    text = re.sub(r'[^\w\s,，]', ' ', text)
    
    # Унификация
    text = re.sub(r'(\d+)\s+(\d+)', r'\1\2', text)
    
    # Ищем все пары "число + ед. времени" в тексте
    pattern = r'(\d+)\s*([а-яёa-z\w]+)'
    matches = re.findall(pattern, text, re.IGNORECASE)
    
    total_seconds = 0
    
    for number_str, unit in matches:
        number = int(number_str)
        unit = unit.lower()
        
        if unit in time_units:
            seconds = number * time_units[unit]
            total_seconds += seconds
        else:
            return None  
    
    return total_seconds if total_seconds > 0 else None

# Загружаем настройки
def load_settings():
    """Загружает настройки из файла"""
    try:
        if SETTINGS_FILE.exists():
            with open(SETTINGS_FILE, 'r', encoding='utf-8') as f:
                settings = json.load(f)
                # Обновляем настройки по умолчанию
                for key, value in DEFAULT_SETTINGS.items():
                    if key not in settings:
                        settings[key] = value
                return settings
        else:
            # Создаем файл с настройками по умолчанию
            save_settings(DEFAULT_SETTINGS)
            return DEFAULT_SETTINGS
    except Exception as e:
        print(f"Ошибка загрузки настроек: {e}")
        return DEFAULT_SETTINGS

def save_settings(settings: dict):
    """Сохраняет настройки в файл"""
    try:
        with open(SETTINGS_FILE, 'w', encoding='utf-8') as f:
            json.dump(settings, f, ensure_ascii=False, indent=2)
        lang = bot_settings.get('language', 'RU')
        # Убираем лог сохранения настроек
    except Exception as e:
        lang = bot_settings.get('language', 'RU')
        logger.error(f"{get_text('settings_save_error', lang)}: {e}")

# Загружаем настройки (вызывается после DEFAULT_SETTINGS)

def get_text(key: str, lang: str = None) -> str:
    """Получает текст на указанном языке"""
    if lang is None:
        lang = bot_settings.get('language', 'RU')
    
    if lang not in TRANSLATIONS:
        lang = 'RU'  
    
    return TRANSLATIONS[lang].get(key, key)

def get_log_text(key: str, **kwargs) -> str:
    """Получает локализованный текст для логов"""
    lang = bot_settings.get('language', 'RU')
    text = get_text(key, lang)
    
    # Заменяем плейсхолдеры в тексте
    try:
        return text.format(**kwargs)
    except KeyError as e:
        # Если не хватает параметров, возвращаем текст как есть
        return text

def log_loaded_env_variables():
    """Выводит локализованные сообщения о загруженных переменных окружения"""
    env_file = Path("config.env")
    
    if not env_file.exists():
        return
    
    try:
        with open(env_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    print(get_log_text('log_env_loaded', env_key=key))
    except Exception:
        pass

# Загружаем переменные окружения 
load_env_file_silent()

# Конфигурация
BOT_TOKEN = os.getenv("BOT_TOKEN")
ADMIN_CHAT_ID = int(os.getenv("ADMIN_CHAT_ID", "0"))
ARCHIVE_DIR = Path(os.getenv("ARCHIVE_DIR", "./archive"))
FILES_DIR = Path(os.getenv("FILES_DIR", "./files"))

# Настройки по умолчанию
DEFAULT_SETTINGS = {
    "save_own_deleted": False,  # Сохранять свои удаленные сообщения
    "send_media": True,         # Отправлять медиа файлы
    "admin_id": ADMIN_CHAT_ID,
    "language": "RU",
    "save_foreign": True,       # Сохранять чужие сообщения
    "auto_cleanup_notifications": True  # Уведомления об автоочистке
}

# Загружаем настройки
bot_settings = load_settings()

# Выводим локализованные сообщения о загруженных переменных окружения
log_loaded_env_variables()

# Папки для сообщений и медиафайлов
ARCHIVE_DIR.mkdir(parents=True, exist_ok=True)
FILES_DIR.mkdir(parents=True, exist_ok=True)

# Создать подпапки для разных типов медиа
PHOTOS_DIR = FILES_DIR / "photos"
VIDEOS_DIR = FILES_DIR / "videos"
AUDIO_DIR = FILES_DIR / "audio"
DOCUMENTS_DIR = FILES_DIR / "documents"
VOICE_DIR = FILES_DIR / "voice"
VIDEO_NOTES_DIR = FILES_DIR / "video_notes"
STICKERS_DIR = FILES_DIR / "stickers"
GIFS_DIR = FILES_DIR / "gifs"

for folder in [PHOTOS_DIR, VIDEOS_DIR, AUDIO_DIR, DOCUMENTS_DIR, VOICE_DIR, VIDEO_NOTES_DIR, STICKERS_DIR, GIFS_DIR]:
    folder.mkdir(parents=True, exist_ok=True)

# Логирование
logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)

# Хранилище сообщений
message_cache = {}
# Глобальный кеш обработанных сообщений для предотвращения дублирования
processed_messages = set()
stats_counters = {"deleted_count": 0, "edited_count": 0}
# Время последнего предупреждения о заполнении диска
last_disk_warning_time = None

def cache_key(chat_id: int, message_id: int) -> str:
    return f"msg:{chat_id}:{message_id}"

async def send_disk_warning_if_needed(bot):
    """Отправляет предупреждение о заполнении диска, если нужно"""
    global last_disk_warning_time
    
    try:
        # Проверяем размер диска
        disk_usage = bot.calculate_disk_usage()
        
        # Если размер больше 1 ГБ
        if disk_usage >= 1073741824:  # 1 ГБ = 1073741824 байт
            # Проверяем, не отправляли ли предупреждение в последние 30 секунд, если нет, то выводим его
            current_time = datetime.now()
            if (last_disk_warning_time is None or 
                (current_time - last_disk_warning_time).total_seconds() > 30):  # 30 секунд
                
                lang = bot_settings.get('language', 'RU')
                warning_text = get_text('disk_full_warning', lang)
                
                await bot.send_message(ADMIN_CHAT_ID, warning_text, parse_mode='HTML')
                last_disk_warning_time = current_time
                logger.info(get_log_text("log_disk_warning_sent"))
                
    except Exception as e:
        logger.error(get_log_text("log_disk_warning_error") + f": {e}")

def save_message_to_file(data: dict):
    """Сохраняет сообщение в файл с шифрованием и сжатием"""
    try:
        
        chat_id = data['chat_id']
        message_id = data['message_id']
        user_id = data.get('from_id', 'unknown')
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        file_ext = get_file_extension()
        filename = ARCHIVE_DIR / f"msg_{chat_id}_{user_id}_{message_id}_{ts}{file_ext}"
        
        encrypted_data = compress_and_encrypt_data(data)
        
        # Сохраняем в бинарном режиме
        with open(filename, 'wb') as f:
            f.write(encrypted_data)
        
        lang = bot_settings.get('language', 'RU')
        # Убираем лог сохранения файла
        return filename
    except Exception as e:
        lang = bot_settings.get('language', 'RU')
        logger.error(f"{get_text('save_error', lang)}: {e}")

def load_message_from_file(filepath: Path) -> dict:
    """Загружает сообщение из файла с расшифровкой и распаковкой"""
    try:
        # Читаем бинарные данные
        with open(filepath, 'rb') as f:
            encrypted_data = f.read()
        
        # Расшифровываем и распаковываем данные
        data = decrypt_and_decompress_data(encrypted_data)
        return data
    except Exception as e:
        logger.error(get_log_text("log_file_load_error", file=filepath) + f": {e}")
        raise

def get_message_metadata_from_filename(filepath: Path) -> dict:
    """Извлекает базовые метаданные из имени файла БЕЗ расшифровки"""
    try:
        filename = filepath.name
        # Формат: msg_{chat_id}_{user_id}_{message_id}_{timestamp}.enc
        parts = filename.split('_')
        if len(parts) >= 5:  # msg, chat_id, user_id, message_id, timestamp.enc
            chat_id = int(parts[1])
            user_id = parts[2]  # может быть 'unknown'
            message_id = int(parts[3])
            timestamp_part = parts[4].replace('.enc', '')  # убираем расширение
            
            # Парсим timestamp 
            try:
                timestamp = datetime.strptime(timestamp_part, "%Y%m%dT%H%M%SZ").timestamp()
            except:
                timestamp = 0
            
            return {
                'chat_id': chat_id,
                'from_id': int(user_id) if user_id != 'unknown' else 0,
                'message_id': message_id,
                'date': timestamp,
                'text': 'Сообщение (для просмотра полного содержимого скачайте архив)',
                'deletion_reason': 'deleted',  # По умолчанию считаем удаленным
                'media': []  # Пустой список медиа
            }
        else:
            return None
    except Exception as e:
        logger.error(get_log_text("log_metadata_extraction_error", file=filepath) + f": {e}")
        return None

class BusinessBot:
    def __init__(self, token: str):
        self.token = token
        self.base_url = f"https://api.telegram.org/bot{token}"
        self.session = None
        self.last_cleanup_details = None
        self.last_cleanup_freed_space = 0
    
    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def get_updates(self, offset: int = None, timeout: int = 30):
        """Получает обновления от Telegram API"""
        params = {
            'timeout': timeout,
            'allowed_updates': json.dumps([
                'message', 'callback_query', 'business_message', 'edited_business_message', 'deleted_business_messages'
            ])
        }
        if offset:
            params['offset'] = offset
        
        async with self.session.get(f"{self.base_url}/getUpdates", params=params) as response:
            return await response.json()
    
    async def send_message(self, chat_id: int, text: str, parse_mode: str = None, reply_markup: dict = None, disable_web_page_preview: bool = None):
        """Отправляет сообщение"""
        data = {
            'chat_id': chat_id,
            'text': text
        }
        if parse_mode:
            data['parse_mode'] = parse_mode
        if reply_markup:
            data['reply_markup'] = reply_markup
        if disable_web_page_preview is not None:
            data['disable_web_page_preview'] = disable_web_page_preview
        
        async with self.session.post(f"{self.base_url}/sendMessage", json=data) as response:
            return await response.json()
    
    async def edit_message_reply_markup(self, chat_id: int, message_id: int, reply_markup: dict):
        """Редактирует клавиатуру сообщения"""
        data = {
            'chat_id': chat_id,
            'message_id': message_id,
            'reply_markup': reply_markup
        }
        
        async with self.session.post(f"{self.base_url}/editMessageReplyMarkup", json=data) as response:
            return await response.json()
    
    async def edit_message_text(self, chat_id: int, message_id: int, text: str, parse_mode: str = None, reply_markup: dict = None):
        """Редактирует текст сообщения"""
        data = {
            'chat_id': chat_id,
            'message_id': message_id,
            'text': text
        }
        if parse_mode:
            data['parse_mode'] = parse_mode
        if reply_markup:
            data['reply_markup'] = reply_markup
        async with self.session.post(f"{self.base_url}/editMessageText", json=data) as response:
            return await response.json()
    
    async def delete_message(self, chat_id: int, message_id: int):
        """Удаляет сообщение"""
        data = {
            'chat_id': chat_id,
            'message_id': message_id
        }
        
        async with self.session.post(f"{self.base_url}/deleteMessage", json=data) as response:
            return await response.json()
    
    async def send_photo(self, chat_id: int, photo_path: str, caption: str = None, parse_mode: str = None):
        """Отправляет фото"""
        try:
            data = aiohttp.FormData()
            data.add_field('chat_id', str(chat_id))
            data.add_field('photo', open(photo_path, 'rb'), filename=os.path.basename(photo_path))
            if caption:
                data.add_field('caption', caption)
            if parse_mode:
                data.add_field('parse_mode', parse_mode)
            
            async with self.session.post(f"{self.base_url}/sendPhoto", data=data) as response:
                return await response.json()
        except Exception as e:
            logger.error(get_log_text("log_photo_send_error") + f": {e}")
            return None
    
    async def send_document(self, chat_id: int, document_path: str, caption: str = None, parse_mode: str = None):
        """Отправляет документ"""
        try:
            data = aiohttp.FormData()
            data.add_field('chat_id', str(chat_id))
            data.add_field('document', open(document_path, 'rb'), filename=os.path.basename(document_path))
            if caption:
                data.add_field('caption', caption)
            if parse_mode:
                data.add_field('parse_mode', parse_mode)
            
            async with self.session.post(f"{self.base_url}/sendDocument", data=data) as response:
                return await response.json()
        except Exception as e:
            logger.error(get_log_text("log_document_send_error") + f": {e}")
            return None
    
    async def send_video(self, chat_id: int, video_path: str, caption: str = None, parse_mode: str = None):
        """Отправляет видео"""
        try:
            data = aiohttp.FormData()
            data.add_field('chat_id', str(chat_id))
            data.add_field('video', open(video_path, 'rb'), filename=os.path.basename(video_path))
            if caption:
                data.add_field('caption', caption)
            if parse_mode:
                data.add_field('parse_mode', parse_mode)
            
            async with self.session.post(f"{self.base_url}/sendVideo", data=data) as response:
                return await response.json()
        except Exception as e:
            logger.error(get_log_text("log_video_send_error") + f": {e}")
            return None
    
    async def send_audio(self, chat_id: int, audio_path: str, caption: str = None, parse_mode: str = None):
        """Отправляет аудио"""
        try:
            data = aiohttp.FormData()
            data.add_field('chat_id', str(chat_id))
            data.add_field('audio', open(audio_path, 'rb'), filename=os.path.basename(audio_path))
            if caption:
                data.add_field('caption', caption)
            if parse_mode:
                data.add_field('parse_mode', parse_mode)
            
            async with self.session.post(f"{self.base_url}/sendAudio", data=data) as response:
                return await response.json()
        except Exception as e:
            logger.error(get_log_text("log_audio_send_error") + f": {e}")
            return None
    
    async def send_voice(self, chat_id: int, voice_path: str, caption: str = None, parse_mode: str = None):
        """Отправляет голосовое сообщение"""
        try:
            data = aiohttp.FormData()
            data.add_field('chat_id', str(chat_id))
            data.add_field('voice', open(voice_path, 'rb'), filename=os.path.basename(voice_path))
            if caption:
                data.add_field('caption', caption)
            if parse_mode:
                data.add_field('parse_mode', parse_mode)
            
            async with self.session.post(f"{self.base_url}/sendVoice", data=data) as response:
                return await response.json()
        except Exception as e:
            logger.error(get_log_text("log_voice_send_error") + f": {e}")
            return None
    
    async def send_video_note(self, chat_id: int, video_note_path: str):
        """Отправляет видео-ноту (кружок)"""
        try:
            data = aiohttp.FormData()
            data.add_field('chat_id', str(chat_id))
            data.add_field('video_note', open(video_note_path, 'rb'), filename=os.path.basename(video_note_path))
            
            async with self.session.post(f"{self.base_url}/sendVideoNote", data=data) as response:
                return await response.json()
        except Exception as e:
            logger.error(get_log_text("log_video_note_send_error") + f": {e}")
            return None

    async def send_animation(self, chat_id: int, animation_path: str, caption: str = None, parse_mode: str = None):
        """Отправляет GIF анимацию"""
        try:
            data = aiohttp.FormData()
            data.add_field('chat_id', str(chat_id))
            data.add_field('animation', open(animation_path, 'rb'), filename=os.path.basename(animation_path))
            if caption:
                data.add_field('caption', caption)
            if parse_mode:
                data.add_field('parse_mode', parse_mode)
            
            async with self.session.post(f"{self.base_url}/sendAnimation", data=data) as response:
                result = await response.json()
                return result
        except Exception as e:
            logger.error(get_log_text("log_animation_send_error") + f": {e}")
            return None
    
    # Команды управления настройками
    async def handle_command(self, message_text: str, chat_id: int):
        """Обрабатывает команды от администратора"""
        global bot_settings
        
        # Проверка на админга
        if chat_id != ADMIN_CHAT_ID:
            logger.info(f"⏭️ Пропускаем команду от не-админа {chat_id} (бот работает только у админа {ADMIN_CHAT_ID})")
            return False
        
        if not message_text.startswith('/'):
            return False
        
        command = message_text.lower().strip()
        
        if command == '/start':
            await self.show_active_status(chat_id)
            return True
        if command == '/settings':
            await self.show_settings(chat_id)
            return True
        if command == '/stats':
            lang = bot_settings.get('language', 'RU')
            stats_text, has_messages = self.build_stats_text()
            
            # Создаем клавиатуру в зависимости от наличия сообщений
            if has_messages:
                stats_keyboard = {
                    "inline_keyboard": [
                        [{"text": get_text('download_archive', lang), "callback_data": "download_archive"}],
                        [{"text": get_text('back', lang), "callback_data": "back_main"}]
                    ]
                }
            else:
                stats_keyboard = {
                    "inline_keyboard": [
                        [{"text": get_text('back', lang), "callback_data": "back_main"}]
                    ]
                }
            
            await self.send_message(chat_id, stats_text, parse_mode='HTML', reply_markup=stats_keyboard)
            return True
        
        return False
    
    def build_active_status_text(self) -> str:
        """Формирует текст статуса бота с учетом выбранного языка"""
        lang = bot_settings.get('language', 'RU')
        foreign_status = get_text('enabled' if bot_settings.get('save_foreign', True) else 'disabled', lang)
        own_status = get_text('enabled' if bot_settings['save_own_deleted'] else 'disabled', lang)
        media_status = get_text('enabled' if bot_settings['send_media'] else 'disabled', lang)
        
        # Статус автоочистки
        auto_cleanup_enabled = bot_settings.get('auto_cleanup_enabled', False)
        auto_cleanup_days = bot_settings.get('auto_cleanup_days', 7)
        
        if auto_cleanup_enabled:
            # Проверяем, есть ли настраиваемый период в секундах
            custom_seconds = bot_settings.get('auto_cleanup_custom_seconds')
            if custom_seconds and custom_seconds != auto_cleanup_days * 86400:
                # Настраиваемый период
                period_text = self.format_custom_period(custom_seconds, lang)
                auto_cleanup_status = f"{get_text('enabled', lang)} ({period_text})"
            else:
                # Стандартный период
                period_text = get_text('auto_cleanup_1_day' if auto_cleanup_days == 1 else 'auto_cleanup_7_days' if auto_cleanup_days == 7 else 'auto_cleanup_14_days' if auto_cleanup_days == 14 else 'auto_cleanup_30_days' if auto_cleanup_days == 30 else 'auto_cleanup_custom', lang)
                auto_cleanup_status = f"{get_text('enabled', lang)} ({period_text})"
        else:
            auto_cleanup_status = get_text('disabled', lang)
        
        return (
            f"{get_text('bot_active', lang)}\n\n"
            f"{get_text('saving_others', lang)}: <b>{foreign_status}</b>\n"
            f"{get_text('saving_own', lang)}: <b>{own_status}</b>\n"
            f"{get_text('saving_media', lang)}: <b>{media_status}</b>\n"
            f"{get_text('auto_cleanup_period', lang)}: <b>{auto_cleanup_status}</b>\n"
            f"{get_text('language', lang)}: <b>{get_language_name(lang)}</b>\n\n"
            f"{get_text('agreement_text', lang)}\n\n"
            f"{get_text('developed_by', lang)}"
        )
    
    async def show_active_status(self, chat_id: int):
        """Показывает активный статус бота"""
        try:
            # Вывод статуса, проверка на админку
            if chat_id != ADMIN_CHAT_ID:
                logger.info(f"⏭️ Пропускаем команду от не-админа {chat_id} (бот работает только у админа {ADMIN_CHAT_ID})")
                return
            
            # Клавиатура с быстрыми действиями
            keyboard_buttons = [{"text": "⚙️", "callback_data": "go_settings"}]
            if chat_id == ADMIN_CHAT_ID:
                keyboard_buttons.append({"text": "📊", "callback_data": "go_stats"})
            
            reply_markup = {
                "inline_keyboard": [keyboard_buttons]
            }
            await self.send_message(chat_id, self.build_active_status_text(), parse_mode='HTML', reply_markup=reply_markup, disable_web_page_preview=True)
        except Exception as e:
            logger.error(get_log_text("log_status_send_error") + f": {e}")
    
    def build_stats_text(self) -> tuple[str, bool]:
        """Формирует текст статистики"""
        try:
            lang = bot_settings.get('language', 'RU')
            
            # Подсчитываем сообщения из архива
            deleted_count = 0
            edited_count = 0
            deleted_foreign = 0
            deleted_own = 0
            edited_foreign = 0
            edited_own = 0
            
            # Подсчитываем медиафайлы
            photos_count = 0
            videos_count = 0
            audio_count = 0
            documents_count = 0
            voice_count = 0
            video_notes_count = 0
            stickers_count = 0
            gifs_count = 0
            
            # Подсчитываем размер диска
            disk_usage = self.calculate_disk_usage()
            disk_usage_formatted = self.format_file_size(disk_usage, lang)
            
            # Подсчитываем файлы архива БЕЗ расшифровки
            for file_path in ARCHIVE_DIR.glob('*'):
                if file_path.is_file():
                    # Извлекаем user_id из имени файла
                    # Формат: msg_{chat_id}_{user_id}_{message_id}_{timestamp}.enc
                    filename = file_path.name
                    parts = filename.split('_')
                    if len(parts) >= 4:  # Новый формат с user_id
                        try:
                            user_id_str = parts[2]  
                            if user_id_str == 'unknown':
                                # Если user_id неизвестен, считаем как "от других"
                                deleted_count += 1
                                deleted_foreign += 1
                            else:
                                user_id = int(user_id_str)
                                is_own = user_id == ADMIN_CHAT_ID
                                
                                # ВСЕ файлы в архиве считаем как удаленные
                                deleted_count += 1
                                if is_own:
                                    deleted_own += 1
                                else:
                                    deleted_foreign += 1
                        except (ValueError, IndexError):
                            # Если не удалось распарсить, считаем как "от других"
                            deleted_count += 1
                            deleted_foreign += 1
                    else:
                        # Старый формат файлов без user_id - считаем как "от других"
                        deleted_count += 1
                        deleted_foreign += 1
            
            # Для отредактированных сообщений используем счетчик из кеша
            edited_count = stats_counters.get("edited_count", 0)
            if edited_count > 0 and deleted_count > 0:
                # Распределяем отредактированные пропорционально удаленным
                total_archive = deleted_count
                edited_own = int((deleted_own / total_archive) * edited_count)
                edited_foreign = edited_count - edited_own
            else:
                edited_own = 0
                edited_foreign = edited_count
            
            # Вычитаем отредактированные из общего количества удаленных
            deleted_count = max(0, deleted_count - edited_count)
            # Корректируем распределение удаленных сообщений
            if deleted_count > 0:
                total_deleted = deleted_own + deleted_foreign
                if total_deleted > 0:
                    deleted_own = int((deleted_own / total_deleted) * deleted_count)
                    deleted_foreign = deleted_count - deleted_own
                else:
                    deleted_own = 0
                    deleted_foreign = deleted_count
            
            # Считаем медиафайлы по папкам
            photos_count = len([f for f in PHOTOS_DIR.glob('*') if f.is_file()])
            videos_count = len([f for f in VIDEOS_DIR.glob('*') if f.is_file()])
            audio_count = len([f for f in AUDIO_DIR.glob('*') if f.is_file()])
            documents_count = len([f for f in DOCUMENTS_DIR.glob('*') if f.is_file()])
            voice_count = len([f for f in VOICE_DIR.glob('*') if f.is_file()])
            video_notes_count = len([f for f in VIDEO_NOTES_DIR.glob('*') if f.is_file()])
            stickers_count = len([f for f in STICKERS_DIR.glob('*') if f.is_file()])
            gifs_count = len([f for f in GIFS_DIR.glob('*') if f.is_file()])
            
            # Распределяем медиа пропорционально сообщениям
            total_messages = deleted_count + edited_count
            if total_messages > 0:
                own_ratio = (deleted_own + edited_own) / total_messages
                foreign_ratio = (deleted_foreign + edited_foreign) / total_messages
                
                photos_own = int(photos_count * own_ratio)
                photos_foreign = photos_count - photos_own
                videos_own = int(videos_count * own_ratio)
                videos_foreign = videos_count - videos_own
                audio_own = int(audio_count * own_ratio)
                audio_foreign = audio_count - audio_own
                documents_own = int(documents_count * own_ratio)
                documents_foreign = documents_count - documents_own
                voice_own = int(voice_count * own_ratio)
                voice_foreign = voice_count - voice_own
                video_notes_own = int(video_notes_count * own_ratio)
                video_notes_foreign = video_notes_count - video_notes_own
                stickers_own = int(stickers_count * own_ratio)
                stickers_foreign = stickers_count - stickers_own
                gifs_own = int(gifs_count * own_ratio)
                gifs_foreign = gifs_count - gifs_own
            else:
                # Медиа от других
                photos_own = 0
                photos_foreign = photos_count
                videos_own = 0
                videos_foreign = videos_count
                audio_own = 0
                audio_foreign = audio_count
                documents_own = 0
                documents_foreign = documents_count
                voice_own = 0
                voice_foreign = voice_count
                video_notes_own = 0
                video_notes_foreign = video_notes_count
                stickers_own = 0
                stickers_foreign = stickers_count
                gifs_own = 0
                gifs_foreign = gifs_count
            
            total_media = photos_count + videos_count + audio_count + documents_count + voice_count + video_notes_count + stickers_count + gifs_count
            
            updated = get_formatted_time(datetime.now(), lang)
            
            # Собираем статистику
            stats_text = f"{get_text('stats_title', lang)}\n\n"
            
            # Статистика сообщений
            if deleted_count > 0:
                stats_text += f"{get_text('saved_deleted', lang)}: <b>{deleted_count}</b> "
                stats_text += f"({get_text('from_others', lang)}: <b>{deleted_foreign}</b>; {get_text('my', lang)}: <b>{deleted_own}</b>)\n"
            else:
                stats_text += f"{get_text('saved_deleted', lang)}: <b>0</b>\n"
            
            if edited_count > 0:
                stats_text += f"{get_text('saved_edited', lang)}: <b>{edited_count}</b> "
                stats_text += f"({get_text('from_others', lang)}: <b>{edited_foreign}</b>; {get_text('my', lang)}: <b>{edited_own}</b>)\n"
            else:
                stats_text += f"{get_text('saved_edited', lang)}: <b>0</b>\n"
            
            # Статистика медиафайлов
            stats_text += f"{get_text('saved_files', lang)}: <b>{total_media}</b>"
            if total_media > 0:
                stats_text += f", {get_text('media_breakdown', lang)}\n"
                
                # Показываем только существующие типы медиа
                if photos_count > 0:
                    stats_text += f"- 📷 {get_text('photo', lang)}: <b>{photos_count}</b> ({get_text('from_others', lang)}: <b>{photos_foreign}</b>; {get_text('my', lang)}: <b>{photos_own}</b>)\n"
                if videos_count > 0:
                    stats_text += f"- 🎥 {get_text('video', lang)}: <b>{videos_count}</b> ({get_text('from_others', lang)}: <b>{videos_foreign}</b>; {get_text('my', lang)}: <b>{videos_own}</b>)\n"
                if audio_count > 0:
                    stats_text += f"- 🎵 {get_text('audio', lang)}: <b>{audio_count}</b> ({get_text('from_others', lang)}: <b>{audio_foreign}</b>; {get_text('my', lang)}: <b>{audio_own}</b>)\n"
                if documents_count > 0:
                    stats_text += f"- 📄 {get_text('document', lang)}: <b>{documents_count}</b> ({get_text('from_others', lang)}: <b>{documents_foreign}</b>; {get_text('my', lang)}: <b>{documents_own}</b>)\n"
                if voice_count > 0:
                    stats_text += f"- 🎤 {get_text('voice', lang)}: <b>{voice_count}</b> ({get_text('from_others', lang)}: <b>{voice_foreign}</b>; {get_text('my', lang)}: <b>{voice_own}</b>)\n"
                if video_notes_count > 0:
                    stats_text += f"- 🎥 {get_text('video_note', lang)}: <b>{video_notes_count}</b> ({get_text('from_others', lang)}: <b>{video_notes_foreign}</b>; {get_text('my', lang)}: <b>{video_notes_own}</b>)\n"
                if stickers_count > 0:
                    stats_text += f"- 🎯 {get_text('sticker', lang)}: <b>{stickers_count}</b> ({get_text('from_others', lang)}: <b>{stickers_foreign}</b>; {get_text('my', lang)}: <b>{stickers_own}</b>)\n"
                if gifs_count > 0:
                    stats_text += f"- 🎬 {get_text('gif', lang)}: <b>{gifs_count}</b> ({get_text('from_others', lang)}: <b>{gifs_foreign}</b>; {get_text('my', lang)}: <b>{gifs_own}</b>)"
            
            # Размер диска и время обновления
            stats_text += f"\n{get_text('auto_cleanup_disk_usage', lang)}: <b>{disk_usage_formatted}</b>\n"
            stats_text += f"{get_text('updated', lang)}: <b>{updated}</b>"
            
            has_messages = deleted_count > 0 or edited_count > 0 or total_media > 0
            
            return stats_text, has_messages
        except Exception as e:
            logger.error(get_log_text("log_stats_formation_error") + f": {e}")
            return get_text('stats_unavailable', lang), False
    
    async def handle_callback_query(self, callback_query: dict):
        """Обрабатывает нажатия на кнопки"""
        global bot_settings
        
        callback_data = callback_query.get('data', '')
        chat_id = callback_query['message']['chat']['id']
        message_id = callback_query['message']['message_id']
        from_user_id = callback_query.get('from', {}).get('id')
        
        # Проверяем права доступа
        if from_user_id != ADMIN_CHAT_ID:
            logger.info(f"⏭️ Пропускаем callback от не-админа {from_user_id} (бот работает только у админа {ADMIN_CHAT_ID})")
            return
        
        lang = bot_settings.get('language', 'RU')
        # Логируем навигацию
        from datetime import datetime, timezone
        current_time = datetime.now().strftime("%d.%m.%Y в %H:%M:%S")
        
        if callback_data == 'go_settings':
            logger.info(f"{current_time} - {get_log_text('log_settings_navigation', callback=callback_data)}")
        elif callback_data == 'back_main':
            logger.info(f"{current_time} - {get_log_text('log_main_menu_navigation', callback=callback_data)}")
        elif callback_data == 'go_stats':
            logger.info(f"{current_time} - {get_log_text('log_stats_navigation', callback=callback_data)}")
        elif callback_data == 'auto_cleanup_settings':
            logger.info(f"{current_time} - {get_log_text('log_cleanup_settings_navigation', callback=callback_data)}")
        elif callback_data == 'back_settings':
            logger.info(f"{current_time} - {get_log_text('log_settings_navigation', callback=callback_data)}")
        elif callback_data == 'choose_lang':
            logger.info(f"{current_time} - {get_log_text('log_language_selection', callback=callback_data)}")
        elif callback_data.startswith('lang_'):
            # Логируется в обработчике
            pass
        elif callback_data == 'toggle_media':
            # Логируется в обработчике
            pass
        elif callback_data == 'toggle_own':
            # Логируется в обработчике
            pass
        elif callback_data == 'toggle_foreign':
            # Логируется в обработчике
            pass
        elif callback_data.startswith('auto_cleanup_'):
            # Логируется в обработчике
            pass
        elif callback_data == 'toggle_auto_cleanup_notifications':
            # Логируется в обработчике
            pass
        elif callback_data == 'clear_all_confirm':
            # Логируется в обработчике
            pass
        elif callback_data == 'clear_all_yes':
            # Логируется в обработчике
            pass
        elif callback_data == 'clear_all_no':
            # Логируется в обработчике
            pass
        elif callback_data == 'disable_auto_cleanup':
            # Логируется в обработчике
            pass
        elif callback_data == 'cancel_custom_period':
            # Логируется в обработчике
            pass
        elif callback_data == 'download_archive':
            # Не логируем, так как есть специальный лог выше
            pass
        else:
            # Остальные callback не логируем
            pass
        
        if callback_data == 'save_own_on':
            bot_settings['save_own_deleted'] = True
            save_settings(bot_settings)
            await self.answer_callback_query(callback_query['id'], "✅ Сохранение своих удаленных включено!")
            await self.update_settings_message(chat_id, message_id)
            
        elif callback_data == 'save_own_off':
            bot_settings['save_own_deleted'] = False
            save_settings(bot_settings)
            await self.answer_callback_query(callback_query['id'], "❌ Сохранение своих удаленных отключено!")
            await self.update_settings_message(chat_id, message_id)
            
        elif callback_data == 'media_on':
            bot_settings['send_media'] = True
            save_settings(bot_settings)
            await self.answer_callback_query(callback_query['id'], "✅ Отправка медиа включена!")
            await self.update_settings_message(chat_id, message_id)
            
        elif callback_data == 'media_off':
            bot_settings['send_media'] = False
            save_settings(bot_settings)
            await self.answer_callback_query(callback_query['id'], "❌ Отправка медиа отключена!")
            await self.update_settings_message(chat_id, message_id)
        
        elif callback_data == 'toggle_foreign':
            old_value = bot_settings.get('save_foreign', True)
            bot_settings['save_foreign'] = not old_value
            save_settings(bot_settings)
            lang = bot_settings.get('language', 'RU')
            status_text = get_text('enabled' if bot_settings['save_foreign'] else 'disabled', lang)
            
            from datetime import datetime, timezone, UTC
            current_time = datetime.now().strftime("%d.%m.%Y в %H:%M:%S")
            lang = bot_settings.get('language', 'RU')
            foreign_status = get_status_text(bot_settings['save_foreign'], lang)
            logger.info(f"{current_time} - {get_log_text('log_foreign_messages_toggle', status=foreign_status, callback=callback_data, old=old_value, new=bot_settings['save_foreign'])}")
            await self.answer_callback_query(callback_query['id'], status_text)
            await self.update_settings_message(chat_id, message_id)
        
        elif callback_data == 'toggle_own':
            old_value = bot_settings['save_own_deleted']
            bot_settings['save_own_deleted'] = not old_value
            save_settings(bot_settings)
            lang = bot_settings.get('language', 'RU')
            status_text = get_text('enabled' if bot_settings['save_own_deleted'] else 'disabled', lang)
            
            from datetime import datetime, timezone, UTC
            current_time = datetime.now().strftime("%d.%m.%Y в %H:%M:%S")
            lang = bot_settings.get('language', 'RU')
            own_status = get_status_text(bot_settings['save_own_deleted'], lang)
            logger.info(f"{current_time} - {get_log_text('log_own_messages_toggle', status=own_status, callback=callback_data, old=old_value, new=bot_settings['save_own_deleted'])}")
            await self.answer_callback_query(callback_query['id'], status_text)
            await self.update_settings_message(chat_id, message_id)
        
        elif callback_data == 'toggle_media':
            old_value = bot_settings['send_media']
            bot_settings['send_media'] = not old_value
            save_settings(bot_settings)
            lang = bot_settings.get('language', 'RU')
            status_text = get_text('enabled' if bot_settings['send_media'] else 'disabled', lang)
            
            from datetime import datetime, timezone, UTC
            current_time = datetime.now().strftime("%d.%m.%Y в %H:%M:%S")
            lang = bot_settings.get('language', 'RU')
            media_status = get_status_text(bot_settings['send_media'], lang)
            logger.info(f"{current_time} - {get_log_text('log_media_toggle', status=media_status, callback=callback_data, old=old_value, new=bot_settings['send_media'])}")
            await self.answer_callback_query(callback_query['id'], status_text)
            await self.update_settings_message(chat_id, message_id)
        
        elif callback_data == 'choose_lang':
            # Показываем выбор языка
            lang_keyboard = {
                "inline_keyboard": [
                    [
                        {"text": "🇷🇺 Русский", "callback_data": "lang_RU"},
                        {"text": "🇬🇧 English", "callback_data": "lang_EN"},
                        {"text": "🇨🇳 中文", "callback_data": "lang_ZH"}
                    ],
                    [
                        {"text": get_text('back', bot_settings.get('language', 'RU')), "callback_data": "back_settings"}
                    ]
                ]
            }
            await self.edit_message_reply_markup(chat_id, message_id, lang_keyboard)
        
        elif callback_data.startswith('lang_'):
            lang = callback_data.split('_', 1)[1]
            if lang in ['RU', 'EN', 'ZH']:
                old_lang = bot_settings.get('language', 'RU')
                bot_settings['language'] = lang
                save_settings(bot_settings)
                from datetime import datetime, timezone, UTC, UTC
                current_time = datetime.now().strftime("%d.%m.%Y в %H:%M:%S")
                lang_names = {'RU': 'русский', 'EN': 'английский', 'ZH': 'китайский'}
                if bot_settings.get('language', 'RU') == 'EN':
                    lang_names = {'RU': 'Russian', 'EN': 'English', 'ZH': 'Chinese'}
                elif bot_settings.get('language', 'RU') == 'ZH':
                    lang_names = {'RU': '俄语', 'EN': '英语', 'ZH': '中文'}
                logger.info(f"{current_time} - {get_log_text('log_language_selected', language=lang_names.get(lang, lang), lang=lang)}")
            await self.update_settings_message(chat_id, message_id)
        
        elif callback_data == 'back_settings':
            await self.update_settings_message(chat_id, message_id)
        
        elif callback_data == 'go_settings':
            await self.show_settings(chat_id)
        
        elif callback_data == 'go_stats':
            if chat_id != ADMIN_CHAT_ID:
                logger.info(f"⏭️ Пропускаем запрос статистики от не-админа {chat_id} (бот работает только у админа {ADMIN_CHAT_ID})")
                return
            
            lang = bot_settings.get('language', 'RU')
            stats_text, has_messages = self.build_stats_text()
            
            # Создаем клавиатуру в зависимости от наличия сообщений
            if has_messages:
                stats_keyboard = {
                    "inline_keyboard": [
                        [{"text": get_text('download_archive', lang), "callback_data": "download_archive"}],
                        [{"text": get_text('back', lang), "callback_data": "back_main"}]
                    ]
                }
            else:
                stats_keyboard = {
                    "inline_keyboard": [
                        [{"text": get_text('back', lang), "callback_data": "back_main"}]
                    ]
                }
            
            await self.send_message(chat_id, stats_text, parse_mode='HTML', reply_markup=stats_keyboard)
        
        elif callback_data == 'back_main':
            await self.show_active_status(chat_id)
        
        elif callback_data == 'auto_cleanup_settings':
            await self.show_auto_cleanup_settings(chat_id)
        
        elif callback_data.startswith('auto_cleanup_details_'):
            # Показываем детали автоочистки
            from datetime import datetime
            current_time = datetime.now().strftime("%d.%m.%Y в %H:%M:%S")
            logger.info(f"{current_time} - {get_log_text('log_cleanup_details_shown', callback=callback_data)}")
            deleted_count = int(callback_data.split('_')[-1])
            # Берем данные об удаленных файлах
            deleted_files_info = getattr(self, 'last_cleanup_details', None)
            freed_space = getattr(self, 'last_cleanup_freed_space', 0)
            await self.show_auto_cleanup_details(chat_id, deleted_count, deleted_files_info, freed_space)
        
        elif callback_data.startswith('auto_cleanup_'):
            if callback_data == 'auto_cleanup_custom':
                from datetime import datetime, timezone, UTC, UTC
                current_time = datetime.now().strftime("%d.%m.%Y в %H:%M:%S")
                logger.info(f"{current_time} - {get_log_text('log_custom_cleanup_setup', callback=callback_data)}")
                # Показываем форму ввода периода
                await self.show_custom_period_input(chat_id)
            else:
                # Берем количество дней
                days = int(callback_data.split('_')[2])
                bot_settings['auto_cleanup_enabled'] = True
                bot_settings['auto_cleanup_days'] = days
                # Убираем кастомный период
                bot_settings.pop('auto_cleanup_custom_seconds', None)
                # Запоминаем время изменения
                bot_settings['auto_cleanup_settings_changed'] = datetime.now().isoformat()
                save_settings(bot_settings)
                
                # Логируем выбор периода
                from datetime import datetime, timezone, UTC, UTC
                current_time = datetime.now().strftime("%d.%m.%Y в %H:%M:%S")
                lang = bot_settings.get('language', 'RU')
                period_text = get_period_name(days, lang)
                logger.info(f"{current_time} - {get_log_text('log_cleanup_period_selected', period=period_text, callback=callback_data)}")
                
                # Отправляем уведомление об успешной установке периода
                lang = bot_settings.get('language', 'RU')
                
                # Перевод для периода
                if days == 1:
                    days_text = get_text('auto_cleanup_1_day', lang)
                elif days == 7:
                    days_text = get_text('auto_cleanup_7_days', lang)
                elif days == 14:
                    days_text = get_text('auto_cleanup_14_days', lang)
                elif days == 30:
                    days_text = get_text('auto_cleanup_30_days', lang)
                else:
                    days_text = f"{days} дней"
                
                # Удаляем предыдущее сообщение об успешной установке периода
                previous_success_message_id = bot_settings.get('last_auto_cleanup_success_message_id')
                if previous_success_message_id:
                    try:
                        await self.delete_message(chat_id, previous_success_message_id)
                    except Exception as e:
                        lang = bot_settings.get('language', 'RU')
                        logger.warning(get_log_text('log_previous_message_delete_error', lang=lang) + f": {e}")
                
                success_message = get_text('auto_cleanup_period_set', lang).format(f"<b>{days_text}</b>")
                success_response = await self.send_message(chat_id, success_message, parse_mode='HTML')
                
                # Сообщения об автоочистке
                try:
                    await self.delete_message(chat_id, message_id)
                except Exception as e:
                    lang = bot_settings.get('language', 'RU')
                    logger.warning(get_log_text('log_old_message_delete_error', error=e, lang=lang))
                
                # Сохраняем ID текущего сообщения об успехе для будущего удаления
                if success_response and 'result' in success_response:
                    success_message_id = success_response['result']['message_id']
                    bot_settings['last_auto_cleanup_success_message_id'] = success_message_id
                    save_settings(bot_settings)
                
                # Показываем обновленное меню автоочистки
                await self.show_auto_cleanup_settings(chat_id)
        
        elif callback_data == 'toggle_auto_cleanup_notifications':
            # Переключаем уведомления об автоочистке
            old_value = bot_settings.get('auto_cleanup_notifications', True)
            bot_settings['auto_cleanup_notifications'] = not old_value
            save_settings(bot_settings)
            lang = bot_settings.get('language', 'RU')
            status_text = get_text('auto_cleanup_notifications_enabled' if bot_settings['auto_cleanup_notifications'] else 'auto_cleanup_notifications_disabled', lang)
            
            from datetime import datetime, timezone, UTC
            current_time = datetime.now().strftime("%d.%m.%Y в %H:%M:%S")
            lang = bot_settings.get('language', 'RU')
            notification_status = get_status_text(bot_settings['auto_cleanup_notifications'], lang)
            logger.info(f"{current_time} - {get_log_text('log_cleanup_notifications_toggle', status=notification_status, callback=callback_data, old=old_value, new=bot_settings['auto_cleanup_notifications'])}")
            
            # Формируем ответ
            if bot_settings['auto_cleanup_notifications']:
                callback_answer = f"🔔 {status_text}"
            else:
                callback_answer = f"🔕 {status_text}"
            await self.answer_callback_query(callback_query['id'], callback_answer)
            
            # Удаляем старое сообщение с настройками автоочистки
            try:
                await self.delete_message(chat_id, message_id)
            except Exception as e:
                lang = bot_settings.get('language', 'RU')
                logger.warning(get_log_text('log_old_message_delete_error', error=e, lang=lang))
            
            await self.show_auto_cleanup_settings(chat_id)
        
        elif callback_data == 'disable_auto_cleanup_notifications':
            # Отключаем уведомления об автоочистке из уведомления
            from datetime import datetime
            current_time = datetime.now().strftime("%d.%m.%Y в %H:%M:%S")
            logger.info(f"{current_time} - {get_log_text('log_cleanup_notifications_disabled', callback=callback_data)}")
            bot_settings['auto_cleanup_notifications'] = False
            save_settings(bot_settings)
            lang = bot_settings.get('language', 'RU')
            
            # Удаляем уведомление об автоочистке
            try:
                await self.delete_message(chat_id, message_id)
            except Exception as e:
                lang = bot_settings.get('language', 'RU')
                logger.warning(get_log_text('log_cleanup_notification_delete_error', error=e, lang=lang))
            
            # Отправляем сообщение о том, что уведомления отключены
            disabled_message = get_text('notifications_disabled_message', lang)
            await self.send_message(chat_id, disabled_message, parse_mode='HTML')
            
            await self.answer_callback_query(callback_query['id'], f"🔕 {get_text('auto_cleanup_notifications', lang)}: {get_text('auto_cleanup_notifications_disabled', lang)}")
        
        elif callback_data == 'clear_all_confirm':
            from datetime import datetime, timezone, UTC
            current_time = datetime.now().strftime("%d.%m.%Y в %H:%M:%S")
            logger.info(f"{current_time} - {get_log_text('log_delete_all_request', callback=callback_data)}")
            await self.show_clear_all_confirm(chat_id)
        
        elif callback_data == 'clear_all_yes':
            from datetime import datetime, timezone, UTC
            current_time = datetime.now().strftime("%d.%m.%Y в %H:%M:%S")
            logger.info(f"{current_time} - {get_log_text('log_delete_all_confirmed', callback=callback_data)}")
            await self.clear_all_data(chat_id)
        
        elif callback_data == 'clear_all_no':
            from datetime import datetime, timezone, UTC
            current_time = datetime.now().strftime("%d.%m.%Y в %H:%M:%S")
            logger.info(f"{current_time} - {get_log_text('log_delete_all_cancelled', callback=callback_data)}")
            lang = bot_settings.get('language', 'RU')
            await self.answer_callback_query(callback_query['id'], get_text('clear_all_cancelled', lang))
            await self.show_auto_cleanup_settings(chat_id)
        
        elif callback_data == 'cancel_custom_period':
            from datetime import datetime, timezone, UTC
            current_time = datetime.now().strftime("%d.%m.%Y в %H:%M:%S")
            logger.info(f"{current_time} - {get_log_text('log_custom_cleanup_cancelled', callback=callback_data)}")
            # Отменяем ввод настраиваемого периода
            bot_settings['waiting_custom_period'] = False
            save_settings(bot_settings)
            lang = bot_settings.get('language', 'RU')
            await self.answer_callback_query(callback_query['id'], get_text('custom_period_cancel', lang))
            await self.show_auto_cleanup_settings(chat_id)
        
        elif callback_data == 'disable_auto_cleanup':
            from datetime import datetime, timezone, UTC
            current_time = datetime.now().strftime("%d.%m.%Y в %H:%M:%S")
            logger.info(f"{current_time} - {get_log_text('log_cleanup_disabled', callback=callback_data)}")
            bot_settings['auto_cleanup_enabled'] = False
            save_settings(bot_settings)
            lang = bot_settings.get('language', 'RU')
            await self.answer_callback_query(callback_query['id'], get_text('auto_cleanup_disabled_msg', lang))
            
            # Удаляем старое сообщение с настройками автоочистки
            try:
                await self.delete_message(chat_id, message_id)
            except Exception as e:
                logger.warning(f"Не удалось удалить старое сообщение: {e}")
            
            await self.show_auto_cleanup_settings(chat_id)
        
        elif callback_data == 'download_archive':
            from datetime import datetime, timezone, UTC
            current_time = datetime.now().strftime("%d.%m.%Y в %H:%M:%S")
            logger.info(f"{current_time} - {get_log_text('log_archive_download_request', callback=callback_data)}")
            await self.download_archive(chat_id)
    
    async def download_archive(self, chat_id: int):
        """Скачивает архив всех сообщений в txt файле"""
        from datetime import datetime, timezone
        try:
            lang = bot_settings.get('language', 'RU')
            
            # Отправляем сообщение о том, что архив формируется
            await self.send_message(ADMIN_CHAT_ID, 
                f"<b>{get_text('archive_wait_message', lang)}</b>\n"
                f"{get_text('archive_wait_description', lang)}", 
                parse_mode='HTML')
            
            # Создаем временный файл
            archive_filename = f"archive_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            archive_path = Path(archive_filename)
            
            # Получаем метаданные для опр-ия периода
            metadata_list = []
            for file_path in ARCHIVE_DIR.glob('*'):
                if file_path.is_file():
                    try:
                        metadata = get_message_metadata_from_filename(file_path)
                        if metadata:
                            metadata_list.append((file_path, metadata))
                    except Exception as e:
                        lang = bot_settings.get('language', 'RU')
                        logger.error(get_log_text('log_file_metadata_read_error', file=str(file_path), error=e, lang=lang))
                        continue
            
            # Сортируем по времени для опр-ия периода
            metadata_list.sort(key=lambda x: x[1].get('date', 0))
            
            # Подсчитываем сообщения по владельцам
            my_count = 0
            other_count = 0
            for _, metadata in metadata_list:
                user_id = metadata.get('from_id', 0)
                if user_id == ADMIN_CHAT_ID:
                    my_count += 1
                else:
                    other_count += 1
            
            # Заголовок архива
            period_text = f"📊 {get_text('archive_header', lang)}\n"
            
            # Записываем в файл
            with open(archive_path, 'w', encoding='utf-8') as f:
                f.write(period_text)
                f.write(f"📅 {get_text('created', lang)}: {datetime.now().strftime(get_text('time_format', lang))}\n")
                f.write(f"📁 {get_text('total_messages', lang)}: {len(metadata_list)} | {get_text('from_others', lang)}: {other_count} | {get_text('my', lang)}: {my_count}\n")
                f.write("=" * 50 + "\n\n")
                
                # Расшифровываем при записи
                for i, (file_path, metadata) in enumerate(metadata_list, 1):
                    try:
                        msg = load_message_from_file(file_path)
                    except Exception as e:
                        lang = bot_settings.get('language', 'RU')
                        logger.error(get_log_text('log_file_decryption_error', file=str(file_path), error=e, lang=lang))
                        # Используем метаданные как fallback
                        msg = metadata
                    # Определяем тип сообщения
                    if msg.get('deletion_reason') == 'deleted':
                        msg_type = f"🗑️ {get_text('deleted', lang)}"
                    elif msg.get('edit_reason') == 'edited':
                        msg_type = f"✏️ {get_text('edited', lang)}"
                    else:
                        msg_type = f"💬 {get_text('normal', lang)}"
                    
                    # Определяем владельца
                    user_id = msg.get('from_id', 0)
                    is_own = user_id == ADMIN_CHAT_ID
                    owner = f"👤 {get_text('my', lang)}" if is_own else f"👥 {get_text('other', lang)}"
                    
                    # Время сообщения
                    msg_date = msg.get('date', 0)
                    if msg_date:
                        msg_time = datetime.fromtimestamp(msg_date).strftime(get_text('time_format', lang))
                    else:
                        msg_time = "Неизвестно"
                    
                    # Текст сообщения
                    text = msg.get('text', '') or msg.get('caption', '') or get_text('no_text', lang)
                    
                    # Медиафайлы
                    media_info = msg.get('media', [])
                    media_text = ""
                    if media_info:
                        media_text = f"\n📎 {get_text('media', lang)}: {len(media_info)} {get_text('files', lang)}"
                    
                    # Записываем сообщение
                    f.write(f"{i}. {msg_type} | {owner}\n")
                    f.write(f"⏰ {msg_time}\n")
                    
                    # Добавляем информацию о чате и пользователе (только для чужих сообщений)
                    chat_id = msg.get('chat_id', 0)
                    user_id = msg.get('from_id', 0)
                    if user_id != ADMIN_CHAT_ID:  # Только для чужих сообщений
                        # Добавляем тег собеседника
                        from_username = msg.get('from_username', '')
                        tag_text = f"@{from_username}" if from_username else get_text('no_tag', lang)
                        f.write(f"💬 Чат: {chat_id} | ID: {user_id} | {get_text('tag', lang)}: {tag_text}\n")
                    
                    f.write(f"💬 {text}{media_text}\n")
                    f.write("-" * 30 + "\n\n")
            
            file_description = get_text('archive_ready', lang)
            
            # Проверяем существование файла
            if not archive_path.exists():
                lang = bot_settings.get('language', 'RU')
                logger.error(get_log_text('log_archive_file_missing', path=str(archive_path), lang=lang))
                await self.send_message(ADMIN_CHAT_ID, get_log_text('log_archive_file_missing', path=str(archive_path), lang=lang))
                return
            
            result = await self.send_document(ADMIN_CHAT_ID, str(archive_path), file_description)
            
            if result and result.get('ok'):
                from datetime import datetime, timezone, UTC, UTC
                current_time = datetime.now().strftime("%d.%m.%Y в %H:%M:%S")
                file_size = archive_path.stat().st_size
                logger.info(f"{current_time} - {get_log_text('log_archive_sent', filename=archive_filename, size=file_size)}")
                # Удаляем временный файл
                try:
                    archive_path.unlink()
                    from datetime import datetime, timezone, UTC, UTC
                    current_time = datetime.now().strftime("%d.%m.%Y в %H:%M:%S")
                    logger.info(f"{current_time} - {get_log_text('log_archive_file_deleted', filename=archive_filename)}")
                except Exception as e:
                    lang = bot_settings.get('language', 'RU')
                    logger.error(get_log_text('log_temp_file_delete_error', filename=archive_filename, error=e, lang=lang))
            else:
                lang = bot_settings.get('language', 'RU')
                logger.error(get_log_text('log_archive_send_error', error=result, lang=lang))
                error_msg = result.get('description', get_text('unknown_error', lang)) if result else get_text('unknown_error', lang)
                await self.send_message(ADMIN_CHAT_ID, get_log_text('log_archive_send_error', error=error_msg, lang=lang))
                logger.error(get_log_text('log_archive_send_error', error=error_msg, lang=lang))
                    
        except Exception as e:
            lang = bot_settings.get('language', 'RU')
            logger.error(get_log_text('log_archive_create_error', error=e, lang=lang))
            await self.send_message(ADMIN_CHAT_ID, get_log_text('log_archive_create_error', error=e, lang=lang))
    
    async def answer_callback_query(self, callback_query_id: str, text: str):
        """Отвечает на callback query"""
        data = {
            'callback_query_id': callback_query_id,
            'text': text
        }
        
        async with self.session.post(f"{self.base_url}/answerCallbackQuery", json=data) as response:
            return await response.json()
    
    async def update_settings_message(self, chat_id: int, message_id: int):
        """Обновляет сообщение с настройками"""
        lang = bot_settings.get('language', 'RU')
        settings_text = f"{get_text('settings_title', lang)}\n\n{get_text('settings_subtitle', lang)}"
        
        reply_markup = self.create_settings_keyboard()
        # Обновляем текст и клавиатуру
        await self.edit_message_text(chat_id, message_id, settings_text, parse_mode='HTML', reply_markup=reply_markup)
    
    def create_settings_keyboard(self):
        """Создает клавиатуру с настройками"""
        lang = bot_settings.get('language', 'RU')
        
        # Создаем кнопки с локализованными текстами
        foreign_status = get_text('enabled' if bot_settings.get('save_foreign', True) else 'disabled', lang)
        own_status = get_text('enabled' if bot_settings['save_own_deleted'] else 'disabled', lang)
        media_status = get_text('enabled' if bot_settings['send_media'] else 'disabled', lang)
        
        # Статус автоочистки
        auto_cleanup_enabled = bot_settings.get('auto_cleanup_enabled', False)
        auto_cleanup_days = bot_settings.get('auto_cleanup_days', 7)
        
        if auto_cleanup_enabled:
            # Проверяем, есть ли настраиваемый период в секундах
            custom_seconds = bot_settings.get('auto_cleanup_custom_seconds')
            if custom_seconds and custom_seconds != auto_cleanup_days * 86400:
                # Настраиваемый период
                period_text = self.format_custom_period(custom_seconds, lang)
                auto_cleanup_status = f"{get_text('auto_cleanup_enabled', lang)} ({period_text})"
            else:
                # Стандартный период
                period_text = get_text('auto_cleanup_1_day' if auto_cleanup_days == 1 else 'auto_cleanup_7_days' if auto_cleanup_days == 7 else 'auto_cleanup_14_days' if auto_cleanup_days == 14 else 'auto_cleanup_30_days' if auto_cleanup_days == 30 else 'auto_cleanup_custom', lang)
                auto_cleanup_status = f"{get_text('auto_cleanup_enabled', lang)} ({period_text})"
        else:
            auto_cleanup_status = get_text('auto_cleanup_disabled', lang)
        
        foreign_label = f"{get_text('others_messages', lang)}: {foreign_status}"
        own_label = f"{get_text('own_messages', lang)}: {own_status}"
        media_label = f"{get_text('media', lang)}: {media_status}"
        auto_cleanup_label = f"{get_text('auto_cleanup', lang)}: {auto_cleanup_status}"
        
        # Определяем язык для кнопки
        lang_names = {"RU": "🇷🇺 Русский", "EN": "🇬🇧 English", "ZH": "🇨🇳 中文"}
        lang_label = lang_names.get(lang, "🇷🇺 Русский")
        
        keyboard = {
            "inline_keyboard": [
                [
                    {"text": foreign_label, "callback_data": "toggle_foreign"}
                ],
                [
                    {"text": own_label, "callback_data": "toggle_own"}
                ],
                [
                    {"text": auto_cleanup_label, "callback_data": "auto_cleanup_settings"}
                ],
                [
                    {"text": media_label, "callback_data": "toggle_media"},
                    {"text": lang_label, "callback_data": "choose_lang"}
                ],
                [
                    {"text": get_text('back', lang), "callback_data": "back_main"}
                ]
            ]
        }
        return keyboard
    
    async def show_settings(self, chat_id: int):
        """Показывает текущие настройки с кнопками"""
        lang = bot_settings.get('language', 'RU')
        settings_text = f"{get_text('settings_title', lang)}\n\n{get_text('settings_subtitle', lang)}"
        
        reply_markup = self.create_settings_keyboard()
        await self.send_message(chat_id, settings_text, parse_mode='HTML', reply_markup=reply_markup)
    
    async def show_auto_cleanup_settings(self, chat_id: int):
        """Показывает настройки автоочистки"""
        try:
            lang = bot_settings.get('language', 'RU')
            auto_cleanup_enabled = bot_settings.get('auto_cleanup_enabled', False)
            auto_cleanup_days = bot_settings.get('auto_cleanup_days', 7)
            
            # Подсчитываем размер диска
            disk_usage = self.calculate_disk_usage()
            disk_usage_formatted = self.format_file_size(disk_usage, lang)
            
            # Формируем статус
            if auto_cleanup_enabled:
                status_text = get_text('auto_cleanup_enabled', lang)
            else:
                status_text = get_text('auto_cleanup_disabled', lang)
            
            # Формируем текущий период
            if auto_cleanup_enabled:
                # Проверяем, есть ли настраиваемый период в секундах
                custom_seconds = bot_settings.get('auto_cleanup_custom_seconds')
                if custom_seconds and custom_seconds != auto_cleanup_days * 86400:
                    # Настраиваемый период
                    current_period = self.format_custom_period(custom_seconds, lang)
                else:
                    # Стандартный период
                    current_period = get_text('auto_cleanup_1_day' if auto_cleanup_days == 1 else 'auto_cleanup_7_days' if auto_cleanup_days == 7 else 'auto_cleanup_14_days' if auto_cleanup_days == 14 else 'auto_cleanup_30_days' if auto_cleanup_days == 30 else 'auto_cleanup_custom', lang)
            else:
                current_period = get_text('auto_cleanup_period_not_set', lang)
            
            # Получаем дату последней автоочистки
            last_cleanup_str = bot_settings.get('last_auto_cleanup', None)
            if last_cleanup_str:
                try:
                    # Парсим дату из ISO формата
                    last_cleanup = datetime.fromisoformat(last_cleanup_str)
                    # Форматируем дату в зависимости от языка
                    if lang == 'RU':
                        last_cleanup_formatted = last_cleanup.strftime("%d.%m.%y в %H:%M")
                    elif lang == 'EN':
                        last_cleanup_formatted = last_cleanup.strftime("%m/%d/%y at %H:%M")
                    else:  # ZH
                        last_cleanup_formatted = last_cleanup.strftime("%y.%m.%d %H:%M")
                except (ValueError, TypeError):
                    last_cleanup_formatted = "-"
            else:
                last_cleanup_formatted = "-"
            
            # Рассчитываем время до следующей очистки
            next_cleanup_text = "-"
            if auto_cleanup_enabled and last_cleanup_str:
                try:
                    last_cleanup = datetime.fromisoformat(last_cleanup_str)
                    # Определяем период в секундах
                    custom_seconds = bot_settings.get('auto_cleanup_custom_seconds')
                    if custom_seconds:
                        cleanup_interval = custom_seconds
                    else:
                        cleanup_interval = auto_cleanup_days * 86400
                    
                    # Вычисляем время следующей очистки
                    next_cleanup_time = last_cleanup + timedelta(seconds=cleanup_interval)
                    now = datetime.now()
                    
                    if next_cleanup_time > now:
                        # Время до следующей очистки
                        time_remaining = int((next_cleanup_time - now).total_seconds())
                        next_cleanup_text = self.format_time_remaining(time_remaining, lang)
                    else:
                        if lang == 'RU':
                            next_cleanup_text = "сейчас"
                        elif lang == 'EN':
                            next_cleanup_text = "now"
                        else:  # ZH
                            next_cleanup_text = "现在"
                except (ValueError, TypeError):
                    next_cleanup_text = "-"
            
            settings_text = f"<b>{get_text('auto_cleanup_title', lang)}</b>\n\n"
            settings_text += f"<b>{get_text('auto_cleanup_status', lang)}:</b> {status_text}\n"
            settings_text += f"<b>{get_text('auto_cleanup_disk_usage', lang)}:</b> {disk_usage_formatted}\n"
            settings_text += f"<b>{get_text('auto_cleanup_current_period', lang)}:</b> {current_period}\n"
            settings_text += f"<b>{get_text('auto_cleanup_last_cleanup', lang)}:</b> {last_cleanup_formatted}\n"
            
            # Показываем время до следующей очистки только если автоочистка включена
            if auto_cleanup_enabled:
                settings_text += f"<b>{get_text('auto_cleanup_next_cleanup', lang)}:</b> {next_cleanup_text}\n"
            
            # Добавляем статус уведомлений только если автоочистка включена
            if auto_cleanup_enabled:
                notifications_enabled = bot_settings.get('auto_cleanup_notifications', True)
                notifications_status = get_text('auto_cleanup_notifications_enabled', lang) if notifications_enabled else get_text('auto_cleanup_notifications_disabled', lang)
                settings_text += f"<b>{get_text('auto_cleanup_notifications', lang)}:</b> {notifications_status}\n"
            
            settings_text += "\n"
            settings_text += f"{get_text('auto_cleanup_select_period', lang)}:"
            
            # Проверяем, есть ли файлы для удаления
            archive_files = len([f for f in ARCHIVE_DIR.glob('*') if f.is_file()])
            photos_count = len([f for f in PHOTOS_DIR.glob('*') if f.is_file()])
            videos_count = len([f for f in VIDEOS_DIR.glob('*') if f.is_file()])
            audio_count = len([f for f in AUDIO_DIR.glob('*') if f.is_file()])
            documents_count = len([f for f in DOCUMENTS_DIR.glob('*') if f.is_file()])
            voice_count = len([f for f in VOICE_DIR.glob('*') if f.is_file()])
            video_notes_count = len([f for f in VIDEO_NOTES_DIR.glob('*') if f.is_file()])
            stickers_count = len([f for f in STICKERS_DIR.glob('*') if f.is_file()])
            gifs_count = len([f for f in GIFS_DIR.glob('*') if f.is_file()])
            
            total_files = archive_files + photos_count + videos_count + audio_count + documents_count + voice_count + video_notes_count + stickers_count + gifs_count
            
            # Клавиатура с периодами
            keyboard_rows = [
                [
                    {"text": get_text('auto_cleanup_1_day', lang), "callback_data": "auto_cleanup_1"},
                    {"text": get_text('auto_cleanup_7_days', lang), "callback_data": "auto_cleanup_7"}
                ],
                [
                    {"text": get_text('auto_cleanup_14_days', lang), "callback_data": "auto_cleanup_14"},
                    {"text": get_text('auto_cleanup_30_days', lang), "callback_data": "auto_cleanup_30"}
                ],
                [
                    {"text": get_text('auto_cleanup_custom', lang), "callback_data": "auto_cleanup_custom"}
                ]
            ]
            
            # Добавляем кнопку уведомлений только если автоочистка включена
            if auto_cleanup_enabled:
                notifications_enabled = bot_settings.get('auto_cleanup_notifications', True)
                keyboard_rows.append([
                    {"text": f"{get_text('auto_cleanup_notifications', lang)}: {get_text('auto_cleanup_notifications_enabled' if notifications_enabled else 'auto_cleanup_notifications_disabled', lang)}", "callback_data": "toggle_auto_cleanup_notifications"}
                ])
            
            # Добавляем кнопку "Очистить все" только если есть файлы
            if total_files > 0:
                keyboard_rows.append([
                    {"text": get_text('clear_all', lang), "callback_data": "clear_all_confirm"}
                ])
            
            # Добавляем кнопку "Отключить автоочистку" только если она включена
            if auto_cleanup_enabled:
                keyboard_rows.append([
                    {"text": get_text('disable_auto_cleanup', lang), "callback_data": "disable_auto_cleanup"}
                ])
            
            keyboard_rows.append([
                {"text": get_text('back', lang), "callback_data": "back_settings"}
            ])
            
            keyboard = {
                "inline_keyboard": keyboard_rows
            }
            
            await self.send_message(chat_id, settings_text, parse_mode='HTML', reply_markup=keyboard)
        except Exception as e:
            logger.error(f"Ошибка отправки настроек автоочистки: {e}")

    async def show_custom_period_input(self, chat_id: int):
        """Показывает форму ввода настраиваемого периода"""
        try:
            lang = bot_settings.get('language', 'RU')
            
            # Формируем сообщение с инструкциями
            instruction_text = f"<b>{get_text('custom_period_title', lang)}</b>\n\n"
            instruction_text += f"{get_text('custom_period_instruction', lang)}\n\n"
            instruction_text += f"{get_text('custom_period_format', lang)}\n"
            instruction_text += f"{get_text('custom_period_example', lang)}"
            
            # Клавиатура с кнопкой отмены
            keyboard = {
                "inline_keyboard": [
                    [
                        {"text": get_text('clear_all_cancel', lang), "callback_data": "cancel_custom_period"}
                    ]
                ]
            }
            
            await self.send_message(chat_id, instruction_text, parse_mode='HTML', reply_markup=keyboard)
            
            # Устанавливаем флаг ожидания ввода настраиваемого периода
            bot_settings['waiting_custom_period'] = True
            save_settings(bot_settings)
            
        except Exception as e:
            logger.error(f"Ошибка отправки формы ввода настраиваемого периода: {e}")

    async def handle_custom_period_input(self, text: str, chat_id: int, message_id: int = None):
        """Обрабатывает ввод настраиваемого периода"""
        try:
            from datetime import datetime, timezone, UTC
            current_time = datetime.now().strftime("%d.%m.%Y в %H:%M:%S")
            
            lang = bot_settings.get('language', 'RU')
            
            # Парсим введенный текст
            seconds = parse_custom_period(text)
            
            if seconds is None:
                # Неверный формат
                logger.info(f"{current_time} - {get_log_text('log_invalid_format')}")
                await self.send_message(chat_id, get_text('custom_period_invalid', lang), parse_mode='HTML')
                return
            
            # Если формат корректный, логируем успешный выбор периода
            logger.info(f"{current_time} - {get_log_text('log_cleanup_period_selected', period=text, callback='auto_cleanup_custom')}")
            
            # Проверяем минимальный период
            if seconds < 60:
                minimum_message = get_text('custom_period_minimum', lang).format(input_value=text)
                await self.send_message(chat_id, minimum_message, parse_mode='HTML')
                
                # Мин. период
                seconds = 60
            
            # Проверяем максимальный период 
            max_seconds = 365 * 24 * 60 * 60  # 365 дней в секундах
            if seconds > max_seconds:
                maximum_message = get_text('custom_period_maximum', lang).format(input_value=text)
                await self.send_message(chat_id, maximum_message, parse_mode='HTML')
                
                # Max. период
                seconds = max_seconds
            
            # Конвертируем секунды в дни для совместимости
            days = seconds // 86400
            
            # Устанавливаем настраиваемый период
            bot_settings['auto_cleanup_enabled'] = True
            bot_settings['auto_cleanup_days'] = days
            bot_settings['auto_cleanup_custom_seconds'] = seconds  # Сохраняем в секундах
            bot_settings['waiting_custom_period'] = False
            # Записываем время изменения настроек
            bot_settings['auto_cleanup_settings_changed'] = datetime.now().isoformat()
            save_settings(bot_settings)
            
            # Удаляем предыдущее сообщение об успешной установке периода
            previous_success_message_id = bot_settings.get('last_auto_cleanup_success_message_id')
            if previous_success_message_id:
                try:
                    await self.delete_message(chat_id, previous_success_message_id)
                except Exception as e:
                    logger.warning(f"Не удалось удалить предыдущее сообщение об успехе: {e}")
            
            # Формируем сообщение об успехе
            period_text = self.format_custom_period(seconds, lang)
            success_message = get_text('custom_period_success', lang).format(period=period_text)
            
            success_response = await self.send_message(chat_id, success_message, parse_mode='HTML')
            
            # Удаляем старое сообщение с настройками автоочистки, если message_id передан
            if message_id:
                try:
                    await self.delete_message(chat_id, message_id)
                except Exception as e:
                    logger.warning(f"Не удалось удалить старое сообщение: {e}")
            
            # Сохраняем ID текущего сообщения об успехе для будущего удаления
            if success_response and 'result' in success_response:
                success_message_id = success_response['result']['message_id']
                bot_settings['last_auto_cleanup_success_message_id'] = success_message_id
                save_settings(bot_settings)
            
            await self.show_auto_cleanup_settings(chat_id)
            
        except Exception as e:
            logger.error(f"Ошибка обработки настраиваемого периода: {e}")
            await self.send_message(chat_id, get_text('custom_period_invalid', lang))

    def format_custom_period(self, seconds: int, lang: str, genitive: bool = False) -> str:
        """Форматирует период в читаемый вид"""
        days = seconds // 86400
        hours = (seconds % 86400) // 3600
        minutes = (seconds % 3600) // 60
        secs = seconds % 60
        
        parts = []
        
        if days > 0:
            if lang == 'RU':
                if genitive:
                    if days == 1:
                        parts.append(f"{days} дня")
                    elif days in [2, 3, 4]:
                        parts.append(f"{days} дней")
                    else:
                        parts.append(f"{days} дней")
                else:
                    if days == 1:
                        parts.append(f"{days} день")
                    elif days in [2, 3, 4]:
                        parts.append(f"{days} дня")
                    else:
                        parts.append(f"{days} дней")
            elif lang == 'EN':
                parts.append(f"{days} day{'s' if days != 1 else ''}")
            elif lang == 'ZH':
                parts.append(f"{days}天")
        
        if hours > 0:
            if lang == 'RU':
                if genitive:
                    if hours == 1:
                        parts.append(f"{hours} часа")
                    elif hours in [2, 3, 4]:
                        parts.append(f"{hours} часов")
                    else:
                        parts.append(f"{hours} часов")
                else:
                    if hours == 1:
                        parts.append(f"{hours} час")
                    elif hours in [2, 3, 4]:
                        parts.append(f"{hours} часа")
                    else:
                        parts.append(f"{hours} часов")
            elif lang == 'EN':
                parts.append(f"{hours} hour{'s' if hours != 1 else ''}")
            elif lang == 'ZH':
                parts.append(f"{hours}小时")
        
        if minutes > 0:
            if lang == 'RU':
                if genitive:
                    if minutes == 1:
                        parts.append(f"{minutes} минуты")
                    elif minutes in [2, 3, 4]:
                        parts.append(f"{minutes} минут")
                    else:
                        parts.append(f"{minutes} минут")
                else:
                    if minutes == 1:
                        parts.append(f"{minutes} минута")
                    elif minutes in [2, 3, 4]:
                        parts.append(f"{minutes} минуты")
                    else:
                        parts.append(f"{minutes} минут")
            elif lang == 'EN':
                parts.append(f"{minutes} minute{'s' if minutes != 1 else ''}")
            elif lang == 'ZH':
                parts.append(f"{minutes}分钟")
        
        if secs > 0:
            if lang == 'RU':
                if genitive:
                    if secs == 1:
                        parts.append(f"{secs} секунды")
                    elif secs in [2, 3, 4]:
                        parts.append(f"{secs} секунд")
                    else:
                        parts.append(f"{secs} секунд")
                else:
                    if secs == 1:
                        parts.append(f"{secs} секунда")
                    elif secs in [2, 3, 4]:
                        parts.append(f"{secs} секунды")
                    else:
                        parts.append(f"{secs} секунд")
            elif lang == 'EN':
                parts.append(f"{secs} second{'s' if secs != 1 else ''}")
            elif lang == 'ZH':
                parts.append(f"{secs}秒")
        
        if lang == 'RU':
            return ", ".join(parts)
        elif lang == 'EN':
            return ", ".join(parts)
        elif lang == 'ZH':
            return "".join(parts)
        
        return ", ".join(parts)

    def format_time_remaining(self, seconds: int, lang: str) -> str:
        """Форматирует оставшееся время в детальный вид"""
        if seconds <= 0:
            if lang == 'RU':
                return "сейчас"
            elif lang == 'EN':
                return "now"
            else:  # ZH
                return "现在"
        
        days = seconds // 86400
        hours = (seconds % 86400) // 3600
        minutes = (seconds % 3600) // 60
        secs = seconds % 60
        
        parts = []
        if days > 0:
            if lang == 'RU':
                parts.append(f"{days} дн")
            elif lang == 'EN':
                parts.append(f"{days} day{'s' if days != 1 else ''}")
            else:  # ZH
                parts.append(f"{days}天")
        
        if hours > 0:
            if lang == 'RU':
                parts.append(f"{hours} ч")
            elif lang == 'EN':
                parts.append(f"{hours} h")
            else:  # ZH
                parts.append(f"{hours}小时")
        
        if minutes > 0:
            if lang == 'RU':
                parts.append(f"{minutes} мин")
            elif lang == 'EN':
                parts.append(f"{minutes} min")
            else:  # ZH
                parts.append(f"{minutes}分钟")
        
        if secs > 0:
            if lang == 'RU':
                parts.append(f"{secs} сек")
            elif lang == 'EN':
                parts.append(f"{secs} sec")
            else:  # ZH
                parts.append(f"{secs}秒")
        
        # Формируем итоговую строку с предлогом
        if lang == 'RU':
            time_str = ", ".join(parts)
            return f"{get_text('through', lang)} {time_str}"
        elif lang == 'EN':
            time_str = ", ".join(parts)
            return f"{get_text('through', lang)} {time_str}"
        else:  # ZH
            time_str = " ".join(parts)
            return f"{get_text('through', lang)}{time_str}"

    async def show_clear_all_confirm(self, chat_id: int):
        """Показывает подтверждение очистки всех данных"""
        try:
            lang = bot_settings.get('language', 'RU')
            
            # Сначала проверяем, есть ли файлы для удаления
            archive_files = len([f for f in ARCHIVE_DIR.glob('*') if f.is_file()])
            
            photos_count = len(list(PHOTOS_DIR.glob('*')))
            videos_count = len(list(VIDEOS_DIR.glob('*')))
            audio_count = len(list(AUDIO_DIR.glob('*')))
            documents_count = len(list(DOCUMENTS_DIR.glob('*')))
            voice_count = len(list(VOICE_DIR.glob('*')))
            video_notes_count = len(list(VIDEO_NOTES_DIR.glob('*')))
            stickers_count = len(list(STICKERS_DIR.glob('*')))
            gifs_count = len(list(GIFS_DIR.glob('*')))
            
            total_files = archive_files + photos_count + videos_count + audio_count + documents_count + voice_count + video_notes_count + stickers_count + gifs_count
            
            # Показываем предупреждение
            confirm_text = f"{get_text('clear_all_confirm', lang)}\n\n"
            confirm_text += f"{get_text('clear_all_will_be_deleted', lang)}\n"
            confirm_text += f"{get_text('clear_all_messages', lang)}\n"
            confirm_text += f"{get_text('clear_all_media', lang)}\n"
            confirm_text += f"{get_text('clear_all_cache', lang)}"
            
            # Клавиатура подтверждения
            keyboard = {
                "inline_keyboard": [
                    [
                        {"text": get_text('clear_all_button', lang), "callback_data": "clear_all_yes"},
                        {"text": get_text('clear_all_cancel', lang), "callback_data": "clear_all_no"}
                    ]
                ]
            }
            
            await self.send_message(chat_id, confirm_text, parse_mode='HTML', reply_markup=keyboard)
        except Exception as e:
            logger.error(f"Ошибка отправки подтверждения очистки: {e}")

    def calculate_disk_usage(self):
        """Подсчитывает размер всех файлов бота"""
        try:
            total_size = 0
            
            # Подсчитываем размер файлов архива (сообщения)
            for file_path in ARCHIVE_DIR.glob('*'):
                if file_path.is_file():
                    total_size += file_path.stat().st_size
            
            # Подсчитываем размер медиафайлов
            for dir_path in [PHOTOS_DIR, VIDEOS_DIR, AUDIO_DIR, DOCUMENTS_DIR, VOICE_DIR, VIDEO_NOTES_DIR, STICKERS_DIR, GIFS_DIR]:
                for file_path in dir_path.glob('*'):
                    if file_path.is_file():
                        total_size += file_path.stat().st_size
            
            return total_size
        except Exception as e:
            logger.error(f"Ошибка подсчета размера диска: {e}")
            return 0

    def format_file_size(self, size_bytes, lang='RU'):
        """Форматирует размер файла в читаемый вид"""
        if size_bytes == 0:
            return f"0 {get_text('bytes', lang)}"
        
        size_names = [
            get_text('bytes', lang),
            get_text('kb', lang),
            get_text('mb', lang),
            get_text('gb', lang),
            get_text('tb', lang)
        ]
        i = 0
        while size_bytes >= 1024 and i < len(size_names) - 1:
            size_bytes /= 1024.0
            i += 1
        
        return f"{size_bytes:.1f} {size_names[i]}"

    async def auto_cleanup_task(self):
        """Фоновая задача для автоматической очистки"""
        while True:
            try:
                # Проверяем, включена ли автоочистка
                if bot_settings.get('auto_cleanup_enabled', False):
                    auto_cleanup_days = bot_settings.get('auto_cleanup_days', 7)
                    custom_seconds = bot_settings.get('auto_cleanup_custom_seconds')
                    
                    # Определяем период в секундах
                    if custom_seconds:
                        cleanup_interval = custom_seconds
                    else:
                        cleanup_interval = auto_cleanup_days * 86400  # Дни в секунды
                    
                    # Получаем время последней очистки и время изменения настроек
                    last_cleanup_str = bot_settings.get('last_auto_cleanup')
                    settings_changed_str = bot_settings.get('auto_cleanup_settings_changed')
                    now = datetime.now()
                    
                    # Определяем точку отсчета для автоочистки
                    reference_time = None
                    if settings_changed_str:
                        try:
                            settings_changed = datetime.fromisoformat(settings_changed_str)
                            if last_cleanup_str:
                                last_cleanup = datetime.fromisoformat(last_cleanup_str)
                                # Если настройки были изменены после последней очистки, используем время изменения настроек
                                if settings_changed > last_cleanup:
                                    reference_time = settings_changed
                                else:
                                    reference_time = last_cleanup
                            else:
                                reference_time = settings_changed
                        except (ValueError, TypeError):
                            pass
                    
                    # Если не удалось определить время изменения настроек, используем время последней очистки
                    if not reference_time and last_cleanup_str:
                        try:
                            reference_time = datetime.fromisoformat(last_cleanup_str)
                        except (ValueError, TypeError):
                            pass
                    
                    # Если автоочистка еще не выполнялась и нет времени изменения настроек
                    if not reference_time:
                        bot_settings['last_auto_cleanup'] = now.isoformat()
                        save_settings(bot_settings)
                        should_cleanup = False
                        logger.info(get_log_text('log_cleanup_interval_set', interval=cleanup_interval))
                    else:
                        time_since_reference = (now - reference_time).total_seconds()
                        should_cleanup = time_since_reference >= cleanup_interval
                    
                    if should_cleanup:
                        # Выполняем очистку
                        deleted_count = await self.perform_auto_cleanup()
                        
                        # Обновляем время последней очистки и очищаем время изменения настроек
                        bot_settings['last_auto_cleanup'] = now.isoformat()
                        # Очищаем время изменения настроек, так как очистка выполнена
                        bot_settings.pop('auto_cleanup_settings_changed', None)
                        save_settings(bot_settings)
                        
                        current_time = datetime.now().strftime("%d.%m.%Y в %H:%M:%S")
                        logger.info(f"{current_time} - {get_log_text('log_cleanup_completed', count=deleted_count)}")
                await asyncio.sleep(30)
                
            except Exception as e:
                logger.error(f"Ошибка в задаче автоочистки: {e}")
                await asyncio.sleep(60)  # Ждем минуту при ошибке
    
    async def perform_auto_cleanup(self):
        """Выполняет автоматическую очистку старых файлов"""
        try:
            auto_cleanup_days = bot_settings.get('auto_cleanup_days', 7)
            custom_seconds = bot_settings.get('auto_cleanup_custom_seconds')
            
            # Определяем период в сек.
            if custom_seconds:
                cleanup_interval = custom_seconds
            else:
                cleanup_interval = auto_cleanup_days * 86400
            
            cutoff_time = datetime.now() - timedelta(seconds=cleanup_interval)
            deleted_count = 0
            deleted_files_info = []
            freed_space = 0
            
            # Удаляем старые файлы архива
            for file_path in ARCHIVE_DIR.glob('*'):
                if file_path.is_file():
                    try:
                        file_time = datetime.fromtimestamp(file_path.stat().st_mtime)
                        if file_time < cutoff_time:
                            # Подсчитываем размер файла перед удалением
                            file_size = file_path.stat().st_size
                            freed_space += file_size
                            
                            # Извлекаем информацию о файле из имени
                            filename = file_path.stem  
                            parts = filename.split('_')
                            if len(parts) >= 4:
                                chat_id = parts[1]
                                user_id = parts[2]
                                message_id = parts[3]
                                
                                # Определяем вледельца сообщения
                                is_own = str(user_id) == str(ADMIN_CHAT_ID)
                                owner_type = "my" if is_own else "other"
                                
                                deleted_files_info.append({
                                    'type': 'archive',
                                    'owner': owner_type,
                                    'chat_id': chat_id,
                                    'user_id': user_id,
                                    'message_id': message_id,
                                    'file_path': str(file_path)
                                })
                            
                            file_path.unlink()
                            deleted_count += 1
                    except Exception as e:
                        logger.error(f"Ошибка удаления файла {file_path}: {e}")
            
            # Удаляем старые медиафайлы
            for dir_path in [PHOTOS_DIR, VIDEOS_DIR, AUDIO_DIR, DOCUMENTS_DIR, VOICE_DIR, VIDEO_NOTES_DIR, STICKERS_DIR, GIFS_DIR]:
                for file_path in dir_path.glob('*'):
                    if file_path.is_file():
                        try:
                            file_time = datetime.fromtimestamp(file_path.stat().st_mtime)
                            if file_time < cutoff_time:
                                # Подсчитываем размер медиафайла перед удалением
                                file_size = file_path.stat().st_size
                                freed_space += file_size
                                
                                # Извлекаем информацию о медиафайле из имени
                                filename = file_path.name
                                parts = filename.split('_')
                                if len(parts) >= 3:
                                    media_type = parts[0]
                                    chat_id = parts[1]
                                    message_id = parts[2]

                                    # Определяем владельца медиа по связанному архивному файлу с тем же chat_id и message_id
                                    owner_type = "other"
                                    try:
                                        for archive_file in ARCHIVE_DIR.glob('*'):
                                            if not archive_file.is_file():
                                                continue
                                            arch_name = archive_file.stem
                                            arch_parts = arch_name.split('_')
                                            # Ожидаемый формат: <prefix>_<chat_id>_<user_id>_<message_id>
                                            if len(arch_parts) >= 4 and arch_parts[1] == chat_id and arch_parts[3] == message_id:
                                                user_id = arch_parts[2]
                                                owner_type = "my" if str(user_id) == str(ADMIN_CHAT_ID) else "other"
                                                break
                                    except Exception:
                                        # В случае ошибки определения владельца оставляем значение по умолчанию
                                        pass

                                    deleted_files_info.append({
                                        'type': 'media',
                                        'media_type': media_type,
                                        'owner': owner_type,
                                        'chat_id': chat_id,
                                        'message_id': message_id,
                                        'file_path': str(file_path)
                                    })
                                
                                file_path.unlink()
                                deleted_count += 1
                        except Exception as e:
                            logger.error(f"Ошибка удаления файла {file_path}: {e}")
            
            # Очищаем кеш сообщений при автоочистке
            if deleted_count > 0:
                global message_cache
                message_cache.clear()
            
            # Сбрасываем счетчики статистики, если удалили все файлы
            if deleted_count > 0:
                # Проверяем, остались ли файлы в архиве
                remaining_archive_files = len([f for f in ARCHIVE_DIR.glob('*') if f.is_file()])
                if remaining_archive_files == 0:
                    # Если архив пуст, сбрасываем счетчики
                    global stats_counters, processed_messages
                    stats_counters["deleted_count"] = 0
                    stats_counters["edited_count"] = 0
                    processed_messages.clear()
            
            # Отправляем уведомление о завершении автоочистки
            if deleted_count > 0:
                await self.send_auto_cleanup_notification(deleted_count, cleanup_interval, deleted_files_info, freed_space)
            
            return deleted_count
            
        except Exception as e:
            logger.error(f"Ошибка при выполнении автоочистки: {e}")
            return 0

    async def send_auto_cleanup_notification(self, deleted_count: int, cleanup_interval: int, deleted_files_info: list = None, freed_space: int = 0):
        """Отправляет уведомление о завершении автоочистки"""
        try:
            # Проверяем, включены ли уведомления об автоочистке
            notifications_enabled = bot_settings.get('auto_cleanup_notifications', True)
            if not notifications_enabled:
                pass  
                return
            
            lang = bot_settings.get('language', 'RU')
            
            # Сохраняем информацию об удаленных файлах в кеше 
            if deleted_files_info:
                self.last_cleanup_details = deleted_files_info
                self.last_cleanup_freed_space = freed_space
            
            # Форматируем период автоочистки
            period_text = self.format_custom_period(cleanup_interval, lang, genitive=True)
            
            # Формируем сообщение
            notification_text = (
                f"⏳ 🔄 <b>{get_text('auto_cleanup_completed', lang)}</b>\n\n"
                f"{get_text('auto_cleanup_data_older', lang)} {period_text} {get_text('auto_cleanup_deleted', lang)}."
            )
            
            # Создаем клавиатуру с кнопками "Подробнее" и "Отключить уведомления"
            keyboard = {
                "inline_keyboard": [
                    [
                        {
                            "text": f"🔍 {get_text('auto_cleanup_details', lang)}",
                            "callback_data": f"auto_cleanup_details_{deleted_count}"
                        }
                    ],
                    [
                        {
                            "text": get_text('disable_notifications', lang),
                            "callback_data": "disable_auto_cleanup_notifications"
                        }
                    ]
                ]
            }
            
            await self.send_message(ADMIN_CHAT_ID, notification_text, parse_mode='HTML', reply_markup=keyboard)
            
        except Exception as e:
            logger.error(f"Ошибка отправки уведомления об автоочистке: {e}")

    async def show_auto_cleanup_details(self, chat_id: int, deleted_count: int, deleted_files_info: list = None, freed_space: int = 0):
        """Показывает детальную статистику автоочистки"""
        try:
            lang = bot_settings.get('language', 'RU')
            
            text = f"🔍 <b>{get_text('auto_cleanup_details', lang)}</b>\n\n"
            
            # Добавляем освобожденное место на диске
            if freed_space > 0:
                freed_space_formatted = self.format_file_size(freed_space, lang)
                text += f"<b>{get_text('disk_space_freed', lang)}:</b> {freed_space_formatted}\n\n"
            else:
                text += "\n"
            
            if deleted_files_info:
                # Подсчитываем статистику по типам и владельцам
                archive_my = 0
                archive_other = 0
                edited_my = 0
                edited_other = 0
                media_my = 0
                media_other = 0
                media_types = {}
                
                # Сбор всех message_id для последующей обработки отредактированных
                message_ids = {}
                for file_info in deleted_files_info:
                    if file_info['type'] == 'archive':
                        message_id = file_info.get('message_id')
                        if message_id:
                            if message_id not in message_ids:
                                message_ids[message_id] = {'count': 0, 'owner': file_info['owner']}
                            message_ids[message_id]['count'] += 1
                
                for file_info in deleted_files_info:
                    if file_info['type'] == 'archive':
                        message_id = file_info.get('message_id')
                        is_edited = message_ids.get(message_id, {}).get('count', 0) > 1
                        
                        if is_edited:
                            # Отредактированное сообщение
                            if file_info['owner'] == 'my':
                                edited_my += 1
                            else:
                                edited_other += 1
                        else:
                            # Удаленное сообщение
                            if file_info['owner'] == 'my':
                                archive_my += 1
                            else:
                                archive_other += 1
                    elif file_info['type'] == 'media':
                        if file_info['owner'] == 'my':
                            media_my += 1
                        else:
                            media_other += 1
                        
                        # Подсчитываем типы медиа
                        media_type = file_info.get('media_type', 'unknown')
                        if media_type not in media_types:
                            media_types[media_type] = {'my': 0, 'other': 0}
                        if file_info['owner'] == 'my':
                            media_types[media_type]['my'] += 1
                        else:
                            media_types[media_type]['other'] += 1
                
                # Показываем статистику по архиву
                if archive_my > 0 or archive_other > 0:
                    text += f"💬 <b>{get_text('deleted_messages', lang)}:</b> {archive_my + archive_other} "
                    if archive_other > 0 and archive_my > 0:
                        text += f"({get_text('from_others', lang)}: {archive_other}; {get_text('my', lang)}: {archive_my})\n"
                    elif archive_other > 0:
                        text += f"({get_text('from_others', lang)}: {archive_other})\n"
                    elif archive_my > 0:
                        text += f"({get_text('my', lang)}: {archive_my})\n"
                    else:
                        text += "\n"
                
                # Показываем статистику по отредактированным сообщениям
                if edited_my > 0 or edited_other > 0:
                    text += f"✏️ <b>{get_text('edited_messages', lang)}:</b> {edited_my + edited_other} "
                    if edited_other > 0 and edited_my > 0:
                        text += f"({get_text('from_others', lang)}: {edited_other}; {get_text('my', lang)}: {edited_my})\n"
                    elif edited_other > 0:
                        text += f"({get_text('from_others', lang)}: {edited_other})\n"
                    elif edited_my > 0:
                        text += f"({get_text('my', lang)}: {edited_my})\n"
                    else:
                        text += "\n"
                
                # Показываем статистику по медиа
                if media_my > 0 or media_other > 0:
                    text += f"📎 <b>{get_text('deleted_media', lang)}:</b> {media_my + media_other} "
                    if media_other > 0 and media_my > 0:
                        text += f"({get_text('from_others', lang)}: {media_other}; {get_text('my', lang)}: {media_my})\n"
                    elif media_other > 0:
                        text += f"({get_text('from_others', lang)}: {media_other})\n"
                    elif media_my > 0:
                        text += f"({get_text('my', lang)}: {media_my})\n"
                    else:
                        text += "\n"
                
                # Показываем детали по типам медиа
                if media_types:
                    for media_type, counts in media_types.items():
                        if counts['my'] > 0 or counts['other'] > 0:
                            type_name = {
                                'photo': f'📷 {get_text("photo", lang)}',
                                'video': f'🎥 {get_text("video", lang)}',
                                'audio': f'🎵 {get_text("audio", lang)}',
                                'document': f'📄 {get_text("document", lang)}',
                                'voice': f'🎤 {get_text("voice", lang)}',
                                'video_note': f'📹 {get_text("video_note", lang)}',
                                'sticker': f'😀 {get_text("sticker", lang)}'
                            }.get(media_type, f'📎 {media_type}')
                            
                            text += f"- {type_name}: {counts['my'] + counts['other']} "
                            if counts['other'] > 0 and counts['my'] > 0:
                                text += f"({get_text('from_others', lang)}: {counts['other']}; {get_text('my', lang)}: {counts['my']})\n"
                            elif counts['other'] > 0:
                                text += f"({get_text('from_others', lang)}: {counts['other']})\n"
                            elif counts['my'] > 0:
                                text += f"({get_text('my', lang)}: {counts['my']})\n"
                            else:
                                text += "\n"
            
            keyboard = {
                "inline_keyboard": [[
                    {
                        "text": get_text('back', lang),
                        "callback_data": "back_main"
                    }
                ]]
            }
            
            await self.send_message(chat_id, text, parse_mode='HTML', reply_markup=keyboard)
            
        except Exception as e:
            logger.error(f"Ошибка показа деталей автоочистки: {e}")

    async def clear_all_data(self, chat_id: int):
        """Очищает все данные"""
        try:
            lang = bot_settings.get('language', 'RU')
            
            # Подсчитываем количество файлов для удаления
            archive_files = len([f for f in ARCHIVE_DIR.glob('*') if f.is_file()])
            
            photos_count = len(list(PHOTOS_DIR.glob('*')))
            videos_count = len(list(VIDEOS_DIR.glob('*')))
            audio_count = len(list(AUDIO_DIR.glob('*')))
            documents_count = len(list(DOCUMENTS_DIR.glob('*')))
            voice_count = len(list(VOICE_DIR.glob('*')))
            video_notes_count = len(list(VIDEO_NOTES_DIR.glob('*')))
            stickers_count = len(list(STICKERS_DIR.glob('*')))
            gifs_count = len(list(GIFS_DIR.glob('*')))
            
            total_files = archive_files + photos_count + videos_count + audio_count + documents_count + voice_count + video_notes_count + stickers_count + gifs_count
            
            # Проверяем, есть ли файлы для удаления
            if total_files == 0:
                # Если архив пуст
                empty_message = get_text('clear_all_empty', lang)
                
                # Клавиатура с кнопкой "Назад"
                keyboard = {
                    "inline_keyboard": [[
                        {"text": get_text('back', lang), "callback_data": "back_main"}
                    ]]
                }
                
                await self.send_message(chat_id, empty_message, reply_markup=keyboard)
                return
            
            # Удаляем все файлы
            deleted_count = 0
            
            # Удаляем файлы архива
            for file_path in ARCHIVE_DIR.glob('*'):
                try:
                    if file_path.is_file():
                        file_path.unlink()
                        deleted_count += 1
                except Exception as e:
                    logger.error(f"Ошибка удаления файла {file_path}: {e}")
            
            # Удаляем медиафайлы
            for dir_path in [PHOTOS_DIR, VIDEOS_DIR, AUDIO_DIR, DOCUMENTS_DIR, VOICE_DIR, VIDEO_NOTES_DIR, STICKERS_DIR, GIFS_DIR]:
                for file_path in dir_path.glob('*'):
                    try:
                        if file_path.is_file():
                            file_path.unlink()
                            deleted_count += 1
                    except Exception as e:
                        logger.error(f"Ошибка удаления файла {file_path}: {e}")
            
            # Очищаем кеш сообщений
            global message_cache
            message_cache.clear()
            
            # Сбрасываем счетчики статистики
            global stats_counters, processed_messages
            stats_counters["deleted_count"] = 0
            stats_counters["edited_count"] = 0
            processed_messages.clear()
            
            # Сохраняем дату последней автоочистки и очищаем время изменения настроек
            from datetime import datetime, timezone, UTC, timedelta, UTC
            bot_settings['last_auto_cleanup'] = datetime.now().isoformat()
            # Очищаем время изменения настроек, так как очистка выполнена
            bot_settings.pop('auto_cleanup_settings_changed', None)
            save_settings(bot_settings)
            
            # Отправляем отчет об очистке
            lang = bot_settings.get('language', 'RU')
            report_text = f"🗑️ <b>{get_text('cleanup_completed', lang)}</b>\n\n"
            report_text += f"💬 {get_text('deleted_messages', lang)}: {archive_files}\n"
            report_text += f"📊 {get_text('deleted_media', lang)}: {photos_count + videos_count + audio_count + documents_count + voice_count + video_notes_count + stickers_count + gifs_count}\n"
            report_text += f"- 📷 {get_text('photo', lang)}: {photos_count}\n"
            report_text += f"- 🎥 {get_text('video', lang)}: {videos_count}\n"
            report_text += f"- 🎵 {get_text('audio', lang)}: {audio_count}\n"
            report_text += f"- 📄 {get_text('document', lang)}: {documents_count}\n"
            report_text += f"- 🎤 {get_text('voice', lang)}: {voice_count}\n"
            report_text += f"- 🎥 {get_text('video_note', lang)}: {video_notes_count}\n"
            report_text += f"- 🎯 {get_text('sticker', lang)}: {stickers_count}\n"
            report_text += f"- 🎬 {get_text('gif', lang)}: {gifs_count}"
            
            # Клавиатура с кнопкой "Назад"
            keyboard = {
                "inline_keyboard": [[
                    {"text": get_text('back', lang), "callback_data": "back_main"}
                ]]
            }
            
            await self.send_message(chat_id, report_text, parse_mode='HTML', reply_markup=keyboard)
            from datetime import datetime, timezone, UTC
            current_time = datetime.now().strftime("%d.%m.%Y в %H:%M:%S")
            logger.info(f"{current_time} - {get_log_text('log_cleanup_completed_detailed_final', count=deleted_count)}")
            
        except Exception as e:
            logger.error(f"Ошибка очистки данных: {e}")
            await self.answer_callback_query(chat_id, f"❌ Ошибка очистки: {e}")

    async def send_voice(self, chat_id: int, voice_path: str, caption: str = None, parse_mode: str = None):
        """Отправляет голосовое сообщение"""
        try:
            data = aiohttp.FormData()
            data.add_field('chat_id', str(chat_id))
            data.add_field('voice', open(voice_path, 'rb'), filename=os.path.basename(voice_path))
            if caption:
                data.add_field('caption', caption)
            if parse_mode:
                data.add_field('parse_mode', parse_mode)
            
            async with self.session.post(f"{self.base_url}/sendVoice", data=data) as response:
                return await response.json()
        except Exception as e:
            logger.error(get_log_text("log_voice_send_error") + f": {e}")
            return None
    
    async def get_me(self):
        """Получает информацию о боте"""
        async with self.session.get(f"{self.base_url}/getMe") as response:
            return await response.json()
    
    async def get_file(self, file_id: str):
        """Получает информацию о файле"""
        async with self.session.get(f"{self.base_url}/getFile", params={'file_id': file_id}) as response:
            return await response.json()
    
    async def download_file(self, file_path: str, local_path: Path):
        """Скачивает файл и сжимает его"""
        try:
            url = f"https://api.telegram.org/file/bot{self.token}/{file_path}"
            async with self.session.get(url) as response:
                if response.status == 200:
                    local_path.parent.mkdir(parents=True, exist_ok=True)
                    with open(local_path, 'wb') as f:
                        async for chunk in response.content.iter_chunked(8192):
                            f.write(chunk)
                    
                    # Сжимаем файл после скачивания
                    if FILE_COMPRESSION_ENABLED:
                        compressed_path = compress_file(local_path)
                        if compressed_path != local_path:
                            # Удаляем оригинальный файл и переименовываем сжатый
                            local_path.unlink()
                            compressed_path.rename(local_path)
                        else:
                            pass
                    else:
                        pass
                    
                    return local_path
                else:
                    logger.error(f"Ошибка скачивания файла: {response.status}")
                    return None
        except Exception as e:
            logger.error(f"Ошибка скачивания файла: {e}")
            return None

    async def set_commands_menu(self):
        """Устанавливает меню команд с английскими подсказками"""
        try:
            # EN подсказки для меню
            commands = [
                {"command": "start", "description": "Main menu"},
                {"command": "settings", "description": "Bot settings"},
                {"command": "stats", "description": "Statistics"}
            ]
            
            data = {
                "commands": commands,
                "scope": {"type": "default"}
            }
            
            async with self.session.post(f"{self.base_url}/setMyCommands", json=data) as response:
                result = await response.json()
                if not result.get('ok'):
                    logger.error(f"❌ Ошибка обновления меню команд: {result}")
                    
        except Exception as e:
            logger.error(f"Ошибка установки меню команд: {e}")

def get_was_form(media_single: str) -> str:
    """Возвращает правильную форму глагола 'был/было' для русского языка"""
    masculine_words = ['документ', 'файл', 'стикер', 'GIF']
    neuter_words = ['фото', 'видео', 'аудио', 'голосовое', 'видео-нота', 'медиафайл']
    
    if media_single in masculine_words:
        return 'Был'
    elif media_single in neuter_words:
        return 'Было'
    else:
        return 'Было' 

def get_media_single_form(media_type: str, lang: str = 'RU') -> str:
    """Возвращает тип медиа в единственном числе"""
    if lang == 'RU':
        single_forms = {
            'Фото': 'фото',
            'Видео': 'видео',
            'Аудио': 'аудио',
            'Документ': 'документ',
            'Документы': 'документ',  
            'Голосовое': 'голосовое',
            'Видео-нота': 'видео-нота',
            'Стикер': 'стикер',
            'GIF': 'GIF',
            'Медиа': 'медиафайл'
        }
    elif lang == 'EN':
        single_forms = {
            'Photos': 'photo',
            'Videos': 'video',
            'Audio': 'audio',
            'Documents': 'document',
            'Voice': 'voice',
            'Video note': 'video note',
            'Stickers': 'sticker',
            'GIF': 'GIF',
            'Media': 'media file'
        }
    else:  # ZH
        single_forms = {
            '照片': '照片',
            '视频': '视频',
            '音频': '音频',
            '文档': '文档',
            '语音': '语音',
            '视频笔记': '视频笔记',
            '贴纸': '贴纸',
            'GIF': 'GIF',
            '媒体': '媒体文件'
        }
    
    return single_forms.get(media_type, media_type.lower())

def get_media_type_name(media_type: str, lang: str = 'RU') -> str:
    """Возвращает локализованное название типа медиа"""
    media_type_names = {
        'RU': {
            'photo': 'фото',
            'video': 'видео',
            'audio': 'аудио',
            'voice': 'голосовое',
            'document': 'документ',
            'sticker': 'стикер',
            'video_note': 'кружок',
            'gif': 'gif',
            'animation': 'gif'
        },
        'EN': {
            'photo': 'photo',
            'video': 'video',
            'audio': 'audio',
            'voice': 'voice',
            'document': 'document',
            'sticker': 'sticker',
            'video_note': 'video note',
            'gif': 'gif',
            'animation': 'gif'
        },
        'ZH': {
            'photo': '照片',
            'video': '视频',
            'audio': '音频',
            'voice': '语音',
            'document': '文档',
            'sticker': '贴纸',
            'video_note': '视频笔记',
            'gif': 'gif',
            'animation': 'gif'
        }
    }
    
    return media_type_names.get(lang, media_type_names['RU']).get(media_type, media_type)

def get_media_connector(lang: str = 'RU') -> str:
    """Возвращает локализованный соединитель для медиа"""
    connectors = {
        'RU': ' и медиа',
        'EN': ' and media',
        'ZH': ' 和媒体'
    }
    return connectors.get(lang, connectors['RU'])

def get_period_name(days: int, lang: str = 'RU') -> str:
    """Возвращает локализованное название периода"""
    period_names = {
        'RU': {
            1: "1 день",
            7: "7 дней", 
            14: "14 дней",
            30: "30 дней"
        },
        'EN': {
            1: "1 day",
            7: "7 days",
            14: "14 days", 
            30: "30 days"
        },
        'ZH': {
            1: "1天",
            7: "7天",
            14: "14天",
            30: "30天"
        }
    }
    
    if days in period_names.get(lang, period_names['RU']):
        return period_names[lang][days]
    else:
        # Для нестандартных периодов
        if lang == 'RU':
            return f"{days} дней"
        elif lang == 'EN':
            return f"{days} days"
        elif lang == 'ZH':
            return f"{days}天"
        else:
            return f"{days} дней"

def get_status_text(status: bool, lang: str = 'RU') -> str:
    """Возвращает локализованный текст статуса (Включено/Отключено)"""
    status_texts = {
        'RU': {
            True: "Включено",
            False: "Отключено"
        },
        'EN': {
            True: "Enabled",
            False: "Disabled"
        },
        'ZH': {
            True: "已启用",
            False: "已禁用"
        }
    }
    
    return status_texts.get(lang, status_texts['RU']).get(status, "Включено" if status else "Отключено")

def get_media_type_from_message(msg: dict, lang: str = 'RU') -> str:
    """Определяет тип медиа в сообщении"""
    # Если это данные из кеша, с полем 'media'
    if 'media' in msg and isinstance(msg['media'], list) and len(msg['media']) > 0:
        media_data = msg['media'][0]
        media_type = media_data.get('type', 'unknown')
        
        # Проверяем, является ли документ GIF по MIME-типу
        if media_type == 'document':
            mime_type = media_data.get('mime_type', '')
            if mime_type == 'image/gif':
                return get_text('gif', lang)
            else:
                return get_text('document', lang)
        elif media_type == 'photo':
            return get_text('photo', lang)
        elif media_type == 'video':
            return get_text('video', lang)
        elif media_type == 'audio':
            return get_text('audio', lang)
        elif media_type == 'voice':
            return get_text('voice', lang)
        elif media_type == 'video_note':
            return get_text('video_note', lang)
        elif media_type == 'sticker':
            return get_text('sticker', lang)
        elif media_type == 'gif':
            return get_text('gif', lang)
        else:
            return get_text('media', lang)
    
    if 'photo' in msg:
        return get_text('photo', lang)
    elif 'video' in msg:
        return get_text('video', lang)
    elif 'audio' in msg:
        return get_text('audio', lang)
    elif 'document' in msg:
        # Проверяем, является ли документ GIF
        document = msg['document']
        mime_type = document.get('mime_type', '')
        if mime_type == 'image/gif':
            return get_text('gif', lang)
        else:
            return get_text('document', lang)
    elif 'voice' in msg:
        return get_text('voice', lang)
    elif 'video_note' in msg:
        return get_text('video_note', lang)
    elif 'sticker' in msg:
        return get_text('sticker', lang)
    elif 'animation' in msg:
        return get_text('gif', lang)
    else:
        return get_text('media', lang)

async def extract_media_info(bot: BusinessBot, msg: dict) -> list:
    """Извлекает информацию о медиа без скачивания файлов"""
    media_info = []
    
    try:
        # Фото
        if 'photo' in msg:
            photo_sizes = msg['photo']
            if photo_sizes:
                largest_photo = photo_sizes[-1]
                file_id = largest_photo['file_id']
                
                # Собираем информацию без скачивания
                media_info.append({
                    "type": "photo",
                    "file_id": file_id,
                    "file_size": largest_photo.get('file_size'),
                    "width": largest_photo.get('width'),
                    "height": largest_photo.get('height')
                })
        
        # Видео
        if 'video' in msg:
            video = msg['video']
            file_id = video['file_id']
            
            # Собираем информацию без скачивания
            media_info.append({
                "type": "video",
                "file_id": file_id,
                "file_size": video.get('file_size'),
                "duration": video.get('duration'),
                "width": video.get('width'),
                "height": video.get('height')
            })
        
        # Документы 
        if 'document' in msg:
            document = msg['document']
            file_id = document['file_id']
            mime_type = document.get('mime_type', '')
            
            has_animation = False
            if 'animation' in msg:
                animation = msg['animation']
                if animation['file_id'] == file_id:
                    has_animation = True
            
            # Если есть animation с тем же file_id, пропускаем document
            if not has_animation:
                # Проверяем, является ли документ GIF
                if mime_type == 'image/gif':
                    # Собираем информацию без скачивания
                    media_info.append({
                        "type": "gif",
                        "file_id": file_id,
                        "file_size": document.get('file_size'),
                        "file_name": document.get('file_name'),
                        "mime_type": mime_type
                    })
                else:
                   # Собираем информацию без скачивания
                    media_info.append({
                        "type": "document",
                        "file_id": file_id,
                        "file_size": document.get('file_size'),
                        "file_name": document.get('file_name'),
                        "mime_type": mime_type
                    })
        
        # Аудио
        if 'audio' in msg:
            audio = msg['audio']
            file_id = audio['file_id']
            
           # Собираем информацию без скачивания
            media_info.append({
                "type": "audio",
                "file_id": file_id,
                "file_size": audio.get('file_size'),
                "duration": audio.get('duration'),
                "title": audio.get('title'),
                "performer": audio.get('performer')
            })
        
        # Голосовые (voice)
        if 'voice' in msg:
            voice = msg['voice']
            file_id = voice['file_id']
            
            # Собираем информацию без скачивания
            media_info.append({
                "type": "voice",
                "file_id": file_id,
                "file_size": voice.get('file_size'),
                "duration": voice.get('duration')
            })
        
        # Стикеры
        if 'sticker' in msg:
            sticker = msg['sticker']
            file_id = sticker['file_id']
            
            # Собираем информацию без скачивания
            media_info.append({
                "type": "sticker",
                "file_id": file_id,
                "file_size": sticker.get('file_size'),
                "emoji": sticker.get('emoji'),
                "set_name": sticker.get('set_name')
            })
        
        # Кружки (video_note)
        if 'video_note' in msg:
            video_note = msg['video_note']
            file_id = video_note['file_id']
            
            # Собираем информацию без скачивания
            media_info.append({
                "type": "video_note",
                "file_id": file_id,
                "file_size": video_note.get('file_size'),
                "duration": video_note.get('duration'),
                "length": video_note.get('length')
            })
        
        # GIF 
        if 'animation' in msg:
            animation = msg['animation']
            file_id = animation['file_id']
            
            # Собираем информацию без скачивания
            media_info.append({
                "type": "gif",
                "file_id": file_id,
                "file_size": animation.get('file_size'),
                "duration": animation.get('duration'),
                "width": animation.get('width'),
                "height": animation.get('height')
            })
    
    except Exception as e:
        logger.error(f"Ошибка обработки медиа: {e}")
    
    return media_info

async def download_media_files(bot: BusinessBot, media_info: list, chat_id: int, message_id: int) -> list:
    """Скачивает медиафайлы и возвращает обновленную информацию"""
    downloaded_media = []
    
    for media in media_info:
        try:
            file_id = media['file_id']
            media_type = media['type']
            
            # Получаем инфо о файле
            file_info = await bot.get_file(file_id)
            if not file_info.get('ok'):
                continue
                
            file_path = file_info['result']['file_path']
            
            # Определяем путь для сохранения
            if media_type == 'photo':
                file_name = f"photo_{chat_id}_{message_id}_{file_id}.jpg"
                local_path = PHOTOS_DIR / file_name
            elif media_type == 'video':
                file_name = f"video_{chat_id}_{message_id}_{file_id}.mp4"
                local_path = VIDEOS_DIR / file_name
            elif media_type == 'document':
                file_name = f"document_{chat_id}_{message_id}_{file_id}.{media.get('file_name', 'dat')}"
                local_path = DOCUMENTS_DIR / file_name
            elif media_type == 'audio':
                file_name = f"audio_{chat_id}_{message_id}_{file_id}.mp3"
                local_path = AUDIO_DIR / file_name
            elif media_type == 'voice':
                file_name = f"voice_{chat_id}_{message_id}_{file_id}.ogg"
                local_path = VOICE_DIR / file_name
            elif media_type == 'sticker':
                file_name = f"sticker_{chat_id}_{message_id}_{file_id}.webp"
                local_path = STICKERS_DIR / file_name
            elif media_type == 'video_note':
                file_name = f"video_note_{chat_id}_{message_id}_{file_id}.mp4"
                local_path = VIDEO_NOTES_DIR / file_name
            elif media_type == 'gif':
                file_name = f"gif_{chat_id}_{message_id}_{file_id}.gif"
                local_path = GIFS_DIR / file_name
            else:
                continue
            
            # Скачиваем файл
            downloaded_path = await bot.download_file(file_path, local_path)
            if downloaded_path:
                # Обновляем инфу о медиа с путем к файлу
                media_copy = media.copy()
                media_copy['file_path'] = str(downloaded_path)
                downloaded_media.append(media_copy)
                
        except Exception as e:
            logger.error(f"Ошибка скачивания медиафайла {media.get('type', 'unknown')}: {e}")
    
    return downloaded_media

async def transcribe_voice_message(voice_path: str) -> str:
    """Анализирует голосовое сообщение"""
    try:
        # Получаем инфу о файле
        file_size = os.path.getsize(voice_path)
        file_size_mb = file_size / (1024 * 1024)
        return f"Голосовое сообщение ({file_size_mb:.2f} МБ)"
        
    except Exception as e:
        logger.error(f"Ошибка анализа голосового: {e}")
        return "Не удалось проанализировать голосовое сообщение"

async def analyze_sticker(sticker_path: str) -> str:
    """Анализирует стикер"""
    try:
        # Открываем изображение
        with Image.open(sticker_path) as img:
            # Получение инфы о стикере
            width, height = img.size
            format_type = img.format
            mode = img.mode
            
            # Анализ
            if format_type == 'WEBP':
                return f"Стикер WEBP ({width}x{height})"
            elif format_type == 'PNG':
                return f"Изображение PNG ({width}x{height})"
            else:
                return f"Изображение {format_type} ({width}x{height})"
                
    except Exception as e:
        logger.error(f"Ошибка анализа стикера: {e}")
        return "Не удалось проанализировать стикер"

async def send_media_notification(bot: BusinessBot, media_info: list, base_text: str):
    """Отправляет медиафайлы"""
    try:
        lang = bot_settings.get('language', 'RU')
        
        # Отправляем текстовое уведомление только если оно не пустое
        if base_text.strip():
            await bot.send_message(ADMIN_CHAT_ID, base_text, parse_mode='HTML')
        
        # Обрабатываем каждый медиафайл
        for i, media in enumerate(media_info):
            # Проверяем наличие file_path
            if 'file_path' not in media:
                logger.warning(f"⚠️ Медиа {media['type']} не имеет file_path, пропускаем")
                continue
                
            # Преобразуем Windows пути в Unix-стиль 
            media_path = Path(media['file_path']).resolve()
            media_type = media['type']
            
            if media_type == 'photo':
                # Проверяем существование файла
                if not media_path.exists():
                    logger.error(f"❌ Файл не найден: {media_path}")
                    continue
                    
                # Фото 
                result = await bot.send_photo(ADMIN_CHAT_ID, media_path)
                if result and result.get('ok'):
                    pass
                else:
                    logger.error(f"❌ Ошибка отправки фото: {result}")
                    
            elif media_type == 'video':
                # Проверяем существование файла
                if not media_path.exists():
                    logger.error(f"❌ Файл не найден: {media_path}")
                    continue
                    
                # Видео
                result = await bot.send_video(ADMIN_CHAT_ID, media_path)
                if result and result.get('ok'):
                    pass
                else:
                    logger.error(f"❌ Ошибка отправки видео: {result}")
                    
            elif media_type == 'video_note':
                # Проверяем существование файла
                if not media_path.exists():
                    logger.error(f"❌ Файл не найден: {media_path}")
                    continue
                    
                # Кружки (video_note)
                result = await bot.send_video_note(ADMIN_CHAT_ID, media_path)
                if result and result.get('ok'):
                    pass
                else:
                    result = await bot.send_video(ADMIN_CHAT_ID, media_path)
                    if result and result.get('ok'):
                        pass
                    else:
                        # Если видео не работает, переименовываем файл и отправляем как документ
                        logger.warning(f"⚠️ Видео тоже не работает, переименовываем и отправляем как документ: {result}")
                        try:
                            # Создаем копию файла с расширением .mp4 для воспроизведения
                            import shutil
                            temp_path = media_path.with_suffix('.mp4')
                            shutil.copy2(media_path, temp_path)
                            
                            result = await bot.send_document(ADMIN_CHAT_ID, temp_path)
                            if result and result.get('ok'):
                                pass
                            else:
                                logger.error(f"❌ Ошибка отправки видео-ноты как документ: {result}")
                            
                            # Удаляем временный файл
                            if temp_path.exists():
                                temp_path.unlink()
                                
                        except Exception as e:
                            logger.error(f"❌ Ошибка при переименовании и отправке видео-ноты: {e}")
                    
            elif media_type == 'gif':
                # Проверяем существование файла
                if not media_path.exists():
                    logger.error(f"❌ Файл не найден: {media_path}")
                    continue
                    
                # GIF как ANIMATION
                result = await bot.send_animation(ADMIN_CHAT_ID, media_path)
                if result and result.get('ok'):
                    pass
                else:
                    # Если animation не работает, пробуем как документ
                    logger.warning(f"⚠️ Animation не работает, пробуем как документ: {result}")
                    result = await bot.send_document(ADMIN_CHAT_ID, media_path)
                    if result and result.get('ok'):
                        pass
                    else:
                        logger.error(f"❌ Ошибка отправки GIF: {result}")
                    
            elif media_type == 'document':
                # Проверяем существование файла
                if not media_path.exists():
                    logger.error(f"❌ Файл не найден: {media_path}")
                    continue
                    
                # Документы
                result = await bot.send_document(ADMIN_CHAT_ID, media_path)
                if result and result.get('ok'):
                    # Убираем лог успешной отправки документа
                    pass
                else:
                    logger.error(f"❌ Ошибка отправки документа: {result}")
                    
            elif media_type == 'audio':
                # Проверяем существование файла
                if not media_path.exists():
                    logger.error(f"❌ Файл не найден: {media_path}")
                    continue
                    
                # Аудио
                result = await bot.send_audio(ADMIN_CHAT_ID, media_path)
                if result and result.get('ok'):
                    pass
                else:
                    logger.error(f"❌ Ошибка отправки аудио: {result}")
                    
            elif media_type == 'voice':
                # Проверяем существование файла
                if not media_path.exists():
                    logger.error(f"❌ Файл не найден: {media_path}")
                    continue
                    
                # Voice
                result = await bot.send_voice(ADMIN_CHAT_ID, media_path)
                if result and result.get('ok'):
                    pass
                else:
                    result = await bot.send_audio(ADMIN_CHAT_ID, media_path)
                    if result and result.get('ok'):
                        pass
                    else:
                        try:
                            # Создаем копию файла с расширением .mp3 для воспроизведения
                            import shutil
                            temp_path = media_path.with_suffix('.mp3')
                            shutil.copy2(media_path, temp_path)
                            
                            result = await bot.send_document(ADMIN_CHAT_ID, temp_path)
                            if result and result.get('ok'):
                                pass
                            else:
                                logger.error(f"❌ Ошибка отправки голосового как документ: {result}")
                            
                            # Удаляем временный файл
                            if temp_path.exists():
                                temp_path.unlink()
                                
                        except Exception as e:
                            logger.error(f"❌ Ошибка при переименовании и отправке голосового: {e}")
                            
            elif media_type == 'sticker':
                # Проверяем существование файла
                if not media_path.exists():
                    logger.error(f"❌ Файл не найден: {media_path}")
                    continue
                    
                # Стикеры конвертируем в GIF и отправляем как animation
                try:
                    # Создаем копию файла с расширением .gif для отправки как анимация
                    import shutil
                    temp_path = media_path.with_suffix('.gif')
                    shutil.copy2(media_path, temp_path)
                    
                    # Отправляем как GIF
                    result = await bot.send_animation(ADMIN_CHAT_ID, temp_path)
                    if result and result.get('ok'):
                        pass
                    else:
                        # Если GIF не работает, пробуем как документ
                        logger.warning(f"⚠️ Animation не работает, пробуем как документ: {result}")
                        result = await bot.send_document(ADMIN_CHAT_ID, temp_path)
                        if result and result.get('ok'):
                            # Убираем лог успешной отправки стикера как документ
                            pass
                        else:
                            logger.error(f"❌ Ошибка отправки стикера: {result}")
                    
                    # Удаляем временный файл
                    if temp_path.exists():
                        temp_path.unlink()
                        
                except Exception as e:
                    logger.error(f"❌ Ошибка при конвертации и отправке стикера: {e}")
                
    except Exception as e:
        logger.error(f"Ошибка отправки медиа-уведомления: {e}")
        import traceback
        traceback.print_exc()

async def process_message(bot: BusinessBot, msg: dict):
    """Обрабатывает обычное сообщение от администратора"""
    chat_id = msg.get('chat', {}).get('id')
    message_id = msg.get('message_id')
    from_user = msg.get('from', {})
    from_user_id = from_user.get('id')
    
    # Проверяем права доступа
    if from_user_id != ADMIN_CHAT_ID:
        logger.info(f"⏭️ Пропускаем сообщение от не-админа {from_user_id} (бот работает только у админа {ADMIN_CHAT_ID})")
        return
    
    # Обрабатываем только сообщения от администратора
    if str(from_user_id) == str(ADMIN_CHAT_ID) and msg.get('text'):
        # Убираем общий лог для всех сообщений
        
        # Проверяем, ожидаем ли мы ввод настраиваемого периода
        if bot_settings.get('waiting_custom_period', False):
            text = msg.get('text', '')
            if text.startswith('/'):
                bot_settings['waiting_custom_period'] = False
                save_settings(bot_settings)
                if await bot.handle_command(text, ADMIN_CHAT_ID):
                    current_time = datetime.now().strftime("%d.%m.%Y в %H:%M:%S")
                    logger.info(f"{current_time} - {get_log_text('log_command_processed', command=text)}")
                return
            await bot.handle_custom_period_input(text, chat_id, message_id)
            return
        
        # Проверяем, является ли это командой
        if await bot.handle_command(msg['text'], ADMIN_CHAT_ID):
            current_time = datetime.now().strftime("%d.%m.%Y в %H:%M:%S")
            logger.info(f"{current_time} - {get_log_text('log_command_processed', command=msg['text'])}")
        else:
            # Если это не команда, отправляем сообщение о нераспознанной команде
            lang = bot_settings.get('language', 'RU')
            unrecognized_message = get_text('command_not_recognized', lang)
            await bot.send_message(ADMIN_CHAT_ID, unrecognized_message, parse_mode='HTML')

async def process_business_message(bot: BusinessBot, msg: dict):
    """Обрабатывает business сообщение"""
    chat_id = msg.get('chat', {}).get('id')
    message_id = msg.get('message_id')
    from_user = msg.get('from', {})
    from_user_id = from_user.get('id')
    
    lang = bot_settings.get('language', 'RU')
    
    # Проверяем, нужно ли сохранять это сообщение
    is_own_message = str(from_user_id) == str(ADMIN_CHAT_ID)
    
    if is_own_message:
        # Проверяем настройку save_own_deleted
        if not bot_settings['save_own_deleted']:
            return
        else:
            pass 
    else:
        # Проверяем настройку save_foreign
        if not bot_settings.get('save_foreign', True):
            return
        else:
            pass 
    
    
    # Извлекаем медиа 
    media_info = await extract_media_info(bot, msg)
    if not bot_settings.get('send_media', True):
        pass
    
    data = {
        "chat_id": chat_id,
        "message_id": message_id,
        "from_id": from_user_id,
        "from_name": from_user.get('first_name', 'Неизвестно'),
        "from_username": from_user.get('username'),
        "date": msg.get('date'),
        "text": msg.get('text', ''),
        "caption": msg.get('caption', ''),
        "media": media_info,
        "versions": [],
        "chat_type": msg.get('chat', {}).get('type'),
        "business_connection_id": msg.get('business_connection_id'),
        "saved_at": datetime.now(timezone.utc).isoformat()
    }
    
    # Сохраняем в кеш
    message_cache[cache_key(chat_id, message_id)] = data

async def process_edited_business_message(bot: BusinessBot, msg: dict):
    """Обрабатывает отредактированное business сообщение"""
    chat_id = msg.get('chat', {}).get('id')
    message_id = msg.get('message_id')
    from_user = msg.get('from', {})
    from_user_id = from_user.get('id')
    
    # Проверяем, есть ли сообщение в кеше
    k = cache_key(chat_id, message_id)
    if k not in message_cache:
        return
    
    lang = bot_settings.get('language', 'RU')
    
    # Проверяем, требуется ли обработка
    is_own_message = str(from_user_id) == str(ADMIN_CHAT_ID)
    
    if is_own_message:
        # Проверяем настройку save_own_deleted
        if not bot_settings['save_own_deleted']:
            logger.info(f"{get_text('skip_own_edited', lang)}: user={from_user_id} (save_own_deleted={bot_settings['save_own_deleted']})")
            return
        else:
            pass
    else:
        # Проверяем настройку save_foreign
        if not bot_settings.get('save_foreign', True):
            logger.info(f"{get_text('skip_edited_foreign', lang)}: user={from_user_id} (save_foreign={bot_settings.get('save_foreign', True)})")
            return
        else:
            pass  
    
    # Увеличиваем счетчик отредактированных
    try:
        stats_counters["edited_count"] += 1
    except Exception:
        pass
    
    k = cache_key(chat_id, message_id)
    if k in message_cache:
        prev_obj = message_cache[k]
        
        # Сохраняем старую версию
        version = {
            "date": datetime.now(timezone.utc).isoformat(),
            "text": prev_obj.get('text'),
            "caption": prev_obj.get('caption'),
            "media": prev_obj.get('media', [])
        }
        prev_obj.setdefault('versions', []).append(version)
        
        # Обновляем текст
        new_text = msg.get('text', '') or msg.get('caption', '') or prev_obj.get('text', '')
        prev_obj['text'] = new_text
        prev_obj['caption'] = msg.get('caption', '')
        
        # Обновляем кеш
        message_cache[k] = prev_obj
        
        # Сначала скачиваем медиафайлы 
        downloaded_media = []
        new_downloaded_media = []
        
        # Скачиваем старые медиафайлы
        if prev_obj.get('media') and bot_settings.get('send_media', True):
            try:
                downloaded_media = await download_media_files(bot, prev_obj['media'], chat_id, message_id)
            except Exception as e:
                logger.error(f"Ошибка скачивания старых медиафайлов: {e}")
                downloaded_media = []
        
        # Скачиваем новые медиафайлы из отредактированного сообщения
        if bot_settings.get('send_media', True):
            try:
                new_media = await extract_media_info(bot, msg)
                if new_media:
                    new_downloaded_media = await download_media_files(bot, new_media, chat_id, message_id)
            except Exception as e:
                logger.error(f"Ошибка скачивания новых медиафайлов: {e}")
                new_downloaded_media = []
        elif prev_obj.get('media') and not bot_settings.get('send_media', True):
            media_info = prev_obj.get('media', [])
            is_own_message = str(prev_obj.get('from_id')) == str(ADMIN_CHAT_ID)
            current_time = datetime.now().strftime("%d.%m.%Y в %H:%M:%S")
            
            if media_info:
                # Определяем тип медиа
                media_type = media_info[0].get('type', 'unknown')
                lang = bot_settings.get('language', 'RU')
                media_type_name = get_media_type_name(media_type, lang)
                
                if is_own_message:
                    logger.info(f"{current_time} - {get_log_text('log_own_edited_media_found', media_type=media_type_name)}")
                else:
                    user_id = prev_obj.get('from_id')
                    logger.info(f"{current_time} - {get_log_text('log_edited_media_found', media_type=media_type_name, user_id=user_id)}")
        
        # Получаем текущий язык для локализации
        lang = bot_settings.get('language', 'RU')
        
        # Формируем текст "Было" и "Стало"
        was_text = version.get('text', '').strip()
        was_caption = version.get('caption', '').strip()
        became_text = new_text.strip()
        became_caption = msg.get('caption', '').strip()
        
        # Определяем что было раньше
        was_content = ""
        if was_text:
            was_content = f"<b>{get_text('was', lang)}:</b>\n<code>{was_text[:150]}{'...' if len(was_text) > 150 else ''}</code>"
        elif was_caption:
            was_content = f"<b>{get_text('was_caption', lang)}:</b>\n<code>{was_caption[:150]}{'...' if len(was_caption) > 150 else ''}</code>"
        elif version.get('media'):
            # Если было медиа, показываем тип медиа
            media_type = get_media_type_from_message(version, lang)
            was_content = f"<b>{get_text('was', lang)}:</b>\n📎 {media_type}"
        else:
            was_content = f"<b>{get_text('was', lang)}:</b>\n<code>{get_text('no_text', lang)}</code>"
        
        # Определяем что стало
        became_content = ""
        if became_text:
            became_content = f"<b>{get_text('became', lang)}:</b>\n<code>{became_text[:150]}{'...' if len(became_text) > 150 else ''}</code>"
        elif became_caption:
            became_content = f"<b>{get_text('became_caption', lang)}:</b>\n<code>{became_caption[:150]}{'...' if len(became_caption) > 150 else ''}</code>"
        elif msg.get('photo') or msg.get('video') or msg.get('audio') or msg.get('voice') or msg.get('video_note') or msg.get('sticker') or msg.get('document') or msg.get('animation'):
            # Если стало медиа, показываем тип медиа
            media_type = get_media_type_from_message(msg, lang)
            became_content = f"<b>{get_text('became', lang)}:</b>\n📎 {media_type}"
        else:
            became_content = f"<b>{get_text('became', lang)}:</b>\n<code>{get_text('no_text', lang)}</code>"
        
        # Проверяем, было ли редактирование медиафайлов
        was_media = version.get('media') and (was_text or was_caption or not was_text and not was_caption)
        became_media = msg.get('photo') or msg.get('video') or msg.get('audio') or msg.get('voice') or msg.get('video_note') or msg.get('sticker') or msg.get('document') or msg.get('animation')
        
        # Проверяем, добавилась ли подпись к медиафайлу
        was_caption_empty = not was_caption or was_caption.strip() == ""
        became_caption_not_empty = became_caption and became_caption.strip() != ""
        caption_added = was_caption_empty and became_caption_not_empty
        
        # Если редактировались медиафайлы, используем специальный формат
        if was_media and became_media:
            media_type = get_media_type_from_message(msg, lang)
            
            # Проверяем, заменился ли сам медиафайл
            if version.get('media') and msg.get('photo'):
                # Для фото сравниваем file_id
                old_file_id = version['media'][0].get('file_id', '')
                new_file_id = msg['photo'][-1].get('file_id', '')  # Последнее
                media_replaced = old_file_id != new_file_id
            elif version.get('media') and (msg.get('video') or msg.get('audio') or msg.get('voice') or msg.get('video_note') or msg.get('sticker') or msg.get('document') or msg.get('animation')):
                # Сравниваем file_id для других видов медиа
                old_file_id = version['media'][0].get('file_id', '')
                new_media_key = 'video' if msg.get('video') else 'audio' if msg.get('audio') else 'voice' if msg.get('voice') else 'video_note' if msg.get('video_note') else 'sticker' if msg.get('sticker') else 'document' if msg.get('document') else 'animation'
                new_file_id = msg[new_media_key].get('file_id', '')
                media_replaced = old_file_id != new_file_id
            
            # Определяем типы медиа до и после изменения
            old_media_type = get_media_type_from_message(version, lang)
            new_media_type = get_media_type_from_message(msg, lang)
            
            # Определяем правильные формы слов в единственном числе
            old_media_single = get_media_single_form(old_media_type, lang)
            new_media_single = get_media_single_form(new_media_type, lang)
            
            # Определяем правильную форму глагола "был/было" для русского языка
            if lang == 'RU':
                old_was_form = get_was_form(old_media_single)
                new_was_form = get_was_form(new_media_single)
            else:
                old_was_form = get_text('was', lang)
                new_was_form = get_text('was', lang)
            
            # Формируем сообщение в зависимости от типа изменения
            if media_replaced and caption_added:
                # Заменился медиафайл и подпись
                was_content = f"📷 📎 {get_text('media_files', lang)} ({new_media_type.lower()}) {get_text('replaced', lang)}. {old_was_form} {old_media_single} №1, {get_text('became', lang).lower()} {new_media_single} №2\n\n{get_text('caption_added', lang)}: {became_caption}"
            elif media_replaced:
                # Только медиафайл заменился
                was_content = f"📷 📎 {get_text('media_files', lang)} ({new_media_type.lower()}) {get_text('replaced', lang)}. {old_was_form} {old_media_single} №1, {get_text('became', lang).lower()} {new_media_single} №2"
            elif caption_added:
                # Используем текущий тип медиа для подписи
                current_media_single = get_media_single_form(new_media_type, lang)
                was_content = f"{get_text('caption_added_to_media', lang).replace('медиафайлу', current_media_single)}: {became_caption}"
            else:
                # Медиафайл не изменился, подпись не добавилась
                was_content = f"<b>{get_text('was', lang)}:</b>\n📎 {media_type}"
                became_content = f"<b>{get_text('became', lang)}:</b>\n📎 {media_type}"
            
            if media_replaced or caption_added:
                became_content = ""
        
        # Уведомляем администратора об редактировании
        notification_text = (
            f"<b>{get_text('message_edited', lang)}</b>\n\n"
            f"<b>{get_text('from_user', lang)}:</b> {prev_obj.get('from_name', get_text('unknown', lang))}\n"
            f"<b>{get_text('tag', lang)}:</b> {'@' + prev_obj['from_username'] if prev_obj.get('from_username') else get_text('no_tag', lang)}\n"
            f"<b>{get_text('chat', lang)}:</b> {chat_id}\n"
            f"<b>{get_text('id', lang)}:</b> {message_id}\n"
            f"<b>{get_text('time', lang)}:</b> {get_formatted_time(datetime.now(), lang)}\n\n"
            f"{was_content}\n\n"
            f"{became_content}"
        )
        
        try:
            # Проверяем настройку отправки медиа
            if not bot_settings['send_media']:
                
                # Если есть медиа, добавляем уведомление о нем
                if prev_obj.get('media'):
                    media_type = get_media_type_from_message(prev_obj, lang)
                    media_notification = get_text('media_disabled_notification', lang).format(media_type=media_type)
                    notification_text += f"\n\n{media_notification}"
                
                await bot.send_message(ADMIN_CHAT_ID, notification_text, parse_mode='HTML')
            else:
                # Проверяем, есть ли медиа, которые нужно отправлять отдельно
                media_to_send = []
                
                if was_media and became_media:
                    media_replaced = False
                    if version.get('media') and msg.get('photo'):
                        # Для фото сравниваем file_id
                        old_file_id = version['media'][0].get('file_id', '')
                        new_file_id = msg['photo'][-1].get('file_id', '')
                        media_replaced = old_file_id != new_file_id
                    elif version.get('media') and (msg.get('video') or msg.get('audio') or msg.get('voice') or msg.get('video_note') or msg.get('sticker') or msg.get('document') or msg.get('animation')):
                        # Сраниваем file_id для других видов медиа
                        old_file_id = version['media'][0].get('file_id', '')
                        new_media_key = 'video' if msg.get('video') else 'audio' if msg.get('audio') else 'voice' if msg.get('voice') else 'video_note' if msg.get('video_note') else 'sticker' if msg.get('sticker') else 'document' if msg.get('document') else 'animation'
                        new_file_id = msg[new_media_key].get('file_id', '')
                        media_replaced = old_file_id != new_file_id
                    
                    if media_replaced:
                        # Медиафайл заменился - отправляем обе версии
                        if downloaded_media:
                            for media in downloaded_media:
                                media_to_send.append(media)
                        if new_downloaded_media:
                            for media in new_downloaded_media:
                                media_to_send.append(media)
                    else:
                        # Редактирована только подпись к медиа
                        if new_downloaded_media:
                            for media in new_downloaded_media:
                                media_to_send.append(media)
                else:
                    # Обычная логика для других случаев
                    if downloaded_media:
                        for media in downloaded_media:
                            media_to_send.append(media)
                    if new_downloaded_media:
                        for media in new_downloaded_media:
                            media_to_send.append(media)
                
                if media_to_send:
                    # Отправляем текстовое уведомление вместе с медиафайлами
                    await send_media_notification(bot, media_to_send, notification_text)
                else:
                    # Отправляем только текстовое уведомление
                    await bot.send_message(ADMIN_CHAT_ID, notification_text, parse_mode='HTML')
        except Exception as e:
            logger.error(f"Ошибка отправки уведомления об редактировании: {e}")
            import traceback
            traceback.print_exc()
        
        # Сохраняем отредактированное сообщение в архив
        try:
            # Используем скачанные медиафайлы для сохранения
            if downloaded_media:
                prev_obj['media'] = downloaded_media
            elif new_downloaded_media:
                # Если нет старых медиафайлов, но есть новые, сохраняем новые
                prev_obj['media'] = new_downloaded_media
            
            # Добавляем информацию о том, что сообщение отредактировано
            prev_obj['edited_at'] = datetime.now().isoformat()
            prev_obj['edit_reason'] = 'edited'
            
            # Сохраняем в файл
            save_message_to_file(prev_obj)
            
            # Определяем тип сообщения и медиа для лога
            is_own_message = str(prev_obj.get('from_id')) == str(ADMIN_CHAT_ID)
            media_info = prev_obj.get('media', [])
            text_content = prev_obj.get('text', '') or prev_obj.get('caption', '')
            
            current_time = datetime.now().strftime("%d.%m.%Y в %H:%M:%S")
            
            # Логируем сохранение только если медиа включено
            if bot_settings.get('send_media', True):
                if is_own_message:
                    if media_info and not text_content.strip():
                        # Только медиа без текста
                        media_types = []
                        for media in media_info:
                            media_type = media.get('type', 'unknown')
                            media_types.append(get_media_type_name(media_type, lang))
                        
                        logger.info(f"{current_time} - {get_log_text('log_own_edited_media_saved', media_types=', '.join(media_types))}")
                    elif media_info and text_content.strip():
                        # Сообщение с текстом и медиа
                        media_types = []
                        for media in media_info:
                            media_type = media.get('type', 'unknown')
                            media_types.append(get_media_type_name(media_type, lang))
                        
                        media_text = f"{get_media_connector(lang)} ({', '.join(media_types)})"
                        logger.info(f"{current_time} - {get_log_text('log_own_edited_message_saved', media_text=media_text)}")
                    else:
                        # Только текст без медиа
                        logger.info(f"{current_time} - {get_log_text('log_own_edited_message_saved_text_only')}")
                else:
                    user_id = prev_obj.get('from_id')
                    if media_info and not text_content.strip():
                        # Только медиа без текста
                        media_types = []
                        for media in media_info:
                            media_type = media.get('type', 'unknown')
                            media_types.append(get_media_type_name(media_type, lang))
                        
                        logger.info(f"{current_time} - {get_log_text('log_edited_media_saved_foreign', user_id=user_id, media_types=', '.join(media_types))}")
                    elif media_info and text_content.strip():
                        # Сообщение с текстом и медиа
                        media_types = []
                        for media in media_info:
                            media_type = media.get('type', 'unknown')
                            media_types.append(get_media_type_name(media_type, lang))
                        
                        media_text = f"{get_media_connector(lang)} ({', '.join(media_types)})"
                        logger.info(f"{current_time} - {get_log_text('log_edited_message_saved_foreign', user_id=user_id, media_text=media_text)}")
                    else:
                        # Только текст без медиа
                        logger.info(f"{current_time} - {get_log_text('log_edited_message_saved_foreign_text_only', user_id=user_id)}")
            
        except Exception as e:
            logger.error(f"Ошибка сохранения отредактированного сообщения в архив: {e}")
    else:
        lang = bot_settings.get('language', 'RU')
        logger.warning(f"{get_text('message_not_found', lang)}: {message_id}")

async def process_deleted_business_messages(bot: BusinessBot, deleted: dict):
    """Обрабатывает удаленные business сообщения"""
    chat_id = deleted.get('chat', {}).get('id')
    message_ids = deleted.get('message_ids', [])
    
    # Проверяем, есть ли в кеше сообщения из этого чата 
    has_messages = False
    for msg_id in message_ids:
        k = cache_key(chat_id, msg_id)
        if k in message_cache:
            has_messages = True
            break
    
    if not has_messages:
        logger.info(get_log_text('log_skip_chat_no_messages', chat_id=chat_id))
        return
    
    lang = bot_settings.get('language', 'RU')
    
    # Уведомляем администратора о каждом удаленном сообщении
    for msg_id in message_ids:
        try:
            stats_counters["deleted_count"] += 1
        except Exception:
            pass
        
        # Глобальное дублирование по message_id
        if msg_id in processed_messages:
            logger.info(get_log_text('log_skip_message_processed', msg_id=msg_id))
            continue
        
        # Помечаем как обработанное глобально
        processed_messages.add(msg_id)
        
        k = cache_key(chat_id, msg_id)
        if k in message_cache:
            msg_data = message_cache[k]
            
            # Проверяем, нужно ли обрабатывать это удаленное сообщение
            is_own_message = str(msg_data.get('from_id')) == str(ADMIN_CHAT_ID)
            
            if is_own_message:
                # Проверяем настройку save_own_deleted
                if not bot_settings['save_own_deleted']:
                    logger.info(f"{get_text('skip_own_deleted', lang)}: user={msg_data.get('from_id')} (save_own_deleted={bot_settings['save_own_deleted']})")
                    continue
                else:
                    pass  
            else:
                # Для чужих сообщений проверяем настройку save_foreign
                if not bot_settings.get('save_foreign', True):
                    logger.info(f"{get_text('skip_deleted_foreign', lang)}: user={msg_data.get('from_id')} (save_foreign={bot_settings.get('save_foreign', True)})")
                    continue
                else:
                    pass  
            
            # Получаем текущий язык для локализации
            lang = bot_settings.get('language', 'RU')
            
            # Сначала скачиваем медиафайлы
            downloaded_media = []
            if msg_data.get('media') and bot_settings.get('send_media', True):
                try:
                    downloaded_media = await download_media_files(bot, msg_data['media'], chat_id, msg_id)
                except Exception as e:
                    logger.error(f"Ошибка скачивания медиафайлов: {e}")
                    downloaded_media = []
            elif msg_data.get('media') and not bot_settings.get('send_media', True):
                # Определяем тип медиа и владельца для специального лога
                media_info = msg_data.get('media', [])
                is_own_message = str(msg_data.get('from_id')) == str(ADMIN_CHAT_ID)
                current_time = datetime.now().strftime("%d.%m.%Y в %H:%M:%S")
                
                if media_info:
                    # Определяем тип медиа
                    media_type = media_info[0].get('type', 'unknown')
                    lang = bot_settings.get('language', 'RU')
                    media_type_name = get_media_type_name(media_type, lang)
                    
                    if is_own_message:
                        logger.info(f"{current_time} - {get_log_text('log_own_deleted_media_found', media_type=media_type_name)}")
                    else:
                        user_id = msg_data.get('from_id')
                        logger.info(f"{current_time} - {get_log_text('log_deleted_media_found', media_type=media_type_name, user_id=user_id)}")
            
            # Формируем информацию о медиа
            media_info = ""
            if msg_data.get('media') and bot_settings.get('send_media', True):
                media_types = [m['type'] for m in msg_data['media']]
                if len(media_types) == 1:
                    media_type = media_types[0]
                    if media_type == 'photo':
                        media_info = f"\n\n<b>📷 {get_text('deleted_media_photo', lang)}:</b>"
                    elif media_type == 'video':
                        media_info = f"\n\n<b>🎥 {get_text('deleted_media_video', lang)}:</b>"
                    elif media_type == 'audio':
                        media_info = f"\n\n<b>🎵 {get_text('deleted_media_audio', lang)}:</b>"
                    elif media_type == 'document':
                        media_info = f"\n\n<b>📄 {get_text('deleted_media_document', lang)}:</b>"
                    elif media_type == 'sticker':
                        # Для стикеров добавляем информацию прямо в текст
                        sticker_size = msg_data['media'][0].get('file_size', 0)
                        sticker_size_mb = sticker_size / (1024 * 1024)
                        media_info = f"\n\n<b>{get_text('deleted_sticker', lang)}</b> ({sticker_size_mb:.2f} {get_text('mb', lang)})"
                    elif media_type == 'voice':
                        # Для голосовых добавляем информацию прямо в текст
                        voice_size = msg_data['media'][0].get('file_size', 0)
                        voice_size_mb = voice_size / (1024 * 1024)
                        media_info = f"\n\n<b>{get_text('deleted_voice', lang)}</b> ({voice_size_mb:.2f} {get_text('mb', lang)})"
                    elif media_type == 'video_note':
                        # Для видео-нот добавляем информацию прямо в текст
                        video_note_size = msg_data['media'][0].get('file_size', 0)
                        video_note_size_mb = video_note_size / (1024 * 1024)
                        media_info = f"\n\n<b>{get_text('deleted_video_note', lang)}</b> ({video_note_size_mb:.2f} {get_text('mb', lang)})"
                    elif media_type == 'gif':
                        # Для GIF добавляем информацию прямо в текст
                        gif_size = msg_data['media'][0].get('file_size', 0)
                        gif_size_mb = gif_size / (1024 * 1024)
                        media_info = f"\n\n<b>{get_text('deleted_gif', lang)}</b> ({gif_size_mb:.2f} {get_text('mb', lang)})"
                else:
                    # Убираем дубликаты и приоритизируем более специфичные типы
                    unique_types = []
                    for media_type in media_types:
                        if media_type not in unique_types:
                            unique_types.append(media_type)
                    
                    # Если есть и "document" и "gif", оставляем только "gif"
                    if 'gif' in unique_types and 'document' in unique_types:
                        unique_types.remove('document')
                    
                    media_info = f"\n\n<b>📎 {get_text('deleted_media', lang)}:</b> {', '.join(unique_types)}"
            
            # Формируем текст уведомления
            text_content = ""
            # Проверяем текст и подпись к медиа
            text = msg_data.get('text', '').strip()
            caption = msg_data.get('caption', '').strip()
            
            if text:
                text_content = f"\n\n<b>{get_text('deleted_text', lang)}:</b>\n<code>{text[:200]}{'...' if len(text) > 200 else ''}</code>"
            elif caption:
                text_content = f"\n\n<b>{get_text('deleted_caption', lang)}:</b>\n<code>{caption[:200]}{'...' if len(caption) > 200 else ''}</code>"
            
            notification_text = (
                f"<b>{get_text('message_deleted', lang)}</b>\n\n"
                f"<b>{get_text('from_user', lang)}:</b> {msg_data.get('from_name', get_text('unknown', lang))}\n"
                f"<b>{get_text('tag', lang)}:</b> {'@' + msg_data['from_username'] if msg_data.get('from_username') else get_text('no_tag', lang)}\n"
                f"<b>{get_text('chat', lang)}:</b> {chat_id}\n"
                f"<b>{get_text('id', lang)}:</b> {msg_id}\n"
                f"<b>{get_text('deletion_time', lang)}:</b> {get_formatted_time(datetime.now(), lang)}\n"
                f"<b>{get_text('send_time', lang)}:</b> {get_formatted_time(datetime.fromtimestamp(msg_data.get('date', 0)), lang)}{text_content}{media_info}"
            )
            
            try:
                # Проверяем настройку отправки медиа
                if not bot_settings['send_media']:
                    
                    # Если есть медиа, добавляем уведомление о нем
                    if msg_data.get('media'):
                        media_type = get_media_type_from_message(msg_data, lang)
                        media_notification = get_text('media_disabled_notification', lang).format(media_type=media_type)
                        notification_text += f"\n\n{media_notification}"
                    
                    await bot.send_message(ADMIN_CHAT_ID, notification_text, parse_mode='HTML')
                else:
                    # Проверяем, есть ли медиа для отправки отдельно
                    media_to_send = []
                    if downloaded_media:
                        for media in downloaded_media:
                            # Добавляем все типы медиа для отправки
                            media_to_send.append(media)
                    else:
                        pass
                    
                    if media_to_send:
                        # Отправляем текстовое уведомление вместе с медиафайлами
                        await send_media_notification(bot, media_to_send, notification_text)
                    else:
                        await bot.send_message(ADMIN_CHAT_ID, notification_text, parse_mode='HTML')
            except Exception as e:
                logger.error(f"Ошибка отправки уведомления об удалении: {e}")
                import traceback
                traceback.print_exc()
            
            # Сохраняем удаленное сообщение в архив
            try:
                # Используем скачанные медиафайлы для сохранения
                if downloaded_media:
                    msg_data['media'] = downloaded_media
                
                # Добавляем информацию о том, что сообщение удалено
                msg_data['deleted_at'] = datetime.now().isoformat()
                msg_data['deletion_reason'] = 'deleted'
                
                # Сохраняем в файл
                save_message_to_file(msg_data)
                
                # Определяем тип сообщения и медиа для лога
                is_own_message = str(msg_data.get('from_id')) == str(ADMIN_CHAT_ID)
                media_info = msg_data.get('media', [])
                text_content = msg_data.get('text', '') or msg_data.get('caption', '')
                
                # Логируем сохранение только если медиа включено
                if bot_settings.get('send_media', True):
                    if is_own_message:
                        if media_info and not text_content.strip():
                            # Только медиа без текста
                            media_types = []
                            for media in media_info:
                                media_type = media.get('type', 'unknown')
                                media_types.append(get_media_type_name(media_type, lang))
                            
                            current_time = datetime.now().strftime("%d.%m.%Y в %H:%M:%S")
                            logger.info(f"{current_time} - {get_log_text('log_own_deleted_media_saved', media_types=', '.join(media_types))}")
                        elif media_info and text_content.strip():
                            # Сообщение с текстом и медиа
                            media_types = []
                            for media in media_info:
                                media_type = media.get('type', 'unknown')
                                media_types.append(get_media_type_name(media_type, lang))
                            
                            media_text = f"{get_media_connector(lang)} ({', '.join(media_types)})"
                            current_time = datetime.now().strftime("%d.%m.%Y в %H:%M:%S")
                            logger.info(f"{current_time} - {get_log_text('log_own_deleted_message_saved', media_text=media_text)}")
                        else:
                            # Только текст без медиа
                            current_time = datetime.now().strftime("%d.%m.%Y в %H:%M:%S")
                            logger.info(f"{current_time} - {get_log_text('log_own_deleted_message_saved_text_only')}")
                    else:
                        user_id = msg_data.get('from_id')
                        if media_info and not text_content.strip():
                            # Только медиа без текста
                            media_types = []
                            for media in media_info:
                                media_type = media.get('type', 'unknown')
                                media_types.append(get_media_type_name(media_type, lang))
                            
                            current_time = datetime.now().strftime("%d.%m.%Y в %H:%M:%S")
                            logger.info(f"{current_time} - {get_log_text('log_deleted_media_saved_foreign', user_id=user_id, media_types=', '.join(media_types))}")
                        elif media_info and text_content.strip():
                            # Сообщение с текстом и медиа
                            media_types = []
                            for media in media_info:
                                media_type = media.get('type', 'unknown')
                                media_types.append(get_media_type_name(media_type, lang))
                            
                            media_text = f"{get_media_connector(lang)} ({', '.join(media_types)})"
                            current_time = datetime.now().strftime("%d.%m.%Y в %H:%M:%S")
                            logger.info(f"{current_time} - {get_log_text('log_deleted_message_saved_foreign', user_id=user_id, media_text=media_text)}")
                        else:
                            # Только текст без медиа
                            current_time = datetime.now().strftime("%d.%m.%Y в %H:%M:%S")
                            logger.info(f"{current_time} - {get_log_text('log_deleted_message_saved_foreign_text_only', user_id=user_id)}")
                
                # Проверяем размер диска и отправляем предупреждение, если нужно
                await send_disk_warning_if_needed(bot)
            except Exception as e:
                logger.error(f"Ошибка сохранения удаленного сообщения в архив: {e}")
        else:
            pass

async def process_update(bot: BusinessBot, update: dict):
    """Обрабатывает одно обновление"""
    update_types = list(update.keys())
    # Убираем логирование получения обновления
    
    # КРИТИЧЕСКАЯ ПРОВЕРКА: бот работает только у админа
    # Проверяем, есть ли в обновлении информация о пользователе
    user_id = None
    if 'message' in update:
        user_id = update['message'].get('from', {}).get('id')
    elif 'callback_query' in update:
        user_id = update['callback_query'].get('from', {}).get('id')
    elif 'business_message' in update:
        user_id = update['business_message'].get('from', {}).get('id')
    elif 'edited_business_message' in update:
        user_id = update['edited_business_message'].get('from', {}).get('id')
    
    # Приватность 
    if 'message' in update and update['message'].get('text', '').startswith('/'):
        if user_id != ADMIN_CHAT_ID:
            logger.info(get_log_text('log_skip_unauthorized', user_id=user_id, admin_id=ADMIN_CHAT_ID))
            return
    
    # Обрабатываем обычные сообщения 
    if 'message' in update:
        await process_message(bot, update['message'])
    
    # Обрабатываем нажатия на кнопки
    if 'callback_query' in update:
        await bot.handle_callback_query(update['callback_query'])
    
    if 'business_message' in update:
        await process_business_message(bot, update['business_message'])
    
    if 'edited_business_message' in update:
        await process_edited_business_message(bot, update['edited_business_message'])
    
    if 'deleted_business_messages' in update:
        await process_deleted_business_messages(bot, update['deleted_business_messages'])

async def main():
    """Главная функция"""
    if not BOT_TOKEN or ADMIN_CHAT_ID == 0:
        print("❌ Установите BOT_TOKEN и ADMIN_CHAT_ID в business_bot.env")
        return

    print(get_log_text('log_ghostkeeper_starting'))
    print(get_log_text('log_token', token=BOT_TOKEN[:20]))
    print(get_log_text('log_admin', admin_id=ADMIN_CHAT_ID))
    print(get_log_text('log_archive_dir', dir=ARCHIVE_DIR))
    print(get_log_text('log_files_dir', dir=FILES_DIR))
    print("-" * 50)

    async with BusinessBot(BOT_TOKEN) as bot:
        # Получаем информацию о боте
        me = await bot.get_me()
        if me.get('ok'):
            bot_info = me['result']
            print(get_log_text('log_bot_info', username=bot_info['username'], first_name=bot_info['first_name']))
        else:
            print(f"❌ Ошибка получения информации о боте: {me}")
            return

        # Устанавливаем меню команд с локализованными подсказками
        await bot.set_commands_menu()

        # Отправляем приветственное сообщение при запуске
        try:
            await bot.show_active_status(ADMIN_CHAT_ID)
        except Exception as e:
            print(f"❌ Ошибка отправки приветственного сообщения: {e}")

        print(get_log_text('log_bot_configured'))
        print(get_log_text('log_encryption_enabled'))
        print()
        print(get_log_text('log_foreign_saving'))
        print(get_log_text('log_own_saving'))
        print(get_log_text('log_media_sending'))
        print(get_log_text('log_encryption_status'))
        print(get_log_text('log_compression_status'))
        print(get_log_text('log_file_compression_status'))
        print()
        print(get_log_text('log_encryption_warning'))
        print("-" * 50)
        print(get_log_text('log_stop_instruction'))
        
        offset = 0
        
        # Запускаем фоновую задачу автоочистки
        cleanup_task = asyncio.create_task(bot.auto_cleanup_task())
        
        try:
            while True:
                # Получаем обновления
                updates_response = await bot.get_updates(offset=offset if offset > 0 else None)
                
                if updates_response.get('ok'):
                    updates = updates_response['result']
                    
                    for update in updates:
                        # Обновляем offset
                        offset = update['update_id'] + 1
                        
                        # Обрабатываем обновление
                        await process_update(bot, update)
                else:
                    # Проверяем, является ли это ошибкой конфликта сессий
                    if updates_response.get('error_code') == 409:
                        logger.error(get_log_text('log_session_conflict'))
                    else:
                        logger.error(f"Ошибка получения обновлений: {updates_response}")
                
                # Небольшая пауза
                await asyncio.sleep(1)
                
        except KeyboardInterrupt:
            print(f"\n{get_log_text('log_bot_stopping')}")
            
            # Отправляем финальную статистику
            file_ext = get_file_extension()
            archive_files = len(list(ARCHIVE_DIR.glob(f'*{file_ext}')))
            
            # Подсчитываем файлы по типам
            photos_count = len(list(PHOTOS_DIR.glob('*')))
            videos_count = len(list(VIDEOS_DIR.glob('*')))
            audio_count = len(list(AUDIO_DIR.glob('*')))
            documents_count = len(list(DOCUMENTS_DIR.glob('*')))
            voice_count = len(list(VOICE_DIR.glob('*')))
            video_notes_count = len(list(VIDEO_NOTES_DIR.glob('*')))
            stickers_count = len(list(STICKERS_DIR.glob('*')))
            gifs_count = len(list(GIFS_DIR.glob('*')))
            total_media = photos_count + videos_count + audio_count + documents_count + voice_count + video_notes_count + stickers_count + gifs_count
            
            stats_text = (
                f"📊 <b>Статистика работы</b>\n\n"
                f"💬 <b>Сообщений сохранено:</b> {len(message_cache)}\n"
                f"📁 <b>Файлов в архиве:</b> {archive_files}\n"
                f"🔐 <b>Шифрование:</b> {'ВКЛ' if ENCRYPTION_ENABLED else 'ВЫКЛ'}\n"
                f"📦 <b>Сжатие:</b> {'ВКЛ' if COMPRESSION_ENABLED else 'ВЫКЛ'} ({COMPRESSION_ALGORITHM.upper()})\n\n"
                f"📷 <b>Медиафайлы по типам:</b>\n"
                f"  📸 Фото: {photos_count}\n"
                f"  🎥 Видео: {videos_count}\n"
                f"  🎵 Аудио: {audio_count}\n"
                f"  📄 Документы: {documents_count}\n"
                f"  🎤 Голосовые: {voice_count}\n"
                f"  🎥 Видео-ноты: {video_notes_count}\n"
                f"  🎯 Стикеры: {stickers_count}\n"
                f"  🎬 GIF: {gifs_count}\n"
                f"  📊 <b>Всего медиа:</b> {total_media}\n\n"
                f"📅 <b>Время работы:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            )
            
            try:
                await bot.send_message(ADMIN_CHAT_ID, stats_text, parse_mode='HTML')
            except Exception as e:
                logger.error(f"Ошибка отправки статистики: {e}")
                
        except Exception as e:
            logger.error(f"Критическая ошибка: {e}")
            import traceback
            traceback.print_exc()
        finally:
            # Отменяем фоновую задачу автоочистки
            cleanup_task.cancel()
            try:
                await cleanup_task
            except asyncio.CancelledError:
                pass

async def run_bot_with_restart():
    """Запускает бота с автоматическим перезапуском"""
    restart_count = 0
    max_restarts = 10  # Максимальное количество перезапусков подряд
    
    while True:
        try:
            print(f"\n{get_log_text('log_bot_starting', attempt=restart_count + 1)}")
            await main()
            
        except KeyboardInterrupt:
            print(f"\n{get_log_text('log_bot_stopped_by_user')}")
            break
            
        except Exception as e:
            restart_count += 1
            print(f"\n💥 Бот упал с ошибкой: {e}")
            print(f"🔄 Перезапуск через 5 секунд... (попытка #{restart_count})")
            
            if restart_count >= max_restarts:
                print(f"\n❌ Достигнуто максимальное количество перезапусков ({max_restarts})")
                print("🛑 Бот остановлен. Проверьте логи и исправьте ошибки.")
                break
            
            # Ждем 5 секунд перед перезапуском
            await asyncio.sleep(5)
            
            # Сбрасываем счетчик перезапусков каждые 10 минут
            if restart_count % 10 == 0:
                print("🔄 Сброс счетчика перезапусков...")
                restart_count = 0

if __name__ == '__main__':
    try:
        asyncio.run(run_bot_with_restart())
    except KeyboardInterrupt:
        print(f"\n{get_log_text('log_bot_stopped_by_user')}")
    except Exception as e:
        print(f"\n❌ Критическая ошибка: {e}")
