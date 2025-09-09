# GhostKeeper Bot - Инструкция по запуску

## Описание
GhostKeeper - это Telegram бот для сохранения удаленных и отредактированных сообщений с шифрованием и сжатием данных.

## Системные требования
- Windows 10/11
- Python 3.8 или выше

## Быстрый запуск (рекомендуется)

### 1. Скачайте и распакуйте архив
- Распакуйте все файлы в любую папку (например, `C:\GhostKeeper\`)

### 2. Запустите бота
- **Дважды кликните на файл `run_ghostkeeper.bat`**
- Скрипт автоматически:
  - Проверит наличие Python
  - Установит необходимые библиотеки
  - Запустит бота

## Ручная настройка

### 1. Установка Python
1. Скачайте Python с [python.org](https://www.python.org/downloads/)
2. При установке **обязательно** поставьте галочку "Add Python to PATH"
3. Проверьте установку: откройте командную строку и введите `python --version`

### 2. Настройка конфигурации
1. Откройте файл `config.env` в любом текстовом редакторе
2. Заполните обязательные параметры:

# Токен бота от @BotFather (как получить описано ниже)
BOT_TOKEN=ваш_токен_бота

# Ваш Telegram ID (узнать можно через @userinfobot)
ADMIN_CHAT_ID=ваш_telegram_id

# Остальные настройки можно оставить по умолчанию
ARCHIVE_DIR=./archive
FILES_DIR=./files
ENCRYPTION_KEY=ghostkeeper-super-secret-key-by-new-meta-studio

### 3. Установка зависимостей
Откройте командную строку в папке с ботом и выполните:
pip install -r requirements.txt

### 4. Запуск бота
python ghostkeeper.py

## Получение токена бота

1. Найдите [@BotFather](https://t.me/BotFather) в Telegram
2. Отправьте команду `/newbot`
3. Введите имя бота (например: "My GhostKeeper")
4. Введите username бота (например: "my_ghostkeeper_bot") - обязательно должно заканчиваться на "bot".
5. Скопируйте полученный токен в формате: 1234567890:ABCdefGHIjklMNOpqrsTUVwxyz

### 2. Настройка бизнес-бота
1. Отправьте `/mybots` боту @BotFather
2. Выберите вашего созданного бота
3. Нажмите "Bot Settings"
4. Нажмите "Business Mode"
5. Нажмите "Turn on"
6. Теперь ваш бот будет работать как бизнес-бот

### 3. Настройка бота в профиле
1. Откройте настройки Telegram
2. Перейдите в "Telegram Business"
3. Выберите "Chatbots"
4. Выберите созданного бота
5. Оставьте включенной галочку "Manage Messages"
6. Готово! Бот настроен в вашем профиле

## Получение своего Telegram ID

### Получение ID через @userinfobot
1. Найдите [@userinfobot](https://t.me/userinfobot) в Telegram
2. Отправьте "/start"
3. Скопируйте ваш ID из ответа


## Структура файлов

GhostKeeper/
├── ghostkeeper.py          # Основной файл бота
├── config.env              # Конфигурация
├── requirements.txt        # Зависимости 
├── run_ghostkeeper.bat     # Скрипт автозапуска
├── GK.ico                  # Иконка приложения
├── bot_settings.json       # Настройки бота (создается автоматически)
├── archive/                # Папка для архива сообщений
├── files/                  # Папка для медиафайлов
└── README.md               # Эта инструкция

## Команды бота

- `/start` - Показать статус бота
- `/settings` - Настройки бота
- `/stats` - Статистика сохраненных сообщений

## Настройки бота

### Основные настройки
- **Сохранение своих сообщений** - сохранять ли ваши удаленные/отредактированные сообщения
- **Сохранение чужих сообщений** - сохранять ли удаленные/отредактированные сообщения от ругих пользователей
- **Отправка медиа** - отправлять ли медиафайлы при уведомлениях
- **Язык интерфейса** - русский, английский, китайский

### Автоочистка
- **Период очистки** - через какой промежуток времени удалять старые сообщения
- **Уведомления** - получать ли уведомления об очистке

## Решение проблем

### Бот не запускается
1. Проверьте, что Python установлен: `python --version`
2. Проверьте файл `config.env` - все ли поля заполнены
3. Проверьте токен бота - правильный ли он
4. Проверьте Telegram ID - числовой ли он

### Ошибка "Module not found"
1. Установите зависимости: `pip install -r requirements.txt`
2. Или запустите `run_ghostkeeper.bat`

### Бот не отвечает
1. Проверьте, что бот запущен
2. Проверьте, что вы отправили команду боту в личные сообщения
3. Проверьте, что в `config.env` указан правильный `ADMIN_CHAT_ID`

### Ошибка доступа к файлам
1. Запустите командную строку от имени администратора
2. Или переместите папку с ботом в другое место

### При возникновении других проблем:
1. Проверьте логи в консоли
2. Убедитесь, что все файлы на месте
3. Проверьте настройки в `config.env`

## Техническая информация

- **Разработка**: [NewMeta Studio](https://t.me/new_metas)
- **Версия**: 1.0
- **Языки**: Python 3.8+
- **Шифрование**: AES-256-GCM
- **Сжатие**: Brotli
- **Формат данных**: JSON + Base64

---

**Условия использования**: https://clck.ru/3P5hmE

---

# GhostKeeper Bot - Setup Instructions

## Description
GhostKeeper is a Telegram bot for saving deleted and edited messages with encryption and data compression.

## System Requirements
- Windows 10/11
- Python 3.8 or higher

## Quick Start (Recommended)

### 1. Download and extract archive
- Extract all files to any folder (e.g., `C:\GhostKeeper\`)

### 2. Run the bot
- **Double-click on `run_ghostkeeper.bat` file**
- The script will automatically:
  - Check for Python installation
  - Install required libraries
  - Start the bot

## Manual Setup

### 1. Install Python
1. Download Python from [python.org](https://www.python.org/downloads/)
2. During installation, **make sure** to check "Add Python to PATH"
3. Verify installation: open command prompt and type `python --version`

### 2. Configure settings
1. Open `config.env` file in any text editor
2. Fill in required parameters:

# Bot token from @BotFather (how to get described below)
BOT_TOKEN=your_bot_token

# Your Telegram ID (get via @userinfobot)
ADMIN_CHAT_ID=your_telegram_id

# Other settings can be left as default
ARCHIVE_DIR=./archive
FILES_DIR=./files
ENCRYPTION_KEY=ghostkeeper-super-secret-key-by-new-meta-studio

### 3. Install dependencies
Open command prompt in bot folder and run:
pip install -r requirements.txt

### 4. Start the bot
python ghostkeeper.py

## Getting Bot Token

1. Find [@BotFather](https://t.me/BotFather) in Telegram
2. Send command `/newbot`
3. Enter bot name (e.g., "My GhostKeeper")
4. Enter bot username (e.g., "my_ghostkeeper_bot") - must end with "bot".
5. Copy the received token in format: 1234567890:ABCdefGHIjklMNOpqrsTUVwxyz

### 2. Configure business bot
1. Send `/mybots` to @BotFather
2. Select your created bot
3. Click "Bot Settings"
4. Click "Business Mode"
5. Click "Turn on"
6. Now your bot will work as a business bot

### 3. Configure bot in profile
1. Open Telegram settings
2. Go to "Telegram Business"
3. Select "Chatbots"
4. Select your created bot
5. Keep the "Manage Messages" checkbox enabled
6. Done! Bot is configured in your profile

## Getting Your Telegram ID

### Getting ID via @userinfobot
1. Find [@userinfobot](https://t.me/userinfobot) in Telegram
2. Send "/start"
3. Copy your ID from the response

## File Structure

GhostKeeper/
├── ghostkeeper.py          # Main bot file
├── config.env              # Configuration
├── requirements.txt        # Dependencies
├── run_ghostkeeper.bat     # Auto-start script
├── GK.ico                  # App icon
├── bot_settings.json       # Bot settings (created automatically)
├── archive/                # Message archive folder
├── files/                  # Media files folder
└── README.md               # This instruction

## Bot Commands

- `/start` - Show bot status
- `/settings` - Bot settings
- `/stats` - Statistics of saved messages

## Bot Settings

### Main Settings
- **Save own messages** - whether to save your deleted/edited messages
- **Save others' messages** - whether to save deleted/edited messages from other users
- **Send media** - whether to send media files in notifications
- **Interface language** - Russian, English, Chinese

### Auto Cleanup
- **Cleanup period** - after what time interval to delete old messages
- **Notifications** - whether to receive cleanup notifications

## Troubleshooting

### Bot won't start
1. Check if Python is installed: `python --version`
2. Check `config.env` file - are all fields filled
3. Check bot token - is it correct
4. Check Telegram ID - is it numeric

### "Module not found" error
1. Install dependencies: `pip install -r requirements.txt`
2. Or run `run_ghostkeeper.bat`

### Bot not responding
1. Check if bot is running
2. Check if you sent command to bot in private messages
3. Check if correct `ADMIN_CHAT_ID` is specified in `config.env`

### File access error
1. Run command prompt as administrator
2. Or move bot folder to another location

### For other problems:
1. Check console logs
2. Make sure all files are in place
3. Check settings in `config.env`

## Technical Information

- **Development**: [NewMeta Studio](https://t.me/new_metas)
- **Version**: 1.0
- **Languages**: Python 3.8+
- **Encryption**: AES-256-GCM
- **Compression**: Brotli
- **Data Format**: JSON + Base64

---

**Terms of Use**: https://clck.ru/3P5hmE

---

# GhostKeeper Bot - 启动说明

## 描述
GhostKeeper 是一个用于保存已删除和已编辑消息的 Telegram 机器人，具有加密和数据压缩功能。

## 系统要求
- Windows 10/11
- Python 3.8 或更高版本

## 快速启动（推荐）

### 1. 下载并解压存档
- 将所有文件解压到任意文件夹（例如 `C:\GhostKeeper\`）

### 2. 启动机器人
- **双击 `run_ghostkeeper.bat` 文件**
- 脚本将自动：
  - 检查 Python 安装
  - 安装必要的库
  - 启动机器人

## 手动设置

### 1. 安装 Python
1. 从 [python.org](https://www.python.org/downloads/) 下载 Python
2. 安装时**务必**勾选"Add Python to PATH"
3. 验证安装：打开命令提示符并输入 `python --version`

### 2. 配置设置
1. 用任意文本编辑器打开 `config.env` 文件
2. 填写必需参数：

# 来自 @BotFather 的机器人令牌（如何获取见下文）
BOT_TOKEN=你的机器人令牌

# 你的 Telegram ID（通过 @userinfobot 获取）
ADMIN_CHAT_ID=你的telegram_id

# 其他设置可以保持默认
ARCHIVE_DIR=./archive
FILES_DIR=./files
ENCRYPTION_KEY=ghostkeeper-super-secret-key-by-new-meta-studio

### 3. 安装依赖
在机器人文件夹中打开命令提示符并运行：
pip install -r requirements.txt

### 4. 启动机器人
python ghostkeeper.py

## 获取机器人令牌

1. 在 Telegram 中找到 [@BotFather](https://t.me/BotFather)
2. 发送命令 `/newbot`
3. 输入机器人名称（例如："My GhostKeeper"）
4. 输入机器人用户名（例如："my_ghostkeeper_bot"）- 必须以"bot"结尾。
5. 复制获得的令牌，格式为：1234567890:ABCdefGHIjklMNOpqrsTUVwxyz

### 2. 配置商业机器人
1. 向 @BotFather 发送 `/mybots`
2. 选择你创建的机器人
3. 点击 "Bot Settings"
4. 点击 "Business Mode"
5. 点击 "Turn on"
6. 现在你的机器人将作为商业机器人工作

### 3. 在个人资料中配置机器人
1. 打开 Telegram 设置
2. 转到 "Telegram Business"
3. 选择 "Chatbots"
4. 选择你创建的机器人
5. 保持 "Manage Messages" 复选框启用
6. 完成！机器人已在你的个人资料中配置

## 获取你的 Telegram ID

### 通过 @userinfobot 获取 ID
1. 在 Telegram 中找到 [@userinfobot](https://t.me/userinfobot)
2. 发送"/start"
3. 从回复中复制你的 ID

## 文件结构

GhostKeeper/
├── ghostkeeper.py          # 主机器人文件
├── config.env              # 配置文件
├── requirements.txt        # 依赖项
├── run_ghostkeeper.bat     # 自动启动脚本
├── GK.ico                  # 应用图标
├── bot_settings.json       # 机器人设置（自动创建）
├── archive/                # 消息存档文件夹
├── files/                  # 媒体文件文件夹
└── README.md               # 本说明

## 机器人命令

- `/start` - 显示机器人状态
- `/settings` - 机器人设置
- `/stats` - 已保存消息统计

## 机器人设置

### 主要设置
- **保存自己的消息** - 是否保存你删除/编辑的消息
- **保存他人的消息** - 是否保存其他用户删除/编辑的消息
- **发送媒体** - 是否在通知中发送媒体文件
- **界面语言** - 俄语、英语、中文

### 自动清理
- **清理周期** - 经过多长时间间隔删除旧消息
- **通知** - 是否接收清理通知

## 故障排除

### 机器人无法启动
1. 检查 Python 是否已安装：`python --version`
2. 检查 `config.env` 文件 - 是否所有字段都已填写
3. 检查机器人令牌 - 是否正确
4. 检查 Telegram ID - 是否为数字

### "Module not found" 错误
1. 安装依赖：`pip install -r requirements.txt`
2. 或运行 `run_ghostkeeper.bat`

### 机器人无响应
1. 检查机器人是否正在运行
2. 检查你是否向机器人发送了私聊命令
3. 检查 `config.env` 中是否指定了正确的 `ADMIN_CHAT_ID`

### 文件访问错误
1. 以管理员身份运行命令提示符
2. 或将机器人文件夹移动到其他位置

### 其他问题：
1. 检查控制台日志
2. 确保所有文件都在正确位置
3. 检查 `config.env` 中的设置

## 技术信息

- **开发**：[NewMeta Studio](https://t.me/new_metas)
- **版本**：1.0
- **语言**：Python 3.8+
- **加密**：AES-256-GCM
- **压缩**：Brotli
- **数据格式**：JSON + Base64

---

**使用条款**：https://clck.ru/3P5hmE