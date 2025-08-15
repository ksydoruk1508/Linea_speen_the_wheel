# 🎯 Linea Spin Automation Script

![Made with](https://img.shields.io/badge/Made%20with-Python-blue)
![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)

---

## 🇬🇧 English

🚀 This script automates the **daily spins** on the Linea Build platform,  
including proxy support, retries, streak tracking, and reward checking.

Supports a **bilingual interface (RU/EN)** and provides a clean output table with wallet statistics.

### 📌 Features
- Automatic spins with retry logic if proxy fails
- Proxy & multi-wallet support
- Streak tracking (7-day, 30-day multipliers)
- Real prize fetching via `/prizes/user` API
- Console table output with results

### 📂 Requirements
- Python **3.10+**
- Download and proceed to derictory
```bash
git clone https://github.com/ksydoruk1508/Linea_speen_the_wheel.git && cd Linea_speen_the_wheel
```
- Install dependencies from `requirements.txt`
```bash
pip install -r requirements.txt
```
- Wallets stored in `private_keys.txt`
- HTTP proxies stored in `proxies.txt` (format: `user:pass@ip:port`)
- Launch the script
```bash
python spin_linea.py
```

### 🛠 Support & Contacts
- **Telegram chat:** [@nod3r_team](https://t.me/nod3r_team)  
- **Telegram channel:** [@nod3r](https://t.me/nod3r)  
- **Bot:** [@wiki_nod3r_bot](https://t.me/wiki_nod3r_bot)  
- **GitHub:** [ksydoruk1508/Linea_speen_the_wheel](https://github.com/ksydoruk1508/Linea_speen_the_wheel)

---

## 🇷🇺 Русский

🚀 Этот скрипт автоматизирует **ежедневные спины** на платформе Linea Build,  
включая поддержку прокси, повторные попытки при ошибках, отслеживание серии (streak) и проверку наград.

Поддерживает **двуязычный интерфейс (RU/EN)** и выводит аккуратную таблицу с результатами по кошелькам.

### 📌 Возможности
- Автоматические спины с повторными попытками при сбое прокси
- Поддержка прокси и работы с несколькими кошельками
- Отслеживание серии (7-дневный и 30-дневный множители)
- Получение актуальных наград через API `/prizes/user`
- Вывод таблицы с результатами в консоль

### 📂 Требования
- Python **3.10+**
- Скачайте и перейдите в директорию
```bash
git clone https://github.com/ksydoruk1508/Linea_speen_the_wheel.git && cd Linea_speen_the_wheel
```
- Установите зависимости из `requirements.txt`
```bash
pip install -r requirements.txt
```
- Кошельки в файле `private_keys.txt`
- HHTP прокси в файле `proxies.txt` (формат: `user:pass@ip:port`)
- Запустите скрипт
```bash
python spin_linea.py
```

### 🛠 Поддержка и контакты
- **Telegram-чат:** [@nod3r_team](https://t.me/nod3r_team)  
- **Telegram-канал:** [@nod3r](https://t.me/nod3r)  
- **Бот:** [@wiki_nod3r_bot](https://t.me/wiki_nod3r_bot)  
- **GitHub:** [ksydoruk1508/Linea_speen_the_wheel](https://github.com/ksydoruk1508/Linea_speen_the_wheel)
