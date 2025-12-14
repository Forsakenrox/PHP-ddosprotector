# 🛡️ DDoS Protector - Nginx-ориентированная защита от атак

[English Version](#%EF%B8%8F-ddos-protector---nginx-focused-ddos-protection)

PHP-скрипт для автоматического обнаружения и блокировки DDoS-атак на веб-сервера Nginx через анализ логов и динамическое управление firewalld.

## ✨ Возможности

- **Автоматический мониторинг** логов Nginx в реальном времени
- **Интеллектуальное блокирование** IP-адресов при превышении лимита запросов
- **Исключение доверенных сетей** Google (поисковые боты, облачные сервисы)
- **Graceful shutdown** с обработкой сигналов SIGTERM и SIGINT
- **Режим принуждения** (`--force`) для запуска даже при недоступности сервиса
- **Автосоздание** необходимых ipset и firewall правил
- **Логирование** заблокированных IP в файл `ipsettoblock.txt`

## 📋 Требования

- **PHP** 7.4+ с расширениями:
  - `pcntl` (для обработки сигналов)
  - `curl` (для проверки доступности сервиса)
- **ОС**: Linux с `firewalld` и `ipset`
- **Веб-сервер**: Nginx с стандартным форматом логов
- **Права**: Запуск от root (для управления firewall)

## 🚀 Установка

### 1. Клонирование и настройка
```bash
git clone https://github.com/Forsakenrox/PHP-ddosprotector.git
cd PHP-ddosprotector
```

### 2. Настройка параметров
Отредактируйте параметры в классе `DdosProtector`:

```php
public $logFile = '/var/log/nginx/your-site.access.log';  // Путь к логам
public $urlToWebApp = "https://your-domain.com/";         // URL для проверки доступности
public $minRequestsToBan = 8;                             // Порог запросов для блокировки
```

### 3. Проверка зависимостей
```bash
php -m | grep pcntl      # Должно вернуть "pcntl"
php -m | grep curl       # Должно вернуть "curl"
systemctl status firewalld  # Должен быть активен
```

## 📖 Использование

### Основной режим
```bash
php ddosprotector.php
```
Скрипт проверит доступность веб-сервиса и при недоступности начнет мониторинг логов.

### Режим принуждения
```bash
php ddosprotector.php --force
```
Запускает защиту независимо от статуса веб-сервиса.

### Автозапуск через systemd (рекомендуется)
Создайте файл `/etc/systemd/system/ddosprotector.service`:

```ini
[Unit]
Description=DDoS Protection Service
After=network.target firewalld.service

[Service]
Type=simple
ExecStart=/usr/bin/php /path/to/ddosprotector.php
Restart=always
RestartSec=60
User=root

[Install]
WantedBy=multi-user.target
```

Затем выполните:
```bash
systemctl daemon-reload
systemctl enable ddosprotector
systemctl start ddosprotector
systemctl status ddosprotector
```

## ⚙️ Как это работает

1. **Проверка доступности**: Скрипт проверяет HTTP-статус целевого URL
2. **Получение белых списков**: Загружает диапазоны IP Google для исключения
3. **Мониторинг логов**: Анализирует логи Nginx в реальном времени через `tail -f`
4. **Выявление атак**: Считает последовательные запросы с одного IP к одному URL
5. **Блокировка**: При превышении порога добавляет IP в firewalld ipset
6. **Автообновление**: Каждые 10 секунд применяет изменения firewall

## 📊 Формат логов Nginx

Скрипт работает **только** со стандартным форматом логов Nginx:
```
log_format main '$remote_addr $remote_user $time_local "$request" '
                '$status $body_bytes_sent "$http_referer" "$http_user_agent"';
```

## 📝 Файлы

- `ddosprotector.php` - основной скрипт
- `ddosprotector.lock` - lock-файл (создается автоматически)
- `ipsettoblock.txt` - журнал заблокированных IP (создается автоматически)

## 🔧 Настройка firewalld

Скрипт автоматически создает ipset `blocklist` и правило:
```bash
firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source ipset="blocklist" drop'
```

Для ручного управления:
```bash
# Просмотр заблокированных IP
firewall-cmd --info-ipset=blocklist

# Разблокировка IP
firewall-cmd --permanent --ipset=blocklist --remove-entry=192.168.1.1
firewall-cmd --reload
```

## ⚠️ Важные примечания

1. **Пороговое значение**: Настройте `$minRequestsToBan` под вашу нагрузку
2. **Ложные срабатывания**: Белые списки Google могут не покрывать все легитимные боты
3. **Производительность**: При высокой нагрузке мониторинг может потреблять ресурсы
4. **IPv6**: В текущей версии поддерживается только IPv4

## 📄 Лицензия

MIT License. Смотрите файл LICENSE для деталей.

---

# 🛡️ DDoS Protector - Nginx-focused DDoS Protection

PHP script for automatic detection and blocking of DDoS attacks on Nginx web servers through log analysis and dynamic firewalld management.

## ✨ Features

- **Automatic real-time monitoring** of Nginx logs
- **Intelligent IP blocking** on request threshold exceedance
- **Google trusted networks exclusion** (search bots, cloud services)
- **Graceful shutdown** with SIGTERM and SIGINT handling
- **Force mode** (`--force`) to run even when service is unavailable
- **Auto-creation** of required ipset and firewall rules
- **Logging** of blocked IPs to `ipsettoblock.txt`

## 📋 Requirements

- **PHP** 7.4+ with extensions:
  - `pcntl` (for signal handling)
  - `curl` (for service availability checks)
- **OS**: Linux with `firewalld` and `ipset`
- **Web server**: Nginx with standard log format
- **Permissions**: Root execution (for firewall management)

## 🚀 Installation

### 1. Clone and configure
```bash
git clone https://github.com/Forsakenrox/PHP-ddosprotector.git
cd PHP-ddosprotector
```

### 2. Configure parameters
Edit parameters in the `DdosProtector` class:

```php
public $logFile = '/var/log/nginx/your-site.access.log';  // Log path
public $urlToWebApp = "https://your-domain.com/";         // URL to check
public $minRequestsToBan = 8;                             // Blocking threshold
```

### 3. Verify dependencies
```bash
php -m | grep pcntl      # Should return "pcntl"
php -m | grep curl       # Should return "curl"
systemctl status firewalld  # Should be active
```

## 📖 Usage

### Normal mode
```bash
php ddosprotector.php
```
Script checks web service availability and starts log monitoring if unavailable.

### Force mode
```bash
php ddosprotector.php --force
```
Starts protection regardless of web service status.

### Auto-start via systemd (recommended)
Create `/etc/systemd/system/ddosprotector.service`:

```ini
[Unit]
Description=DDoS Protection Service
After=network.target firewalld.service

[Service]
Type=simple
ExecStart=/usr/bin/php /path/to/ddosprotector.php
Restart=always
RestartSec=60
User=root

[Install]
WantedBy=multi-user.target
```

Then execute:
```bash
systemctl daemon-reload
systemctl enable ddosprotector
systemctl start ddosprotector
systemctl status ddosprotector
```

## ⚙️ How It Works

1. **Availability check**: Verifies target URL HTTP status
2. **Whitelist retrieval**: Downloads Google IP ranges for exclusion
3. **Log monitoring**: Analyzes Nginx logs in real-time via `tail -f`
4. **Attack detection**: Counts sequential requests from single IP to same URL
5. **Blocking**: Adds IP to firewalld ipset when threshold exceeded
6. **Auto-update**: Applies firewall changes every 10 seconds

## 📊 Nginx Log Format

Script works **only** with standard Nginx log format:
```
log_format main '$remote_addr $remote_user $time_local "$request" '
                '$status $body_bytes_sent "$http_referer" "$http_user_agent"';
```

## 📝 Files

- `ddos_protector.php` - main script
- `ddosprotector.lock` - lock file (auto-generated)
- `ipsettoblock.txt` - blocked IPs journal (auto-generated)

## 🔧 Firewalld Configuration

Script automatically creates ipset `blocklist` and rule:
```bash
firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source ipset="blocklist" drop'
```

For manual management:
```bash
# View blocked IPs
firewall-cmd --info-ipset=blocklist

# Unblock IP
firewall-cmd --permanent --ipset=blocklist --remove-entry=192.168.1.1
firewall-cmd --reload
```

## ⚠️ Important Notes

1. **Threshold value**: Configure `$minRequestsToBan` for your load
2. **False positives**: Google whitelists may not cover all legitimate bots
3. **Performance**: High load monitoring may consume resources
4. **IPv6**: Current version supports IPv4 only

## 📄 License

MIT License. See LICENSE file for details.

---

## 🤝 Contributing

Issues and pull requests are welcome.

## ⭐ Support

If this project helped you, please give it a star!
```
