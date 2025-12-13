<?php
class DdosProtector
{
    public $isForced = false;
    public $lockFile = "ddosprotector.lock";
    public $filePointer = null;
    public $logFile = '/var/log/nginx/your.access.log';
    public $urlToWebApp = "https://www.example.com/";
    public $minRequestsToBan = 8;

    public function __construct($argv)
    {
        $this->isForced = in_array('--force', $argv);
        $this->filePointer = fopen($this->lockFile, 'c');
    }

    //Разблокируем скрипт, т.к. он отработал
    function exitProgramm($message = "")
    {
        try {
            flock($this->filePointer, LOCK_UN);
            fclose($this->filePointer);
            unlink('ddosprotector.lock');
        } catch (\Throwable $th) {
            //throw $th;
        }
        die($message);
    }

    // функция поиска вхождения в подсеть адреса
    function netMatch($ip,  $ipRrangeArray)
    {
        foreach ($ipRrangeArray as $cidr) {
            if (count(explode('/', $cidr)) > 1) {
                list($subnet, $mask) = explode('/', $cidr);
                if (((ip2long($ip) & ($mask = ~((1 << (32 - $mask)) - 1))) == (ip2long($subnet) & $mask))) {
                    return true;
                }
            } elseif ($ip === $cidr) {
                return true;
            }
        }
        return false;
    }

    public function run()
    {
        // добавляем обработку сигналов для консоли
        pcntl_async_signals(true);
        pcntl_signal(SIGTERM, function () {
            $this->exitProgramm("Получен SIGTERM\n");
        });
        pcntl_signal(SIGINT,  function () {
            $this->exitProgramm("Получен SIGINT\n");
        });

        echo "проверяем запущен ли другой процесс по протекции от ддос \n";
        if ($this->isForced == true) {
            echo "Режим --force активирован!\n";
        } else {
            echo "Обычный режим.\n";
        }

        if (!$this->isForced) {
            if (!$this->filePointer) {
                die("Не удалось открыть lock-файл.\n");
            }
            if (!flock($this->filePointer, LOCK_EX | LOCK_NB)) {
                die("Процесс уже запущен (lock-файл занят).\n");
            }
        } else {
            try {
                flock($this->filePointer, LOCK_EX | LOCK_NB);
            } catch (\Throwable $th) {
                //throw $th;
            }
        }

        //Отправляем запрос что бы проверить что вебсервис доступен
        echo "Отправляем запрос что бы проверить что вебсервис доступен...\n";
        $httpRequest = curl_init($this->urlToWebApp);
        curl_setopt($httpRequest, CURLOPT_TIMEOUT, 10);
        curl_setopt($httpRequest, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($httpRequest, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($httpRequest, CURLOPT_SSL_VERIFYPEER, 0);
        $result = curl_exec($httpRequest);
        $http_status = curl_getinfo($httpRequest, CURLINFO_HTTP_CODE);
        curl_close($httpRequest);
        echo "Ответ от вебсервиса: " . $http_status . "\n";

        if ($http_status != 200 || $this->isForced == true) {
            echo "сервис недоступен либо форсированый режим, возможно идёт ддос, запуск карателя...\n";

            $googleNetworks = [];
            echo "получаем список адресов ботов кравлеров что бы не блокировать их...\n";
            try {
                $urls = [
                    'https://www.gstatic.com/ipranges/goog.json',
                    'https://www.gstatic.com/ipranges/cloud.json',
                    'https://developers.google.com/search/apis/ipranges/googlebot.json',
                    'https://developers.google.com/search/apis/ipranges/special-crawlers.json'
                ];
                foreach ($urls as $url) {
                    $json = @file_get_contents($url);
                    if ($json) {
                        $data = json_decode($json, true);
                        if (isset($data['prefixes'])) {
                            foreach ($data['prefixes'] as $p) {
                                if (!empty($p['ipv4Prefix'])) $googleNetworks[] = $p['ipv4Prefix'];
                            }
                        }
                    }
                }
                $googleNetworks = array_unique(array_filter($googleNetworks));
                echo "список получен, количество адресов: " . count($googleNetworks) . "\n";
            } catch (\Throwable $th) {
                echo "в процессе получения адресов ботов кравлеров гугла произошла ошибка\n";
            }
            echo "анализ логов запущен \n";
            // Команда для запуска tail -f
            $command = "tail -n 0 -f " . escapeshellarg($this->logFile);

            // Открываем процесс tail -f
            $handle = popen($command, 'r');

            if (!$handle) {
                $this->exitProgramm("Не удалось запустить tail -n 0 -f.\n");
            }

            $bannedIps = [];
            $previousBannedIpsCount = 0;
            $previousMicrotime = microtime(true);
            $previousIp = null;
            $previousTime = null;
            $previousPath = null;
            $count = 0;
            // Чтение вывода tail -f построчно
            while (!feof($handle)) {
                $line = fgets($handle);
                // Если строка не пустая, обрабатываем её
                if ($line !== false) {
                    preg_match('/^(\S+) (\S+) (\S+) \[([^\]]+)\] "(\S+) (\S+) (\S+)" (\d+) (\d+) "([^"]*)" "([^"]*)"$/', $line, $matches);
                    $ip = $matches[1] ?? null;
                    $datetime = $matches[4] ?? null;
                    $action = $matches[5] ?? null;
                    $route = $matches[6] ?? null;
                    $status_code = $matches[8] ?? null;

                    if ($status_code == 206) {
                        continue;
                    }
                    // Пропускаем строки, которые не соответствуют паттерну
                    if ($ip === null || $datetime === null || $route === null) {
                        continue;
                    }
                    // Пропускаем строки с IP, которые уже в тюрьме
                    if (in_array($ip, $bannedIps)) {
                        continue;
                    }

                    // Проверяем, совпадают ли IP, время и путь с предыдущими
                    // if ($ip === $previousIp && $datetime === $previousTime) {
                    if ($ip === $previousIp && $datetime === $previousTime && $route === $previousPath) {
                        $count++;
                    } else {
                        // Сбрасываем счетчик, если хотя бы один параметр отличается
                        $count = 1;
                    }

                    // Если найдено 5 повторений подряд, добавляем IP в "тюрьму"
                    if ($count >= $this->minRequestsToBan) {
                        if ($this->netMatch($ip, $googleNetworks)) {
                            echo "$ip входит в белый список пропускаем";
                            continue;
                        }
                        $output = null;
                        $exitcode = null;
                        $file = fopen('ipsettoblock.txt', 'a');
                        fwrite($file, $ip . "\n");
                        fclose($file);
                        // exec("ipset add blocklist $ip", $output, $exitcode);
                        exec("firewall-cmd --permanent --ipset=blocklist --add-entry=$ip", $output, $exitcode);
                        // exec("ipset del abc 1.1.1.1", $output, $exitcode);

                        if ($exitcode == 0) {
                            array_push($bannedIps, $ip);
                            echo $ip . " banned \n";
                        } else {
                            echo "код завершения добавления в blocklist для ip $ip = $exitcode, не удаётся забанить\n";
                            echo "Возможно не создан ipset, пробуем создать и повторно забанить...\n";
                            exec("firewall-cmd --permanent --new-ipset=blocklist --type=hash:ip", $output2, $exitcode2);
                            if ($exitcode2 == 0) {
                                echo "ipset создан\n";
                                shell_exec("firewall-cmd --permanent --add-rich-rule='rule family=\"ipv4\" source ipset=\"blocklist\" drop'");
                                shell_exec("firewall-cmd --reload > /dev/null 2>&1 &");
                                exec("firewall-cmd --permanent --ipset=blocklist --add-entry=$ip", $output, $exitcode);
                                if ($exitcode == 0) {
                                    echo $ip . " banned \n";
                                }
                            }
                        }
                        // Сбрасываем счетчик после добавления IP в тюрьму
                        $count = 0;
                    }
                    //проверяем что между прошлым и текущим микротаймом прошло более 10 секунд, что количество забаненных ip с прошлого сохранённого состояния увеличилось, то устанавливаем текущий микротайм и сохраняем новое количество баненных ip и релоадим фаервол
                    if (microtime(true) - $previousMicrotime > 10 && $previousBannedIpsCount < count($bannedIps)) {
                        echo "применяю фаервол...\n";
                        // shell_exec("firewall-cmd --permanent --ipset=blocklist --add-entries-from-file=/root/ipsettoblock.txt > /dev/null 2>&1 &");
                        shell_exec("firewall-cmd --reload > /dev/null 2>&1 &");
                        $previousMicrotime = microtime(true);
                        $previousBannedIpsCount = count($bannedIps);
                    }
                    //если активности по ддосу нет  течении 10 минут, то завершаем работу
                    if (microtime(true) - $previousMicrotime > 600 && $previousBannedIpsCount == count($bannedIps)) {
                        $this->exitProgramm("Атаки долго не наблюдается, скрипт завершает работу \n");
                    }

                    //проверяем какие адреса попадают в лог и на утечки памяти
                    // echo "Новая строка: " . trim($ip) . " " . memory_get_usage() . "\n";

                    // Обновляем предыдущие значения
                    $previousIp = $ip;
                    $previousTime = $datetime;
                    $previousPath = $route;
                }
            }
        } else {
            $this->exitProgramm("Проблем не обнаружено, завершаем работу \n");
        }
    }
}
(new DdosProtector($argv))->run();
