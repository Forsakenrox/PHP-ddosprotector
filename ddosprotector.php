<?php
class DdosProtector
{
    public $isForced = false;
    public $lockFile = "ddosprotector.lock";
    public $filePointer = null;
    public $logFile = '/var/log/nginx/access.log';
    public $urlToWebApp = "https://www.example.com/";
    public $minRequestsToBan = 8;

    public function __construct($argv)
    {
        $this->isForced = in_array('--force', $argv);
        $this->filePointer = fopen($this->lockFile, 'c');
    }

    // Unlock the script as it has finished working
    public function exitProgram($message = "")
    {
        try {
            flock($this->filePointer, LOCK_UN);
            fclose($this->filePointer);
            unlink('ddosprotector.lock');
        } catch (Throwable $th) {
            //throw $th;
        }
        die($message);
    }

    // Function to check if an IP matches a subnet or exact IP
    public function netMatch($ip,  $ipRrangeArray)
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
        // Add signal handling for graceful termination
        pcntl_async_signals(true);
        pcntl_signal(SIGTERM, function () {
            $this->exitProgram("Received SIGTERM\n");
        });
        pcntl_signal(SIGINT, function () {
            $this->exitProgram("Received SIGINT\n");
        });

        echo "Checking if another DDOS protection process is running...\n";
        if ($this->isForced) {
            echo "Force mode activated!\n";
        } else {
            echo "Normal mode.\n";
        }

        if (!$this->isForced) {
            if (!$this->filePointer) {
                $this->exitProgram("Failed to open lock file.\n");
            }
            if (!flock($this->filePointer, LOCK_EX | LOCK_NB)) {
                $this->exitProgram("Process is already running (lock file is busy).\n");
            }
        } else {
            try {
                flock($this->filePointer, LOCK_EX | LOCK_NB);
            } catch (Throwable $th) {
                // Suppress possible errors in force mode
            }
        }

        // Send a request to check if the web service is available
        echo "Sending a request to check if the web service is available...\n";
        $httpRequest = curl_init($this->urlToWebApp);
        curl_setopt($httpRequest, CURLOPT_TIMEOUT, 10);
        curl_setopt($httpRequest, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($httpRequest, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($httpRequest, CURLOPT_SSL_VERIFYPEER, 0);
        $result = curl_exec($httpRequest);
        $httpStatus = curl_getinfo($httpRequest, CURLINFO_HTTP_CODE);
        curl_close($httpRequest);
        echo "Response from web service: " . $httpStatus . "\n";

        if ($httpStatus != 200 || $this->isForced) {
            echo "Service is unavailable or force mode is active, possible DDOS attack, starting protection...\n";

            $googleNetworks = [];
            echo "Fetching list of Google bot and crawler IP ranges to avoid blocking them...\n";

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
                                if (!empty($p['ipv4Prefix'])) {
                                    $googleNetworks[] = $p['ipv4Prefix'];
                                }
                            }
                        }
                    }
                }
                $googleNetworks = array_unique(array_filter($googleNetworks));
                echo "List fetched, number of ranges: " . count($googleNetworks) . "\n";
            } catch (Throwable $th) {
                echo "Error while fetching Google bot IP ranges\n";
            }

            echo "Log analysis started...\n";
            $command = "tail -n 0 -f " . escapeshellarg($this->logFile);
            $handle = popen($command, 'r');
            if (!$handle) {
                $this->exitProgram("Failed to start tail -n 0 -f.\n");
            }

            $bannedIps = [];
            $previousBannedIpsCount = 0;
            $previousMicrotime = microtime(true);
            $previousIp = null;
            $previousTime = null;
            $previousPath = null;
            $count = 0;

            while (($line = fgets($handle)) !== false) {
                if (trim($line) === '') {
                    continue;
                }

                if (!preg_match('/^(\S+) (\S+) (\S+) \[([^\]]+)\] "(\S+) (\S+) (\S+)" (\d+) (\d+) "([^"]*)" "([^"]*)"$/', $line, $matches)) {
                    continue;
                }

                $ip = $matches[1] ?? null;
                $datetime = $matches[4] ?? null;
                $route = $matches[6] ?? null;
                $statusCode = (int)($matches[8] ?? 0);

                if ($statusCode == 206) {
                    continue;
                }

                if ($ip === null || $datetime === null || $route === null) {
                    continue;
                }

                if (in_array($ip, $bannedIps)) {
                    continue;
                }

                if ($ip === $previousIp && $datetime === $previousTime && $route === $previousPath) {
                    $count++;
                } else {
                    $count = 1;
                }

                if ($count >= $this->minRequestsToBan) {
                    if ($this->netMatch($ip, $googleNetworks)) {
                        echo "$ip is in Google whitelist, skipping\n";
                        continue;
                    }

                    $output = [];
                    $exitCode = 0;
                    exec("firewall-cmd --permanent --ipset=blocklist --add-entry=$ip", $output, $exitCode);

                    if ($exitCode == 0) {
                        $bannedIps[] = $ip;
                        $file = fopen('ipsettoblock.txt', 'a');
                        fwrite($file, $ip . "\n");
                        fclose($file);
                        echo "$ip banned\n";
                    } else {
                        echo "Failed to add $ip to blocklist (exit code: $exitCode)\n";
                        echo "Trying to create ipset and add again...\n";

                        try {
                            exec("firewall-cmd --permanent --new-ipset=blocklist --type=hash:ip", $output, $exitCode);
                            if ($exitCode == 0) {
                                echo "ipset created\n";
                                shell_exec("firewall-cmd --permanent --add-rich-rule='rule family=\"ipv4\" source ipset=\"blocklist\" drop'");
                                shell_exec("firewall-cmd --reload > /dev/null 2>&1 &");
                                exec("firewall-cmd --permanent --ipset=blocklist --add-entry=$ip", $output, $exitCode);
                                if ($exitCode == 0) {
                                    $bannedIps[] = $ip;
                                    echo "$ip banned\n";
                                }
                            }
                        } catch (Throwable $th) {
                            // Suppress errors during ipset creation
                        }
                    }
                    $count = 0;
                }

                if ((microtime(true) - $previousMicrotime > 10) && ($previousBannedIpsCount < count($bannedIps))) {
                    echo "Applying firewall changes...\n";
                    shell_exec("firewall-cmd --reload > /dev/null 2>&1 &");
                    $previousMicrotime = microtime(true);
                    $previousBannedIpsCount = count($bannedIps);
                }

                if ((microtime(true) - $previousMicrotime > 600) && ($previousBannedIpsCount == count($bannedIps))) {
                    $this->exitProgram("No attack activity for a long time, terminating script\n");
                }

                $previousIp = $ip;
                $previousTime = $datetime;
                $previousPath = $route;
            }

            pclose($handle);
        } else {
            $this->exitProgram("No issues detected, terminating\n");
        }
    }
}

(new DdosProtector($argv))->run();
