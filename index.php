<?php
// =============================================================================
// ПРОЕКТ: Proxy Manager
// =============================================================================
// Автор:      https://t.me/bober41
// Исходники:  https://github.com/eldevex/Proxy-Manager
// =============================================================================

error_reporting(E_ALL & ~E_DEPRECATED);
ini_set('display_errors', '0');

// --- Системные константы (часть копирайта встроена в логику) ---
define('PM_A', base64_decode('aHR0cHM6Ly90Lm1lL2JvYmVyNDE=')); // https://t.me/bober41
define('PM_B', base64_decode('aHR0cHM6Ly9naXRodWIuY29tL2VsZGV2ZXgvUHJveHktTWFuYWdlcg==')); // https://github.com/eldevex/Proxy-Manager
define('PM_C', 'Fixed_Device_V1_2026'); // seed базируется на версии автора

$my_secret_seed = PM_C;
$subsDir = __DIR__ . '/subs';
$registryFile = $subsDir . '/.registry.json';
$settingsFile = $subsDir . '/.settings.json';
$usersFile = $subsDir . '/.users.json';

if (!is_dir($subsDir)) {
    mkdir($subsDir, 0755, true);
}
foreach ([$registryFile, $settingsFile, $usersFile] as $f) {
    if (!file_exists($f)) {
        file_put_contents($f, json_encode([]));
    }
}

// ==================== УТИЛИТЫ ====================

function sanitizeLogin(string $login): ?string {
    $login = trim($login);
    if (!preg_match('/^[a-zA-Z0-9_\-]+$/', $login)) return null;
    if (strlen($login) > 32) return null;
    return $login;
}

function hashPassword(string $password): string {
    // Соль основана на константе автора — удаление сломает совместимость
    return hash('sha256', $password . substr(PM_C, 0, 8));
}

function loadUsers(): array {
    global $usersFile;
    $content = file_get_contents($usersFile);
    $data = json_decode($content, true);
    if (!is_array($data)) return [];
    return $data;
}

function saveUsers(array $users): bool {
    global $usersFile;
    $json = json_encode($users, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
    return file_put_contents($usersFile, $json, LOCK_EX) !== false;
}

function authenticateUser(string $login, string $password): bool {
    $users = loadUsers();
    if (!isset($users[$login])) return false;
    return $users[$login]['password_hash'] === hashPassword($password);
}

function userExists(string $login): bool {
    $users = loadUsers();
    return isset($users[$login]);
}

function createUser(string $login, string $password): bool {
    $users = loadUsers();
    $users[$login] = [
        'password_hash' => hashPassword($password),
        'created_at' => time()
    ];
    return saveUsers($users);
}

function loadRegistry(): array {
    global $registryFile;
    $content = file_get_contents($registryFile);
    $data = json_decode($content, true);
    if (!is_array($data)) return [];
    return $data;
}

function saveRegistry(array $registry): bool {
    global $registryFile;
    $json = json_encode($registry, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
    return file_put_contents($registryFile, $json, LOCK_EX) !== false;
}

function loadSettings(): array {
    global $settingsFile;
    $content = file_get_contents($settingsFile);
    $data = json_decode($content, true);
    if (!is_array($data)) return [];
    return $data;
}

function saveSettings(array $settings): bool {
    global $settingsFile;
    $json = json_encode($settings, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
    return file_put_contents($settingsFile, $json, LOCK_EX) !== false;
}

function getUserSeed(string $login, string $defaultSeed): string {
    $settings = loadSettings();
    $seed = $settings[$login]['hwid_seed'] ?? '';
    return $seed !== '' ? $seed : $defaultSeed;
}

function getSubFilePath(string $hash): string {
    global $subsDir;
    return $subsDir . '/' . $hash . '.txt';
}

function getHash(string $name, string $login): string {
    // PM_C встроен в генерацию хешей — удаление изменит все существующие подписки
    return substr(hash('sha256', $name . '|' . $login . '|' . PM_C), 0, 16);
}

function getHwid(string $seed): string {
    return substr(hash('sha256', $seed), 0, 16);
}

function isProxyLine(string $line): bool {
    $protocols = ['vless://', 'vmess://', 'ss://', 'ssr://', 'trojan://', 'hysteria://', 'hysteria2://', 'tuic://', 'wireguard://'];
    foreach ($protocols as $proto) {
        if (stripos($line, $proto) === 0) return true;
    }
    return false;
}

function getCurlHeaders(string $hwid): array {
    return [
        "User-Agent: Happ/3.17.0/Android/17756505247711753599",
        "X-Hwid: " . $hwid,
        "X-Device-Id: " . $hwid,
        "X-Ver-Os: 29",
        "X-Device-Os: Android",
        "X-Device-Model: samsung SM-A217F",
        "X-Device-Locale: ru",
        "Accept: */*",
        "Accept-Encoding: gzip",
        "Content-Length: 0",
        "Connection: close"
    ];
}

function fetchSubscription(string $url, string $seed): ?array {
    $hwid = getHwid($seed);
    $headers = getCurlHeaders($hwid);
    $raw_headers = [];

    $curl = curl_init($url);
    curl_setopt_array($curl, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_TIMEOUT => 15,
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_SSL_VERIFYHOST => false,
        CURLOPT_HTTPHEADER => $headers,
        CURLOPT_ENCODING => "",
        CURLOPT_HEADERFUNCTION => function($ch, $header) use (&$raw_headers) {
            $len = strlen($header);
            $h = trim($header);
            if ($h !== '' && strpos($h, ':') !== false) {
                $raw_headers[] = $h;
            }
            return $len;
        }
    ]);

    $response = curl_exec($curl);
    if ($response === false) {
        curl_close($curl);
        return null;
    }
    $status_code = curl_getinfo($curl, CURLINFO_HTTP_CODE);
    curl_close($curl);

    return [
        'body'    => $response,
        'headers' => $raw_headers,
        'status'  => $status_code
    ];
}

function parseUpstreamHeaders(array $raw_headers): array {
    $upstream = [];
    foreach ($raw_headers as $h) {
        $parts = explode(':', $h, 2);
        if (count($parts) === 2) {
            $upstream[strtolower(trim($parts[0]))] = trim($parts[1]);
        }
    }
    return $upstream;
}

function proxySubscriptionHeaders(array $upstream): void {
    $to_proxy = [
        'subscription-userinfo',
        'profile-update-interval',
        'profile-web-page-url',
        'content-disposition',
    ];
    foreach ($to_proxy as $key) {
        if (isset($upstream[$key]) && $upstream[$key] !== '') {
            $header_name = str_replace(' ', '-', ucwords(str_replace('-', ' ', $key)));
            header("{$header_name}: " . $upstream[$key]);
        }
    }
}

function extractLinksFromText(string $text): array {
    $lines = explode("\n", $text);
    $links = [];
    foreach ($lines as $line) {
        $line = trim($line);
        if (empty($line)) continue;
        if (isProxyLine($line)) {
            $links[] = $line;
        }
    }
    return $links;
}

function buildVlessLink($outbound, $remarks) {
    if (($outbound['protocol'] ?? '') !== 'vless') return null;

    $settings = $outbound['settings'] ?? [];
    $vnext = $settings['vnext'][0] ?? null;
    if (!$vnext) return null;

    $user = $vnext['users'][0] ?? null;
    if (!$user) return null;

    $uuid       = $user['id'] ?? '';
    $address    = $vnext['address'] ?? '';
    $port       = $vnext['port'] ?? 443;
    $encryption = $user['encryption'] ?? 'none';
    $flow       = $user['flow'] ?? '';

    $stream   = $outbound['streamSettings'] ?? [];
    $network  = $stream['network'] ?? 'tcp';
    $security = $stream['security'] ?? 'none';

    $params = ['encryption' => $encryption];
    if ($flow) $params['flow'] = $flow;
    if ($security && $security !== 'none') $params['security'] = $security;

    if ($security === 'reality') {
        $reality = $stream['realitySettings'] ?? [];
        if (!empty($reality['serverName']))  $params['sni'] = $reality['serverName'];
        if (!empty($reality['publicKey']))   $params['pbk'] = $reality['publicKey'];
        if (!empty($reality['shortId']))     $params['sid'] = $reality['shortId'];
        if (!empty($reality['fingerprint'])) $params['fp']  = $reality['fingerprint'];
        if (isset($reality['spiderX']) && $reality['spiderX'] !== '') {
            $params['spx'] = $reality['spiderX'];
        }
    }

    if ($security === 'tls') {
        $tls = $stream['tlsSettings'] ?? [];
        if (!empty($tls['serverName']))  $params['sni'] = $tls['serverName'];
        if (!empty($tls['fingerprint'])) $params['fp']  = $tls['fingerprint'];
        if (!empty($tls['alpn'])) {
            $params['alpn'] = implode(',', $tls['alpn']);
        }
    }

    $params['type'] = $network;

    if ($network === 'tcp') {
        $header = $stream['tcpSettings']['header'] ?? [];
        if (!empty($header['type'])) $params['headerType'] = $header['type'];
    }

    if ($network === 'ws') {
        $ws = $stream['wsSettings'] ?? [];
        if (!empty($ws['path'])) $params['path'] = $ws['path'];
        $headers = $ws['headers'] ?? [];
        if (!empty($headers['Host'])) $params['host'] = $headers['Host'];
    }

    if ($network === 'grpc') {
        $grpc = $stream['grpcSettings'] ?? [];
        if (!empty($grpc['serviceName'])) $params['serviceName'] = $grpc['serviceName'];
        if (!empty($grpc['authority']))   $params['authority']   = $grpc['authority'];
        if (isset($grpc['mode']) && $grpc['mode'] !== false && $grpc['mode'] !== '') {
            $params['mode'] = $grpc['mode'];
        }
    }

    if ($network === 'xhttp') {
        $xhttp = $stream['xhttpSettings'] ?? [];
        if (!empty($xhttp['mode'])) $params['mode'] = $xhttp['mode'];
        if (isset($xhttp['path']) && $xhttp['path'] !== '') $params['path'] = $xhttp['path'];
        if (!empty($xhttp['host'])) $params['host'] = $xhttp['host'];
    }

    $queryParts = [];
    foreach ($params as $k => $v) {
        if ($v !== '' && $v !== null && $v !== false) {
            $queryParts[] = $k . '=' . rawurlencode((string)$v);
        }
    }
    $query = implode('&', $queryParts);

    $remarksEncoded = rawurlencode($remarks);
    return "vless://{$uuid}@{$address}:{$port}?{$query}#{$remarksEncoded}";
}

function buildHysteria2Link($outbound, $remarks) {
    $protocol = $outbound['protocol'] ?? '';
    $settings = $outbound['settings'] ?? [];

    $version = $settings['version'] ?? 2;
    if ($protocol === 'hysteria' && $version != 2) {
        return null;
    }
    if ($protocol !== 'hysteria' && $protocol !== 'hysteria2') {
        return null;
    }

    $address = $settings['address'] ?? '';
    $port    = $settings['port'] ?? 443;

    $stream = $outbound['streamSettings'] ?? [];
    $hysteriaSettings = $stream['hysteriaSettings'] ?? [];
    $auth = $hysteriaSettings['auth'] ?? '';

    if (!$address || !$auth) return null;

    $security = $stream['security'] ?? 'none';
    $tlsSettings = $stream['tlsSettings'] ?? [];

    $params = [];

    if ($security === 'tls') {
        if (!empty($tlsSettings['serverName']))  $params['sni'] = $tlsSettings['serverName'];
        if (!empty($tlsSettings['fingerprint'])) $params['fp']  = $tlsSettings['fingerprint'];
        if (!empty($tlsSettings['alpn'])) {
            $params['alpn'] = implode(',', $tlsSettings['alpn']);
        }
    }

    if (!empty($hysteriaSettings['obfs'])) {
        $params['obfs'] = $hysteriaSettings['obfs'];
        if (!empty($hysteriaSettings['obfs-password'])) {
            $params['obfs-password'] = $hysteriaSettings['obfs-password'];
        }
    }

    $queryParts = [];
    foreach ($params as $k => $v) {
        if ($v !== '' && $v !== null && $v !== false) {
            $queryParts[] = $k . '=' . rawurlencode((string)$v);
        }
    }
    $query = implode('&', $queryParts);

    $remarksEncoded = rawurlencode($remarks);
    $scheme = 'hysteria2';

    if ($query) {
        return "{$scheme}://{$auth}@{$address}:{$port}?{$query}#{$remarksEncoded}";
    }
    return "{$scheme}://{$auth}@{$address}:{$port}#{$remarksEncoded}";
}

function parseSubscriptionResponse(string $response, array $raw_headers): ?array {
    $upstream = parseUpstreamHeaders($raw_headers);

    if (stripos($response, 'Limit of devices reached') !== false) {
        return null;
    }

    $decoded = base64_decode($response, true);
    if ($decoded !== false && strlen($decoded) > 10) {
        if (stripos($decoded, 'Limit of devices reached') !== false) {
            return null;
        }
        $response = $decoded;
    }

    $json_start = strpos($response, '[');
    if ($json_start !== false) {
        $json_str = substr($response, $json_start);
        $json_end = strrpos($json_str, ']');
        if ($json_end !== false) {
            $json_str = substr($json_str, 0, $json_end + 1);
            $configs = json_decode($json_str, true);

            if (is_array($configs) && !empty($configs) && isset($configs[0]['outbounds'])) {
                $links = [];
                foreach ($configs as $cfg) {
                    $remarks = $cfg['remarks'] ?? 'Unnamed';
                    $outbounds = $cfg['outbounds'] ?? [];

                    $vlessOutbounds = [];
                    foreach ($outbounds as $outbound) {
                        if (($outbound['protocol'] ?? '') === 'vless') {
                            $vlessOutbounds[] = $outbound;
                        }
                    }
                    foreach ($vlessOutbounds as $i => $outbound) {
                        $currentRemarks = $remarks;
                        if (count($vlessOutbounds) > 1) {
                            $tag = $outbound['tag'] ?? ('proxy-' . ($i + 1));
                            $currentRemarks = $remarks . ' [' . $tag . ']';
                        }
                        $link = buildVlessLink($outbound, $currentRemarks);
                        if ($link) $links[] = $link;
                    }

                    foreach ($outbounds as $outbound) {
                        $proto = $outbound['protocol'] ?? '';
                        if ($proto === 'hysteria' || $proto === 'hysteria2') {
                            $link = buildHysteria2Link($outbound, $remarks);
                            if ($link) $links[] = $link;
                        }
                    }
                }
                if (!empty($links)) {
                    return ['links' => $links, 'upstream' => $upstream];
                }
            }
        }
    }

    $links = extractLinksFromText($response);
    if (!empty($links)) {
        return ['links' => $links, 'upstream' => $upstream];
    }

    return null;
}

function fetchAndParseLinks(string $url, string $seed): array {
    $result = fetchSubscription($url, $seed);
    if (!$result || $result['status'] >= 400) return [];
    $parsed = parseSubscriptionResponse($result['body'], $result['headers']);
    if ($parsed !== null && !empty($parsed['links'])) {
        return $parsed['links'];
    }
    return extractLinksFromText($result['body']);
}

function dedupLines(array $lines): array {
    $seen = [];
    $result = [];
    foreach ($lines as $line) {
        $trimmed = trim($line);
        if ($trimmed === '') {
            $result[] = $line;
            continue;
        }
        if (!isProxyLine($trimmed)) {
            $result[] = $line;
            continue;
        }
        if (!isset($seen[$trimmed])) {
            $seen[$trimmed] = true;
            $result[] = $line;
        }
    }
    return $result;
}

function refreshAutoSub(string $hash, array $config, string $seed): bool {
    $urls = $config['urls'] ?? [];
    $keep_comments = !empty($config['keep_comments']);
    $dedup = !empty($config['dedup']);
    $allLines = [];
    $sourcesMeta = [];
    
    foreach ($urls as $url) {
        if (empty($url)) continue;
        $result = fetchSubscription($url, $seed);
        if ($result !== null && $result['status'] < 400) {
            $upstream = parseUpstreamHeaders($result['headers']);
            $sourcesMeta[$url] = [
                'subscription-userinfo' => $upstream['subscription-userinfo'] ?? '',
                'profile-update-interval' => $upstream['profile-update-interval'] ?? '',
                'profile-web-page-url' => $upstream['profile-web-page-url'] ?? '',
                'content-disposition' => $upstream['content-disposition'] ?? '',
                'fetched_at' => time(),
            ];
            
            if ($keep_comments) {
                $body = $result['body'];
                $decoded = base64_decode($body, true);
                if ($decoded !== false && strlen($decoded) > 10) $body = $decoded;
                foreach (explode("\n", $body) as $line) {
                    $line = trim($line);
                    if ($line !== '') $allLines[] = $line;
                }
            } else {
                $parsed = parseSubscriptionResponse($result['body'], $result['headers']);
                if ($parsed !== null && !empty($parsed['links'])) {
                    foreach ($parsed['links'] as $link) $allLines[] = $link;
                } else {
                    foreach (extractLinksFromText($result['body']) as $link) $allLines[] = $link;
                }
            }
        }
    }
    if (empty($allLines)) {
        return false;
    }
    if ($dedup) {
        $allLines = dedupLines($allLines);
    }
    $content = implode("\n", $allLines) . "\n";
    $filePath = getSubFilePath($hash);
    file_put_contents($filePath, $content, LOCK_EX);

    $registry = loadRegistry();
    if (isset($registry[$hash]) && is_array($registry[$hash])) {
        $registry[$hash]['last_update'] = time();
        $registry[$hash]['sources_meta'] = $sourcesMeta;
        saveRegistry($registry);
    }
    return true;
}

// ==================== API / GET ====================

// --- Выдача подписки (?i=hash) ---
if (isset($_GET['i']) && $_GET['i'] !== '') {
    $hash = preg_replace('/[^a-f0-9]/', '', $_GET['i']);
    if (strlen($hash) !== 16) {
        header("HTTP/1.1 400 Bad Request");
        die("Invalid subscription hash.");
    }

    $registry = loadRegistry();
    if (!isset($registry[$hash])) {
        header("HTTP/1.1 404 Not Found");
        die("Subscription not found.");
    }

    $entry = $registry[$hash];
    $userSeed = getUserSeed($entry['owner'] ?? '', $my_secret_seed);

    if (!empty($entry['auto'])) {
        $period = $entry['period'] ?? 3600;
        $last = $entry['last_update'] ?? 0;
        if (time() - $last > $period) {
            refreshAutoSub($hash, $entry, $userSeed);
            $registry = loadRegistry();
            $entry = $registry[$hash];
        }
    }

    $filePath = getSubFilePath($hash);
    if (!file_exists($filePath)) {
        header("HTTP/1.1 404 Not Found");
        die("Subscription file not found.");
    }

    $content = file_get_contents($filePath);
    header("Content-Type: text/plain; charset=utf-8");
    
    // Проксируем заголовки только если 1 источник
    if (!empty($entry['auto']) && !empty($entry['sources_meta']) && count($entry['urls'] ?? []) === 1) {
        $url = $entry['urls'][0];
        $meta = $entry['sources_meta'][$url] ?? [];
        if (!empty($meta)) {
            $upstream = [];
            foreach (['subscription-userinfo', 'profile-update-interval', 'profile-web-page-url', 'content-disposition'] as $k) {
                if (!empty($meta[$k])) $upstream[$k] = $meta[$k];
            }
            if (!empty($upstream)) {
                proxySubscriptionHeaders($upstream);
            }
        }
    }
    
    if (!empty($entry['keep_comments'])) {
        echo $content;
    } else {
        $links = extractLinksFromText($content);
        if (!empty($links)) {
            echo implode("\n", $links);
        } else {
            echo $content;
        }
    }
    exit;
}

// --- Проксирование подписки (?url=...) ---
if (!empty($_GET['url'])) {
    $subscription_url = urldecode($_GET['url']);
    $result = fetchSubscription($subscription_url, $my_secret_seed);

    if ($result === null) {
        header("HTTP/1.1 500 Internal Server Error");
        die("Ошибка: не удалось получить подписку.");
    }

    if ($result['status'] >= 400) {
        header("HTTP/1.1 502 Bad Gateway");
        die("Ошибка: сервер подписки вернул HTTP {$result['status']}.");
    }

    if (stripos($result['body'], 'Limit of devices reached') !== false) {
        header("Content-Type: text/plain; charset=utf-8");
        die("SERVER ERROR: Лимит устройств исчерпан.");
    }

    $parsed = parseSubscriptionResponse($result['body'], $result['headers']);
    if ($parsed !== null && !empty($parsed['links'])) {
        header("Content-Type: text/plain; charset=utf-8");
        proxySubscriptionHeaders($parsed['upstream']);
        echo implode("\n", $parsed['links']);
        exit;
    }

    header("Content-Type: text/plain; charset=utf-8");
    if ($parsed !== null) {
        proxySubscriptionHeaders($parsed['upstream']);
    }
    echo $result['body'];
    exit;
}

// --- API endpoints (POST JSON) ---
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    header('Content-Type: application/json; charset=utf-8');

    $input = json_decode(file_get_contents('php://input'), true);
    if (!$input) {
        $input = $_POST;
    }

    $action = $input['action'] ?? '';
    $login = sanitizeLogin($input['login'] ?? '');
    $password = $input['password'] ?? '';

    // --- Логин (создание пользователя при первом входе) ---
    if ($action === 'login') {
        if (!$login) {
            echo json_encode(['success' => false, 'error' => 'Логин может содержать только латинские буквы, цифры, _ и - (макс. 32 символа)']);
            exit;
        }
        if (empty($password)) {
            echo json_encode(['success' => false, 'error' => 'Введите пароль']);
            exit;
        }
        if (!userExists($login)) {
            if (!createUser($login, $password)) {
                echo json_encode(['success' => false, 'error' => 'Ошибка создания пользователя']);
                exit;
            }
            echo json_encode(['success' => true, 'message' => 'Аккаунт создан и выполнен вход']);
            exit;
        }
        if (!authenticateUser($login, $password)) {
            echo json_encode(['success' => false, 'error' => 'Неверный пароль']);
            exit;
        }
        echo json_encode(['success' => true, 'message' => 'Вход выполнен']);
        exit;
    }

    // --- Все остальные действия требуют авторизации ---
    if (!$login || !authenticateUser($login, $password)) {
        echo json_encode(['success' => false, 'error' => 'Неверный логин или пароль']);
        exit;
    }

    $registry = loadRegistry();
    $userSeed = getUserSeed($login, $my_secret_seed);

    switch ($action) {
        case 'get_settings':
            $settings = loadSettings();
            $userSettings = $settings[$login] ?? [];
            echo json_encode([
                'success' => true,
                'hwid_seed' => $userSettings['hwid_seed'] ?? '',
            ]);
            exit;

        case 'save_settings':
            $hwid_seed = trim($input['hwid_seed'] ?? '');
            $settings = loadSettings();
            if (!isset($settings[$login])) $settings[$login] = [];
            $settings[$login]['hwid_seed'] = $hwid_seed;
            saveSettings($settings);
            echo json_encode(['success' => true, 'message' => 'Настройки сохранены']);
            exit;

        case 'get_subs':
            $mine = [];
            foreach ($registry as $hash => $entry) {
                if (($entry['owner'] ?? '') === $login) {
                    $filePath = getSubFilePath($hash);
                    $lineCount = 0;
                    if (file_exists($filePath)) {
                        $content = file_get_contents($filePath);
                        if (!empty($entry['keep_comments'])) {
                            $lineCount = count(array_filter(explode("\n", trim($content)), fn($l) => trim($l) !== ''));
                        } else {
                            $lineCount = count(extractLinksFromText($content));
                        }
                    }
                    $mine[] = [
                        'name' => $entry['name'] ?? 'Unknown',
                        'hash' => $hash,
                        'lines' => $lineCount,
                        'link' => '?' . http_build_query(['i' => $hash]),
                        'auto' => !empty($entry['auto']),
                        'dedup' => !empty($entry['dedup']),
                        'keep_comments' => !empty($entry['keep_comments']),
                        'public' => !empty($entry['public']),
                    ];
                }
            }
            echo json_encode(['success' => true, 'subs' => $mine]);
            exit;

        case 'get_public_subs':
            $public = [];
            foreach ($registry as $hash => $entry) {
                if (!empty($entry['public']) && ($entry['owner'] ?? '') !== $login) {
                    $filePath = getSubFilePath($hash);
                    $lineCount = 0;
                    if (file_exists($filePath)) {
                        $content = file_get_contents($filePath);
                        if (!empty($entry['keep_comments'])) {
                            $lineCount = count(array_filter(explode("\n", trim($content)), fn($l) => trim($l) !== ''));
                        } else {
                            $lineCount = count(extractLinksFromText($content));
                        }
                    }
                    $public[] = [
                        'name' => $entry['name'] ?? 'Unknown',
                        'hash' => $hash,
                        'owner' => $entry['owner'] ?? 'unknown',
                        'lines' => $lineCount,
                        'link' => '?' . http_build_query(['i' => $hash]),
                        'auto' => !empty($entry['auto']),
                        'dedup' => !empty($entry['dedup']),
                        'keep_comments' => !empty($entry['keep_comments']),
                        'public' => true,
                    ];
                }
            }
            echo json_encode(['success' => true, 'subs' => $public]);
            exit;

        case 'get_content':
            $hash = preg_replace('/[^a-f0-9]/', '', $input['hash'] ?? '');
            if (strlen($hash) !== 16) {
                echo json_encode(['success' => false, 'error' => 'Invalid hash']);
                exit;
            }
            if (!isset($registry[$hash]) || ($registry[$hash]['owner'] ?? '') !== $login) {
                echo json_encode(['success' => false, 'error' => 'Not found or access denied']);
                exit;
            }
            $filePath = getSubFilePath($hash);
            $content = file_exists($filePath) ? file_get_contents($filePath) : '';
            $entry = $registry[$hash];
            $isAuto = !empty($entry['auto']);
            echo json_encode([
                'success' => true,
                'content' => $content,
                'name' => $entry['name'] ?? '',
                'auto' => $isAuto,
                'urls' => $isAuto ? ($entry['urls'] ?? []) : [],
                'period' => $isAuto ? ($entry['period'] ?? 3600) : 0,
                'last_update' => $isAuto ? ($entry['last_update'] ?? 0) : 0,
                'dedup' => !empty($entry['dedup']),
                'keep_comments' => !empty($entry['keep_comments']),
                'public' => !empty($entry['public']),
            ]);
            exit;

        case 'save_sub':
            $name = trim($input['name'] ?? '');
            if (empty($name)) {
                echo json_encode(['success' => false, 'error' => 'Укажите название подписки']);
                exit;
            }
            if (strlen($name) > 128) {
                echo json_encode(['success' => false, 'error' => 'Название слишком длинное (макс. 128 символов)']);
                exit;
            }

            $hash = getHash($name, $login);

            $nameExists = false;
            foreach ($registry as $existingHash => $existingEntry) {
                if (($existingEntry['owner'] ?? '') === $login && ($existingEntry['name'] ?? '') === $name) {
                    $nameExists = true;
                    break;
                }
            }
            if ($nameExists) {
                echo json_encode(['success' => false, 'error' => 'У вас уже есть подписка с таким названием. Выберите другое название.']);
                exit;
            }

            $proxies = trim($input['proxies'] ?? '');
            $subUrl = trim($input['sub_url'] ?? '');
            $auto = !empty($input['auto']);
            $urls = $input['urls'] ?? [];
            $period = intval($input['period'] ?? 0);
            $dedup = !empty($input['dedup']);
            $keep_comments = !empty($input['keep_comments']);
            $public = !empty($input['public']);

            if ($auto) {
                if (is_array($urls)) {
                    $urls = array_values(array_filter(array_map('trim', $urls), fn($u) => !empty($u)));
                } else {
                    $urls = [];
                }
                if (count($urls) > 5) $urls = array_slice($urls, 0, 5);
                if (empty($urls)) {
                    echo json_encode(['success' => false, 'error' => 'Укажите хотя бы один URL для автообновления']);
                    exit;
                }
                if ($period < 3600) {
                    echo json_encode(['success' => false, 'error' => 'Минимальный период автообновления — 1 час']);
                    exit;
                }
            }

            $allLines = [];

            // Ручные прокси
            if (!empty($proxies)) {
                $lines = explode("\n", $proxies);
                foreach ($lines as $line) {
                    $line = trim($line);
                    if ($line === '') continue;
                    if ($keep_comments || isProxyLine($line)) {
                        $allLines[] = $line;
                    }
                }
            }

            // Однократный URL
            if (!empty($subUrl)) {
                $result = fetchSubscription($subUrl, $userSeed);
                if ($result !== null && $result['status'] < 400) {
                    if ($keep_comments) {
                        $body = $result['body'];
                        $decoded = base64_decode($body, true);
                        if ($decoded !== false && strlen($decoded) > 10) $body = $decoded;
                        foreach (explode("\n", $body) as $line) {
                            $line = trim($line);
                            if ($line !== '') $allLines[] = $line;
                        }
                    } else {
                        $parsed = parseSubscriptionResponse($result['body'], $result['headers']);
                        if ($parsed !== null && !empty($parsed['links'])) {
                            foreach ($parsed['links'] as $link) $allLines[] = $link;
                        } else {
                            foreach (extractLinksFromText($result['body']) as $link) $allLines[] = $link;
                        }
                    }
                }
            }

            // Авто-URL + сбор мета-заголовков
            $sourcesMeta = [];
            if ($auto) {
                foreach ($urls as $url) {
                    $result = fetchSubscription($url, $userSeed);
                    if ($result !== null && $result['status'] < 400) {
                        $upstream = parseUpstreamHeaders($result['headers']);
                        $sourcesMeta[$url] = [
                            'subscription-userinfo' => $upstream['subscription-userinfo'] ?? '',
                            'profile-update-interval' => $upstream['profile-update-interval'] ?? '',
                            'profile-web-page-url' => $upstream['profile-web-page-url'] ?? '',
                            'content-disposition' => $upstream['content-disposition'] ?? '',
                            'fetched_at' => time(),
                        ];
                        
                        if ($keep_comments) {
                            $body = $result['body'];
                            $decoded = base64_decode($body, true);
                            if ($decoded !== false && strlen($decoded) > 10) $body = $decoded;
                            foreach (explode("\n", $body) as $line) {
                                $line = trim($line);
                                if ($line !== '') $allLines[] = $line;
                            }
                        } else {
                            $parsed = parseSubscriptionResponse($result['body'], $result['headers']);
                            if ($parsed !== null && !empty($parsed['links'])) {
                                foreach ($parsed['links'] as $link) $allLines[] = $link;
                            } else {
                                foreach (extractLinksFromText($result['body']) as $link) $allLines[] = $link;
                            }
                        }
                    }
                }
            }

            if ($dedup) {
                $allLines = dedupLines($allLines);
            }

            if (empty($allLines)) {
                echo json_encode(['success' => false, 'error' => 'Нет данных для сохранения. Добавьте прокси или укажите рабочую ссылку на подписку.']);
                exit;
            }

            $content = implode("\n", $allLines) . "\n";
            $filePath = getSubFilePath($hash);

            if (file_put_contents($filePath, $content, LOCK_EX) === false) {
                echo json_encode(['success' => false, 'error' => 'Ошибка записи файла']);
                exit;
            }

            $registry[$hash] = [
                'owner' => $login,
                'name' => $name,
                'dedup' => $dedup,
                'keep_comments' => $keep_comments,
                'public' => $public,
            ];
            if ($auto) {
                $registry[$hash]['auto'] = true;
                $registry[$hash]['urls'] = $urls;
                $registry[$hash]['period'] = $period;
                $registry[$hash]['last_update'] = time();
                $registry[$hash]['sources_meta'] = $sourcesMeta;
            }

            if (!saveRegistry($registry)) {
                echo json_encode(['success' => false, 'error' => 'Ошибка записи реестра']);
                exit;
            }

            $link = '?' . http_build_query(['i' => $hash]);
            echo json_encode([
                'success' => true,
                'message' => 'Подписка сохранена!',
                'name' => $name,
                'hash' => $hash,
                'link' => $link,
                'count' => count($allLines)
            ]);
            exit;

        case 'update_sub':
            $hash = preg_replace('/[^a-f0-9]/', '', $input['hash'] ?? '');
            if (strlen($hash) !== 16) {
                echo json_encode(['success' => false, 'error' => 'Invalid hash']);
                exit;
            }
            if (!isset($registry[$hash]) || ($registry[$hash]['owner'] ?? '') !== $login) {
                echo json_encode(['success' => false, 'error' => 'Not found or access denied']);
                exit;
            }

            $content = trim($input['content'] ?? '');
            $filePath = getSubFilePath($hash);
            file_put_contents($filePath, $content . "\n", LOCK_EX);
            echo json_encode(['success' => true, 'message' => 'Обновлено']);
            exit;

        case 'clear_sub':
            $hash = preg_replace('/[^a-f0-9]/', '', $input['hash'] ?? '');
            if (strlen($hash) !== 16) {
                echo json_encode(['success' => false, 'error' => 'Invalid hash']);
                exit;
            }
            if (!isset($registry[$hash]) || ($registry[$hash]['owner'] ?? '') !== $login) {
                echo json_encode(['success' => false, 'error' => 'Not found or access denied']);
                exit;
            }
            $filePath = getSubFilePath($hash);
            file_put_contents($filePath, '', LOCK_EX);
            echo json_encode(['success' => true, 'message' => 'Очищено', 'content' => '']);
            exit;

        case 'append_sub':
            $hash = preg_replace('/[^a-f0-9]/', '', $input['hash'] ?? '');
            $subUrl = trim($input['sub_url'] ?? '');

            if (strlen($hash) !== 16) {
                echo json_encode(['success' => false, 'error' => 'Invalid hash']);
                exit;
            }
            if (!isset($registry[$hash]) || ($registry[$hash]['owner'] ?? '') !== $login) {
                echo json_encode(['success' => false, 'error' => 'Not found or access denied']);
                exit;
            }
            if (empty($subUrl)) {
                echo json_encode(['success' => false, 'error' => 'Укажите ссылку на подписку']);
                exit;
            }

            $keep_comments = !empty($registry[$hash]['keep_comments']);
            $result = fetchSubscription($subUrl, $userSeed);
            if ($result === null || $result['status'] >= 400) {
                echo json_encode(['_success' => false, 'error' => 'Не удалось скачать подписку']);
                exit;
            }

            $newLines = [];
            if ($keep_comments) {
                $body = $result['body'];
                $decoded = base64_decode($body, true);
                if ($decoded !== false && strlen($decoded) > 10) $body = $decoded;
                foreach (explode("\n", $body) as $line) {
                    $line = trim($line);
                    if ($line !== '') $newLines[] = $line;
                }
            } else {
                $parsed = parseSubscriptionResponse($result['body'], $result['headers']);
                if ($parsed !== null && !empty($parsed['links'])) {
                    $newLines = $parsed['links'];
                } else {
                    $newLines = extractLinksFromText($result['body']);
                }
            }

            if (empty($newLines)) {
                echo json_encode(['success' => false, 'error' => 'Не удалось извлечь прокси из подписки']);
                exit;
            }

            $filePath = getSubFilePath($hash);
            $current = file_exists($filePath) ? file_get_contents($filePath) : '';
            $current = rtrim($current);

            $append = implode("\n", $newLines);
            if ($current !== '') {
                $final = $current . "\n" . $append . "\n";
            } else {
                $final = $append . "\n";
            }

            file_put_contents($filePath, $final, LOCK_EX);
            echo json_encode(['success' => true, 'message' => 'Добавлено ' . count($newLines) . ' строк', 'content' => $final]);
            exit;

        case 'update_auto':
            $hash = preg_replace('/[^a-f0-9]/', '', $input['hash'] ?? '');
            $urls = $input['urls'] ?? [];
            $period = intval($input['period'] ?? 0);

            if (strlen($hash) !== 16) {
                echo json_encode(['success' => false, 'error' => 'Invalid hash']);
                exit;
            }
            if (!isset($registry[$hash]) || ($registry[$hash]['owner'] ?? '') !== $login) {
                echo json_encode(['success' => false, 'error' => 'Not found or access denied']);
                exit;
            }
            if (empty($registry[$hash]['auto'])) {
                echo json_encode(['success' => false, 'error' => 'Подписка не является автообновляемой']);
                exit;
            }

            if (is_array($urls)) {
                $urls = array_values(array_filter(array_map('trim', $urls), fn($u) => !empty($u)));
            } else {
                $urls = [];
            }
            if (count($urls) > 5) $urls = array_slice($urls, 0, 5);
            if (empty($urls)) {
                echo json_encode(['success' => false, 'error' => 'Укажите хотя бы один URL']);
                exit;
            }
            if ($period < 3600) {
                echo json_encode(['success' => false, 'error' => 'Минимальный период — 1 час']);
                exit;
            }

            $registry[$hash]['urls'] = $urls;
            $registry[$hash]['period'] = $period;
            saveRegistry($registry);
            echo json_encode(['success' => true, 'message' => 'Настройки автообновления сохранены']);
            exit;

        case 'force_update':
            $hash = preg_replace('/[^a-f0-9]/', '', $input['hash'] ?? '');
            if (strlen($hash) !== 16) {
                echo json_encode(['success' => false, 'error' => 'Invalid hash']);
                exit;
            }
            if (!isset($registry[$hash]) || ($registry[$hash]['owner'] ?? '') !== $login) {
                echo json_encode(['success' => false, 'error' => 'Not found or access denied']);
                exit;
            }
            if (empty($registry[$hash]['auto'])) {
                echo json_encode(['success' => false, 'error' => 'Подписка не является автообновляемой']);
                exit;
            }

            $ok = refreshAutoSub($hash, $registry[$hash], $userSeed);
            if ($ok) {
                echo json_encode(['success' => true, 'message' => 'Подписка обновлена']);
            } else {
                echo json_encode(['success' => false, 'error' => 'Не удалось скачать ни одну из подписок. Проверьте URL.']);
            }
            exit;

        case 'delete_sub':
            $hash = preg_replace('/[^a-f0-9]/', '', $input['hash'] ?? '');
            if (strlen($hash) !== 16) {
                echo json_encode(['success' => false, 'error' => 'Invalid hash']);
                exit;
            }
            if (!isset($registry[$hash]) || ($registry[$hash]['owner'] ?? '') !== $login) {
                echo json_encode(['success' => false, 'error' => 'Not found or access denied']);
                exit;
            }

            $filePath = getSubFilePath($hash);
            if (file_exists($filePath)) {
                unlink($filePath);
            }
            unset($registry[$hash]);
            saveRegistry($registry);
            echo json_encode(['success' => true, 'message' => 'Удалено']);
            exit;

        case 'update_flags':
            $hash = preg_replace('/[^a-f0-9]/', '', $input['hash'] ?? '');
            if (strlen($hash) !== 16) {
                echo json_encode(['success' => false, 'error' => 'Invalid hash']);
                exit;
            }
            if (!isset($registry[$hash]) || ($registry[$hash]['owner'] ?? '') !== $login) {
                echo json_encode(['success' => false, 'error' => 'Not found or access denied']);
                exit;
            }
            $registry[$hash]['dedup'] = !empty($input['dedup']);
            $registry[$hash]['keep_comments'] = !empty($input['keep_comments']);
            $registry[$hash]['public'] = !empty($input['public']);
            saveRegistry($registry);
            echo json_encode(['success' => true, 'message' => 'Настройки обновлены']);
            exit;

        case 'save_all':
            $hash = preg_replace('/[^a-f0-9]/', '', $input['hash'] ?? '');
            if (strlen($hash) !== 16) {
                echo json_encode(['success' => false, 'error' => 'Invalid hash']);
                exit;
            }
            if (!isset($registry[$hash]) || ($registry[$hash]['owner'] ?? '') !== $login) {
                echo json_encode(['success' => false, 'error' => 'Not found or access denied']);
                exit;
            }

            $content = trim($input['content'] ?? '');
            $filePath = getSubFilePath($hash);
            file_put_contents($filePath, $content . "\n", LOCK_EX);

            $registry[$hash]['dedup'] = !empty($input['dedup']);
            $registry[$hash]['keep_comments'] = !empty($input['keep_comments']);
            $registry[$hash]['public'] = !empty($input['public']);

            if (!empty($registry[$hash]['auto'])) {
                $urls = $input['urls'] ?? [];
                $period = intval($input['period'] ?? 0);
                if (is_array($urls)) {
                    $urls = array_values(array_filter(array_map('trim', $urls), fn($u) => !empty($u)));
                } else {
                    $urls = [];
                }
                if (count($urls) > 5) $urls = array_slice($urls, 0, 5);
                if (!empty($urls) && $period >= 3600) {
                    $registry[$hash]['urls'] = $urls;
                    $registry[$hash]['period'] = $period;
                }
            }

            saveRegistry($registry);
            echo json_encode(['success' => true, 'message' => 'Все изменения сохранены']);
            exit;

        case 'get_sources_info':
            $hash = preg_replace('/[^a-f0-9]/', '', $input['hash'] ?? '');
            if (strlen($hash) !== 16) {
                echo json_encode(['success' => false, 'error' => 'Invalid hash']);
                exit;
            }
            if (!isset($registry[$hash]) || ($registry[$hash]['owner'] ?? '') !== $login) {
                echo json_encode(['success' => false, 'error' => 'Not found or access denied']);
                exit;
            }
            if (empty($registry[$hash]['auto'])) {
                echo json_encode(['success' => false, 'error' => 'Подписка не является автообновляемой']);
                exit;
            }

            $meta = $registry[$hash]['sources_meta'] ?? [];
            $sources = [];
            foreach ($meta as $url => $info) {
                $userinfo = $info['subscription-userinfo'] ?? '';
                $parsed = [];
                if ($userinfo) {
                    $parts = explode(';', $userinfo);
                    foreach ($parts as $part) {
                        $kv = explode('=', trim($part), 2);
                        if (count($kv) === 2) $parsed[trim($kv[0])] = trim($kv[1]);
                    }
                }
                $expire = isset($parsed['expire']) ? (int)$parsed['expire'] : 0;
                $total = isset($parsed['total']) ? (int)$parsed['total'] : 0;
                $upload = isset($parsed['upload']) ? (int)$parsed['upload'] : 0;
                $download = isset($parsed['download']) ? (int)$parsed['download'] : 0;
                $remaining = $total - $upload - $download;

                $sources[] = [
                    'url' => $url,
                    'upload' => $upload,
                    'download' => $download,
                    'total' => $total,
                    'remaining' => $remaining > 0 ? $remaining : 0,
                    'expire' => $expire,
                    'expire_date' => $expire > 0 ? date('Y-m-d H:i', $expire) : null,
                    'fetched_at' => $info['fetched_at'] ?? 0,
                    'raw' => $userinfo,
                ];
            }
            echo json_encode(['success' => true, 'sources' => $sources]);
            exit;
    }

    echo json_encode(['success' => false, 'error' => 'Unknown action']);
    exit;
}

// ==================== HTML INTERFACE ====================
?>

<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Proxy Manager</title>
    <style>
        :root {
            --bg: #0a0a0a;
            --fg: #e0e0e0;
            --card-bg: #141414;
            --card-border: #333;
            --input-bg: #141414;
            --input-border: #333;
            --input-fg: #e0e0e0;
            --primary: #2b7fff;
            --success: #28a745;
            --danger: #dc3545;
            --secondary: #333;
            --secondary-fg: #fff;
            --badge-bg: #1a5fb4;
            --badge2-bg: #6f42c1;
            --badge3-bg: #17a2b8;
            --badge4-bg: #e8590c;
            --hint: #666;
            --meta: #666;
            --link: #2b7fff;
            --result-bg: #0f2b1f;
            --result-border: #28a745;
            --result-code: #0a0a0a;
            --result-code-border: #1a3a2a;
            --result-code-fg: #4ade80;
            --tab-inactive: #666;
            --header-border: #333;
            --auto-block-bg: #0f0f0f;
            --auto-block-border: #222;
            --modal-overlay: rgba(0,0,0,0.85);
            --login-box-bg: #141414;
            --sub-link-bg: #0a0a0a;
            --sub-link-border: #222;
            --error: #ff4444;
            /* PM_SIG: часть цифровой подписи проекта */
            --pm-s1: #0a0a0a;
        }
        body.light {
            --bg: #f5f5f7;
            --fg: #1a1a1a;
            --card-bg: #ffffff;
            --card-border: #e0e0e0;
            --input-bg: #ffffff;
            --input-border: #d0d0d0;
            --input-fg: #1a1a1a;
            --primary: #0066cc;
            --success: #28a745;
            --danger: #dc3545;
            --secondary: #e0e0e0;
            --secondary-fg: #333;
            --badge-bg: #0066cc;
            --badge2-bg: #6f42c1;
            --badge3-bg: #17a2b8;
            --badge4-bg: #e8590c;
            --hint: #888;
            --meta: #888;
            --link: #0066cc;
            --result-bg: #e8f5e9;
            --result-border: #28a745;
            --result-code: #f0f0f0;
            --result-code-border: #c8e6c9;
            --result-code-fg: #2e7d32;
            --tab-inactive: #888;
            --header-border: #e0e0e0;
            --auto-block-bg: #fafafa;
            --auto-block-border: #e0e0e0;
            --modal-overlay: rgba(0,0,0,0.5);
            --login-box-bg: #ffffff;
            --sub-link-bg: #f5f5f5;
            --sub-link-border: #e0e0e0;
            --error: #dc3545;
            --pm-s1: #f5f5f5;
        }
        * { box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background: var(--bg);
            color: var(--fg);
            margin: 0;
            padding: 20px;
            line-height: 1.5;
            transition: background 0.3s, color 0.3s;
        }
        .container { max-width: 800px; margin: 0 auto; }
        h2 { color: var(--fg); border-bottom: 1px solid var(--header-border); padding-bottom: 10px; margin-top: 0; }
        h3 { color: var(--fg); margin-top: 30px; opacity: 0.8; }

        label { display: block; margin: 15px 0 5px; font-weight: 500; color: var(--hint); font-size: 14px; }
        input[type="text"], input[type="password"], textarea, select {
            width: 100%;
            background: var(--input-bg);
            border: 1px solid var(--input-border);
            color: var(--input-fg);
            padding: 12px;
            border-radius: 8px;
            font-family: monospace;
            font-size: 14px;
            outline: none;
            transition: border-color 0.2s, background 0.3s, color 0.3s;
        }
        input[type="text"]:focus, input[type="password"]:focus, textarea:focus, select:focus { border-color: var(--primary); }
        textarea { resize: vertical; min-height: 120px; }
        select { appearance: none; cursor: pointer; }

        .hint { color: var(--hint); font-size: 12px; margin-top: 4px; }
        .error { color: var(--error); font-size: 14px; margin-top: 8px; }
        .success { color: var(--success); font-size: 14px; margin-top: 8px; }

        button {
            margin-top: 12px;
            padding: 10px 20px;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-size: 14px;
            font-weight: 600;
            transition: all 0.2s;
            display: inline-flex;
            align-items: center;
            gap: 6px;
            background: var(--secondary);
            color: var(--secondary-fg);
        }
        button:hover { opacity: 0.9; transform: translateY(-1px); }
        button:active { transform: translateY(0); }
        button:disabled { opacity: 0.5; cursor: not-allowed; transform: none; }

        .btn-primary { background: var(--primary); color: #fff; }
        .btn-success { background: var(--success); color: #fff; }
        .btn-danger { background: var(--danger); color: #fff; }
        .btn-secondary { background: var(--secondary); color: var(--secondary-fg); }
        .btn-copy { background: var(--badge-bg); color: #fff; padding: 6px 12px; font-size: 12px; margin-top: 0; }

        .screen { display: none; }
        .screen.active { display: block; }

        .login-box {
            max-width: 400px;
            margin: 100px auto;
            background: var(--login-box-bg);
            border: 1px solid var(--card-border);
            border-radius: 12px;
            padding: 30px;
            text-align: center;
            transition: background 0.3s, border-color 0.3s;
        }
        .login-box h2 { border: none; text-align: center; }

        .sub-card {
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            border-radius: 10px;
            padding: 16px;
            margin-bottom: 12px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 10px;
            transition: background 0.3s, border-color 0.3s;
        }
        .sub-info { flex: 1; min-width: 200px; }
        .sub-name { font-weight: 600; color: var(--fg); font-size: 16px; display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
        .sub-meta { color: var(--meta); font-size: 12px; margin-top: 4px; }
        .sub-link { 
            color: var(--link); 
            font-size: 12px; 
            word-break: break-all; 
            margin-top: 6px;
            font-family: monospace;
            background: var(--sub-link-bg);
            padding: 6px 10px;
            border-radius: 6px;
            border: 1px solid var(--sub-link-border);
            transition: background 0.3s, border-color 0.3s;
        }
        .sub-actions { display: flex; gap: 8px; flex-wrap: wrap; }
        .badge {
            background: var(--badge-bg);
            color: #fff;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 600;
        }
        .badge-purple { background: var(--badge2-bg); }
        .badge-cyan { background: var(--badge3-bg); }
        .badge-orange { background: var(--badge4-bg); }

        .modal-overlay {
            display: none;
            position: fixed;
            top: 0; left: 0; right: 0; bottom: 0;
            background: var(--modal-overlay);
            z-index: 100;
            justify-content: center;
            align-items: center;
            padding: 20px;
        }
        .modal-overlay.active { display: flex; }
        .modal {
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            border-radius: 12px;
            padding: 24px;
            width: 100%;
            max-width: 700px;
            max-height: 90vh;
            overflow-y: auto;
            transition: background 0.3s, border-color 0.3s;
        }
        .modal-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }
        .modal-header h3 { margin: 0; }
        .close-btn {
            background: none;
            border: none;
            color: var(--hint);
            font-size: 24px;
            cursor: pointer;
            padding: 0;
            margin: 0;
        }
        .close-btn:hover { color: var(--fg); }

        .result-box {
            background: var(--result-bg);
            border: 1px solid var(--result-border);
            border-radius: 8px;
            padding: 16px;
            margin-top: 16px;
            display: none;
        }
        .result-box.active { display: block; }
        .result-box .link-row {
            display: flex;
            gap: 8px;
            align-items: center;
            margin-top: 10px;
        }
        .result-box code {
            background: var(--result-code);
            padding: 8px 12px;
            border-radius: 6px;
            font-family: monospace;
            font-size: 13px;
            word-break: break-all;
            flex: 1;
            border: 1px solid var(--result-code-border);
            color: var(--result-code-fg);
            transition: background 0.3s, border-color 0.3s, color 0.3s;
        }

        .tabs {
            display: flex;
            gap: 4px;
            margin-bottom: 20px;
            border-bottom: 1px solid var(--header-border);
            padding-bottom: 0;
            overflow-x: auto;
        }
        .tab {
            padding: 10px 20px;
            cursor: pointer;
            border-bottom: 2px solid transparent;
            color: var(--tab-inactive);
            font-weight: 500;
            transition: all 0.2s;
            white-space: nowrap;
        }
        .tab:hover { color: var(--fg); }
        .tab.active {
            color: var(--primary);
            border-bottom-color: var(--primary);
        }
        .tab-content { display: none; }
        .tab-content.active { display: block; }

        .auto-block {
            display: none;
            margin-top: 16px;
            padding: 16px;
            background: var(--auto-block-bg);
            border: 1px solid var(--auto-block-border);
            border-radius: 8px;
            transition: background 0.3s, border-color 0.3s;
        }
        .auto-block.active { display: block; }
        .auto-urls { display: flex; flex-direction: column; gap: 8px; }
        .auto-urls input { margin-top: 0; }

        .modal-actions {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
            margin-top: 16px;
            padding-top: 16px;
            border-top: 1px solid var(--auto-block-border);
        }
        .auto-section {
            display: none;
            margin-top: 20px;
            padding-top: 20px;
            border-top: 1px solid var(--auto-block-border);
        }
        .auto-section.active { display: block; }

        .panel-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 10px;
            margin-bottom: 20px;
        }
        .panel-header-left {
            display: flex;
            align-items: center;
            gap: 12px;
            flex-wrap: wrap;
        }
        .panel-header h2 {
            margin: 0;
            border: none;
            padding: 0;
        }
        .user-badge {
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            padding: 6px 12px;
            border-radius: 6px;
            font-family: monospace;
            font-size: 13px;
            color: var(--primary);
        }
        .panel-actions {
            display: flex;
            gap: 8px;
        }
        .panel-actions button {
            margin-top: 0;
            padding: 8px 12px;
        }

        .flags-section {
            margin-top: 16px;
            padding-top: 16px;
            border-top: 1px solid var(--auto-block-border);
        }
        .flags-section label {
            display: flex;
            align-items: center;
            gap: 8px;
            cursor: pointer;
            margin-top: 8px;
        }
        .flags-section label input[type="checkbox"] {
            width: auto;
            margin: 0;
        }

        /* --- Source Info Modal --- */
        .source-card {
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            border-radius: 10px;
            padding: 16px;
            margin-bottom: 12px;
            transition: background 0.3s, border-color 0.3s;
        }
        .source-url {
            font-family: monospace;
            font-size: 12px;
            color: var(--link);
            word-break: break-all;
            margin-bottom: 12px;
            padding-bottom: 10px;
            border-bottom: 1px solid var(--auto-block-border);
        }
        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 10px;
            margin-bottom: 12px;
        }
        .metric {
            background: var(--auto-block-bg);
            border: 1px solid var(--auto-block-border);
            border-radius: 6px;
            padding: 8px 10px;
        }
        .metric-label {
            font-size: 11px;
            color: var(--hint);
            margin-bottom: 2px;
        }
        .metric-value {
            font-size: 14px;
            font-weight: 600;
            color: var(--fg);
        }
        .progress-wrap {
            margin-bottom: 10px;
        }
        .progress-label {
            font-size: 12px;
            color: var(--hint);
            margin-bottom: 4px;
        }
        .progress-bg {
            background: var(--auto-block-border);
            border-radius: 4px;
            height: 8px;
            overflow: hidden;
        }
        .progress-fill {
            background: var(--primary);
            height: 100%;
            border-radius: 4px;
            transition: width 0.3s;
        }
        .source-footer {
            display: flex;
            justify-content: space-between;
            font-size: 12px;
            color: var(--fg);
            flex-wrap: wrap;
            gap: 6px;
        }

        /* --- Footer / Copyright --- */
        .pm-footer {
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid var(--header-border);
            text-align: center;
            font-size: 12px;
            color: var(--hint);
        }
        .pm-footer a {
            color: var(--link);
            text-decoration: none;
        }
        .pm-footer a:hover {
            text-decoration: underline;
        }

        @media (max-width: 600px) {
            .sub-card { flex-direction: column; align-items: flex-start; }
            .panel-header { flex-direction: column; align-items: flex-start; }
            .modal-actions { flex-direction: column; }
            .modal-actions button { width: 100%; justify-content: center; }
            .metrics-grid { grid-template-columns: 1fr; }
        }
    </style>
</head>
<body>
<div class="container">

<!-- Экран логина -->
<div id="loginScreen" class="screen active">
    <div class="login-box">
        <h2>🔐 Proxy Manager</h2>
        <p style="color:var(--hint); font-size:14px;">Введите логин и пароль для входа</p>
        <input type="text" id="loginInput" placeholder="Логин" autocomplete="off" style="text-align:center; margin-top:20px;">
        <input type="password" id="passwordInput" placeholder="Пароль" autocomplete="off" style="text-align:center; margin-top:12px;">
        <div class="hint">Логин: a-z, 0-9, _, - (макс. 32 символа). Новый аккаунт создаётся автоматически.</div>
        <div id="loginError" class="error"></div>
        <button class="btn-primary" onclick="doLogin()" style="width:100%; margin-top:16px;">Войти</button>
    </div>
</div>

<!-- Экран панели -->
<div id="panelScreen" class="screen">
    <div class="panel-header">
        <div class="panel-header-left">
            <h2>🛰 Proxy Manager</h2>
            <span class="user-badge">👤 <span id="displayLogin">---</span></span>
        </div>
        <div class="panel-actions">
            <button class="btn-secondary" onclick="toggleTheme()" id="themeBtn" style="font-size:16px;">☀️</button>
            <button class="btn-secondary" onclick="openSettings()">⚙️ Настройки</button>
            <button class="btn-secondary" onclick="doLogout()">🚪 Выйти</button>
        </div>
    </div>

    <div class="tabs">
        <div class="tab active" onclick="switchTab('create')">➕ Создать</div>
        <div class="tab" onclick="switchTab('list')">📋 Мои</div>
        <div class="tab" onclick="switchTab('public')">🌐 Публичные</div>
    </div>

    <!-- Вкладка создания -->
    <div id="tab-create" class="tab-content active">
        <label for="subName">Название подписки:</label>
        <input type="text" id="subName" placeholder="Моя подписка №1">
        <div class="hint">Любое название. В ссылке будет зашифрованный хеш.</div>

        <label style="display:flex; align-items:center; gap:8px; cursor:pointer; margin-top:12px;">
            <input type="checkbox" id="autoToggle" onchange="toggleAuto()" style="width:auto;">
            <span>🔄 Автообновление (подписка будет автоматически обновляться из указанных URL)</span>
        </label>

        <div id="autoBlock" class="auto-block">
            <label>URL подписок для автообновления (макс. 5):</label>
            <div id="autoUrls" class="auto-urls">
                <input type="text" class="auto-url" placeholder="https://example.com/sub?token=...">
            </div>
            <button class="btn-secondary" onclick="addAutoUrl()" id="addUrlBtn" style="margin-top:8px; padding:6px 12px; font-size:12px;">+ Добавить URL</button>

            <label style="margin-top:16px;">Период обновления:</label>
            <select id="autoPeriod">
                <option value="3600">1 час</option>
                <option value="10800">3 часа</option>
                <option value="21600">6 часов</option>
                <option value="43200">12 часов</option>
                <option value="86400">24 часа</option>
            </select>
            <div class="hint">Минимум 1 час. При запросе клиентом ?i=hash файл обновится автоматически, если прошло больше выбранного времени.</div>
        </div>

        <label style="display:flex; align-items:center; gap:8px; cursor:pointer; margin-top:16px;">
            <input type="checkbox" id="dedupToggle" style="width:auto;">
            <span>🔄 Удалять дублирующиеся прокси (дедупликация)</span>
        </label>

        <label style="display:flex; align-items:center; gap:8px; cursor:pointer; margin-top:8px;">
            <input type="checkbox" id="commentsToggle" style="width:auto;">
            <span>💬 Сохранять комментарии из подписок (строки с #)</span>
        </label>

        <label style="display:flex; align-items:center; gap:8px; cursor:pointer; margin-top:8px;">
            <input type="checkbox" id="publicToggle" style="width:auto;">
            <span>🌐 Публичная подписка (видна всем пользователям)</span>
        </label>

        <label for="proxies" style="margin-top:16px;">Прокси (по одной ссылке на строку):</label>
        <textarea id="proxies" placeholder="vless://...&#10;vmess://...&#10;trojan://..."></textarea>
        <div class="hint">Поддерживаются: vless, vmess, ss, ssr, trojan, hysteria, hysteria2, tuic, wireguard</div>

        <label for="subUrl">Или ссылка на подписку (однократно при создании):</label>
        <input type="text" id="subUrl" placeholder="https://example.com/subscription?token=...">
        <div class="hint">Будет скачана и добавлена один раз. Для регулярного обновления используйте автообновление.</div>

        <button class="btn-success" onclick="saveSub()">💾 Сохранить подписку</button>
        <div id="saveError" class="error"></div>

        <div id="saveResult" class="result-box">
            <div style="font-weight:600; color:var(--result-code-fg);">✅ Подписка сохранена!</div>
            <div style="margin-top:8px; color:var(--hint); font-size:13px;">Ссылка для клиента:</div>
            <div class="link-row">
                <code id="resultLink"></code>
                <button class="btn-copy" onclick="copyResult()">📋 Копировать</button>
            </div>
        </div>
    </div>

    <!-- Вкладка моих подписок -->
    <div id="tab-list" class="tab-content">
        <div id="subsList">
            <div style="color:var(--hint); text-align:center; padding:40px;">Загрузка...</div>
        </div>
    </div>

    <!-- Вкладка публичных подписок -->
    <div id="tab-public" class="tab-content">
        <div id="publicSubsList">
            <div style="color:var(--hint); text-align:center; padding:40px;">Загрузка...</div>
        </div>
    </div>

    <!-- Футер с копирайтом -->
    <div class="pm-footer" id="pmFooter"></div>
</div>

<!-- Модалка редактирования -->
<div id="editModal" class="modal-overlay">
    <div class="modal">
        <div class="modal-header">
            <div>
                <h3>✏️ Редактировать подписку</h3>
                <div id="editFlags" style="color:var(--hint); font-size:12px; margin-top:4px;"></div>
            </div>
            <button class="close-btn" onclick="closeEdit()">&times;</button>
        </div>

        <input type="hidden" id="editHash">
        <input type="hidden" id="editName">

        <label>Содержимое файла:</label>
        <textarea id="editContent" rows="8"></textarea>
        <div class="hint">Каждая строка — отдельная ссылка на прокси</div>

        <div class="flags-section">
            <h4 style="margin:0 0 12px 0; color:var(--fg); font-size:14px;">⚙️ Флаги подписки</h4>
            <label>
                <input type="checkbox" id="editDedupToggle" onchange="autoSaveFlag('dedup', this.checked)">
                <span>🔄 Удалять дублирующиеся прокси (дедупликация)</span>
            </label>
            <label>
                <input type="checkbox" id="editCommentsToggle" onchange="autoSaveFlag('keep_comments', this.checked)">
                <span>💬 Сохранять комментарии из подписок (строки с #)</span>
            </label>
            <label>
                <input type="checkbox" id="editPublicToggle" onchange="autoSaveFlag('public', this.checked)">
                <span>🌐 Публичная подписка (видна всем пользователям)</span>
            </label>
        </div>

        <div id="editAutoSection" class="auto-section">
            <h3 style="margin-top:0; color:var(--primary);">🔄 Настройки автообновления</h3>

            <label>URL подписок (макс. 5):</label>
            <div id="editAutoUrls" class="auto-urls"></div>

            <label style="margin-top:12px;">Период обновления:</label>
            <select id="editAutoPeriod">
                <option value="3600">1 час</option>
                <option value="10800">3 часа</option>
                <option value="21600">6 часов</option>
                <option value="43200">12 часов</option>
                <option value="86400">24 часа</option>
            </select>
        </div>

        <div class="modal-actions">
            <button class="btn-success" onclick="saveAll()">💾 Сохранить всё</button>
            <button class="btn-secondary" onclick="appendToSub()">📥 Добавить из подписки</button>
            <button class="btn-danger" onclick="clearSub()">🧹 Очистить содержимое</button>
        </div>

        <div id="editAppendWrap" style="display:none; margin-top:16px;">
            <label>Ссылка на подписку для добавления:</label>
            <input type="text" id="editAppendUrl" placeholder="https://example.com/sub?token=...">
            <div class="hint">Будет скачано и дописано в конец текущего файла</div>
            <button class="btn-success" onclick="doAppend()" style="margin-top:8px;">✅ Подтвердить добавление</button>
            <button class="btn-secondary" onclick="cancelAppend()" style="margin-top:8px;">Отмена</button>
        </div>

        <div id="editError" class="error"></div>
    </div>
</div>

<!-- Модалка информации об источниках -->
<div id="sourcesInfoModal" class="modal-overlay">
    <div class="modal">
        <div class="modal-header">
            <h3>📊 Информация об источниках</h3>
            <button class="close-btn" onclick="closeSourcesInfo()">&times;</button>
        </div>
        <input type="hidden" id="sourcesInfoHash">
        <div id="sourcesInfoList">
            <div style="color:var(--hint); text-align:center; padding:20px;">Загрузка...</div>
        </div>
    </div>
</div>

<!-- Модалка настроек пользователя -->
<div id="settingsModal" class="modal-overlay">
    <div class="modal" style="max-width: 500px;">
        <div class="modal-header">
            <h3>⚙️ Настройки пользователя</h3>
            <button class="close-btn" onclick="closeSettings()">&times;</button>
        </div>

        <label>HWID Seed (строка для генерации X-Hwid):</label>
        <input type="text" id="settingsHwid" placeholder="Оставьте пустым для значения по умолчанию">
        <div class="hint">Используется при скачивании подписок. Если пусто — используется системный seed.</div>

        <div style="margin-top:16px;">
            <button class="btn-success" onclick="saveSettings()">💾 Сохранить настройки</button>
        </div>
        <div id="settingsError" class="error"></div>
    </div>
</div>

</div>

<script>
// =============================================================================
// КОПИРАЙТ ВСТРОЕН В ЛОГИКУ — УДАЛЕНИЕ СЛОМАЕТ ФУНКЦИОНАЛЬНОСТЬ
// =============================================================================

// Часть 1: константы, используемые в генерации ключей localStorage
const _pm_k = ['pm','_','l','o','g','i','n'].join('');
const _pm_p = ['pm','_','p','a','s','s','w','o','r','d'].join('');

// Часть 2: метаданные проекта (используются в валидации)
const _pm_meta = (function(){
    const a = atob('aHR0cHM6Ly90Lm1lL2JvYmVyNDE='); // https://t.me/bober41
    const b = atob('aHR0cHM6Ly9naXRodWIuY29tL2VsZGV2ZXgvUHJveHktTWFuYWdlcg=='); // https://github.com/eldevex/Proxy-Manager
    const c = [80,114,111,120,121,32,77,97,110,97,103,101,114].map(x=>String.fromCharCode(x)).join(''); // Proxy Manager
    return {a,b,c};
})();

// Часть 3: валидация целостности — проверяет, что метаданные не повреждены
function _pm_check() {
    try {
        return _pm_meta.a.length > 10 && _pm_meta.b.length > 20 && _pm_meta.c === 'Proxy Manager';
    } catch(e) { return false; }
}

const API_URL = '';
let currentLogin = localStorage.getItem(_pm_k) || '';
let currentPassword = localStorage.getItem(_pm_p) || '';

if (currentLogin && currentPassword && _pm_check()) {
    showPanel();
    loadSubs();
}

function doLogin() {
    const login = document.getElementById('loginInput').value.trim();
    const password = document.getElementById('passwordInput').value;

    if (!login || !/^[a-zA-Z0-9_\-]+$/.test(login)) {
        document.getElementById('loginError').textContent = 'Логин может содержать только a-z, 0-9, _, - (макс. 32 символа)';
        return;
    }
    if (!password) {
        document.getElementById('loginError').textContent = 'Введите пароль';
        return;
    }

    document.getElementById('loginError').textContent = '';
    const btn = event.target;
    btn.disabled = true;
    btn.textContent = 'Вход...';

    fetch(API_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'login', login, password })
    })
    .then(r => r.json())
    .then(data => {
        btn.disabled = false;
        btn.textContent = 'Войти';
        if (!data.success) {
            document.getElementById('loginError').textContent = data.error;
            return;
        }
        currentLogin = login;
        currentPassword = password;
        localStorage.setItem(_pm_k, login);
        localStorage.setItem(_pm_p, password);
        document.getElementById('loginError').textContent = '';
        showPanel();
        loadSubs();
    })
    .catch(() => {
        btn.disabled = false;
        btn.textContent = 'Войти';
        document.getElementById('loginError').textContent = 'Ошибка сети';
    });
}

function doLogout() {
    localStorage.removeItem(_pm_k);
    localStorage.removeItem(_pm_p);
    currentLogin = '';
    currentPassword = '';
    document.getElementById('loginInput').value = '';
    document.getElementById('passwordInput').value = '';
    document.getElementById('loginScreen').classList.add('active');
    document.getElementById('panelScreen').classList.remove('active');
}

function showPanel() {
    document.getElementById('loginScreen').classList.remove('active');
    document.getElementById('panelScreen').classList.add('active');
    document.getElementById('displayLogin').textContent = currentLogin;
    applyTheme();
    renderFooter();
}

// Часть 4: генерация футера из обфусцированных данных
function renderFooter() {
    if (!_pm_check()) return;
    const el = document.getElementById('pmFooter');
    if (!el) return;
    const a = _pm_meta.a;
    const b = _pm_meta.b;
    const t = _pm_meta.c;
    el.innerHTML = 
        '© ' + new Date().getFullYear() + ' ' + t + ' — ' +
        'Автор: <a href="' + a + '" target="_blank" rel="noopener">@bober41</a> · ' +
        'Исходный код: <a href="' + b + '" target="_blank" rel="noopener">GitHub</a>';
}

function applyTheme() {
    const theme = localStorage.getItem('pm_theme') || 'dark';
    document.body.classList.toggle('light', theme === 'light');
    const btn = document.getElementById('themeBtn');
    if (btn) btn.textContent = theme === 'light' ? '🌙' : '☀️';
}

function toggleTheme() {
    const current = localStorage.getItem('pm_theme') || 'dark';
    const next = current === 'dark' ? 'light' : 'dark';
    localStorage.setItem('pm_theme', next);
    applyTheme();
}

function switchTab(tab) {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
    event.target.classList.add('active');
    document.getElementById('tab-' + tab).classList.add('active');
    if (tab === 'list') loadSubs();
    if (tab === 'public') loadPublicSubs();
}

function toggleAuto() {
    const checked = document.getElementById('autoToggle').checked;
    document.getElementById('autoBlock').classList.toggle('active', checked);
}

function addAutoUrl() {
    const container = document.getElementById('autoUrls');
    if (container.children.length >= 5) return;
    const input = document.createElement('input');
    input.type = 'text';
    input.className = 'auto-url';
    input.placeholder = 'https://example.com/sub?token=...';
    container.appendChild(input);
    if (container.children.length >= 5) {
        document.getElementById('addUrlBtn').style.display = 'none';
    }
}

async function api(action, data) {
    const payload = { ...data, action, login: currentLogin, password: currentPassword };
    const res = await fetch(API_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
    });
    return res.json();
}

async function saveSub() {
    const name = document.getElementById('subName').value.trim();
    const proxies = document.getElementById('proxies').value;
    const subUrl = document.getElementById('subUrl').value.trim();
    const auto = document.getElementById('autoToggle').checked ? 1 : 0;
    const dedup = document.getElementById('dedupToggle').checked ? 1 : 0;
    const keep_comments = document.getElementById('commentsToggle').checked ? 1 : 0;
    const public_flag = document.getElementById('publicToggle').checked ? 1 : 0;

    document.getElementById('saveError').textContent = '';
    document.getElementById('saveResult').classList.remove('active');

    if (!name) {
        document.getElementById('saveError').textContent = 'Укажите название подписки';
        return;
    }

    let urls = [];
    let period = 0;
    if (auto) {
        document.querySelectorAll('.auto-url').forEach(inp => {
            if (inp.value.trim()) urls.push(inp.value.trim());
        });
        period = parseInt(document.getElementById('autoPeriod').value);
        if (urls.length === 0) {
            document.getElementById('saveError').textContent = 'Укажите хотя бы один URL для автообновления';
            return;
        }
    } else if (!proxies.trim() && !subUrl) {
        document.getElementById('saveError').textContent = 'Добавьте прокси или укажите ссылку на подписку';
        return;
    }

    const btn = event.target;
    btn.disabled = true;
    btn.textContent = 'Сохранение...';

    try {
        const data = await api('save_sub', { name, proxies, sub_url: subUrl, auto, urls, period, dedup, keep_comments, public: public_flag });
        btn.disabled = false;
        btn.textContent = '💾 Сохранить подписку';

        if (!data.success) {
            document.getElementById('saveError').textContent = data.error;
            return;
        }

        document.getElementById('saveResult').classList.add('active');
        document.getElementById('resultLink').textContent = window.location.origin + window.location.pathname + data.link;

        document.getElementById('subName').value = '';
        document.getElementById('proxies').value = '';
        document.getElementById('subUrl').value = '';
        document.getElementById('autoToggle').checked = false;
        document.getElementById('dedupToggle').checked = false;
        document.getElementById('commentsToggle').checked = false;
        document.getElementById('publicToggle').checked = false;
        toggleAuto();
        document.querySelectorAll('.auto-url').forEach((inp, i) => { if (i > 0) inp.remove(); else inp.value = ''; });
        document.getElementById('addUrlBtn').style.display = 'inline-flex';

    } catch (e) {
        btn.disabled = false;
        btn.textContent = '💾 Сохранить подписку';
        document.getElementById('saveError').textContent = 'Ошибка сети';
    }
}

function copyResult() {
    const text = document.getElementById('resultLink').textContent;
    navigator.clipboard.writeText(text).then(() => {
        const btn = event.target;
        const old = btn.textContent;
        btn.textContent = '✅ Скопировано';
        setTimeout(() => btn.textContent = old, 2000);
    });
}

async function loadSubs() {
    const container = document.getElementById('subsList');
    container.innerHTML = '<div style="color:var(--hint); text-align:center; padding:40px;">Загрузка...</div>';

    try {
        const data = await api('get_subs', {});
        if (!data.success) {
            container.innerHTML = '<div style="color:var(--error); text-align:center; padding:40px;">Ошибка загрузки</div>';
            return;
        }

        if (data.subs.length === 0) {
            container.innerHTML = '<div style="color:var(--hint); text-align:center; padding:40px;">У вас пока нет подписок. Создайте первую во вкладке «Создать».</div>';
            return;
        }

        let html = '';
        data.subs.forEach(sub => {
            const fullLink = window.location.origin + window.location.pathname + sub.link;
            let badges = '';
            if (sub.auto) badges += '<span class="badge">🔄 Авто</span>';
            if (sub.dedup) badges += '<span class="badge badge-purple">🔄 Дедуп</span>';
            if (sub.keep_comments) badges += '<span class="badge badge-cyan">💬 Комментарии</span>';
            if (sub.public) badges += '<span class="badge badge-orange">🌐 Публичная</span>';

            html += `
            <div class="sub-card">
                <div class="sub-info">
                    <div class="sub-name">${escapeHtml(sub.name)}${badges}</div>
                    <div class="sub-meta">${sub.lines} строк · Создано вами</div>
                    <div class="sub-link">${escapeHtml(fullLink)}</div>
                </div>
                <div class="sub-actions">
                    <button class="btn-copy" onclick="copyLink('${escapeHtml(fullLink)}')">📋 Копировать</button>
                    <button class="btn-secondary" onclick="openEdit('${escapeHtml(sub.hash)}', '${escapeHtml(sub.name)}')">✏️ Изменить</button>
                    ${sub.auto ? `
                        <button class="btn-secondary" onclick="forceUpdate('${escapeHtml(sub.hash)}')">🔄 Обновить</button>
                        <button class="btn-secondary" onclick="openSourcesInfo('${escapeHtml(sub.hash)}')">📊 Инфо</button>
                    ` : ''}
                    <button class="btn-danger" onclick="deleteSub('${escapeHtml(sub.hash)}')">🗑 Удалить</button>
                </div>
            </div>`;
        });
        container.innerHTML = html;

    } catch (e) {
        container.innerHTML = '<div style="color:var(--error); text-align:center; padding:40px;">Ошибка сети</div>';
    }
}

async function loadPublicSubs() {
    const container = document.getElementById('publicSubsList');
    container.innerHTML = '<div style="color:var(--hint); text-align:center; padding:40px;">Загрузка...</div>';

    try {
        const data = await api('get_public_subs', {});
        if (!data.success) {
            container.innerHTML = '<div style="color:var(--error); text-align:center; padding:40px;">Ошибка загрузки</div>';
            return;
        }

        if (data.subs.length === 0) {
            container.innerHTML = '<div style="color:var(--hint); text-align:center; padding:40px;">Пока нет публичных подписок от других пользователей.</div>';
            return;
        }

        let html = '';
        data.subs.forEach(sub => {
            const fullLink = window.location.origin + window.location.pathname + sub.link;
            let badges = '';
            if (sub.auto) badges += '<span class="badge">🔄 Авто</span>';
            if (sub.dedup) badges += '<span class="badge badge-purple">🔄 Дедуп</span>';
            if (sub.keep_comments) badges += '<span class="badge badge-cyan">💬 Комментарии</span>';
            badges += '<span class="badge badge-orange">🌐 Публичная</span>';

            html += `
            <div class="sub-card">
                <div class="sub-info">
                    <div class="sub-name">${escapeHtml(sub.name)}${badges}</div>
                    <div class="sub-meta">${sub.lines} строк · Автор: ${escapeHtml(sub.owner)}</div>
                    <div class="sub-link">${escapeHtml(fullLink)}</div>
                </div>
                <div class="sub-actions">
                    <button class="btn-copy" onclick="copyLink('${escapeHtml(fullLink)}')">📋 Копировать</button>
                </div>
            </div>`;
        });
        container.innerHTML = html;

    } catch (e) {
        container.innerHTML = '<div style="color:var(--error); text-align:center; padding:40px;">Ошибка сети</div>';
    }
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function copyLink(link) {
    navigator.clipboard.writeText(link).then(() => {
        const btn = event.target;
        const old = btn.textContent;
        btn.textContent = '✅ Скопировано';
        setTimeout(() => btn.textContent = old, 2000);
    });
}

async function deleteSub(hash) {
    if (!confirm('Удалить подписку? Это необратимо.')) return;

    try {
        const data = await api('delete_sub', { hash });
        if (data.success) {
            loadSubs();
        } else {
            alert(data.error);
        }
    } catch (e) {
        alert('Ошибка сети');
    }
}

async function openEdit(hash, name) {
    try {
        const data = await api('get_content', { hash });
        if (!data.success) {
            alert(data.error);
            return;
        }
        document.getElementById('editHash').value = hash;
        document.getElementById('editName').value = data.name || name;
        document.getElementById('editContent').value = data.content;
        document.getElementById('editError').textContent = '';
        document.getElementById('editAppendWrap').style.display = 'none';
        document.getElementById('editAppendUrl').value = '';

        document.getElementById('editDedupToggle').checked = !!data.dedup;
        document.getElementById('editCommentsToggle').checked = !!data.keep_comments;
        document.getElementById('editPublicToggle').checked = !!data.public;

        let flags = [];
        if (data.dedup) flags.push('🔄 Дедупликация включена');
        if (data.keep_comments) flags.push('💬 Комментарии сохраняются');
        if (data.public) flags.push('🌐 Публичная подписка');
        document.getElementById('editFlags').textContent = flags.join(' · ');

        const autoSection = document.getElementById('editAutoSection');
        if (data.auto) {
            autoSection.classList.add('active');
            const container = document.getElementById('editAutoUrls');
            container.innerHTML = '';
            for (let i = 0; i < 5; i++) {
                const inp = document.createElement('input');
                inp.type = 'text';
                inp.className = 'edit-auto-url';
                inp.value = data.urls[i] || '';
                inp.placeholder = 'https://example.com/sub?token=...';
                container.appendChild(inp);
            }
            document.getElementById('editAutoPeriod').value = data.period || 3600;
        } else {
            autoSection.classList.remove('active');
        }

        document.getElementById('editModal').classList.add('active');
    } catch (e) {
        alert('Ошибка сети');
    }
}

function closeEdit() {
    document.getElementById('editModal').classList.remove('active');
}

async function autoSaveFlag(flagName, value) {
    const hash = document.getElementById('editHash').value;
    const dedup = flagName === 'dedup' ? value : document.getElementById('editDedupToggle').checked;
    const keep_comments = flagName === 'keep_comments' ? value : document.getElementById('editCommentsToggle').checked;
    const public_flag = flagName === 'public' ? value : document.getElementById('editPublicToggle').checked;

    try {
        const data = await api('update_flags', { hash, dedup: dedup ? 1 : 0, keep_comments: keep_comments ? 1 : 0, public: public_flag ? 1 : 0 });
        if (data.success) {
            let flags = [];
            if (dedup) flags.push('🔄 Дедупликация включена');
            if (keep_comments) flags.push('💬 Комментарии сохраняются');
            if (public_flag) flags.push('🌐 Публичная подписка');
            document.getElementById('editFlags').textContent = flags.join(' · ');
            loadSubs();
        } else {
            document.getElementById('editError').textContent = data.error;
        }
    } catch (e) {
        document.getElementById('editError').textContent = 'Ошибка сети';
    }
}

async function saveAll() {
    const hash = document.getElementById('editHash').value;
    const content = document.getElementById('editContent').value;
    const dedup = document.getElementById('editDedupToggle').checked ? 1 : 0;
    const keep_comments = document.getElementById('editCommentsToggle').checked ? 1 : 0;
    const public_flag = document.getElementById('editPublicToggle').checked ? 1 : 0;

    let urls = [];
    let period = 0;
    const autoSection = document.getElementById('editAutoSection');
    if (autoSection.classList.contains('active')) {
        document.querySelectorAll('.edit-auto-url').forEach(inp => {
            if (inp.value.trim()) urls.push(inp.value.trim());
        });
        period = parseInt(document.getElementById('editAutoPeriod').value);
    }

    document.getElementById('editError').textContent = '';

    const btn = event.target;
    btn.disabled = true;
    const originalText = btn.textContent;
    btn.textContent = 'Сохранение...';

    try {
        const data = await api('save_all', {
            hash,
            content,
            dedup,
            keep_comments,
            public: public_flag,
            urls,
            period
        });

        btn.disabled = false;
        btn.textContent = originalText;

        if (!data.success) {
            document.getElementById('editError').textContent = data.error;
            return;
        }

        closeEdit();
        loadSubs();

    } catch (e) {
        btn.disabled = false;
        btn.textContent = originalText;
        document.getElementById('editError').textContent = 'Ошибка сети';
    }
}

function clearSub() {
    const hash = document.getElementById('editHash').value;
    if (!confirm('Очистить ВСЕ содержимое этой подписки? Файл станет пустым.')) return;

    api('clear_sub', { hash }).then(data => {
        if (data.success) {
            document.getElementById('editContent').value = '';
            document.getElementById('editError').textContent = '';
            loadSubs();
        } else {
            document.getElementById('editError').textContent = data.error;
        }
    }).catch(() => {
        document.getElementById('editError').textContent = 'Ошибка сети';
    });
}

function appendToSub() {
    document.getElementById('editAppendWrap').style.display = 'block';
    document.getElementById('editAppendUrl').focus();
}

function cancelAppend() {
    document.getElementById('editAppendWrap').style.display = 'none';
    document.getElementById('editAppendUrl').value = '';
}

async function doAppend() {
    const hash = document.getElementById('editHash').value;
    const url = document.getElementById('editAppendUrl').value.trim();
    document.getElementById('editError').textContent = '';

    if (!url) {
        document.getElementById('editError').textContent = 'Введите ссылку на подписку';
        return;
    }

    const btn = event.target;
    btn.disabled = true;
    btn.textContent = 'Загрузка...';

    try {
        const data = await api('append_sub', { hash, sub_url: url });
        btn.disabled = false;
        btn.textContent = '✅ Подтвердить добавление';

        if (!data.success) {
            document.getElementById('editError').textContent = data.error;
            return;
        }

        document.getElementById('editContent').value = data.content;
        document.getElementById('editAppendUrl').value = '';
        document.getElementById('editAppendWrap').style.display = 'none';
        loadSubs();

    } catch (e) {
        btn.disabled = false;
        btn.textContent = '✅ Подтвердить добавление';
        document.getElementById('editError').textContent = 'Ошибка сети';
    }
}

async function forceUpdate(hash) {
    const targetHash = hash || document.getElementById('editHash').value;
    const btn = event.target;
    const originalText = btn.textContent;
    btn.disabled = true;
    btn.textContent = 'Обновление...';

    try {
        const data = await api('force_update', { hash: targetHash });
        btn.disabled = false;
        btn.textContent = originalText;
        if (data.success) {
            alert('Подписка обновлена!');
            loadSubs();
        } else {
            alert(data.error || 'Ошибка');
        }
    } catch (e) {
        btn.disabled = false;
        btn.textContent = originalText;
        alert('Ошибка сети');
    }
}

// --- Sources Info ---
function formatBytes(bytes) {
    if (!bytes || bytes <= 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    const val = bytes / Math.pow(1024, i);
    return val.toFixed(2) + ' ' + units[i];
}

function formatDate(ts) {
    if (!ts) return '—';
    return new Date(ts * 1000).toLocaleString('ru-RU', { day:'2-digit', month:'2-digit', year:'numeric', hour:'2-digit', minute:'2-digit' });
}

async function openSourcesInfo(hash) {
    try {
        const data = await api('get_sources_info', { hash });
        if (!data.success) {
            alert(data.error);
            return;
        }
        document.getElementById('sourcesInfoHash').value = hash;
        renderSourcesInfo(data.sources);
        document.getElementById('sourcesInfoModal').classList.add('active');
    } catch (e) {
        alert('Ошибка сети');
    }
}

function renderSourcesInfo(sources) {
    const container = document.getElementById('sourcesInfoList');
    if (!sources || sources.length === 0) {
        container.innerHTML = '<div style="color:var(--hint); text-align:center; padding:20px;">Нет данных. Выполните обновление подписки.</div>';
        return;
    }
    let html = '';
    sources.forEach(src => {
        const total = src.total || 0;
        const used = (src.upload || 0) + (src.download || 0);
        const pct = total > 0 ? Math.round((used / total) * 100) : 0;

        html += `
        <div class="source-card">
            <div class="source-url">${escapeHtml(src.url)}</div>
            <div class="metrics-grid">
                <div class="metric">
                    <div class="metric-label">Загружено ↑</div>
                    <div class="metric-value">${formatBytes(src.upload)}</div>
                </div>
                <div class="metric">
                    <div class="metric-label">Скачано ↓</div>
                    <div class="metric-value">${formatBytes(src.download)}</div>
                </div>
                <div class="metric">
                    <div class="metric-label">Всего</div>
                    <div class="metric-value">${formatBytes(src.total)}</div>
                </div>
                <div class="metric">
                    <div class="metric-label">Осталось</div>
                    <div class="metric-value" style="color:var(--success);">${formatBytes(src.remaining)}</div>
                </div>
            </div>
            <div class="progress-wrap">
                <div class="progress-label">Использовано: ${pct}%</div>
                <div class="progress-bg">
                    <div class="progress-fill" style="width:${pct}%;"></div>
                </div>
            </div>
            <div class="source-footer">
                <span>⏳ Истекает: ${src.expire_date ? escapeHtml(src.expire_date) : '—'}</span>
                <span style="color:var(--hint);">Обновлено: ${formatDate(src.fetched_at)}</span>
            </div>
        </div>`;
    });
    container.innerHTML = html;
}

function closeSourcesInfo() {
    document.getElementById('sourcesInfoModal').classList.remove('active');
}

// Settings
async function openSettings() {
    try {
        const data = await api('get_settings', {});
        document.getElementById('settingsHwid').value = data.hwid_seed || '';
        document.getElementById('settingsModal').classList.add('active');
    } catch (e) {
        alert('Ошибка загрузки настроек');
    }
}

function closeSettings() {
    document.getElementById('settingsModal').classList.remove('active');
}

async function saveSettings() {
    const hwid_seed = document.getElementById('settingsHwid').value.trim();
    document.getElementById('settingsError').textContent = '';

    try {
        const data = await api('save_settings', { hwid_seed });
        if (data.success) {
            closeSettings();
            alert('Настройки сохранены');
        } else {
            document.getElementById('settingsError').textContent = data.error || 'Ошибка';
        }
    } catch (e) {
        document.getElementById('settingsError').textContent = 'Ошибка сети';
    }
}

// Закрытие модалок по клику вне их
document.getElementById('editModal').addEventListener('click', function(e) {
    if (e.target === this) closeEdit();
});
document.getElementById('settingsModal').addEventListener('click', function(e) {
    if (e.target === this) closeSettings();
});
document.getElementById('sourcesInfoModal').addEventListener('click', function(e) {
    if (e.target === this) closeSourcesInfo();
});

// Enter в поле пароля
document.getElementById('passwordInput').addEventListener('keypress', function(e) {
    if (e.key === 'Enter') doLogin();
});
</script>

</body>
</html>
