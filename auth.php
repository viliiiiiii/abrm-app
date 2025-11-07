<?php
declare(strict_types=1);

require_once __DIR__ . '/helpers.php';

/**
 * Attempt login using the CORE database as the source of truth.
 * When a matching legacy record is found, it is synchronised into CORE
 * before completing authentication.
 */
function attempt_login(string $email, string $password): bool {
    $email = trim($email);
    if ($email === '' || $password === '') {
        return false;
    }

    $core = core_pdo_optional();
    if (!$core) {
        throw new RuntimeException('Authentication service is unavailable. Please contact your administrator.');
    }

    $user = core_find_user_by_email($email, true);
    if ($user && !empty($user['pass_hash']) && password_verify($password, (string)$user['pass_hash'])) {
        auth_login((int)$user['id']);
        enforce_not_suspended();
        log_event('login', 'user', (int)$user['id'], ['source' => 'core']);
        return true;
    }

    $legacy = legacy_find_user_by_email($email);
    if (!$legacy || empty($legacy['pass_hash']) || !password_verify($password, (string)$legacy['pass_hash'])) {
        return false;
    }

    try {
        core_sync_legacy_user($core, $legacy);
        $user = core_find_user_by_email($email, true, true);
    } catch (Throwable $e) {
        try {
            error_log('CORE sync failure during login: ' . $e->getMessage());
        } catch (Throwable $_) {}
        throw new RuntimeException('Unable to upgrade account into the CORE directory. Please contact your administrator.', 0, $e);
    }

    if ($user && !empty($user['id'])) {
        auth_login((int)$user['id']);
        enforce_not_suspended();
        log_event('login', 'user', (int)$user['id'], ['source' => 'legacy-sync']);
        return true;
    }

    return false;
}

/** Sign the user out and redirect */
function logout_and_redirect(string $to = 'login.php'): void {
    auth_logout();
    redirect_with_message($to, 'You have been signed out.', 'success');
}