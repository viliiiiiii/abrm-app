<?php
declare(strict_types=1);

require_once __DIR__ . '/helpers.php';
require_once __DIR__ . '/auth.php';

// Already logged in? Bounce to home (or ?next)
if (current_user()) {
    $next = $_GET['next'] ?? '';
    $dest = '/index.php';
    if ($next) {
        // only allow internal, relative paths
        $p = parse_url($next, PHP_URL_PATH);
        if (is_string($p) && str_starts_with($p, '/')) {
            $dest = $p . (($_SERVER['QUERY_STRING'] ?? '') && !str_contains($p, '?') ? '' : '');
        }
    }
    header('Location: ' . $dest);
    exit;
}

/* ----------------------
   Simple rate limiting
   ---------------------- */
$ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
$bucketKey = 'login_rl_' . $ip;
if (!isset($_SESSION)) { session_start(); } // should already be started in helpers, but be safe

$bucket = $_SESSION[$bucketKey] ?? ['count' => 0, 'until' => 0];
$now    = time();

$cooldownActive = ($bucket['until'] ?? 0) > $now;
$timeLeft       = max(0, (int)($bucket['until'] ?? 0) - $now);

$error = '';
$next  = (string)($_GET['next'] ?? ($_POST['next'] ?? ''));
$authException = null;

// Preserve entered email between attempts
$prefillEmail = (string)($_POST['email'] ?? '');

// If too many recent failures, short-circuit
if (is_post() && $cooldownActive) {
    $mins = ceil($timeLeft / 60);
    $error = "Too many failed attempts. Try again in {$mins} minute" . ($mins === 1 ? '' : 's') . '.';
} elseif (is_post()) {
    if (!verify_csrf_token($_POST[CSRF_TOKEN_NAME] ?? null)) {
        $error = 'Invalid CSRF token.';
    } else {
        // Honeypot: real users leave this blank
        $hp = trim((string)($_POST['company'] ?? ''));
        if ($hp !== '') {
            // Treat as success to bots, but do nothing.
            $error = 'Invalid credentials.'; // generic
        } else {
            $email    = trim((string)($_POST['email'] ?? ''));
            $password = (string)($_POST['password'] ?? '');

            if ($email === '' || $password === '') {
                $error = 'Email and password are required.';
            } else {
                // Attempt login
                try {
                    $loginSuccess = attempt_login($email, $password);
                } catch (RuntimeException $e) {
                    $authException = $e->getMessage();
                    $loginSuccess = false;
                }

                if (!$loginSuccess) {
                    if ($authException !== null) {
                        $error = $authException;
                    } else {
                        // bump bucket
                        $bucket['count'] = (int)($bucket['count'] ?? 0) + 1;
                        if ($bucket['count'] >= 5) {
                            $bucket['until'] = $now + 5 * 60; // 5 minutes
                            $bucket['count'] = 0;             // reset count after applying cooldown
                        }
                        $_SESSION[$bucketKey] = $bucket;
                        $error = 'Invalid credentials.';
                    }
                } else {
                    // success: clear rate limit
                    unset($_SESSION[$bucketKey]);

                    // Safe redirect: only allow relative internal path
                    $dest = '/index.php';
                    if ($next) {
                        $path = parse_url($next, PHP_URL_PATH);
                        $qs   = parse_url($next, PHP_URL_QUERY);
                        if (is_string($path) && str_starts_with($path, '/')) {
                            $dest = $path . ($qs ? ('?' . $qs) : '');
                        }
                    }
                    redirect_with_message($dest, 'Welcome back!');
                }
            }
        }
    }
}

$coreHealthy = core_pdo_available();
$title = 'Login';
include __DIR__ . '/includes/header.php';
?>
<!-- Prevent indexing -->
<meta name="robots" content="noindex, nofollow">

<style>
.auth-wrapper {
  min-height: calc(100dvh - 120px);
  display: grid;
  place-items: center;
  padding: 32px 16px;
  background: radial-gradient(circle at 10% 20%, rgba(59,130,246,0.12), transparent 55%),
              radial-gradient(circle at 80% 0%, rgba(14,165,233,0.15), transparent 50%),
              linear-gradient(180deg, rgba(15,23,42,0.02) 0%, rgba(15,23,42,0.05) 100%);
}

.auth-shell {
  display: grid;
  gap: 28px;
  width: min(900px, 100%);
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  align-items: stretch;
}

.auth-info {
  position: relative;
  padding: 32px;
  border-radius: 24px;
  background: rgba(255, 255, 255, 0.82);
  border: 1px solid rgba(148, 163, 184, 0.28);
  box-shadow: 0 24px 45px rgba(15, 23, 42, 0.12);
  backdrop-filter: blur(16px);
}

.auth-info h1 {
  margin: 0 0 12px;
  font-size: 28px;
  line-height: 1.15;
  color: #0f172a;
}

.auth-info p {
  margin: 0 0 18px;
  color: #475569;
  font-size: 15px;
}

.auth-points {
  list-style: none;
  margin: 0;
  padding: 0;
  display: grid;
  gap: 10px;
  font-size: 14px;
  color: #1f2937;
}

.auth-points li {
  display: flex;
  gap: 10px;
  align-items: flex-start;
}

.auth-points span.icon {
  color: #2563eb;
  font-size: 16px;
  line-height: 1.4;
}

.auth-card {
  position: relative;
  padding: 28px 24px;
  border-radius: 24px;
  background: rgba(255, 255, 255, 0.92);
  border: 1px solid rgba(148, 163, 184, 0.28);
  box-shadow: 0 18px 40px rgba(15, 23, 42, 0.12);
  backdrop-filter: blur(12px);
}

.auth-card h2 {
  margin: 0 0 8px;
  font-size: 22px;
  color: #0f172a;
}

.auth-sub {
  margin: 0 0 24px;
  color: #64748b;
  font-size: 14px;
}

.form-row {
  display: grid;
  gap: 8px;
  margin-bottom: 18px;
}

.form-row label {
  font-weight: 600;
  color: #0f172a;
  font-size: 13px;
  letter-spacing: 0.01em;
}

.input {
  width: 100%;
  padding: 12px 14px;
  border-radius: 12px;
  border: 1px solid rgba(148, 163, 184, 0.45);
  background: rgba(255, 255, 255, 0.98);
  box-shadow: inset 0 1px 2px rgba(15, 23, 42, 0.08);
  transition: border-color 0.18s ease, box-shadow 0.18s ease;
}

.input:focus {
  outline: none;
  border-color: rgba(59, 130, 246, 0.6);
  box-shadow: 0 0 0 4px rgba(59, 130, 246, 0.18);
}

.pw-wrap { position: relative; }

.pw-toggle {
  position: absolute;
  right: 10px;
  top: 50%;
  transform: translateY(-50%);
  border: 0;
  background: transparent;
  cursor: pointer;
  color: #64748b;
  padding: 6px;
  border-radius: 10px;
  transition: background 0.2s ease, color 0.2s ease;
}

.pw-toggle:hover {
  color: #1f2937;
  background: rgba(148, 163, 184, 0.18);
}

.actions {
  display: flex;
  gap: 10px;
  align-items: center;
  justify-content: space-between;
  margin-top: 12px;
}

.btn.wide {
  width: 100%;
  padding: 12px;
  border-radius: 999px;
  font-size: 15px;
  font-weight: 600;
  text-transform: none;
  box-shadow: 0 16px 30px rgba(37, 99, 235, 0.22);
}

.small-links {
  display: flex;
  justify-content: space-between;
  margin-top: 12px;
  font-size: 12px;
}

.small-links a {
  color: #2563eb;
  text-decoration: none;
}

.small-links a:hover {
  text-decoration: underline;
}

.status-badge {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 8px 12px;
  border-radius: 999px;
  background: rgba(59, 130, 246, 0.12);
  color: #1d4ed8;
  font-size: 12px;
  font-weight: 600;
}

.status-badge--error {
  background: rgba(239, 68, 68, 0.12);
  color: #b91c1c;
}

.hp { position: absolute !important; left: -10000px !important; width: 1px; height: 1px; overflow: hidden; }

@media (max-width: 720px) {
  .auth-wrapper { padding: 24px 12px; }
  .auth-info { padding: 24px 20px; border-radius: 20px; }
  .auth-card { padding: 24px 20px; border-radius: 20px; }
}
</style>

<div class="auth-wrapper">
  <div class="auth-shell">
    <section class="auth-info" aria-label="Application overview">
      <h1>Field operations control center</h1>
      <p>Review punch lists, coordinate rooms, and keep your inventory moving. Everything funnels through your CORE directory.</p>
      <ul class="auth-points">
        <li><span class="icon">✅</span><span>Centralised authentication using the CORE governance database.</span></li>
        <li><span class="icon">📋</span><span>Realtime status on tasks, rooms, and inventory transfers.</span></li>
        <li><span class="icon">🔐</span><span>Role-based access, sector awareness, and activity logging.</span></li>
      </ul>
      <?php if (!$coreHealthy): ?>
        <p class="status-badge status-badge--error" role="status">⚠️ CORE database offline – login may be unavailable.</p>
      <?php else: ?>
        <p class="status-badge" role="status">🔗 CORE directory connected</p>
      <?php endif; ?>
    </section>

    <form method="post" class="card auth-card" action="/login.php<?php echo $next ? ('?next=' . urlencode($next)) : ''; ?>" novalidate>
      <h2>Punch List Login</h2>
      <p class="auth-sub">Sign in with your CORE credentials to continue.</p>

      <?php if ($error): ?>
        <div class="flash flash-error" role="alert"><?php echo sanitize($error); ?></div>
      <?php elseif (!empty($_GET['msg'])): ?>
        <div class="flash"><?php echo sanitize((string)$_GET['msg']); ?></div>
      <?php endif; ?>

      <div class="form-row">
        <label for="email">Email</label>
        <input
          id="email"
          class="input"
          type="email"
          name="email"
          required
          autocomplete="username"
          autofocus
          value="<?php echo sanitize($prefillEmail); ?>">
      </div>

      <div class="form-row">
        <label for="password">Password</label>
        <div class="pw-wrap">
          <input
            id="password"
            class="input"
            type="password"
            name="password"
            required
            autocomplete="current-password">
          <button class="pw-toggle" type="button" aria-label="Show password" title="Show password" id="pwToggle">👁</button>
        </div>
      </div>

      <!-- Honeypot (leave empty) -->
      <div class="hp" aria-hidden="true">
        <label for="company">Company</label>
        <input id="company" type="text" name="company" tabindex="-1" autocomplete="off">
      </div>

      <input type="hidden" name="<?php echo CSRF_TOKEN_NAME; ?>" value="<?php echo csrf_token(); ?>">
      <?php if ($next): ?>
        <input type="hidden" name="next" value="<?php echo sanitize($next); ?>">
      <?php endif; ?>

      <div class="actions">
        <button type="submit" class="btn primary wide">Login</button>
      </div>

      <div class="small-links">
        <span></span>
        <span class="muted">Need help? Contact your admin.</span>
      </div>
    </form>
  </div>
</div>

<script>
(function(){
  const t = document.getElementById('pwToggle');
  const p = document.getElementById('password');
  if (!t || !p) return;
  t.addEventListener('click', () => {
    const show = p.type === 'password';
    p.type = show ? 'text' : 'password';
    t.textContent = show ? '🙈' : '👁';
    t.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
  });
})();
</script>

<?php include __DIR__ . '/includes/footer.php'; ?>
