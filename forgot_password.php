<?php
session_start();

$cn30 = mysqli_connect("localhost", "root", "", "30mm");

if (!$cn30) {
    error_log("Database connection failed: " . mysqli_connect_error());
    die("Database unavailable.");
}

mysqli_set_charset($cn30, "utf8mb4");

/*
    Set this to false in production.
    It is true here only so you can test OTP locally without SMS API.
*/
$show_otp_for_testing = true;

$otp_lifetime = 300;              // 5 minutes
$max_otp_attempts = 5;            // maximum wrong OTP attempts
$reset_verified_lifetime = 600;   // 10 minutes to change password after OTP verification

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

function reset_flash(string $type, string $text): void
{
    $_SESSION['reset_flash'][] = [
        'type' => $type,
        'text' => $text
    ];
}

function clear_reset_otp(): void
{
    unset(
        $_SESSION['generated_otp'],
        $_SESSION['otp_created_at'],
        $_SESSION['otp_attempts'],
        $_SESSION['debug_otp']
    );
}

function clear_reset_all(): void
{
    unset(
        $_SESSION['reset_user_id'],
        $_SESSION['reset_verified'],
        $_SESSION['reset_verified_at'],
        $_SESSION['generated_otp'],
        $_SESSION['otp_created_at'],
        $_SESSION['otp_attempts'],
        $_SESSION['debug_otp']
    );
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        reset_flash('danger', 'Invalid form submission. Please try again.');
        header("Location: forgot_password.php");
        exit();
    }

    /*
        Start over / request new OTP
    */
    if (isset($_POST['start_over'])) {
        clear_reset_all();
        header("Location: forgot_password.php");
        exit();
    }

    /*
        STEP 1: Check phone number and generate OTP
    */
    if (isset($_POST['send_otp'])) {
        $phone = trim($_POST['phone'] ?? '');

        if ($phone === '') {
            reset_flash('warning', 'Please enter your registered phone number.');
            header("Location: forgot_password.php");
            exit();
        }

        $stmt = mysqli_prepare($cn30, "SELECT ID FROM register WHERE phone = ? LIMIT 1");

        if (!$stmt) {
            reset_flash('danger', 'Database error. Please try again.');
            header("Location: forgot_password.php");
            exit();
        }

        mysqli_stmt_bind_param($stmt, "s", $phone);
        mysqli_stmt_execute($stmt);

        $result = mysqli_stmt_get_result($stmt);
        $row = mysqli_fetch_assoc($result);

        mysqli_stmt_close($stmt);

        if ($row) {
            $otp = (string) random_int(100000, 999999);

            $_SESSION['reset_user_id'] = (int) $row['ID'];
            $_SESSION['generated_otp'] = $otp;
            $_SESSION['otp_created_at'] = time();
            $_SESSION['otp_attempts'] = 0;

            unset($_SESSION['reset_verified'], $_SESSION['reset_verified_at']);

            if ($show_otp_for_testing) {
                $_SESSION['debug_otp'] = $otp;
            } else {
                unset($_SESSION['debug_otp']);
            }

            reset_flash('success', 'OTP sent to your registered phone number.');
        } else {
            reset_flash('warning', 'Phone number not found.');
        }

        header("Location: forgot_password.php");
        exit();
    }

    /*
        STEP 2: Verify OTP
    */
    if (isset($_POST['verify_otp'])) {
        if (empty($_SESSION['generated_otp']) || empty($_SESSION['reset_user_id'])) {
            reset_flash('warning', 'Please request an OTP first.');
            header("Location: forgot_password.php");
            exit();
        }

        if (time() - ($_SESSION['otp_created_at'] ?? 0) > $otp_lifetime) {
            clear_reset_otp();
            reset_flash('warning', 'OTP expired. Please request a new OTP.');
            header("Location: forgot_password.php");
            exit();
        }

        if (($_SESSION['otp_attempts'] ?? 0) >= $max_otp_attempts) {
            clear_reset_all();
            reset_flash('danger', 'Too many incorrect attempts. Please request a new OTP.');
            header("Location: forgot_password.php");
            exit();
        }

        $entered_otp = trim($_POST['otp'] ?? '');

        if (!ctype_digit($entered_otp) || strlen($entered_otp) !== 6) {
            $_SESSION['otp_attempts'] = ($_SESSION['otp_attempts'] ?? 0) + 1;

            if ($_SESSION['otp_attempts'] >= $max_otp_attempts) {
                clear_reset_all();
                reset_flash('danger', 'Too many incorrect attempts. Please request a new OTP.');
            } else {
                reset_flash('warning', 'Please enter a valid 6-digit OTP.');
            }

            header("Location: forgot_password.php");
            exit();
        }

        if (hash_equals($_SESSION['generated_otp'], $entered_otp)) {
            $userId = $_SESSION['reset_user_id'];

            clear_reset_otp();

            $_SESSION['reset_user_id'] = $userId;
            $_SESSION['reset_verified'] = true;
            $_SESSION['reset_verified_at'] = time();

            reset_flash('success', 'OTP verified successfully. Set your new password.');
        } else {
            $_SESSION['otp_attempts'] = ($_SESSION['otp_attempts'] ?? 0) + 1;

            if ($_SESSION['otp_attempts'] >= $max_otp_attempts) {
                clear_reset_all();
                reset_flash('danger', 'Too many incorrect attempts. Please request a new OTP.');
            } else {
                reset_flash('danger', 'Invalid OTP. Please try again.');
            }
        }

        header("Location: forgot_password.php");
        exit();
    }

    /*
        STEP 3: Update password
    */
    if (isset($_POST['update_password'])) {
        if (empty($_SESSION['reset_verified']) || empty($_SESSION['reset_user_id'])) {
            reset_flash('warning', 'Please verify OTP first.');
            header("Location: forgot_password.php");
            exit();
        }

        if (time() - ($_SESSION['reset_verified_at'] ?? 0) > $reset_verified_lifetime) {
            clear_reset_all();
            reset_flash('warning', 'Reset session expired. Please request a new OTP.');
            header("Location: forgot_password.php");
            exit();
        }

        $new_password = $_POST['new_password'] ?? '';
        $confirm_password = $_POST['confirm_password'] ?? '';

        if (strlen($new_password) < 8) {
            reset_flash('warning', 'Password must be at least 8 characters long.');
            header("Location: forgot_password.php");
            exit();
        }

        if ($new_password !== $confirm_password) {
            reset_flash('warning', 'Passwords do not match.');
            header("Location: forgot_password.php");
            exit();
        }

        $hashed_password = password_hash($new_password, PASSWORD_DEFAULT);
        $userId = (int) $_SESSION['reset_user_id'];

        $stmt = mysqli_prepare($cn30, "UPDATE register SET Password = ? WHERE ID = ? LIMIT 1");

        if ($stmt) {
            mysqli_stmt_bind_param($stmt, "si", $hashed_password, $userId);

            if (mysqli_stmt_execute($stmt) && mysqli_stmt_affected_rows($stmt) > 0) {
                mysqli_stmt_close($stmt);

                clear_reset_all();

                header("Location: login.php?reset=success");
                exit();
            }

            mysqli_stmt_close($stmt);
        }

        reset_flash('danger', 'Could not update password. Please try again.');
        header("Location: forgot_password.php");
        exit();
    }

    header("Location: forgot_password.php");
    exit();
}

$flashes = $_SESSION['reset_flash'] ?? [];
unset($_SESSION['reset_flash']);

$step = 1;

if (!empty($_SESSION['reset_verified'])) {
    $step = 3;
} elseif (!empty($_SESSION['generated_otp'])) {
    $step = 2;
}

/*
    If OTP expired while user was on the page, move back to step 1.
*/
if ($step === 2 && isset($_SESSION['otp_created_at']) && (time() - $_SESSION['otp_created_at'] > $otp_lifetime)) {
    clear_reset_otp();
    $step = 1;
    $flashes[] = [
        'type' => 'warning',
        'text' => 'OTP expired. Please request a new OTP.'
    ];
}

/*
    If verified reset session expired, move back to step 1.
*/
if ($step === 3 && isset($_SESSION['reset_verified_at']) && (time() - $_SESSION['reset_verified_at'] > $reset_verified_lifetime)) {
    clear_reset_all();
    $step = 1;
    $flashes[] = [
        'type' => 'warning',
        'text' => 'Reset session expired. Please request a new OTP.'
    ];
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reset Password</title>

    <link rel="stylesheet" href="Rutu2.css">
    <link rel="stylesheet" href="bootstrap/css/bootstrap.min.css">
</head>
<body class="bg-light">

<div class="container d-flex justify-content-center align-items-center vh-100">
    <div class="card shadow" style="width: 380px;">
        <div class="card-body">
            <h5 class="text-center mb-4">Password Recovery</h5>

            <?php if (!empty($flashes)): ?>
                <?php foreach ($flashes as $flash): ?>
                    <div class="alert alert-<?php echo htmlspecialchars($flash['type'] ?? 'info', ENT_QUOTES, 'UTF-8'); ?> py-2 small">
                        <?php echo htmlspecialchars($flash['text'] ?? '', ENT_QUOTES, 'UTF-8'); ?>
                    </div>
                <?php endforeach; ?>
            <?php endif; ?>

            <?php if ($step === 1): ?>
                <form method="post">
                    <input type="hidden" name="csrf_token"
                           value="<?php echo htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8'); ?>">

                    <p class="small text-muted">
                        Enter your registered phone number to receive an OTP.
                    </p>

                    <input type="tel"
                           name="phone"
                           class="form-control mb-3"
                           placeholder="Registered Phone Number"
                           autocomplete="tel"
                           required>

                    <button type="submit" name="send_otp" class="btn btn-primary w-100">
                        Send OTP
                    </button>
                </form>

            <?php elseif ($step === 2): ?>
                <form method="post">
                    <input type="hidden" name="csrf_token"
                           value="<?php echo htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8'); ?>">

                    <p class="small text-success text-center">
                        OTP sent to your registered phone number.
                    </p>

                    <?php if ($show_otp_for_testing && !empty($_SESSION['debug_otp'])): ?>
                        <div class="alert alert-warning small">
                            Testing Mode OTP:
                            <strong><?php echo htmlspecialchars($_SESSION['debug_otp'], ENT_QUOTES, 'UTF-8'); ?></strong>
                            <br>
                            Disable this in production.
                        </div>
                    <?php endif; ?>

                    <input type="text"
                           name="otp"
                           class="form-control mb-3"
                           placeholder="Enter 6-digit OTP"
                           inputmode="numeric"
                           pattern="[0-9]{6}"
                           minlength="6"
                           maxlength="6"
                           required
                           autofocus>

                    <button type="submit" name="verify_otp" class="btn btn-success w-100">
                        Verify OTP
                    </button>
                </form>

                <form method="post" class="text-center mt-2">
                    <input type="hidden" name="csrf_token"
                           value="<?php echo htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8'); ?>">

                    <button type="submit" name="start_over" class="btn btn-link btn-sm text-decoration-none p-0">
                        Start over
                    </button>
                </form>

            <?php elseif ($step === 3): ?>
                <form method="post">
                    <input type="hidden" name="csrf_token"
                           value="<?php echo htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8'); ?>">

                    <p class="small text-muted">
                        Create a strong new password.
                    </p>

                    <input type="password"
                           name="new_password"
                           class="form-control mb-3"
                           placeholder="New Password"
                           minlength="8"
                           autocomplete="new-password"
                           required>

                    <input type="password"
                           name="confirm_password"
                           class="form-control mb-3"
                           placeholder="Confirm Password"
                           minlength="8"
                           autocomplete="new-password"
                           required>

                    <button type="submit" name="update_password" class="btn btn-warning w-100">
                        Update Password
                    </button>
                </form>
            <?php endif; ?>

            <div class="text-center mt-3">
                <a href="login.php" class="small text-decoration-none">Back to Login</a>
            </div>
        </div>
    </div>
</div>

</body>
</html>