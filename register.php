<?php
session_start();

$cn30 = mysqli_connect("localhost", "root", "", "30mm");

if (!$cn30) {
    error_log("Database connection failed: " . mysqli_connect_error());
    die("Database unavailable.");
}

mysqli_set_charset($cn30, "utf8mb4");

/* --------------------
   CSRF TOKEN
-------------------- */
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

/* --------------------
   HELPERS
-------------------- */
function e($value): string
{
    return htmlspecialchars($value ?? '', ENT_QUOTES, 'UTF-8');
}

function valid_csrf(): bool
{
    return isset($_POST['csrf_token'], $_SESSION['csrf_token'])
        && hash_equals($_SESSION['csrf_token'], $_POST['csrf_token']);
}

function validate_dob($dob): bool
{
    if (empty($dob)) {
        return false;
    }

    try {
        $birth = new DateTime($dob);
        $today = new DateTime('today');

        return $birth <= $today;
    } catch (Exception $e) {
        return false;
    }
}

function process_certificate(string $field): array
{
    if (empty($_FILES[$field]['name'])) {
        return [
            'ok' => true,
            'path' => null
        ];
    }

    if ($_FILES[$field]['error'] !== UPLOAD_ERR_OK) {
        return [
            'ok' => false,
            'error' => 'There was a problem uploading the birth certificate.'
        ];
    }

    $allowedExt = ['pdf', 'jpg', 'jpeg', 'png'];
    $allowedMime = ['application/pdf', 'image/jpeg', 'image/png'];

    $ext = strtolower(pathinfo($_FILES[$field]['name'], PATHINFO_EXTENSION));

    if (!in_array($ext, $allowedExt, true)) {
        return [
            'ok' => false,
            'error' => 'Birth certificate must be PDF, JPG or PNG.'
        ];
    }

    $tmpName = $_FILES[$field]['tmp_name'];

    $mime = '';

    if (function_exists('mime_content_type')) {
        $mime = mime_content_type($tmpName);
    } elseif (function_exists('finfo_open')) {
        $finfo = finfo_open(FILEINFO_MIME_TYPE);
        $mime = finfo_file($finfo, $tmpName);
        finfo_close($finfo);
    }

    if (!in_array($mime, $allowedMime, true)) {
        return [
            'ok' => false,
            'error' => 'Invalid birth certificate file.'
        ];
    }

    if (strpos($mime, 'image/') === 0 && !@getimagesize($tmpName)) {
        return [
            'ok' => false,
            'error' => 'Invalid image file.'
        ];
    }

    if ($_FILES[$field]['size'] > 2 * 1024 * 1024) {
        return [
            'ok' => false,
            'error' => 'Birth certificate must be under 2MB.'
        ];
    }

    if (!is_dir('uploads/certificates')) {
        @mkdir('uploads/certificates', 0755, true);
    }

    $newName = "uploads/certificates/cert_" . bin2hex(random_bytes(8)) . "." . $ext;

    if (!move_uploaded_file($tmpName, $newName)) {
        return [
            'ok' => false,
            'error' => 'Could not save birth certificate.'
        ];
    }

    return [
        'ok' => true,
        'path' => $newName
    ];
}

/* --------------------
   FLASH MESSAGE
-------------------- */
$register_flash = $_SESSION['register_flash'] ?? null;
unset($_SESSION['register_flash']);

$name = "";
$email = "";
$dob = "";
$username = "";

/* --------------------
   HANDLE REGISTRATION
-------------------- */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['register_action'])) {
    $name     = trim($_POST['name'] ?? "");
    $email    = trim($_POST['email'] ?? "");
    $dob      = trim($_POST['DOB'] ?? "");
    $username = trim($_POST['username'] ?? "");
    $password = trim($_POST['password'] ?? "");

    /*
        Public registration must only create student accounts.
    */
    $role = "student";

    if (!valid_csrf()) {
        $register_flash = [
            'type' => 'failure',
            'text' => 'Invalid form submission. Please try again.'
        ];
    } elseif (empty($name) || empty($email) || empty($dob) || empty($username) || empty($password)) {
        $register_flash = [
            'type' => 'warning',
            'text' => 'All fields are required!'
        ];
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $register_flash = [
            'type' => 'warning',
            'text' => 'Please enter a valid email address.'
        ];
    } elseif (!validate_dob($dob)) {
        $register_flash = [
            'type' => 'warning',
            'text' => 'Please enter a valid date of birth.'
        ];
    } elseif (strlen($password) < 6) {
        $register_flash = [
            'type' => 'warning',
            'text' => 'Password must be at least 6 characters long.'
        ];
    } elseif (empty($_FILES['birth_certificate']['name'])) {
        $register_flash = [
            'type' => 'warning',
            'text' => 'Birth certificate is required.'
        ];
    } else {
        $check = mysqli_prepare($cn30, "SELECT Username FROM register WHERE Username = ? LIMIT 1");

        if ($check) {
            mysqli_stmt_bind_param($check, "s", $username);
            mysqli_stmt_execute($check);
            mysqli_stmt_store_result($check);

            if (mysqli_stmt_num_rows($check) > 0) {
                $register_flash = [
                    'type' => 'warning',
                    'text' => 'Username already exists!'
                ];
            } else {
                $certificate = process_certificate('birth_certificate');

                if (!$certificate['ok']) {
                    $register_flash = [
                        'type' => 'warning',
                        'text' => $certificate['error']
                    ];
                } elseif (empty($certificate['path'])) {
                    $register_flash = [
                        'type' => 'warning',
                        'text' => 'Birth certificate is required.'
                    ];
                } else {
                    $hashed_password = password_hash($password, PASSWORD_DEFAULT);
                    $birthCertificatePath = $certificate['path'];

                    $insert = mysqli_prepare(
                        $cn30,
                        "INSERT INTO register
                        (Name, Email, DOB, Username, Password, role, active, birth_certificate)
                        VALUES (?, ?, ?, ?, ?, ?, 1, ?)"
                    );

                    if ($insert) {
                        mysqli_stmt_bind_param(
                            $insert,
                            "sssssss",
                            $name,
                            $email,
                            $dob,
                            $username,
                            $hashed_password,
                            $role,
                            $birthCertificatePath
                        );

                        if (mysqli_stmt_execute($insert)) {
                            $_SESSION['register_flash'] = [
                                'type' => 'success',
                                'text' => 'Account created successfully as Student!',
                                'redirect' => 'login.php'
                            ];

                            header("Location: register.php");
                            exit();
                        } else {
                            error_log("Registration insert failed: " . mysqli_error($cn30));

                            $register_flash = [
                                'type' => 'failure',
                                'text' => 'Registration failed. Please try again.'
                            ];
                        }

                        mysqli_stmt_close($insert);
                    } else {
                        error_log("Registration prepare failed: " . mysqli_error($cn30));

                        $register_flash = [
                            'type' => 'failure',
                            'text' => 'Registration failed. Please try again.'
                        ];
                    }
                }
            }

            mysqli_stmt_close($check);
        } else {
            error_log("Username check prepare failed: " . mysqli_error($cn30));

            $register_flash = [
                'type' => 'failure',
                'text' => 'Registration failed. Please try again.'
            ];
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register</title>

    <link rel="stylesheet" href="Rutu2.css">
    <link rel="stylesheet" href="bootstrap/css/bootstrap.min.css">
    <link rel="stylesheet" href="bootstrap/icons/font/bootstrap-icons.css">

    <link rel="stylesheet" href="notiflix/notiflix-3.2.7.min.css">
    <script src="bootstrap/js/bootstrap.bundle.min.js"></script>
    <script src="notiflix/notiflix-3.2.7.min.js"></script>
</head>
<body>

<div class="image-wrapper2">
    <div class="container">
        <form method="post"
              class="center-box"
              id="regForm"
              enctype="multipart/form-data">

            <input type="hidden" name="register_action" value="1">
            <input type="hidden" name="csrf_token" value="<?php echo e($_SESSION['csrf_token']); ?>">

            <div class="card p-4">
                <h3 class="text-center mb-4">
                    Register <i class="bi bi-person-plus-fill"></i>
                </h3>

                <div class="input-group mb-3">
                    <span class="input-group-text">
                        <i class="bi bi-person-badge-fill"></i>
                    </span>

                    <input type="text"
                           class="form-control"
                           name="name"
                           placeholder="Name"
                           value="<?php echo e($name); ?>"
                           required>
                </div>

                <div class="input-group mb-3">
                    <span class="input-group-text">
                        <i class="bi bi-envelope-at-fill"></i>
                    </span>

                    <input type="email"
                           class="form-control"
                           name="email"
                           placeholder="Email"
                           value="<?php echo e($email); ?>"
                           required>
                </div>

                <div class="input-group mb-3">
                    <span class="input-group-text">
                        <i class="bi bi-calendar3"></i>
                    </span>

                    <input type="date"
                           class="form-control"
                           name="DOB"
                           value="<?php echo e($dob); ?>"
                           required>
                </div>

                <div class="input-group mb-3">
                    <span class="input-group-text">
                        <i class="bi bi-file-earmark-text-fill"></i>
                    </span>

                    <input type="file"
                           class="form-control"
                           name="birth_certificate"
                           accept=".pdf,image/jpeg,image/png"
                           required>
                </div>

                <div class="form-text small mb-3">
                    Birth certificate must be PDF, JPG or PNG. Maximum size: 2MB.
                </div>

                <div class="input-group mb-3">
                    <span class="input-group-text">
                        <i class="bi bi-shield-lock"></i>
                    </span>

                    <input type="hidden" name="role" value="student">
                    <span class="form-control bg-light">Register as Student</span>
                </div>

                <div class="input-group mb-3">
                    <span class="input-group-text">
                        <i class="bi bi-person"></i>
                    </span>

                    <input type="text"
                           class="form-control"
                           name="username"
                           placeholder="Username"
                           value="<?php echo e($username); ?>"
                           autocomplete="username"
                           required>
                </div>

                <div class="input-group mb-3">
                    <span class="input-group-text">
                        <i class="bi bi-key"></i>
                    </span>

                    <input type="password"
                           class="form-control"
                           name="password"
                           id="pass"
                           placeholder="Password"
                           minlength="6"
                           autocomplete="new-password"
                           required>

                    <span class="input-group-text" onclick="togglePassword()" style="cursor:pointer">
                        <i class="bi bi-eye-fill" id="eyeIcon"></i>
                    </span>
                </div>

                <button type="submit"
                        class="btn btn-primary w-100"
                        onclick="return handleRegister();">
                    Register
                </button>
            </div>
        </form>
    </div>
</div>

<script>
function togglePassword() {
    const pass = document.getElementById("pass");
    const icon = document.getElementById("eyeIcon");

    if (pass.type === "password") {
        pass.type = "text";
        icon.classList.replace("bi-eye-fill", "bi-eye-slash-fill");
    } else {
        pass.type = "password";
        icon.classList.replace("bi-eye-slash-fill", "bi-eye-fill");
    }
}

function handleRegister() {
    const form = document.getElementById("regForm");

    if (!form.checkValidity()) {
        form.reportValidity();
        return false;
    }

    if (!window.Notiflix) {
        return true;
    }

    Notiflix.Loading.standard('Saving Data...', {
        backgroundColor: 'rgba(0,0,0,0.8)'
    });

    setTimeout(function () {
        form.submit();
    }, 800);

    return false;
}
</script>

<?php if (!empty($register_flash)): ?>
<script>
window.addEventListener('DOMContentLoaded', function () {
    const flashType = <?php echo json_encode(
        in_array($register_flash['type'] ?? '', ['success', 'failure', 'warning', 'info'], true)
            ? $register_flash['type']
            : 'info'
    ); ?>;

    const flashText = <?php echo json_encode(
        $register_flash['text'] ?? '',
        JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP
    ); ?>;

    const redirectUrl = <?php echo json_encode(
        $register_flash['redirect'] ?? '',
        JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP
    ); ?>;

    const flashTitle = flashType.charAt(0).toUpperCase() + flashType.slice(1);

    if (window.Notiflix) {
        Notiflix.Report[flashType](
            flashTitle,
            flashText,
            "OK",
            function () {
                if (redirectUrl) {
                    window.location.href = redirectUrl;
                }
            }
        );
    } else if (redirectUrl) {
        window.location.href = redirectUrl;
    }
});
</script>
<?php endif; ?>

</body>
</html>