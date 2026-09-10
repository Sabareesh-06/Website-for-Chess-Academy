<?php
session_start();

$cn30 = mysqli_connect("localhost", "root", "", "30mm");

if (!$cn30) {
    error_log("Database connection failed: " . mysqli_connect_error());
    die("Database unavailable.");
}

mysqli_set_charset($cn30, "utf8mb4");

$error = "";
$info = "";

if (isset($_GET['reset']) && $_GET['reset'] === 'success') {
    $info = "Password updated successfully. Please log in.";
}

/* --------------------
   GUEST LOGIN
-------------------- */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['guest_login'])) {
    session_regenerate_id(true);

    $_SESSION['Username'] = 'Guest_' . rand(100, 999);
    $_SESSION['Name'] = 'Academy Visitor';
    $_SESSION['role'] = 'guest';
    $_SESSION['profile_image'] = 'images/chess.jpeg';

    header("Location: ani1.php");
    exit();
}

/* --------------------
   NORMAL LOGIN
-------------------- */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login_action'])) {
    $username = trim($_POST['uname'] ?? '');
    $password = trim($_POST['password'] ?? '');

    if (!empty($username) && !empty($password)) {
        $query = "SELECT * FROM register WHERE Username = ? LIMIT 1";
        $stmt = mysqli_prepare($cn30, $query);

        if ($stmt) {
            mysqli_stmt_bind_param($stmt, "s", $username);
            mysqli_stmt_execute($stmt);

            $result = mysqli_stmt_get_result($stmt);
            $row = mysqli_fetch_assoc($result);

            if ($row) {
                $isActive = !array_key_exists('active', $row) || (int)$row['active'] === 1;

                $passwordOk = password_verify($password, $row['Password']);

                /*
                    Temporary migration support:
                    If old password is still plain text, verify it once,
                    then automatically upgrade it to password_hash().
                */
                if (!$passwordOk && is_string($row['Password']) && hash_equals($row['Password'], $password)) {
                    $passwordOk = true;

                    $newHash = password_hash($password, PASSWORD_DEFAULT);
                    $userId = $row['ID'] ?? 0;

                    $updateStmt = mysqli_prepare($cn30, "UPDATE register SET Password = ? WHERE ID = ?");

                    if ($updateStmt) {
                        mysqli_stmt_bind_param($updateStmt, "si", $newHash, $userId);
                        mysqli_stmt_execute($updateStmt);
                        mysqli_stmt_close($updateStmt);
                    }
                }

                if ($passwordOk && $isActive) {
                    session_regenerate_id(true);

                    $_SESSION['ID'] = $row['ID'] ?? null;
                    $_SESSION['Username'] = $row['Username'];
                    $_SESSION['Name'] = $row['Name'] ?? $row['Username'];
                    $_SESSION['Email'] = $row['Email'] ?? '';
                    $_SESSION['role'] = $row['role'] ?? 'student';
                    $_SESSION['profile_image'] = !empty($row['profile_image'])
                        ? $row['profile_image']
                        : 'images/chess.jpeg';

                    header("Location: ani1.php");
                    exit();
                }
            }

            $error = "Invalid Username or Password.";
            mysqli_stmt_close($stmt);
        } else {
            $error = "Database query error.";
        }
    } else {
        $error = "Please fill all fields.";
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Login Page</title>

    <link rel="stylesheet" href="Rutu2.css">
    <link rel="stylesheet" href="bootstrap/css/bootstrap.min.css">
    <link rel="stylesheet" href="bootstrap/icons/font/bootstrap-icons.css">
</head>
<body>

<div class="image-wrapper">
    <div class="container">
        <form method="post" class="center-box" id="loginForm">
            <input type="hidden" name="login_action" value="1">

            <div class="card">
                <div class="card-body">
                    <div class="card text-center mb-3">
                        <div class="two">
                            <div class="card-body fw-bold">
                                LogIn <i class="bi bi-arrow-right-circle-fill"></i>
                            </div>
                        </div>
                    </div>

                    <?php if (!empty($info)) { ?>
                        <div class="alert alert-success text-center">
                            <?php echo htmlspecialchars($info, ENT_QUOTES, 'UTF-8'); ?>
                        </div>
                    <?php } ?>

                    <?php if (!empty($error)) { ?>
                        <div class="alert alert-danger text-center">
                            <?php echo htmlspecialchars($error, ENT_QUOTES, 'UTF-8'); ?>
                        </div>
                    <?php } ?>

                    <div class="input-group mb-3">
                        <span class="input-group-text">
                            <i class="bi bi-person-circle"></i>
                        </span>
                        <input type="text"
                               class="form-control"
                               name="uname"
                               id="uname_field"
                               placeholder="Username"
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
                               autocomplete="current-password"
                               required>

                        <span class="input-group-text" onclick="togglePassword()" style="cursor:pointer">
                            <i class="bi bi-eye-fill" id="eyeIcon"></i>
                        </span>
                    </div>

                    <div class="text-center mt-3">
                        <a href="forgot_password.php" class="text-decoration-none small text-muted">
                            <i class="bi bi-question-circle"></i> Forgot Password?
                        </a>
                    </div>

                    <button type="submit" class="btn btn-primary w-100 mb-2">
                        Log In
                    </button>

                    <button type="submit"
                            name="guest_login"
                            class="btn btn-outline-secondary w-100"
                            formnovalidate>
                        <i class="bi bi-eye"></i> Enter as Guest
                    </button>
                </div>
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
</script>

</body>
</html>