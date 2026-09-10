<?php
session_start();

mysqli_report(MYSQLI_REPORT_OFF);

/* --------------------
   LOGOUT
-------------------- */
if (isset($_GET['logout'])) {
    $_SESSION = [];

    if (ini_get("session.use_cookies")) {
        $params = session_get_cookie_params();
        setcookie(
            session_name(),
            '',
            time() - 42000,
            $params["path"],
            $params["domain"],
            $params["secure"],
            $params["httponly"]
        );
    }

    session_destroy();

    header("Location: login.php");
    exit();
}

/* --------------------
   DATABASE CONNECTION
-------------------- */
$cn30 = mysqli_connect("localhost", "root", "", "30mm");

if (!$cn30) {
    error_log("Database connection failed: " . mysqli_connect_error());
    die("Database unavailable.");
}

mysqli_set_charset($cn30, "utf8mb4");

/* --------------------
   SAFE DB HELPERS
-------------------- */
if (!function_exists('stu_safe_query')) {
    function stu_safe_query($conn, string $sql): void
    {
        try {
            mysqli_query($conn, $sql);
        } catch (Throwable $e) {
            error_log("Ignored MySQL error: " . $e->getMessage());
        }
    }
}

if (!function_exists('stu_column_exists')) {
    function stu_column_exists($conn, string $table, string $column): bool
    {
        try {
            $result = mysqli_query($conn, "SHOW COLUMNS FROM `$table` LIKE '$column'");
            return $result && mysqli_num_rows($result) > 0;
        } catch (Throwable $e) {
            return false;
        }
    }
}

if (!function_exists('stu_add_column_if_missing')) {
    function stu_add_column_if_missing($conn, string $table, string $column, string $definition): void
    {
        if (!stu_column_exists($conn, $table, $column)) {
            stu_safe_query($conn, "ALTER TABLE `$table` ADD COLUMN `$column` $definition");
        }
    }
}

/* --------------------
   BASIC REQUIRED TABLES / COLUMNS
-------------------- */
stu_safe_query(
    $cn30,
    "CREATE TABLE IF NOT EXISTS messages (
        id INT AUTO_INCREMENT PRIMARY KEY,
        sender VARCHAR(100) NOT NULL,
        receiver VARCHAR(100) NOT NULL,
        message TEXT NOT NULL,
        type VARCHAR(20) NOT NULL DEFAULT 'public',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"
);

stu_add_column_if_missing($cn30, "register", "DOB", "DATE NULL");
stu_add_column_if_missing($cn30, "register", "age", "VARCHAR(10) NULL");
stu_add_column_if_missing($cn30, "register", "birth_certificate", "VARCHAR(255) NULL");
stu_add_column_if_missing($cn30, "register", "points", "INT NOT NULL DEFAULT 0");
stu_add_column_if_missing($cn30, "register", "profile_image", "VARCHAR(255) DEFAULT 'images/chess.jpeg'");
stu_add_column_if_missing($cn30, "register", "quotes", "TEXT NULL");
stu_add_column_if_missing($cn30, "register", "active", "TINYINT(1) NOT NULL DEFAULT 1");

stu_safe_query($cn30, "ALTER TABLE register MODIFY Password VARCHAR(255) NOT NULL");

/* --------------------
   LOGIN GUARD
   Guest is allowed to view students.
-------------------- */
if (!isset($_SESSION['role'])) {
    header("Location: login.php");
    exit();
}

$role = $_SESSION['role'];

/* --------------------
   CSRF TOKEN
-------------------- */
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

/* --------------------
   HELPERS
-------------------- */
function flash(string $type, string $title, string $message): void
{
    $_SESSION['student_flash'][] = [
        'type' => $type,
        'title' => $title,
        'message' => $message
    ];
}

function e($value): string
{
    return htmlspecialchars($value ?? '', ENT_QUOTES, 'UTF-8');
}

function valid_csrf(): bool
{
    return isset($_POST['csrf_token'], $_SESSION['csrf_token'])
        && hash_equals($_SESSION['csrf_token'], $_POST['csrf_token']);
}

function calculate_age($dob): ?int
{
    if (empty($dob)) {
        return null;
    }

    try {
        $birth = new DateTime($dob);
        $today = new DateTime('today');

        if ($birth > $today) {
            return null;
        }

        return (int)$today->diff($birth)->y;
    } catch (Exception $e) {
        return null;
    }
}

function process_profile_image(string $field, string $current = 'images/chess.jpeg'): array
{
    if (empty($_FILES[$field]['name'])) {
        return [
            'ok' => true,
            'path' => $current
        ];
    }

    if ($_FILES[$field]['error'] !== UPLOAD_ERR_OK) {
        return [
            'ok' => false,
            'error' => 'There was a problem uploading the image.'
        ];
    }

    $allowedExt = ['jpg', 'jpeg', 'png', 'webp', 'gif'];
    $allowedMime = ['image/jpeg', 'image/png', 'image/webp', 'image/gif'];

    $ext = strtolower(pathinfo($_FILES[$field]['name'], PATHINFO_EXTENSION));
    $tmpName = $_FILES[$field]['tmp_name'];
    $imageInfo = @getimagesize($tmpName);

    if (
        !$imageInfo ||
        !in_array($ext, $allowedExt, true) ||
        !in_array($imageInfo['mime'] ?? '', $allowedMime, true) ||
        $_FILES[$field]['size'] > 2 * 1024 * 1024
    ) {
        return [
            'ok' => false,
            'error' => 'Please upload a valid JPG, JPEG, PNG, WEBP or GIF image under 2MB.'
        ];
    }

    if (!is_dir('images')) {
        @mkdir('images', 0755, true);
    }

    $newName = "images/student_" . bin2hex(random_bytes(8)) . "." . $ext;

    if (!move_uploaded_file($tmpName, $newName)) {
        return [
            'ok' => false,
            'error' => 'Could not save uploaded image.'
        ];
    }

    return [
        'ok' => true,
        'path' => $newName
    ];
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
   RANDOM QUOTES
-------------------- */
$quotes = [
    "🌟 Believe in yourself!",
    "♟️ Every Master was once a beginner.",
    "🚀 Reach for the stars!",
    "💡 Mistakes help us learn!",
    "🏆 Playing is the best part!",
    "🌈 You can do amazing things!",
    "🧠 Every move is a new idea.",
    "⭐ Mistakes prove you are trying.",
    "🦁 Try a new move today!",
    "🤝 Good sportsmanship wins games.",
    "🎨 Your mind is magic!",
    "🐢 Never stop trying.",
    "🎈 Kindness is a superpower!",
    "📚 Every game makes you smarter.",
    "✨ Make it a great game!"
];

$random_quote = $quotes[array_rand($quotes)];

/* --------------------
   ADMIN / MASTER: SEND MESSAGE
-------------------- */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['send_msg_action'])) {
    if (!valid_csrf()) {
        flash('failure', 'Invalid Request', 'Security token missing.');
        header("Location: student.php");
        exit();
    }

    if (!in_array($role, ['admin', 'master'], true)) {
        flash('failure', 'Denied', 'Only admin or master can send messages.');
        header("Location: student.php");
        exit();
    }

    $sender  = $_SESSION['Username'] ?? 'system';
    $message = trim($_POST['message_text'] ?? '');
    $target  = $_POST['msg_target'] ?? '';

    if ($message === '') {
        flash('warning', 'Empty Message', 'Message cannot be empty.');
        header("Location: student.php");
        exit();
    }

    if ($target === 'all') {
        $receiver = 'all';
        $type = 'public';

        $stmt = mysqli_prepare(
            $cn30,
            "INSERT INTO messages (sender, receiver, message, type) VALUES (?, ?, ?, ?)"
        );

        if ($stmt) {
            mysqli_stmt_bind_param($stmt, "ssss", $sender, $receiver, $message, $type);

            if (mysqli_stmt_execute($stmt)) {
                flash('success', 'Message Sent', 'Sent to all students.');
            } else {
                flash('failure', 'Message Failed', 'Could not send message.');
            }

            mysqli_stmt_close($stmt);
        } else {
            flash('failure', 'Message Failed', 'Database error.');
        }
    } else {
        $receiver = trim($_POST['student_username'] ?? '');

        if ($receiver === '') {
            flash('warning', 'Missing Username', 'Please enter student username.');
            header("Location: student.php");
            exit();
        }

        $check = mysqli_prepare(
            $cn30,
            "SELECT ID FROM register WHERE Username = ? AND role = 'student' LIMIT 1"
        );

        if (!$check) {
            flash('failure', 'Message Failed', 'Database error.');
            header("Location: student.php");
            exit();
        }

        mysqli_stmt_bind_param($check, "s", $receiver);
        mysqli_stmt_execute($check);
        mysqli_stmt_store_result($check);

        if (mysqli_stmt_num_rows($check) === 0) {
            flash(
                'failure',
                'Student Not Found',
                '"Failure is simply the opportunity to begin again, this time more intelligently." - Henry Ford'
            );
        } else {
            $type = 'private';

            $stmt = mysqli_prepare(
                $cn30,
                "INSERT INTO messages (sender, receiver, message, type) VALUES (?, ?, ?, ?)"
            );

            if ($stmt) {
                mysqli_stmt_bind_param($stmt, "ssss", $sender, $receiver, $message, $type);

                if (mysqli_stmt_execute($stmt)) {
                    flash('success', 'Message Sent', 'Private message sent successfully.');
                } else {
                    flash('failure', 'Message Failed', 'Could not send message.');
                }

                mysqli_stmt_close($stmt);
            } else {
                flash('failure', 'Message Failed', 'Database error.');
            }
        }

        mysqli_stmt_close($check);
    }

    header("Location: student.php");
    exit();
}

/* --------------------
   ADMIN / MASTER: DELETE STUDENT
-------------------- */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['delete_student'])) {
    if (!valid_csrf()) {
        flash('failure', 'Invalid Request', 'Security token missing.');
        header("Location: student.php");
        exit();
    }

    if (!in_array($role, ['admin', 'master'], true)) {
        flash('failure', 'Denied', 'Only admin or master can delete students.');
        header("Location: student.php");
        exit();
    }

    $id = intval($_POST['student_id'] ?? 0);

    if ($id <= 0) {
        flash('warning', 'Invalid Request', 'Invalid student ID.');
        header("Location: student.php");
        exit();
    }

    $stmt = mysqli_prepare(
        $cn30,
        "DELETE FROM register WHERE ID = ? AND (role = 'student' OR role = 'user')"
    );

    if ($stmt) {
        mysqli_stmt_bind_param($stmt, "i", $id);

        if (mysqli_stmt_execute($stmt) && mysqli_stmt_affected_rows($stmt) > 0) {
            flash('success', 'Deleted Successfully', 'Student profile has been removed.');
        } else {
            flash('failure', 'Delete Failed', 'Student not found or could not be deleted.');
        }

        mysqli_stmt_close($stmt);
    } else {
        flash('failure', 'Delete Failed', 'Database error.');
    }

    header("Location: student.php");
    exit();
}

/* --------------------
   ADMIN / MASTER: REGISTER STUDENT
-------------------- */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['register_student'])) {
    if (!valid_csrf()) {
        flash('failure', 'Invalid Request', 'Security token missing.');
        header("Location: student.php");
        exit();
    }

    if (!in_array($role, ['admin', 'master'], true)) {
        flash('failure', 'Denied', 'Only admin or master can register students.');
        header("Location: student.php");
        exit();
    }

    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';
    $name     = trim($_POST['name'] ?? '');
    $dob      = trim($_POST['dob'] ?? '');
    $school   = trim($_POST['school'] ?? '');
    $rating   = trim($_POST['rating'] ?? '');
    $phone    = trim($_POST['phone'] ?? '');
    $email    = trim($_POST['email'] ?? '');
    $desc     = trim($_POST['description'] ?? '');

    $age = calculate_age($dob);

    if (
        $username === '' ||
        $password === '' ||
        $name === '' ||
        $dob === '' ||
        $school === '' ||
        $rating === '' ||
        $phone === '' ||
        $email === ''
    ) {
        flash('warning', 'Missing Data', 'All required fields must be filled.');
        header("Location: student.php");
        exit();
    }

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        flash('warning', 'Invalid Email', 'Please enter a valid email address.');
        header("Location: student.php");
        exit();
    }

    if ($age === null) {
        flash('warning', 'Invalid Date of Birth', 'Please enter a valid DOB.');
        header("Location: student.php");
        exit();
    }

    if (strlen($password) < 6) {
        flash('warning', 'Weak Password', 'Password must be at least 6 characters long.');
        header("Location: student.php");
        exit();
    }

    if (empty($_FILES['birth_certificate']['name'])) {
        flash('warning', 'Missing Certificate', 'Birth certificate is required.');
        header("Location: student.php");
        exit();
    }

    $check = mysqli_prepare($cn30, "SELECT Username FROM register WHERE Username = ? LIMIT 1");

    if (!$check) {
        flash('failure', 'Registration Failed', 'Database error.');
        header("Location: student.php");
        exit();
    }

    mysqli_stmt_bind_param($check, "s", $username);
    mysqli_stmt_execute($check);
    mysqli_stmt_store_result($check);

    if (mysqli_stmt_num_rows($check) > 0) {
        flash('warning', 'Username Exists', 'That username is already taken.');
        header("Location: student.php");
        exit();
    }

    mysqli_stmt_close($check);

    $imageUpload = process_profile_image('profile_image');

    if (!$imageUpload['ok']) {
        flash('warning', 'Invalid Image', $imageUpload['error']);
        header("Location: student.php");
        exit();
    }

    $certificateUpload = process_certificate('birth_certificate');

    if (!$certificateUpload['ok']) {
        flash('warning', 'Invalid Certificate', $certificateUpload['error']);
        header("Location: student.php");
        exit();
    }

    if (empty($certificateUpload['path'])) {
        flash('warning', 'Missing Certificate', 'Birth certificate is required.');
        header("Location: student.php");
        exit();
    }

    $hashedPassword = password_hash($password, PASSWORD_DEFAULT);
    $studentRole = 'student';
    $imagePath = $imageUpload['path'];
    $certificatePath = $certificateUpload['path'];
    $ageValue = (string)$age;

    $stmt = mysqli_prepare(
        $cn30,
        "INSERT INTO register
        (Username, Password, Name, DOB, age, school, phone, Email, rating, quotes, role, active, profile_image, birth_certificate)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)"
    );

    if ($stmt) {
        mysqli_stmt_bind_param(
            $stmt,
            "sssssssssssss",
            $username,
            $hashedPassword,
            $name,
            $dob,
            $ageValue,
            $school,
            $phone,
            $email,
            $rating,
            $desc,
            $studentRole,
            $imagePath,
            $certificatePath
        );

        if (mysqli_stmt_execute($stmt)) {
            flash('success', 'Student Registered', 'Student account created successfully.');
        } else {
            flash('failure', 'Registration Failed', 'Could not save student profile.');
        }

        mysqli_stmt_close($stmt);
    } else {
        flash('failure', 'Registration Failed', 'Database error.');
    }

    header("Location: student.php");
    exit();
}

/* --------------------
   ADMIN / MASTER / SELF: EDIT STUDENT
-------------------- */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['update_student'])) {
    if (!valid_csrf()) {
        flash('failure', 'Invalid Request', 'Security token missing.');
        header("Location: student.php");
        exit();
    }

    $id = intval($_POST['student_id'] ?? 0);

    if ($id <= 0) {
        flash('warning', 'Invalid Request', 'Invalid student ID.');
        header("Location: student.php");
        exit();
    }

    $targetStmt = mysqli_prepare(
        $cn30,
        "SELECT ID, Username, Password, profile_image, role, birth_certificate
         FROM register
         WHERE ID = ? AND (role = 'student' OR role = 'user')
         LIMIT 1"
    );

    if (!$targetStmt) {
        flash('failure', 'Update Failed', 'Database error.');
        header("Location: student.php");
        exit();
    }

    mysqli_stmt_bind_param($targetStmt, "i", $id);
    mysqli_stmt_execute($targetStmt);

    $targetResult = mysqli_stmt_get_result($targetStmt);
    $target = mysqli_fetch_assoc($targetResult);

    mysqli_stmt_close($targetStmt);

    if (!$target) {
        flash('failure', 'Update Failed', 'Student not found.');
        header("Location: student.php");
        exit();
    }

    $isPrivileged = in_array($role, ['admin', 'master'], true);
    $isSelf = isset($_SESSION['Username'])
        && hash_equals((string)$target['Username'], (string)$_SESSION['Username']);

    if (!$isPrivileged && !$isSelf) {
        flash('failure', 'Denied', 'You are not allowed to edit this profile.');
        header("Location: student.php");
        exit();
    }

    $name   = trim($_POST['edit_name'] ?? '');
    $dob    = trim($_POST['edit_dob'] ?? '');
    $school = trim($_POST['edit_school'] ?? '');
    $rating = trim($_POST['edit_rating'] ?? '');
    $phone  = trim($_POST['edit_phone'] ?? '');
    $email  = trim($_POST['edit_email'] ?? '');
    $desc   = trim($_POST['edit_desc'] ?? '');

    $age = calculate_age($dob);

    $newPassword = trim($_POST['edit_password'] ?? '');
    $password = $target['Password'];

    if (
        $name === '' ||
        $dob === '' ||
        $school === '' ||
        $rating === '' ||
        $phone === '' ||
        $email === ''
    ) {
        flash('warning', 'Missing Data', 'All required fields must be filled.');
        header("Location: student.php");
        exit();
    }

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        flash('warning', 'Invalid Email', 'Please enter a valid email address.');
        header("Location: student.php");
        exit();
    }

    if ($age === null) {
        flash('warning', 'Invalid Date of Birth', 'Please enter a valid DOB.');
        header("Location: student.php");
        exit();
    }

    if ($newPassword !== '' && strlen($newPassword) < 6) {
        flash('warning', 'Weak Password', 'Password must be at least 6 characters long.');
        header("Location: student.php");
        exit();
    }

    if ($newPassword !== '') {
        $password = password_hash($newPassword, PASSWORD_DEFAULT);
    }

    $currentImage = !empty($target['profile_image'])
        ? $target['profile_image']
        : 'images/chess.jpeg';

    $currentCertificate = $target['birth_certificate'] ?? '';

    $imageUpload = process_profile_image('edit_profile_image', $currentImage);

    if (!$imageUpload['ok']) {
        flash('warning', 'Invalid Image', $imageUpload['error']);
        header("Location: student.php");
        exit();
    }

    $imagePath = $imageUpload['path'];

    if (!empty($_FILES['edit_birth_certificate']['name'])) {
        $certificateUpload = process_certificate('edit_birth_certificate');

        if (!$certificateUpload['ok']) {
            flash('warning', 'Invalid Certificate', $certificateUpload['error']);
            header("Location: student.php");
            exit();
        }

        if (!empty($certificateUpload['path'])) {
            $currentCertificate = $certificateUpload['path'];
        }
    }

    $ageValue = (string)$age;

    $stmt = mysqli_prepare(
        $cn30,
        "UPDATE register
        SET Name = ?, DOB = ?, age = ?, school = ?, phone = ?, Email = ?, rating = ?, quotes = ?, profile_image = ?, Password = ?, birth_certificate = ?
        WHERE ID = ? AND (role = 'student' OR role = 'user')"
    );

    if ($stmt) {
        mysqli_stmt_bind_param(
            $stmt,
            "sssssssssssi",
            $name,
            $dob,
            $ageValue,
            $school,
            $phone,
            $email,
            $rating,
            $desc,
            $imagePath,
            $password,
            $currentCertificate,
            $id
        );

        if (mysqli_stmt_execute($stmt)) {
            flash('success', 'Updated Successfully', 'Profile information has been saved.');
        } else {
            flash('failure', 'Update Failed', 'Could not update profile.');
        }

        mysqli_stmt_close($stmt);
    } else {
        flash('failure', 'Update Failed', 'Database error.');
    }

    header("Location: student.php");
    exit();
}

/* --------------------
   FETCH STUDENTS
-------------------- */
$search = trim($_GET['search'] ?? '');
$likeSearch = '%' . addcslashes($search, '%_') . '%';

$stmt = mysqli_prepare(
    $cn30,
    "SELECT *
     FROM register
     WHERE (role = 'student' OR role = 'user')
       AND Name LIKE ?
     ORDER BY ID DESC"
);

$students = [];

if ($stmt) {
    mysqli_stmt_bind_param($stmt, "s", $likeSearch);
    mysqli_stmt_execute($stmt);

    $result = mysqli_stmt_get_result($stmt);

    while ($row = mysqli_fetch_assoc($result)) {
        $students[] = $row;
    }

    mysqli_stmt_close($stmt);
}

$flashes = $_SESSION['student_flash'] ?? [];
unset($_SESSION['student_flash']);

$currentRole = $_SESSION['role'] ?? 'guest';
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Student Directory</title>

    <link rel="stylesheet" href="Rutu3.css">
    <link rel="stylesheet" href="bootstrap/css/bootstrap.min.css">
    <link rel="stylesheet" href="bootstrap/icons/font/bootstrap-icons.css">
    <link rel="stylesheet" href="notiflix/notiflix-3.2.7.min.css">

    <script src="bootstrap/js/bootstrap.bundle.min.js"></script>
    <script src="notiflix/notiflix-3.2.7.min.js"></script>

    <style>
        .add-card {
            border: 2px dashed #198754;
            cursor: pointer;
            min-height: 400px;
            display: flex;
            align-items: center;
            justify-content: center;
            background: #f8f9fa;
            transition: 0.3s;
        }

        .add-card:hover {
            background: #e9ecef;
        }

        .card-img-top {
            height: 180px;
            object-fit: cover;
        }

        .badge-username {
            font-size: 0.7rem;
            background: #e9ecef;
            color: #6c757d;
            padding: 2px 5px;
            border-radius: 4px;
        }

        .nav-tabs .nav-link {
            color: #ffffff;
            font-weight: 500;
            border: none;
        }

        .nav-tabs .nav-link.active {
            color: #ffffff !important;
            border-bottom: 3px solid #fdfdfd;
            background: none;
        }

        .btn-primary {
            background-color: #3f3737;
            border-color: #433737;
        }

        .btn-primary:hover {
            background-color: #655050;
            border-color: #ffffff;
        }

        .btn-outline-primary {
            color: #ffffff;
            border-color: #3b5e81;
        }

        .btn-outline-primary:hover {
            background-color: #7ebcfa;
            color: #fff;
        }

        footer {
            background-color: #f8f9fa;
            border-top: 1px solid #dee2e6;
            padding: 30px 0;
            margin-top: 60px;
        }
    </style>
</head>
<body>

<script>
    const initialQuote = <?php echo json_encode(
        $random_quote,
        JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP | JSON_UNESCAPED_UNICODE
    ); ?>;

    if (window.Notiflix) {
        Notiflix.Loading.pulse(initialQuote, {
            backgroundColor: 'rgba(255,255,255,0.95)',
            svgColor: '#000000',
            messageColor: '#000000',
            messageFontSize: '18px'
        });
    }

    window.addEventListener('load', function () {
        setTimeout(function () {
            if (window.Notiflix) {
                Notiflix.Loading.remove();
            }
        }, 3000);
    });
</script>

<button class="btn btn-sm btn-info m-2" onclick="window.location.href='ani1.php'">
    <i class="bi bi-house-up-fill"></i> Home
</button>

<ul class="nav nav-tabs" id="myTab" role="tablist">
    <li class="nav-item dropdown">
        <button class="nav-link dropdown-toggle" data-bs-toggle="dropdown">
            <i class="bi bi-people-fill"></i> Members
        </button>

        <ul class="dropdown-menu shadow">
            <li><a class="dropdown-item" href="master.php">Master</a></li>
            <li><a class="dropdown-item" href="student.php">Student</a></li>
        </ul>
    </li>

    <?php if (in_array($currentRole, ['admin', 'master', 'student'], true)): ?>
        <li class="nav-item">
            <button class="nav-link" onclick="window.location.href='puzzle.php'">
                <i class="bi bi-puzzle-fill"></i> Daily Puzzles
            </button>
        </li>
    <?php endif; ?>

    <?php if (in_array($currentRole, ['admin', 'master'], true)): ?>
        <li class="nav-item ms-auto">
            <button class="btn btn-primary btn-sm mt-1 me-2"
                    data-bs-toggle="modal"
                    data-bs-target="#registerStudentModal">
                <i class="bi bi-person-plus-fill"></i> Register Student
            </button>
        </li>

        <li class="nav-item">
            <button class="btn btn-outline-primary btn-sm mt-1 me-2"
                    data-bs-toggle="modal"
                    data-bs-target="#messageModal">
                <i class="bi bi-chat-dots-fill"></i> Send Message
            </button>
        </li>

        <?php if ($currentRole === 'admin'): ?>
            <li class="nav-item">
                <button class="nav-link" onclick="window.location.href='studentProfile.php'">
                    <i class="bi bi-person-fill"></i> Student Profile
                </button>
            </li>
        <?php endif; ?>

        <?php if ($currentRole !== 'guest'): ?>
            <li class="nav-item">
                <button class="nav-link" onclick="window.location.href='inbox.php'">
                    <i class="bi bi-inbox-fill"></i> Inbox
                </button>
            </li>
        <?php endif; ?>

        <li class="nav-item">
            <button class="nav-link" data-bs-toggle="offcanvas" data-bs-target="#contactOffcanvas">
                <i class="bi bi-telephone-fill"></i> Contact
            </button>
        </li>
    <?php else: ?>
        <?php if ($currentRole !== 'guest'): ?>
            <li class="nav-item ms-auto">
                <button class="nav-link" onclick="window.location.href='inbox.php'">
                    <i class="bi bi-inbox-fill"></i> Inbox
                </button>
            </li>

            <li class="nav-item">
                <button class="nav-link" data-bs-toggle="offcanvas" data-bs-target="#contactOffcanvas">
                    <i class="bi bi-telephone-fill"></i> Contact
                </button>
            </li>
        <?php else: ?>
            <li class="nav-item ms-auto">
                <button class="nav-link" data-bs-toggle="offcanvas" data-bs-target="#contactOffcanvas">
                    <i class="bi bi-telephone-fill"></i> Contact
                </button>
            </li>
        <?php endif; ?>
    <?php endif; ?>

    <li class="nav-item dropdown">
        <button class="nav-link dropdown-toggle" data-bs-toggle="dropdown">
            <i class="bi bi-person-circle text-dark"></i>
        </button>

        <ul class="dropdown-menu dropdown-menu-end text-center p-3 shadow" style="width: 220px;">
            <li>
                <?php if ($currentRole !== 'guest'): ?>
                    <img src="<?php echo e($_SESSION['profile_image'] ?? 'images/chess.jpeg'); ?>"
                         class="rounded-circle mb-2 border"
                         style="width:70px; height:70px; object-fit:cover;"
                         alt="Profile Image">

                    <p class="mb-1 small">
                        <strong><?php echo e($_SESSION['Name'] ?? 'Guest'); ?></strong>
                    </p>

                    <span class="badge bg-success mb-2">
                        <?php echo e(ucfirst($currentRole ?: 'guest')); ?>
                    </span>
                <?php else: ?>
                    <img src="images/chess.jpeg"
                         class="rounded-circle mb-2 border"
                         style="width:70px; height:70px; object-fit:cover;"
                         alt="Guest Image">

                    <p class="mb-1 small">
                        <strong>Guest</strong>
                    </p>

                    <span class="badge bg-secondary mb-2">Guest</span>
                <?php endif; ?>

                <br>

                <button class="btn btn-sm btn-danger w-100"
                        onclick="window.location.href='student.php?logout=1'">
                    <i class="bi bi-person-fill-dash"></i> Logout
                </button>
            </li>
        </ul>
    </li>
</ul>

<ul class="nav nav-tabs">
    <li class="nav-item">
        <a class="nav-link" href="master.php">Master</a>
    </li>

    <li class="nav-item">
        <a class="nav-link active" href="student.php">Student</a>
    </li>

    <li class="nav-item ms-auto me-2">
        <form class="input-group" method="GET" style="width: 250px; margin-top: 2px;">
            <input type="text"
                   name="search"
                   class="form-control form-control-sm"
                   placeholder="Search..."
                   value="<?php echo e($search); ?>">

            <button class="btn btn-primary btn-sm" type="submit">
                <i class="bi bi-search"></i>
            </button>
        </form>
    </li>
</ul>

<div class="container mt-3">
    <div class="row">
        <?php if (in_array($role, ['admin', 'master'], true)): ?>
            <div class="col-md-3 mb-3">
                <div class="card add-card" data-bs-toggle="modal" data-bs-target="#registerStudentModal">
                    <div class="text-center text-success">
                        <i class="bi bi-plus-circle fs-1"></i>
                        <p class="fw-bold mt-2">Add Student</p>
                    </div>
                </div>
            </div>
        <?php endif; ?>

        <?php if (empty($students)): ?>
            <div class="col-12">
                <div class="alert alert-info text-center">No student records found.</div>
            </div>
        <?php endif; ?>

        <?php foreach ($students as $row): ?>
            <?php
            $canEdit = in_array($role, ['admin', 'master'], true)
                || (isset($_SESSION['Username']) && hash_equals((string)($row['Username'] ?? ''), (string)$_SESSION['Username']));

            $displayAge = calculate_age($row['DOB'] ?? '');

            if ($displayAge === null) {
                $displayAge = $row['age'] ?? '';
            }

            $hasCertificate = !empty($row['birth_certificate']);

            $canViewCertificate =
                in_array($role, ['admin', 'master'], true)
                ||
                (isset($_SESSION['Username']) && hash_equals((string)($row['Username'] ?? ''), (string)$_SESSION['Username']));

            $isOwnProfile =
                isset($_SESSION['Username'])
                && hash_equals((string)($row['Username'] ?? ''), (string)$_SESSION['Username']);
            ?>

            <div class="col-md-3 mb-3">
                <div class="card border-success h-100 shadow-sm">
                    <div class="card-header bg-transparent border-success d-flex justify-content-between align-items-center">
                        <div>
                            <strong><?php echo e($row['Name'] ?? ''); ?></strong><br>
                            <span class="badge-username">ID: <?php echo e($row['Username'] ?? ''); ?></span>
                        </div>

                        <div>
                            <?php if ($canEdit): ?>
                                <i class="bi bi-pencil-square text-primary me-2"
                                   style="cursor:pointer"
                                   data-id="<?php echo e($row['ID'] ?? ''); ?>"
                                   data-name="<?php echo e($row['Name'] ?? ''); ?>"
                                   data-dob="<?php echo e($row['DOB'] ?? ''); ?>"
                                   data-school="<?php echo e($row['school'] ?? ''); ?>"
                                   data-rating="<?php echo e($row['rating'] ?? ''); ?>"
                                   data-phone="<?php echo e($row['phone'] ?? ''); ?>"
                                   data-email="<?php echo e($row['Email'] ?? ''); ?>"
                                   data-desc="<?php echo e($row['quotes'] ?? ''); ?>"
                                   onclick="openEditStudent(this)"></i>
                            <?php endif; ?>

                            <?php if (in_array($role, ['admin', 'master'], true)): ?>
                                <form method="POST"
                                      style="display:inline;"
                                      onsubmit="return confirm('Delete this profile permanently?');">
                                    <input type="hidden" name="csrf_token" value="<?php echo e($_SESSION['csrf_token']); ?>">
                                    <input type="hidden" name="delete_student" value="1">
                                    <input type="hidden" name="student_id" value="<?php echo e($row['ID'] ?? ''); ?>">

                                    <button type="submit"
                                            style="border:none; background:none; padding:0;">
                                        <i class="bi bi-trash text-danger" style="cursor:pointer"></i>
                                    </button>
                                </form>
                            <?php endif; ?>
                        </div>
                    </div>

                    <img src="<?php echo e(!empty($row['profile_image']) ? $row['profile_image'] : 'images/chess.jpeg'); ?>"
                         class="card-img-top"
                         alt="Student Photo">

                    <div class="card-body text-success">
                        <h5 class="card-title"><?php echo e($row['school'] ?? ''); ?></h5>

                        <p class="card-text small">
                            <strong>Age:</strong> <?php echo e($displayAge); ?><br>

                            <strong>Rating:</strong>
                            <span class="badge bg-success"><?php echo e($row['rating'] ?? ''); ?></span><br>

                            <strong>Phone:</strong> <?php echo e($row['phone'] ?? ''); ?><br>

                            <strong>Points:</strong> <?php echo e($row['points'] ?? 0); ?><br>

                            <strong>Puzzles:</strong>
                            <a href="puzzle.php?user=<?php echo (int)($row['ID'] ?? 0); ?>" class="text-decoration-none">
                                View Shared Puzzles
                            </a><br>

                            <strong>Certificate:</strong>

                            <?php if ($hasCertificate): ?>
                                <span class="badge bg-info text-dark">Uploaded</span>

                                <?php if ($canViewCertificate): ?>
                                    <div class="mt-2">
                                        <a target="_blank"
                                           class="btn btn-sm btn-info me-1"
                                           href="certificate.php?id=<?php echo e($row['ID'] ?? ''); ?>&action=view">
                                            <i class="bi bi-eye"></i> View
                                        </a>

                                        <a class="btn btn-sm btn-secondary"
                                           href="certificate.php?id=<?php echo e($row['ID'] ?? ''); ?>&action=download">
                                            <i class="bi bi-download"></i> Download
                                        </a>
                                    </div>
                                <?php endif; ?>
                            <?php else: ?>
                                <span class="badge bg-secondary">Missing</span>
                            <?php endif; ?>
                        </p>

                        <?php if ($isOwnProfile && $currentRole === 'student'): ?>
                            <div class="mt-2">
                                <a href="puzzle.php" class="btn btn-sm btn-outline-success w-100">
                                    <i class="bi bi-puzzle-fill"></i> Share Puzzle
                                </a>
                            </div>
                        <?php endif; ?>

                        <p class="card-text small border-top pt-2">
                            <i><?php echo e($row['quotes'] ?? ''); ?></i>
                        </p>
                    </div>
                </div>
            </div>
        <?php endforeach; ?>
    </div>
</div>

<div class="offcanvas offcanvas-end" tabindex="-1" id="contactOffcanvas">
    <div class="offcanvas-header border-bottom">
        <h5 class="offcanvas-title">Academy Contact</h5>
        <button type="button" class="btn-close" data-bs-dismiss="offcanvas"></button>
    </div>

    <div class="offcanvas-body text-center">
        <img src="images/chess.jpeg"
             class="img-fluid rounded mb-4 shadow-sm"
             style="max-width: 150px;"
             alt="Academy Logo">

        <div class="text-start px-3">
            <h6><i class="bi bi-building text-success"></i> Golden Chess Academy</h6>
            <p class="small text-muted">123 Academy Lane, Trichy<br>Tamil Nadu, India</p>

            <hr>

            <p><i class="bi bi-envelope-fill text-dark"></i> baskar@gmail.com</p>
            <p><i class="bi bi-telephone-fill text-dark"></i> +91 88831 17520</p>
        </div>
    </div>
</div>

<div class="modal fade" id="registerStudentModal" tabindex="-1">
    <div class="modal-dialog">
        <form method="post" enctype="multipart/form-data" class="modal-content" data-loading="1">
            <div class="modal-header">
                <h5>Register Student</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>

            <div class="modal-body">
                <input type="hidden" name="register_student" value="1">
                <input type="hidden" name="csrf_token" value="<?php echo e($_SESSION['csrf_token']); ?>">

                <label class="small fw-bold text-muted">Account Credentials</label>

                <div class="row g-2 mb-2">
                    <div class="col-6">
                        <input type="text"
                               name="username"
                               placeholder="Username"
                               class="form-control"
                               autocomplete="off"
                               required>
                    </div>

                    <div class="col-6">
                        <input type="password"
                               name="password"
                               placeholder="Password"
                               class="form-control"
                               minlength="6"
                               autocomplete="new-password"
                               required>
                    </div>
                </div>

                <label class="small fw-bold text-muted">Profile Photo</label>
                <input type="file" name="profile_image" class="form-control mb-2" accept="image/*">

                <label class="small fw-bold text-danger">Birth Certificate</label>
                <input type="file"
                       name="birth_certificate"
                       class="form-control mb-2"
                       accept=".pdf,image/jpeg,image/png"
                       required>

                <div class="form-text small mb-2">
                    Birth certificate must be PDF, JPG or PNG. Max 2MB.
                </div>

                <input type="text" name="name" placeholder="Full Name" class="form-control mb-2" required>

                <input type="date" name="dob" id="register_dob" class="form-control mb-2" required>
                <input type="text" id="register_age_display" class="form-control mb-2" placeholder="Age (auto)" readonly>

                <input type="text" name="school" placeholder="School" class="form-control mb-2" required>
                <input type="text" name="rating" placeholder="Rating" class="form-control mb-2" required>
                <input type="text" name="phone" placeholder="Phone" class="form-control mb-2" required>
                <input type="email" name="email" placeholder="Email" class="form-control mb-2" required>

                <textarea name="description"
                          placeholder="Bio/Quotes"
                          class="form-control mb-2"
                          rows="3"></textarea>
            </div>

            <div class="modal-footer">
                <button type="submit" class="btn btn-success w-100">
                    Register Student
                </button>
            </div>
        </form>
    </div>
</div>

<div class="modal fade" id="editStudentModal" tabindex="-1">
    <div class="modal-dialog">
        <form method="post" enctype="multipart/form-data" class="modal-content" data-loading="1">
            <div class="modal-header">
                <h5>Edit Profile Details</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>

            <div class="modal-body">
                <input type="hidden" name="update_student" value="1">
                <input type="hidden" name="csrf_token" value="<?php echo e($_SESSION['csrf_token']); ?>">
                <input type="hidden" name="student_id" id="s_id">

                <label class="small fw-bold text-muted">Profile Photo</label>
                <input type="file" name="edit_profile_image" class="form-control mb-2" accept="image/*">

                <label class="small fw-bold text-muted">Update Birth Certificate</label>
                <input type="file"
                       name="edit_birth_certificate"
                       class="form-control mb-2"
                       accept=".pdf,image/jpeg,image/png">

                <div class="form-text small mb-2">
                    Leave certificate empty if you do not want to change it.
                </div>

                <label class="small fw-bold text-muted">Reset Password</label>
                <input type="password"
                       name="edit_password"
                       id="s_pass"
                       class="form-control mb-3"
                       placeholder="Leave blank to keep current password"
                       minlength="6"
                       autocomplete="new-password">

                <input type="text" name="edit_name" id="s_name" class="form-control mb-2" required>

                <input type="date" name="edit_dob" id="s_dob" class="form-control mb-2" required>
                <input type="text" id="s_age_display" class="form-control mb-2" placeholder="Age (auto)" readonly>

                <input type="text" name="edit_school" id="s_school" class="form-control mb-2" required>
                <input type="text" name="edit_rating" id="s_rating" class="form-control mb-2" required>
                <input type="text" name="edit_phone" id="s_phone" class="form-control mb-2" required>
                <input type="email" name="edit_email" id="s_email" class="form-control mb-2" required>

                <textarea name="edit_desc"
                          id="s_desc"
                          class="form-control mb-2"
                          rows="3"></textarea>
            </div>

            <div class="modal-footer">
                <button type="submit" class="btn btn-primary w-100">
                    Update Profile
                </button>
            </div>
        </form>
    </div>
</div>

<?php if (in_array($role, ['admin', 'master'], true)): ?>
    <div class="modal fade" id="messageModal" tabindex="-1">
        <div class="modal-dialog">
            <form method="post" class="modal-content">
                <div class="modal-header">
                    <h5>Send Message</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>

                <div class="modal-body">
                    <input type="hidden" name="send_msg_action" value="1">
                    <input type="hidden" name="csrf_token" value="<?php echo e($_SESSION['csrf_token']); ?>">

                    <select name="msg_target" id="msg_target" class="form-select mb-3">
                        <option value="all">Whole Class</option>
                        <option value="individual">Specific Student</option>
                    </select>

                    <input type="text"
                           name="student_username"
                           id="student_input"
                           class="form-control mb-3"
                           placeholder="Enter Student Username"
                           style="display:none;">

                    <textarea name="message_text"
                              class="form-control"
                              rows="4"
                              placeholder="Type your announcement here..."
                              required></textarea>
                </div>

                <div class="modal-footer">
                    <button type="submit" class="btn btn-primary w-100">Broadcast</button>
                </div>
            </form>
        </div>
    </div>
<?php endif; ?>

<script>
function calculateAgeFromDate(dateString) {
    if (!dateString) {
        return '';
    }

    const birth = new Date(dateString);
    const today = new Date();

    if (isNaN(birth.getTime()) || birth > today) {
        return '';
    }

    let age = today.getFullYear() - birth.getFullYear();
    const monthDiff = today.getMonth() - birth.getMonth();

    if (monthDiff < 0 || (monthDiff === 0 && today.getDate() < birth.getDate())) {
        age--;
    }

    return age;
}

function updateAgePreview(dobId, ageId) {
    const dobField = document.getElementById(dobId);
    const ageField = document.getElementById(ageId);

    if (!dobField || !ageField) {
        return;
    }

    ageField.value = calculateAgeFromDate(dobField.value);
}

function openEditStudent(element) {
    const data = element.dataset;

    document.getElementById('s_id').value = data.id || '';
    document.getElementById('s_name').value = data.name || '';
    document.getElementById('s_dob').value = data.dob || '';
    document.getElementById('s_school').value = data.school || '';
    document.getElementById('s_rating').value = data.rating || '';
    document.getElementById('s_phone').value = data.phone || '';
    document.getElementById('s_email').value = data.email || '';
    document.getElementById('s_desc').value = data.desc || '';
    document.getElementById('s_pass').value = '';

    updateAgePreview('s_dob', 's_age_display');

    new bootstrap.Modal(document.getElementById('editStudentModal')).show();
}

document.addEventListener('DOMContentLoaded', function () {
    const jsQuotes = <?php echo json_encode(
        $quotes,
        JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP | JSON_UNESCAPED_UNICODE
    ); ?>;

    function startLoadingQuote() {
        if (!window.Notiflix) {
            return;
        }

        const randomQ = jsQuotes[Math.floor(Math.random() * jsQuotes.length)];

        Notiflix.Loading.circle(randomQ, {
            backgroundColor: 'rgba(255,255,255,0.95)',
            svgColor: '#000000',
            messageColor: '#000000',
            messageFontSize: '18px'
        });
    }

    document.querySelectorAll('form[data-loading]').forEach(function (form) {
        form.addEventListener('submit', function (e) {
            if (!form.checkValidity()) {
                return;
            }

            e.preventDefault();

            startLoadingQuote();

            setTimeout(function () {
                form.submit();
            }, 1000);
        });
    });

    const registerDob = document.getElementById('register_dob');
    if (registerDob) {
        registerDob.addEventListener('change', function () {
            updateAgePreview('register_dob', 'register_age_display');
        });
    }

    const editDob = document.getElementById('s_dob');
    if (editDob) {
        editDob.addEventListener('change', function () {
            updateAgePreview('s_dob', 's_age_display');
        });
    }

    const msgTarget = document.getElementById('msg_target');
    const studentInput = document.getElementById('student_input');

    function toggleStudentInput() {
        if (!msgTarget || !studentInput) {
            return;
        }

        const isIndividual = msgTarget.value === 'individual';

        studentInput.style.display = isIndividual ? 'block' : 'none';
        studentInput.required = isIndividual;
    }

    if (msgTarget) {
        msgTarget.addEventListener('change', toggleStudentInput);
        toggleStudentInput();
    }

    const messageForm = document.querySelector('#messageModal form');

    if (messageForm) {
        messageForm.addEventListener('submit', function (e) {
            if (
                msgTarget &&
                msgTarget.value === 'individual' &&
                studentInput &&
                studentInput.value.trim() === ''
            ) {
                e.preventDefault();

                if (window.Notiflix) {
                    Notiflix.Notify.failure('⚠️ Please enter student username!');
                }

                return;
            }

            e.preventDefault();

            startLoadingQuote();

            setTimeout(function () {
                messageForm.submit();
            }, 1000);
        });
    }
});
</script>

<?php if (!empty($flashes)): ?>
<script>
window.addEventListener('load', function () {
    const flashes = <?php echo json_encode(
        $flashes,
        JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP | JSON_UNESCAPED_UNICODE
    ); ?>;

    flashes.forEach(function (flashItem, index) {
        setTimeout(function () {
            const allowedTypes = ['success', 'failure', 'warning', 'info'];
            const type = allowedTypes.includes(flashItem.type)
                ? flashItem.type
                : 'info';

            if (window.Notiflix) {
                Notiflix.Report[type](flashItem.title, flashItem.message, 'OK');
            }
        }, 3200 + (index * 500));
    });
});
</script>
<?php endif; ?>

</body>
</html>