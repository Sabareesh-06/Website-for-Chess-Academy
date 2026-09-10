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
   BASIC SAFE SETUP
-------------------- */
@mysqli_query(
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

@mysqli_query($cn30, "ALTER TABLE register ADD COLUMN profile_image VARCHAR(255) DEFAULT 'images/chess.jpeg'");
@mysqli_query($cn30, "ALTER TABLE register ADD COLUMN quotes TEXT NULL");
@mysqli_query($cn30, "ALTER TABLE register ADD COLUMN active TINYINT(1) NOT NULL DEFAULT 1");
@mysqli_query($cn30, "ALTER TABLE register MODIFY Password VARCHAR(255) NOT NULL");

/* --------------------
   LOGIN GUARD
   Guest is allowed to view masters.
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
    $_SESSION['master_flash'][] = [
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

    $newName = "images/master_" . bin2hex(random_bytes(8)) . "." . $ext;

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
   ADMIN ONLY: REGISTER STUDENT
-------------------- */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['register_action'])) {
    if (!valid_csrf()) {
        flash('failure', 'Invalid Request', 'Security token missing.');
        header("Location: master.php");
        exit();
    }

    if ($role !== 'admin') {
        flash('failure', 'Denied', 'Only admin can register students.');
        header("Location: master.php");
        exit();
    }

    $name     = trim($_POST['name'] ?? '');
    $age      = trim($_POST['age'] ?? '');
    $school   = trim($_POST['school'] ?? '');
    $phone    = trim($_POST['phone'] ?? '');
    $email    = trim($_POST['email'] ?? '');
    $rating   = trim($_POST['rating'] ?? '');
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';

    if (
        $name === '' ||
        $age === '' ||
        $school === '' ||
        $phone === '' ||
        $email === '' ||
        $rating === '' ||
        $username === '' ||
        $password === ''
    ) {
        flash('warning', 'Missing Data', 'All fields are required.');
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        flash('warning', 'Invalid Email', 'Please enter a valid email address.');
    } elseif (!ctype_digit($age) || (int)$age <= 0) {
        flash('warning', 'Invalid Age', 'Please enter a valid age.');
    } elseif (strlen($password) < 6) {
        flash('warning', 'Weak Password', 'Password must be at least 6 characters long.');
    } else {
        $check = mysqli_prepare($cn30, "SELECT Username FROM register WHERE Username = ? LIMIT 1");

        if ($check) {
            mysqli_stmt_bind_param($check, "s", $username);
            mysqli_stmt_execute($check);
            mysqli_stmt_store_result($check);

            if (mysqli_stmt_num_rows($check) > 0) {
                flash('warning', 'Username Exists', 'That username is already taken.');
            } else {
                $upload = process_profile_image('student_photo');

                if (!$upload['ok']) {
                    flash('warning', 'Invalid Image', $upload['error']);
                } else {
                    $hashedPassword = password_hash($password, PASSWORD_DEFAULT);
                    $studentRole = 'student';
                    $profilePath = $upload['path'];

                    $stmt = mysqli_prepare(
                        $cn30,
                        "INSERT INTO register
                        (Name, age, school, phone, Email, rating, Username, Password, role, profile_image)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
                    );

                    if ($stmt) {
                        mysqli_stmt_bind_param(
                            $stmt,
                            "ssssssssss",
                            $name,
                            $age,
                            $school,
                            $phone,
                            $email,
                            $rating,
                            $username,
                            $hashedPassword,
                            $studentRole,
                            $profilePath
                        );

                        if (mysqli_stmt_execute($stmt)) {
                            flash('success', 'Student Registered', 'Student account created successfully.');
                        } else {
                            flash('failure', 'Registration Failed', 'Could not save student record.');
                        }

                        mysqli_stmt_close($stmt);
                    } else {
                        flash('failure', 'Registration Failed', 'Database error.');
                    }
                }
            }

            mysqli_stmt_close($check);
        } else {
            flash('failure', 'Registration Failed', 'Database error.');
        }
    }

    header("Location: master.php");
    exit();
}

/* --------------------
   ADMIN / MASTER: SEND MESSAGE
-------------------- */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['send_msg_action'])) {
    if (!valid_csrf()) {
        flash('failure', 'Invalid Request', 'Security token missing.');
        header("Location: master.php");
        exit();
    }

    if (!in_array($role, ['admin', 'master'], true)) {
        flash('failure', 'Denied', 'Only admin or master can send messages.');
        header("Location: master.php");
        exit();
    }

    $sender  = $_SESSION['Username'] ?? 'system';
    $message = trim($_POST['message_text'] ?? '');
    $target  = $_POST['msg_target'] ?? '';

    if ($message === '') {
        flash('warning', 'Empty Message', 'Message cannot be empty.');
        header("Location: master.php");
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
            header("Location: master.php");
            exit();
        }

        $check = mysqli_prepare(
            $cn30,
            "SELECT ID FROM register WHERE Username = ? AND role = 'student' LIMIT 1"
        );

        if ($check) {
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
        } else {
            flash('failure', 'Message Failed', 'Database error.');
        }
    }

    header("Location: master.php");
    exit();
}

/* --------------------
   ADMIN ONLY: DELETE MASTER
-------------------- */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['delete_master'])) {
    if (!valid_csrf()) {
        flash('failure', 'Invalid Request', 'Security token missing.');
        header("Location: master.php");
        exit();
    }

    if ($role !== 'admin') {
        flash('failure', 'Denied', 'Only admin can delete masters.');
        header("Location: master.php");
        exit();
    }

    $id = intval($_POST['master_id'] ?? 0);

    if ($id <= 0) {
        flash('warning', 'Invalid Request', 'Invalid master ID.');
        header("Location: master.php");
        exit();
    }

    $stmt = mysqli_prepare(
        $cn30,
        "DELETE FROM register WHERE ID = ? AND role = 'master'"
    );

    if ($stmt) {
        mysqli_stmt_bind_param($stmt, "i", $id);

        if (mysqli_stmt_execute($stmt) && mysqli_stmt_affected_rows($stmt) > 0) {
            flash('success', 'Master Removed', 'Master profile has been deleted.');
        } else {
            flash('failure', 'Delete Failed', 'Master not found or could not be deleted.');
        }

        mysqli_stmt_close($stmt);
    } else {
        flash('failure', 'Delete Failed', 'Database error.');
    }

    header("Location: master.php");
    exit();
}

/* --------------------
   ADMIN ONLY: ADD MASTER
-------------------- */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['add_master'])) {
    if (!valid_csrf()) {
        flash('failure', 'Invalid Request', 'Security token missing.');
        header("Location: master.php");
        exit();
    }

    if ($role !== 'admin') {
        flash('failure', 'Denied', 'Only admin can add masters.');
        header("Location: master.php");
        exit();
    }

    $name       = trim($_POST['name'] ?? '');
    $role_title = trim($_POST['role_title'] ?? '');
    $phone      = trim($_POST['phone'] ?? '');
    $email      = trim($_POST['email'] ?? '');
    $rating     = trim($_POST['rating'] ?? '');
    $desc       = trim($_POST['description'] ?? '');
    $username   = trim($_POST['username'] ?? '');
    $password   = $_POST['password'] ?? '';

    if (
        $name === '' ||
        $role_title === '' ||
        $phone === '' ||
        $email === '' ||
        $rating === '' ||
        $username === '' ||
        $password === ''
    ) {
        flash('warning', 'Missing Data', 'All required fields must be filled.');
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        flash('warning', 'Invalid Email', 'Please enter a valid email address.');
    } elseif (strlen($password) < 6) {
        flash('warning', 'Weak Password', 'Password must be at least 6 characters long.');
    } else {
        $check = mysqli_prepare($cn30, "SELECT Username FROM register WHERE Username = ? LIMIT 1");

        if ($check) {
            mysqli_stmt_bind_param($check, "s", $username);
            mysqli_stmt_execute($check);
            mysqli_stmt_store_result($check);

            if (mysqli_stmt_num_rows($check) > 0) {
                flash('warning', 'Username Exists', 'That username is already taken.');
            } else {
                $upload = process_profile_image('profile_image');

                if (!$upload['ok']) {
                    flash('warning', 'Invalid Image', $upload['error']);
                } else {
                    $hashedPassword = password_hash($password, PASSWORD_DEFAULT);
                    $masterRole = 'master';
                    $imagePath = $upload['path'];

                    $stmt = mysqli_prepare(
                        $cn30,
                        "INSERT INTO register
                        (Username, Password, Name, school, phone, Email, rating, quotes, role, profile_image)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
                    );

                    if ($stmt) {
                        mysqli_stmt_bind_param(
                            $stmt,
                            "ssssssssss",
                            $username,
                            $hashedPassword,
                            $name,
                            $role_title,
                            $phone,
                            $email,
                            $rating,
                            $desc,
                            $masterRole,
                            $imagePath
                        );

                        if (mysqli_stmt_execute($stmt)) {
                            flash('success', 'Master Added', 'New master successfully registered.');
                        } else {
                            flash('failure', 'Add Failed', 'Could not save master profile.');
                        }

                        mysqli_stmt_close($stmt);
                    } else {
                        flash('failure', 'Add Failed', 'Database error.');
                    }
                }
            }

            mysqli_stmt_close($check);
        } else {
            flash('failure', 'Add Failed', 'Database error.');
        }
    }

    header("Location: master.php");
    exit();
}

/* --------------------
   ADMIN OR SELF: UPDATE MASTER
-------------------- */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['update_master'])) {
    if (!valid_csrf()) {
        flash('failure', 'Invalid Request', 'Security token missing.');
        header("Location: master.php");
        exit();
    }

    $id = intval($_POST['master_id'] ?? 0);

    if ($id <= 0) {
        flash('warning', 'Invalid Request', 'Invalid master ID.');
        header("Location: master.php");
        exit();
    }

    $stmt = mysqli_prepare(
        $cn30,
        "SELECT ID, Username, Password, profile_image, role
         FROM register
         WHERE ID = ? AND role = 'master'
         LIMIT 1"
    );

    if (!$stmt) {
        flash('failure', 'Update Failed', 'Database error.');
        header("Location: master.php");
        exit();
    }

    mysqli_stmt_bind_param($stmt, "i", $id);
    mysqli_stmt_execute($stmt);

    $result = mysqli_stmt_get_result($stmt);
    $target = mysqli_fetch_assoc($result);

    mysqli_stmt_close($stmt);

    if (!$target) {
        flash('failure', 'Update Failed', 'Master not found.');
        header("Location: master.php");
        exit();
    }

    $sessionUsername = $_SESSION['Username'] ?? '';
    $isAdmin = $role === 'admin';
    $isSelf = $sessionUsername !== '' && hash_equals((string)$target['Username'], (string)$sessionUsername);

    if (!$isAdmin && !$isSelf) {
        flash('failure', 'Denied', 'You are not allowed to edit this master profile.');
        header("Location: master.php");
        exit();
    }

    $name      = trim($_POST['edit_name'] ?? '');
    $roleTitle = trim($_POST['edit_role'] ?? '');
    $phone     = trim($_POST['edit_phone'] ?? '');
    $email     = trim($_POST['edit_email'] ?? '');
    $rating    = trim($_POST['edit_rating'] ?? '');
    $desc      = trim($_POST['edit_desc'] ?? '');

    $newPassword = trim($_POST['edit_password'] ?? '');
    $password = $target['Password'];

    if (
        $name === '' ||
        $roleTitle === '' ||
        $phone === '' ||
        $email === '' ||
        $rating === ''
    ) {
        flash('warning', 'Missing Data', 'All required fields must be filled.');
        header("Location: master.php");
        exit();
    }

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        flash('warning', 'Invalid Email', 'Please enter a valid email address.');
        header("Location: master.php");
        exit();
    }

    if ($newPassword !== '' && strlen($newPassword) < 6) {
        flash('warning', 'Weak Password', 'Password must be at least 6 characters long.');
        header("Location: master.php");
        exit();
    }

    if ($newPassword !== '') {
        $password = password_hash($newPassword, PASSWORD_DEFAULT);
    }

    $currentImage = !empty($target['profile_image'])
        ? $target['profile_image']
        : 'images/chess.jpeg';

    $upload = process_profile_image('edit_profile_image', $currentImage);

    if (!$upload['ok']) {
        flash('warning', 'Invalid Image', $upload['error']);
        header("Location: master.php");
        exit();
    }

    $imagePath = $upload['path'];

    $update = mysqli_prepare(
        $cn30,
        "UPDATE register
        SET Name = ?, school = ?, phone = ?, Email = ?, rating = ?, quotes = ?, profile_image = ?, Password = ?
        WHERE ID = ? AND role = 'master'"
    );

    if ($update) {
        mysqli_stmt_bind_param(
            $update,
            "ssssssssi",
            $name,
            $roleTitle,
            $phone,
            $email,
            $rating,
            $desc,
            $imagePath,
            $password,
            $id
        );

        if (mysqli_stmt_execute($update)) {
            flash('success', 'Profile Updated', 'Master information has been saved.');
        } else {
            flash('failure', 'Update Failed', 'Could not update master profile.');
        }

        mysqli_stmt_close($update);
    } else {
        flash('failure', 'Update Failed', 'Database error.');
    }

    header("Location: master.php");
    exit();
}

/* --------------------
   FETCH MASTERS
-------------------- */
$search = trim($_GET['search'] ?? '');
$likeSearch = '%' . addcslashes($search, '%_') . '%';

$stmt = mysqli_prepare(
    $cn30,
    "SELECT *
     FROM register
     WHERE role = 'master'
       AND Name LIKE ?
     ORDER BY ID DESC"
);

$masters = [];

if ($stmt) {
    mysqli_stmt_bind_param($stmt, "s", $likeSearch);
    mysqli_stmt_execute($stmt);

    $result = mysqli_stmt_get_result($stmt);

    while ($row = mysqli_fetch_assoc($result)) {
        $masters[] = $row;
    }

    mysqli_stmt_close($stmt);
}

$flashes = $_SESSION['master_flash'] ?? [];
unset($_SESSION['master_flash']);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Master Directory</title>

    <link rel="stylesheet" href="Rutu3.css">
    <link rel="stylesheet" href="bootstrap/css/bootstrap.min.css">
    <link rel="stylesheet" href="bootstrap/icons/font/bootstrap-icons.css">
    <link rel="stylesheet" href="notiflix/notiflix-3.2.7.min.css">

    <script src="bootstrap/js/bootstrap.bundle.min.js"></script>
    <script src="notiflix/notiflix-3.2.7.min.js"></script>

    <style>
        .add-card {
            border: 2px dashed #0d6efd;
            cursor: pointer;
            min-height: 400px;
            display: flex;
            align-items: center;
            justify-content: center;
            background: #f0f7ff;
            transition: 0.3s;
        }

        .add-card:hover {
            background: #e2efff;
            border-style: solid;
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

    <?php if (in_array($role, ['admin', 'master', 'student'], true)): ?>
        <li class="nav-item">
            <button class="nav-link" onclick="window.location.href='puzzle.php'">
                <i class="bi bi-puzzle-fill"></i> Daily Puzzles
            </button>
        </li>
    <?php endif; ?>

    <?php if (in_array($role, ['admin', 'master'], true)): ?>
        <li class="nav-item ms-auto">
            <button class="btn btn-outline-primary btn-sm mt-1 me-2"
                    data-bs-toggle="modal"
                    data-bs-target="#messageModal">
                <i class="bi bi-chat-dots-fill"></i> Send Message
            </button>
        </li>

        <?php if ($role === 'admin'): ?>
            <li class="nav-item">
                <button class="btn btn-primary btn-sm mt-1 me-2"
                        data-bs-toggle="modal"
                        data-bs-target="#registerModal">
                    <i class="bi bi-person-plus-fill"></i> Register Student
                </button>
            </li>

            <li class="nav-item">
                <button class="nav-link" onclick="window.location.href='studentProfile.php'">
                    <i class="bi bi-person-fill"></i> Student Profile
                </button>
            </li>
        <?php endif; ?>

        <?php if ($role !== 'guest'): ?>
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
        <?php if ($role !== 'guest'): ?>
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
                <?php if ($role !== 'guest'): ?>
                    <img src="<?php echo e($_SESSION['profile_image'] ?? 'images/chess.jpeg'); ?>"
                         class="rounded-circle mb-2 border"
                         style="width:70px; height:70px; object-fit:cover;"
                         alt="Profile Image">

                    <p class="mb-1 small">
                        <strong><?php echo e($_SESSION['Name'] ?? 'Guest'); ?></strong>
                    </p>

                    <span class="badge bg-success mb-2">
                        <?php echo e(ucfirst($role ?: 'guest')); ?>
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
                        onclick="window.location.href='master.php?logout=1'">
                    <i class="bi bi-person-fill-dash"></i> Logout
                </button>
            </li>
        </ul>
    </li>
</ul>

<ul class="nav nav-tabs">
    <li class="nav-item">
        <a class="nav-link active" href="master.php">Master</a>
    </li>

    <li class="nav-item">
        <a class="nav-link" href="student.php">Student</a>
    </li>

    <li class="nav-item ms-auto me-2">
        <form class="input-group" method="GET" style="width: 250px; margin-top: 2px;">
            <input type="text"
                   name="search"
                   class="form-control form-control-sm"
                   placeholder="Search Masters..."
                   value="<?php echo e($search); ?>">

            <button class="btn btn-primary btn-sm" type="submit">
                <i class="bi bi-search"></i>
            </button>
        </form>
    </li>
</ul>

<div class="container mt-3">
    <div class="row">
        <?php if ($role === 'admin'): ?>
            <div class="col-md-3 mb-3">
                <div class="card add-card" data-bs-toggle="modal" data-bs-target="#addMasterModal">
                    <div class="text-center text-primary">
                        <i class="bi bi-person-plus-fill fs-1"></i>
                        <p class="fw-bold mt-2">Add New Master</p>
                    </div>
                </div>
            </div>
        <?php endif; ?>

        <?php if (empty($masters)): ?>
            <div class="col-12">
                <div class="alert alert-info text-center">No master records found.</div>
            </div>
        <?php endif; ?>

        <?php foreach ($masters as $row): ?>
            <?php
            $sessionUsername = $_SESSION['Username'] ?? '';
            $canEdit = $role === 'admin'
                || ($sessionUsername !== '' && hash_equals((string)($row['Username'] ?? ''), (string)$sessionUsername));
            ?>

            <div class="col-md-3 mb-3">
                <div class="card border-primary h-100 shadow-sm">
                    <div class="card-header bg-transparent border-primary d-flex justify-content-between align-items-center">
                        <div>
                            <strong><?php echo e($row['Name'] ?? ''); ?></strong><br>
                            <span class="badge-username">User: <?php echo e($row['Username'] ?? ''); ?></span>
                        </div>

                        <div>
                            <?php if ($canEdit): ?>
                                <i class="bi bi-pencil-square text-primary me-2"
                                   style="cursor:pointer"
                                   data-id="<?php echo e($row['ID'] ?? ''); ?>"
                                   data-name="<?php echo e($row['Name'] ?? ''); ?>"
                                   data-role="<?php echo e($row['school'] ?? ''); ?>"
                                   data-rating="<?php echo e($row['rating'] ?? ''); ?>"
                                   data-phone="<?php echo e($row['phone'] ?? ''); ?>"
                                   data-email="<?php echo e($row['Email'] ?? ''); ?>"
                                   data-desc="<?php echo e($row['quotes'] ?? ''); ?>"
                                   onclick="openEditMaster(this)"></i>
                            <?php endif; ?>

                            <?php if ($role === 'admin'): ?>
                                <form method="POST"
                                      style="display:inline;"
                                      onsubmit="return confirm('Delete this Master profile?');">
                                    <input type="hidden" name="csrf_token" value="<?php echo e($_SESSION['csrf_token']); ?>">
                                    <input type="hidden" name="delete_master" value="1">
                                    <input type="hidden" name="master_id" value="<?php echo e($row['ID'] ?? ''); ?>">

                                    <button type="submit" style="border:none; background:none; padding:0;">
                                        <i class="bi bi-trash text-danger" style="cursor:pointer"></i>
                                    </button>
                                </form>
                            <?php endif; ?>
                        </div>
                    </div>

                    <img src="<?php echo e(!empty($row['profile_image']) ? $row['profile_image'] : 'images/chess.jpeg'); ?>"
                         class="card-img-top"
                         alt="Master Photo">

                    <div class="card-body">
                        <h5 class="card-title text-primary"><?php echo e($row['school'] ?? ''); ?></h5>

                        <p class="card-text small">
                            <strong>Rating:</strong>
                            <span class="badge bg-primary"><?php echo e($row['rating'] ?? ''); ?></span><br>

                            <strong>Email:</strong> <?php echo e($row['Email'] ?? ''); ?><br>
                            <strong>Phone:</strong> <?php echo e($row['phone'] ?? ''); ?>
                        </p>

                        <p class="card-text small border-top pt-2 text-muted">
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

<?php if ($role === 'admin'): ?>
    <div class="modal fade" id="addMasterModal" tabindex="-1">
        <div class="modal-dialog">
            <form method="post" enctype="multipart/form-data" class="modal-content" data-loading="1">
                <div class="modal-header">
                    <h5>Add New Academy Master</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>

                <div class="modal-body">
                    <input type="hidden" name="add_master" value="1">
                    <input type="hidden" name="csrf_token" value="<?php echo e($_SESSION['csrf_token']); ?>">

                    <label class="small fw-bold text-muted">Login Access</label>

                    <div class="row g-2 mb-3">
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
                    <input type="file" name="profile_image" class="form-control mb-3" accept="image/*">

                    <label class="small fw-bold text-muted">Professional Details</label>

                    <input type="text" name="name" placeholder="Full Name" class="form-control mb-2" required>
                    <input type="text" name="role_title" placeholder="Job Title (e.g. FIDE Master)" class="form-control mb-2" required>
                    <input type="text" name="rating" placeholder="Current Rating" class="form-control mb-2" required>
                    <input type="text" name="phone" placeholder="Contact Phone" class="form-control mb-2" required>
                    <input type="email" name="email" placeholder="Contact Email" class="form-control mb-2" required>

                    <textarea name="description"
                              placeholder="Short Bio / Experience"
                              class="form-control"
                              rows="3"></textarea>
                </div>

                <div class="modal-footer">
                    <button type="submit" class="btn btn-primary w-100">Register Master</button>
                </div>
            </form>
        </div>
    </div>
<?php endif; ?>

<div class="modal fade" id="editMasterModal" tabindex="-1">
    <div class="modal-dialog">
        <form method="post" enctype="multipart/form-data" class="modal-content" data-loading="1">
            <div class="modal-header">
                <h5>Update Master Profile</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>

            <div class="modal-body">
                <input type="hidden" name="update_master" value="1">
                <input type="hidden" name="csrf_token" value="<?php echo e($_SESSION['csrf_token']); ?>">
                <input type="hidden" name="master_id" id="m_id">

                <label class="small fw-bold text-muted">Update Photo</label>
                <input type="file" name="edit_profile_image" class="form-control mb-3" accept="image/*">

                <label class="small fw-bold text-muted">Account Password</label>
                <input type="password"
                       name="edit_password"
                       id="m_pass"
                       class="form-control mb-3"
                       placeholder="Leave blank to keep current password"
                       minlength="6"
                       autocomplete="new-password">

                <label class="small fw-bold text-muted">Personal Info</label>

                <input type="text" name="edit_name" id="m_name" class="form-control mb-2" required>
                <input type="text" name="edit_role" id="m_role" class="form-control mb-2" required>
                <input type="text" name="edit_rating" id="m_rating" class="form-control mb-2" required>
                <input type="text" name="edit_phone" id="m_phone" class="form-control mb-2" required>
                <input type="email" name="edit_email" id="m_email" class="form-control mb-2" required>

                <textarea name="edit_desc" id="m_desc" class="form-control" rows="3"></textarea>
            </div>

            <div class="modal-footer">
                <button type="submit" class="btn btn-primary w-100">Save Changes</button>
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

<?php if ($role === 'admin'): ?>
    <div class="modal fade" id="registerModal" tabindex="-1">
        <div class="modal-dialog modal-dialog-centered">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">Register Student</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>

                <div class="modal-body">
                    <form method="post" enctype="multipart/form-data" data-loading="1">
                        <input type="hidden" name="register_action" value="1">
                        <input type="hidden" name="csrf_token" value="<?php echo e($_SESSION['csrf_token']); ?>">

                        <div class="mb-3 text-center">
                            <label class="small fw-bold d-block">Profile Photo</label>
                            <input type="file" name="student_photo" class="form-control" accept="image/*">
                        </div>

                        <div class="mb-3">
                            <label class="small fw-bold">Full Name</label>
                            <input type="text"
                                   name="name"
                                   id="reg_name"
                                   class="form-control"
                                   required
                                   placeholder="Enter student name">
                        </div>

                        <div class="row">
                            <div class="col-6 mb-3">
                                <label class="small fw-bold">Login Username</label>
                                <input type="text"
                                       name="username"
                                       id="reg_user"
                                       class="form-control"
                                       required
                                       placeholder="Username"
                                       autocomplete="off">
                            </div>

                            <div class="col-6 mb-3">
                                <label class="small fw-bold">Login Password</label>
                                <input type="password"
                                       name="password"
                                       class="form-control"
                                       minlength="6"
                                       autocomplete="new-password"
                                       required
                                       placeholder="Set password">
                            </div>
                        </div>

                        <div class="row">
                            <div class="col-6 mb-3">
                                <label class="small fw-bold">Age</label>
                                <input type="number" name="age" class="form-control" min="1" required>
                            </div>

                            <div class="col-6 mb-3">
                                <label class="small fw-bold">Rating</label>
                                <input type="text" name="rating" class="form-control" required>
                            </div>
                        </div>

                        <div class="mb-3">
                            <label class="small fw-bold">School/Academy</label>
                            <input type="text" name="school" class="form-control" required>
                        </div>

                        <div class="row">
                            <div class="col-6 mb-3">
                                <label class="small fw-bold">Phone</label>
                                <input type="text" name="phone" class="form-control" required>
                            </div>

                            <div class="col-6 mb-3">
                                <label class="small fw-bold">Email</label>
                                <input type="email" name="email" class="form-control" required>
                            </div>
                        </div>

                        <button type="submit" class="btn btn-success w-100">Create Account</button>
                    </form>
                </div>
            </div>
        </div>
    </div>
<?php endif; ?>

<script>
function openEditMaster(element) {
    const data = element.dataset;

    document.getElementById('m_id').value = data.id || '';
    document.getElementById('m_name').value = data.name || '';
    document.getElementById('m_role').value = data.role || '';
    document.getElementById('m_rating').value = data.rating || '';
    document.getElementById('m_phone').value = data.phone || '';
    document.getElementById('m_email').value = data.email || '';
    document.getElementById('m_desc').value = data.desc || '';
    document.getElementById('m_pass').value = '';

    new bootstrap.Modal(document.getElementById('editMasterModal')).show();
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

    const regName = document.getElementById('reg_name');
    const regUser = document.getElementById('reg_user');

    if (regName && regUser) {
        regName.addEventListener('input', function () {
            let nameParts = this.value.trim().split(' ');

            if (nameParts[0] !== "") {
                let suggested = nameParts[0].toLowerCase() + Math.floor(Math.random() * 900 + 100);
                regUser.value = suggested;
            }
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