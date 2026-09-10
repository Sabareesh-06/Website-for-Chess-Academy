<?php
session_start();

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
   LOGIN + ROLE GUARD
-------------------- */
if (!isset($_SESSION['role'])) {
    header("Location: login.php");
    exit();
}

$role = $_SESSION['role'];

if (!in_array($role, ['admin', 'master'], true)) {
    header("Location: ani1.php");
    exit();
}

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
    $_SESSION['student_profile_flash'][] = [
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

function process_upload(
    string $field,
    array $allowedExt,
    array $allowedMime,
    string $dir,
    int $maxSize = 2097152
): array {
    if (empty($_FILES[$field]['name'])) {
        return [
            'ok' => true,
            'path' => null
        ];
    }

    if ($_FILES[$field]['error'] !== UPLOAD_ERR_OK) {
        return [
            'ok' => false,
            'error' => 'There was a problem uploading the file.'
        ];
    }

    $ext = strtolower(pathinfo($_FILES[$field]['name'], PATHINFO_EXTENSION));

    if (!in_array($ext, $allowedExt, true)) {
        return [
            'ok' => false,
            'error' => 'File type not allowed.'
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
            'error' => 'Invalid file content.'
        ];
    }

    if (strpos($mime, 'image/') === 0 && !@getimagesize($tmpName)) {
        return [
            'ok' => false,
            'error' => 'Invalid image file.'
        ];
    }

    if ($_FILES[$field]['size'] > $maxSize) {
        return [
            'ok' => false,
            'error' => 'File size must be under 2MB.'
        ];
    }

    if (!is_dir($dir)) {
        @mkdir($dir, 0755, true);
    }

    $newName = rtrim($dir, '/') . '/' . bin2hex(random_bytes(8)) . '.' . $ext;

    if (!move_uploaded_file($tmpName, $newName)) {
        return [
            'ok' => false,
            'error' => 'Could not save uploaded file.'
        ];
    }

    return [
        'ok' => true,
        'path' => $newName
    ];
}

/* --------------------
   CHECK BIRTH CERTIFICATE COLUMN
-------------------- */
$hasBirthCertificateColumn = false;

$columnCheck = mysqli_query($cn30, "SHOW COLUMNS FROM register LIKE 'birth_certificate'");

if ($columnCheck && mysqli_num_rows($columnCheck) > 0) {
    $hasBirthCertificateColumn = true;
} else {
    if (@mysqli_query($cn30, "ALTER TABLE register ADD COLUMN birth_certificate VARCHAR(255) DEFAULT NULL")) {
        $hasBirthCertificateColumn = true;
    }
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
   ADMIN / MASTER: REGISTER STUDENT
-------------------- */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['register_action'])) {
    if (!valid_csrf()) {
        flash('failure', 'Invalid Request', 'Security token missing.');
        header("Location: studentProfile.php");
        exit();
    }

    if (!$hasBirthCertificateColumn) {
        flash('failure', 'Database Error', 'birth_certificate column is missing.');
        header("Location: studentProfile.php");
        exit();
    }

    $name     = trim($_POST['name'] ?? '');
    $email    = trim($_POST['email'] ?? '');
    $dob      = trim($_POST['DOB'] ?? '');
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';

    $age = calculate_age($dob);

    if ($name === '' || $email === '' || $dob === '' || $username === '' || $password === '') {
        flash('warning', 'Missing Data', 'All fields are required.');
        header("Location: studentProfile.php");
        exit();
    }

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        flash('warning', 'Invalid Email', 'Please enter a valid email address.');
        header("Location: studentProfile.php");
        exit();
    }

    if (!strtotime($dob) || $age === null) {
        flash('warning', 'Invalid Date', 'Please enter a valid date of birth.');
        header("Location: studentProfile.php");
        exit();
    }

    if (strlen($password) < 6) {
        flash('warning', 'Weak Password', 'Password must be at least 6 characters long.');
        header("Location: studentProfile.php");
        exit();
    }

    if (empty($_FILES['birth_certificate']['name'])) {
        flash('warning', 'Missing Certificate', 'Birth certificate is required.');
        header("Location: studentProfile.php");
        exit();
    }

    $check = mysqli_prepare($cn30, "SELECT Username FROM register WHERE Username = ? LIMIT 1");

    if (!$check) {
        flash('failure', 'Registration Failed', 'Database error.');
        header("Location: studentProfile.php");
        exit();
    }

    mysqli_stmt_bind_param($check, "s", $username);
    mysqli_stmt_execute($check);
    mysqli_stmt_store_result($check);

    if (mysqli_stmt_num_rows($check) > 0) {
        flash('warning', 'Username Exists', 'That username is already taken.');
        header("Location: studentProfile.php");
        exit();
    }

    mysqli_stmt_close($check);

    $certificateUpload = process_upload(
        'birth_certificate',
        ['pdf', 'jpg', 'jpeg', 'png'],
        ['application/pdf', 'image/jpeg', 'image/png'],
        'uploads/certificates'
    );

    if (!$certificateUpload['ok']) {
        flash('warning', 'Invalid Certificate', $certificateUpload['error']);
        header("Location: studentProfile.php");
        exit();
    }

    if (empty($certificateUpload['path'])) {
        flash('warning', 'Missing Certificate', 'Birth certificate is required.');
        header("Location: studentProfile.php");
        exit();
    }

    $hashedPassword = password_hash($password, PASSWORD_DEFAULT);
    $studentRole = 'student';
    $ageValue = (string)$age;
    $birthCertificatePath = $certificateUpload['path'];

    $insert = mysqli_prepare(
        $cn30,
        "INSERT INTO register
        (Name, Email, DOB, age, Username, Password, role, active, birth_certificate)
        VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)"
    );

    if ($insert) {
        mysqli_stmt_bind_param(
            $insert,
            "ssssssss",
            $name,
            $email,
            $dob,
            $ageValue,
            $username,
            $hashedPassword,
            $studentRole,
            $birthCertificatePath
        );

        if (mysqli_stmt_execute($insert)) {
            flash('success', 'Student Registered', 'Student account created successfully.');
        } else {
            flash('failure', 'Registration Failed', 'Could not save student record.');
        }

        mysqli_stmt_close($insert);
    } else {
        flash('failure', 'Registration Failed', 'Database error.');
    }

    header("Location: studentProfile.php");
    exit();
}

/* --------------------
   ADMIN / MASTER: SEND MESSAGE
-------------------- */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['send_msg_action'])) {
    if (!valid_csrf()) {
        flash('failure', 'Invalid Request', 'Security token missing.');
        header("Location: studentProfile.php");
        exit();
    }

    $sender  = $_SESSION['Username'] ?? 'system';
    $message = trim($_POST['message_text'] ?? '');
    $target  = $_POST['msg_target'] ?? '';

    if ($message === '') {
        flash('warning', 'Empty Message', 'Message cannot be empty.');
    } elseif ($target === 'all') {
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
        } else {
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
    }

    header("Location: studentProfile.php");
    exit();
}

/* --------------------
   ADMIN / MASTER: UPDATE STUDENT
-------------------- */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['update_student_action'])) {
    if (!valid_csrf()) {
        flash('failure', 'Invalid Request', 'Security token missing.');
        header("Location: studentProfile.php");
        exit();
    }

    $id    = intval($_POST['student_id'] ?? 0);
    $name  = trim($_POST['name'] ?? '');
    $email = trim($_POST['email'] ?? '');
    $dob   = trim($_POST['DOB'] ?? '');

    $age = calculate_age($dob);

    if ($id <= 0) {
        flash('warning', 'Invalid Request', 'Invalid student ID.');
        header("Location: studentProfile.php");
        exit();
    }

    if ($name === '' || $email === '' || $dob === '') {
        flash('warning', 'Missing Data', 'All required fields must be filled.');
        header("Location: studentProfile.php");
        exit();
    }

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        flash('warning', 'Invalid Email', 'Please enter a valid email address.');
        header("Location: studentProfile.php");
        exit();
    }

    if (!strtotime($dob) || $age === null) {
        flash('warning', 'Invalid Date', 'Please enter a valid date of birth.');
        header("Location: studentProfile.php");
        exit();
    }

    $stmt = mysqli_prepare(
        $cn30,
        "SELECT * FROM register WHERE ID = ? AND (role = 'student' OR role = 'user') LIMIT 1"
    );

    if (!$stmt) {
        flash('failure', 'Update Failed', 'Database error.');
        header("Location: studentProfile.php");
        exit();
    }

    mysqli_stmt_bind_param($stmt, "i", $id);
    mysqli_stmt_execute($stmt);

    $result = mysqli_stmt_get_result($stmt);
    $current = mysqli_fetch_assoc($result);

    mysqli_stmt_close($stmt);

    if (!$current) {
        flash('failure', 'Update Failed', 'Student not found.');
        header("Location: studentProfile.php");
        exit();
    }

    $profileImage = !empty($current['profile_image'])
        ? $current['profile_image']
        : 'images/chess.jpeg';

    $birthCertificate = $current['birth_certificate'] ?? '';
    $ageValue = (string)$age;

    $photoUpload = process_upload(
        'student_photo',
        ['jpg', 'jpeg', 'png', 'webp', 'gif'],
        ['image/jpeg', 'image/png', 'image/webp', 'image/gif'],
        'images'
    );

    if (!$photoUpload['ok']) {
        flash('warning', 'Invalid Photo', $photoUpload['error']);
        header("Location: studentProfile.php");
        exit();
    }

    if ($photoUpload['path'] !== null) {
        $profileImage = $photoUpload['path'];
    }

    if ($hasBirthCertificateColumn) {
        $certificateUpload = process_upload(
            'birth_certificate',
            ['pdf', 'jpg', 'jpeg', 'png'],
            ['application/pdf', 'image/jpeg', 'image/png'],
            'uploads/certificates'
        );

        if (!$certificateUpload['ok']) {
            flash('warning', 'Invalid Certificate', $certificateUpload['error']);
            header("Location: studentProfile.php");
            exit();
        }

        if ($certificateUpload['path'] !== null) {
            $birthCertificate = $certificateUpload['path'];
        }
    } else {
        if (!empty($_FILES['birth_certificate']['name'])) {
            flash('warning', 'Certificate Storage Unavailable', 'Birth certificate column is not available in database.');
            header("Location: studentProfile.php");
            exit();
        }
    }

    $studentRole = 'student';

    if ($hasBirthCertificateColumn) {
        $update = mysqli_prepare(
            $cn30,
            "UPDATE register
            SET Name = ?, Email = ?, DOB = ?, age = ?, role = ?, profile_image = ?, birth_certificate = ?
            WHERE ID = ? AND (role = 'student' OR role = 'user')"
        );

        if ($update) {
            mysqli_stmt_bind_param(
                $update,
                "sssssssi",
                $name,
                $email,
                $dob,
                $ageValue,
                $studentRole,
                $profileImage,
                $birthCertificate,
                $id
            );

            if (mysqli_stmt_execute($update)) {
                flash('success', 'Updated Successfully', 'Student record updated successfully.');
            } else {
                flash('failure', 'Update Failed', 'Could not update student record.');
            }

            mysqli_stmt_close($update);
        } else {
            flash('failure', 'Update Failed', 'Database error.');
        }
    } else {
        $update = mysqli_prepare(
            $cn30,
            "UPDATE register
            SET Name = ?, Email = ?, DOB = ?, age = ?, role = ?, profile_image = ?
            WHERE ID = ? AND (role = 'student' OR role = 'user')"
        );

        if ($update) {
            mysqli_stmt_bind_param(
                $update,
                "ssssssi",
                $name,
                $email,
                $dob,
                $ageValue,
                $studentRole,
                $profileImage,
                $id
            );

            if (mysqli_stmt_execute($update)) {
                flash('success', 'Updated Successfully', 'Student record updated successfully.');
            } else {
                flash('failure', 'Update Failed', 'Could not update student record.');
            }

            mysqli_stmt_close($update);
        } else {
            flash('failure', 'Update Failed', 'Database error.');
        }
    }

    header("Location: studentProfile.php");
    exit();
}

/* --------------------
   ADMIN / MASTER: DELETE STUDENT
-------------------- */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['delete_student_action'])) {
    if (!valid_csrf()) {
        flash('failure', 'Invalid Request', 'Security token missing.');
        header("Location: studentProfile.php");
        exit();
    }

    $id = intval($_POST['student_id'] ?? 0);

    if ($id <= 0) {
        flash('warning', 'Invalid Request', 'Invalid student ID.');
        header("Location: studentProfile.php");
        exit();
    }

    $stmt = mysqli_prepare(
        $cn30,
        "DELETE FROM register WHERE ID = ? AND (role = 'student' OR role = 'user')"
    );

    if ($stmt) {
        mysqli_stmt_bind_param($stmt, "i", $id);

        if (mysqli_stmt_execute($stmt) && mysqli_stmt_affected_rows($stmt) > 0) {
            flash('success', 'Deleted Successfully', 'Student record deleted successfully.');
        } else {
            flash('failure', 'Delete Failed', 'Student not found or could not be deleted.');
        }

        mysqli_stmt_close($stmt);
    } else {
        flash('failure', 'Delete Failed', 'Database error.');
    }

    header("Location: studentProfile.php");
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

$flashes = $_SESSION['student_profile_flash'] ?? [];
unset($_SESSION['student_profile_flash']);

$currentRole = $_SESSION['role'] ?? 'guest';
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Manage Students</title>

    <link rel="stylesheet" href="Rutu3.css">
    <link rel="stylesheet" href="bootstrap/css/bootstrap.min.css">
    <link rel="stylesheet" href="bootstrap/icons/font/bootstrap-icons.css">
    <link rel="stylesheet" href="notiflix/notiflix-3.2.7.min.css">

    <script src="bootstrap/js/bootstrap.bundle.min.js"></script>
    <script src="notiflix/notiflix-3.2.7.min.js"></script>

    <style>
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

<ul class="nav nav-tabs m-2" id="myTab" role="tablist">
    <li class="nav-item dropdown">
        <button class="nav-link dropdown-toggle" data-bs-toggle="dropdown">
            <i class="bi bi-people-fill"></i> Members
        </button>

        <ul class="dropdown-menu shadow">
            <li><a class="dropdown-item" href="master.php">Master</a></li>
            <li><a class="dropdown-item" href="student.php">Student</a></li>
        </ul>
    </li>

    <li class="nav-item">
        <button class="nav-link" onclick="window.location.href='puzzle.php'">
            <i class="bi bi-puzzle-fill"></i> Daily Puzzles
        </button>
    </li>

    <li class="nav-item ms-auto">
        <button class="btn btn-outline-primary btn-sm mt-1 me-2"
                data-bs-toggle="modal"
                data-bs-target="#messageModal">
            <i class="bi bi-chat-dots-fill"></i> Send Message
        </button>
    </li>

    <li class="nav-item">
        <button class="btn btn-primary btn-sm mt-1 me-2"
                data-bs-toggle="modal"
                data-bs-target="#registerModal">
            <i class="bi bi-person-plus-fill"></i> Register Student
        </button>
    </li>

    <li class="nav-item">
        <button class="nav-link active">
            <i class="bi bi-person-fill"></i> Student Profile
        </button>
    </li>

    <li class="nav-item">
        <button class="nav-link" data-bs-toggle="offcanvas" data-bs-target="#contactOffcanvas">
            <i class="bi bi-telephone-fill"></i> Contact
        </button>
    </li>

    <li class="nav-item dropdown">
        <button class="nav-link dropdown-toggle" data-bs-toggle="dropdown">
            <i class="bi bi-person-circle text-dark"></i>
        </button>

        <ul class="dropdown-menu dropdown-menu-end text-center p-3 shadow" style="width: 220px;">
            <li>
                <img src="<?php echo e($_SESSION['profile_image'] ?? 'images/chess.jpeg'); ?>"
                     class="rounded-circle mb-2 border"
                     style="width:70px; height:70px; object-fit:cover;"
                     alt="Profile Image">

                <p class="mb-1 small">
                    <strong>
                        <?php echo e($_SESSION['Name'] ?? 'Guest'); ?>
                    </strong>
                </p>

                <span class="badge bg-success mb-2">
                    <?php echo e(ucfirst($currentRole ?: 'guest')); ?>
                </span>

                <br>

                <button class="btn btn-sm btn-danger w-100"
                        onclick="window.location.href='studentProfile.php?logout=1'">
                    <i class="bi bi-person-fill-dash"></i> Logout
                </button>
            </li>
        </ul>
    </li>
</ul>

<div class="container mt-3">
    <div class="card mb-3">
        <div class="card-header">
            <div class="row align-items-center">
                <div class="col-9 fw-bold">Student Management Directory</div>

                <div class="col-3">
                    <form class="input-group" method="GET">
                        <input type="text"
                               name="search"
                               class="form-control"
                               placeholder="Search..."
                               value="<?php echo e($search); ?>">

                        <button class="btn btn-primary" type="submit">
                            <i class="bi bi-search"></i>
                        </button>
                    </form>
                </div>
            </div>
        </div>
    </div>

    <div class="card table-wrapper">
        <table class="table table-bordered mb-0">
            <thead class="table-light">
                <tr>
                    <th>S.No</th>
                    <th>Name</th>
                    <th>Email</th>
                    <th>DOB</th>
                    <th>Age</th>
                    <th>Role</th>
                    <th>Files Status</th>
                    <th>Action</th>
                </tr>
            </thead>

            <tbody>
                <?php if (empty($students)): ?>
                    <tr>
                        <td colspan="8" class="text-center text-muted">No student records found.</td>
                    </tr>
                <?php else: ?>
                    <?php $sno = 1; ?>
                    <?php foreach ($students as $row): ?>
                        <?php
                        $profileAge = calculate_age($row['DOB'] ?? '');

                        if ($profileAge === null) {
                            $profileAge = $row['age'] ?? '';
                        }
                        ?>

                        <tr>
                            <td><?php echo $sno++; ?></td>
                            <td><?php echo e($row['Name']); ?></td>
                            <td><?php echo e($row['Email']); ?></td>
                            <td><?php echo e($row['DOB'] ?? ''); ?></td>
                            <td><?php echo e($profileAge); ?></td>
                            <td><?php echo e(ucfirst($row['role'])); ?></td>

                            <td>
                                <?php if (!empty($row['profile_image'])): ?>
                                    <span class="badge bg-success">Photo</span>
                                <?php else: ?>
                                    <span class="badge bg-secondary">No Photo</span>
                                <?php endif; ?>

                                <?php if ($hasBirthCertificateColumn): ?>
                                    <?php if (!empty($row['birth_certificate'])): ?>
                                        <span class="badge bg-info text-dark">Certificate</span>
                                    <?php else: ?>
                                        <span class="badge bg-secondary">No Certificate</span>
                                    <?php endif; ?>
                                <?php endif; ?>
                            </td>

                            <td>
                                <?php if (!empty($row['birth_certificate'])): ?>
                                    <a target="_blank"
                                       class="btn btn-sm btn-info me-1"
                                       title="View Certificate"
                                       href="certificate.php?id=<?php echo e($row['ID']); ?>&action=view">
                                        <i class="bi bi-eye"></i>
                                    </a>

                                    <a class="btn btn-sm btn-secondary me-1"
                                       title="Download Certificate"
                                       href="certificate.php?id=<?php echo e($row['ID']); ?>&action=download">
                                        <i class="bi bi-download"></i>
                                    </a>
                                <?php endif; ?>

                                <button type="button"
                                        class="btn btn-sm btn-primary me-1"
                                        data-id="<?php echo e($row['ID']); ?>"
                                        data-name="<?php echo e($row['Name']); ?>"
                                        data-email="<?php echo e($row['Email']); ?>"
                                        data-dob="<?php echo e($row['DOB'] ?? ''); ?>"
                                        onclick="openEditStudent(this)">
                                    <i class="bi bi-pencil-square"></i>
                                </button>

                                <form method="POST"
                                      style="display:inline;"
                                      onsubmit="return confirm('Delete this student record permanently?');">
                                    <input type="hidden" name="csrf_token" value="<?php echo e($_SESSION['csrf_token']); ?>">
                                    <input type="hidden" name="delete_student_action" value="1">
                                    <input type="hidden" name="student_id" value="<?php echo e($row['ID']); ?>">

                                    <button type="submit" class="btn btn-sm btn-danger">
                                        <i class="bi bi-trash"></i>
                                    </button>
                                </form>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                <?php endif; ?>
            </tbody>
        </table>
    </div>
</div>

<div class="modal fade" id="editModal" tabindex="-1">
    <div class="modal-dialog">
        <form method="POST" enctype="multipart/form-data" class="modal-content" id="editForm" data-loading="1">
            <div class="modal-header">
                <h5 class="modal-title">Edit Student Profile</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>

            <div class="modal-body">
                <input type="hidden" name="update_student_action" value="1">
                <input type="hidden" name="csrf_token" value="<?php echo e($_SESSION['csrf_token']); ?>">
                <input type="hidden" name="student_id" id="edit_id">

                <div class="mb-3">
                    <label class="form-label fw-bold">Name</label>
                    <input type="text" class="form-control" name="name" id="edit_name" required>
                </div>

                <div class="mb-3">
                    <label class="form-label fw-bold">Email</label>
                    <input type="email" class="form-control" name="email" id="edit_email" required>
                </div>

                <div class="mb-3">
                    <label class="form-label fw-bold">Date of Birth</label>
                    <input type="date" class="form-control" name="DOB" id="edit_dob" required>
                </div>

                <div class="mb-3">
                    <label class="form-label fw-bold">Age</label>
                    <input type="text" class="form-control" id="profile_age_preview" readonly>
                </div>

                <div class="mb-3">
                    <label class="form-label fw-bold">Role</label>
                    <input type="text" class="form-control" value="Student" disabled>
                    <input type="hidden" name="role" value="student">
                </div>

                <div class="mb-3">
                    <label class="form-label fw-bold">Profile Photo</label>
                    <input type="file" class="form-control" name="student_photo" accept="image/*">
                </div>

                <?php if ($hasBirthCertificateColumn): ?>
                    <div class="mb-3">
                        <label class="form-label fw-bold text-danger">Birth Certificate</label>
                        <input type="file" class="form-control" name="birth_certificate" accept=".pdf,image/jpeg,image/png">
                        <div class="form-text small">
                            Leave empty if you do not want to change the certificate.
                        </div>
                    </div>
                <?php endif; ?>
            </div>

            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                <button type="submit" class="btn btn-success">Save Changes</button>
            </div>
        </form>
    </div>
</div>

<div class="modal fade" id="registerModal" tabindex="-1">
    <div class="modal-dialog modal-dialog-centered">
        <form method="POST" enctype="multipart/form-data" class="modal-content" data-loading="1">
            <div class="modal-header">
                <h5 class="modal-title">Register Student</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>

            <div class="modal-body">
                <input type="hidden" name="register_action" value="1">
                <input type="hidden" name="csrf_token" value="<?php echo e($_SESSION['csrf_token']); ?>">

                <div class="mb-3">
                    <label class="small fw-bold">Full Name</label>
                    <input type="text" name="name" class="form-control" required>
                </div>

                <div class="mb-3">
                    <label class="small fw-bold">Email</label>
                    <input type="email" name="email" class="form-control" required>
                </div>

                <div class="mb-3">
                    <label class="small fw-bold">Date of Birth</label>
                    <input type="date" name="DOB" id="reg_dob" class="form-control" required>
                </div>

                <div class="mb-3">
                    <label class="small fw-bold">Age</label>
                    <input type="text" id="reg_age_display" class="form-control" readonly>
                </div>

                <div class="mb-3">
                    <label class="small fw-bold text-danger">Birth Certificate</label>
                    <input type="file"
                           name="birth_certificate"
                           class="form-control"
                           accept=".pdf,image/jpeg,image/png"
                           required>

                    <div class="form-text small">
                        PDF, JPG or PNG. Max 2MB.
                    </div>
                </div>

                <div class="mb-3">
                    <label class="small fw-bold">Username</label>
                    <input type="text" name="username" class="form-control" required autocomplete="off">
                </div>

                <div class="mb-3">
                    <label class="small fw-bold">Password</label>
                    <input type="password"
                           name="password"
                           class="form-control"
                           minlength="6"
                           autocomplete="new-password"
                           required>
                </div>
            </div>

            <div class="modal-footer">
                <button type="submit" class="btn btn-success w-100">Create Account</button>
            </div>
        </form>
    </div>
</div>

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

    document.getElementById('edit_id').value = data.id || '';
    document.getElementById('edit_name').value = data.name || '';
    document.getElementById('edit_email').value = data.email || '';
    document.getElementById('edit_dob').value = data.dob || '';

    updateAgePreview('edit_dob', 'profile_age_preview');

    new bootstrap.Modal(document.getElementById('editModal')).show();
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

    const editDob = document.getElementById('edit_dob');
    if (editDob) {
        editDob.addEventListener('change', function () {
            updateAgePreview('edit_dob', 'profile_age_preview');
        });
    }

    const regDob = document.getElementById('reg_dob');
    if (regDob) {
        regDob.addEventListener('change', function () {
            updateAgePreview('reg_dob', 'reg_age_display');
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