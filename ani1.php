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
   LOGIN GUARD
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
    $_SESSION['ani1_flash'][] = [
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
        header("Location: ani1.php");
        exit();
    }

    if ($role !== 'admin') {
        flash('failure', 'Denied', 'Only admin can register students.');
        header("Location: ani1.php");
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
                $profile_path = "images/chess.jpeg";

                if (!empty($_FILES["student_photo"]["name"])) {
                    if ($_FILES["student_photo"]["error"] !== UPLOAD_ERR_OK) {
                        flash('warning', 'Upload Error', 'There was a problem uploading the photo.');
                        header("Location: ani1.php");
                        exit();
                    }

                    $allowedExt = ['jpg', 'jpeg', 'png', 'webp', 'gif'];
                    $allowedMime = ['image/jpeg', 'image/png', 'image/webp', 'image/gif'];

                    $ext = strtolower(pathinfo($_FILES["student_photo"]["name"], PATHINFO_EXTENSION));
                    $tmpName = $_FILES["student_photo"]["tmp_name"];
                    $imageInfo = @getimagesize($tmpName);

                    if (
                        $imageInfo &&
                        in_array($ext, $allowedExt, true) &&
                        in_array($imageInfo['mime'] ?? '', $allowedMime, true) &&
                        $_FILES["student_photo"]["size"] <= 2 * 1024 * 1024
                    ) {
                        if (!is_dir('images')) {
                            @mkdir('images', 0755, true);
                        }

                        $newName = "images/student_" . bin2hex(random_bytes(8)) . "." . $ext;

                        if (move_uploaded_file($tmpName, $newName)) {
                            $profile_path = $newName;
                        } else {
                            flash('failure', 'Upload Failed', 'Could not save uploaded photo.');
                            header("Location: ani1.php");
                            exit();
                        }
                    } else {
                        flash('warning', 'Invalid Image', 'Please upload a valid JPG, JPEG, PNG, WEBP or GIF image under 2MB.');
                        header("Location: ani1.php");
                        exit();
                    }
                }

                $hashedPassword = password_hash($password, PASSWORD_DEFAULT);
                $studentRole = "student";

                $insert = mysqli_prepare(
                    $cn30,
                    "INSERT INTO register
                    (Name, age, school, phone, Email, rating, Username, Password, role, profile_image)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
                );

                if ($insert) {
                    mysqli_stmt_bind_param(
                        $insert,
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
                        $profile_path
                    );

                    if (mysqli_stmt_execute($insert)) {
                        flash('success', 'Student Registered', 'Username: ' . $username);
                    } else {
                        flash('failure', 'Registration Failed', 'Could not save the student.');
                    }

                    mysqli_stmt_close($insert);
                } else {
                    flash('failure', 'Registration Failed', 'Database error.');
                }
            }

            mysqli_stmt_close($check);
        } else {
            flash('failure', 'Registration Failed', 'Database error.');
        }
    }

    header("Location: ani1.php");
    exit();
}

/* --------------------
   ADMIN / MASTER: SEND MESSAGE
-------------------- */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['send_msg_action'])) {
    if (!valid_csrf()) {
        flash('failure', 'Invalid Request', 'Security token missing.');
        header("Location: ani1.php");
        exit();
    }

    if (!in_array($role, ['admin', 'master'], true)) {
        flash('failure', 'Denied', 'Only admin or master can send messages.');
        header("Location: ani1.php");
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

    header("Location: ani1.php");
    exit();
}

$flashes = $_SESSION['ani1_flash'] ?? [];
unset($_SESSION['ani1_flash']);
?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard</title>

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

        window.addEventListener('load', function() {
            setTimeout(function() {
                if (window.Notiflix) {
                    Notiflix.Loading.remove();
                }
            }, 3000);
        });
    </script>

    <ul class="nav nav-tabs" id="myTab" role="tablist">
        <li class="nav-item">
            <button class="nav-link active" data-bs-toggle="tab" data-bs-target="#home-tab-pane">
                <i class="bi bi-house-door-fill"></i> Home
            </button>
        </li>

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

        <?php
        $currentRole = $_SESSION['role'] ?? 'guest';
        ?>


        <?php if (in_array($currentRole, ['admin', 'master'], true)): ?>
            <!-- Right side starts here for admin/master -->
            <li class="nav-item ms-auto">
                <button class="btn btn-outline-primary btn-sm mt-1 me-2"
                    data-bs-toggle="modal"
                    data-bs-target="#messageModal">
                    <i class="bi bi-chat-dots-fill"></i> Send Message
                </button>
            </li>

            <?php if ($currentRole === 'admin'): ?>
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

            <li class="nav-item">
                <button class="nav-link" onclick="window.location.href='inbox.php'">
                    <i class="bi bi-inbox-fill"></i> Inbox
                </button>
            </li>

            <li class="nav-item">
                <button class="nav-link" data-bs-toggle="offcanvas" data-bs-target="#contactOffcanvas">
                    <i class="bi bi-telephone-fill"></i> Contact
                </button>
            </li>

        <?php elseif ($currentRole !== 'guest'): ?>
            <!-- Student: Inbox visible -->
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
            <!-- Guest: NO Inbox -->
            <li class="nav-item ms-auto">
                <button class="nav-link" data-bs-toggle="offcanvas" data-bs-target="#contactOffcanvas">
                    <i class="bi bi-telephone-fill"></i> Contact
                </button>
            </li>
        <?php endif; ?>


        <!-- Profile dropdown with Logout inside -->
        <li class="nav-item dropdown">
            <button class="nav-link dropdown-toggle" data-bs-toggle="dropdown">
                <i class="bi bi-person-circle text-dark"></i>
            </button>

            <ul class="dropdown-menu dropdown-menu-end text-center p-3 shadow" style="width: 220px;">
                <li>
                    <?php if ($currentRole !== 'guest'): ?>
                        <img src="<?php echo htmlspecialchars($_SESSION['profile_image'] ?? 'images/chess.jpeg', ENT_QUOTES, 'UTF-8'); ?>"
                            class="rounded-circle mb-2 border"
                            style="width:70px; height:70px; object-fit:cover;"
                            alt="Profile Image">

                        <p class="mb-1 small">
                            <strong>
                                <?php echo htmlspecialchars($_SESSION['Name'] ?? 'Guest', ENT_QUOTES, 'UTF-8'); ?>
                            </strong>
                        </p>

                        <span class="badge bg-success mb-2">
                            <?php echo htmlspecialchars(ucfirst($currentRole ?: 'guest'), ENT_QUOTES, 'UTF-8'); ?>
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
                        onclick="window.location.href='ani1.php?logout=1'">
                        <i class="bi bi-person-fill-dash"></i> Logout
                    </button>
                </li>
            </ul>
        </li>
    </ul>

    <div class="container mt-5">
        <div class="row align-items-center">
            <div class="col-md-6">
                <h2 class="display-6 fw-bold">
                    Welcome, <?php echo e($_SESSION['Name'] ?? 'Guest'); ?>
                </h2>

                <p class="text-muted">Golden Chess Academy Dashboard</p>

                <hr style="width: 50px; border: 2px solid #198754;">

                <p>
                    Track your progress, connect with masters, and stay updated with academy announcements.
                </p>
            </div>

            <div class="col-md-6">
                <div id="heroCarousel" class="carousel slide carousel-fade" data-bs-ride="carousel">
                    <div class="carousel-indicators">
                        <button type="button"
                            data-bs-target="#heroCarousel"
                            data-bs-slide-to="0"
                            class="active"></button>

                        <button type="button"
                            data-bs-target="#heroCarousel"
                            data-bs-slide-to="1"></button>
                    </div>

                    <div class="carousel-inner shadow rounded border">
                        <div class="carousel-item active" data-bs-interval="5000">
                            <img src="images/il_fullxfull.2509541207_aqvv.jpg"
                                class="d-block w-100"
                                style="height:350px; object-fit:cover;"
                                alt="Chess Academy">
                        </div>

                        <div class="carousel-item" data-bs-interval="5000">
                            <img src="images/king-chess-piece-on-chessboard.webp"
                                class="d-block w-100"
                                style="height:350px; object-fit:cover;"
                                alt="Strategy Masterclass">
                        </div>
                    </div>

                    <button class="carousel-control-prev"
                        type="button"
                        data-bs-target="#heroCarousel"
                        data-bs-slide="prev">
                        <span class="carousel-control-prev-icon" aria-hidden="true"></span>
                    </button>

                    <button class="carousel-control-next"
                        type="button"
                        data-bs-target="#heroCarousel"
                        data-bs-slide="next">
                        <span class="carousel-control-next-icon" aria-hidden="true"></span>
                    </button>
                </div>
            </div>
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

    <footer>
        <div class="container text-center">
            <div class="row">
                <div class="col-md-4">
                    <h6 class="fw-bold"><i class="bi bi-buildings-fill"></i> Academy</h6>
                    <p class="small text-muted">Trichy, TN Branch</p>
                </div>

                <div class="col-md-4">
                    <h6 class="fw-bold"><i class="bi bi-telephone-fill"></i> Quick Contact</h6>
                    <p class="small text-muted">baskar@gmail.com</p>
                </div>

                <div class="col-md-4">
                    <h6 class="fw-bold"><i class="bi bi-clock-fill"></i> Hours</h6>
                    <p class="small text-muted">10:00 AM - 08:00 PM</p>
                </div>
            </div>

            <p class="mt-3 mb-0 small text-muted">&copy; 2026 Golden Chess Academy</p>
        </div>
    </footer>

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
                        <form method="post" enctype="multipart/form-data">
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
                                        placeholder="Username">
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
                                    <input type="number" name="age" class="form-control" required>
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
        document.addEventListener('DOMContentLoaded', function() {
            const jsQuotes = <?php echo json_encode(
                                    $quotes,
                                    JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP | JSON_UNESCAPED_UNICODE
                                ); ?>;

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

            const messageForm = document.querySelector('#messageModal form');

            if (messageForm) {
                messageForm.addEventListener('submit', function(e) {
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

                    setTimeout(function() {
                        messageForm.submit();
                    }, 1200);
                });
            }

            const registerForm = document.querySelector('#registerModal form');

            if (registerForm) {
                registerForm.addEventListener('submit', function(e) {
                    e.preventDefault();

                    startLoadingQuote();

                    setTimeout(function() {
                        registerForm.submit();
                    }, 1200);
                });
            }

            const regName = document.getElementById('reg_name');
            const regUser = document.getElementById('reg_user');

            if (regName && regUser) {
                regName.addEventListener('input', function() {
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
            window.addEventListener('load', function() {
                const flashes = <?php echo json_encode(
                                    $flashes,
                                    JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP | JSON_UNESCAPED_UNICODE
                                ); ?>;

                flashes.forEach(function(flashItem, index) {
                    setTimeout(function() {
                        const allowedTypes = ['success', 'failure', 'warning', 'info'];
                        const type = allowedTypes.includes(flashItem.type) ?
                            flashItem.type :
                            'info';

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