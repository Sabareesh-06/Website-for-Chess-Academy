<?php
session_start();

/*
   Disable MySQLi exception throwing globally.
   This helps avoid fatal errors like duplicate column issues.
*/
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

/*
   Keep old variable names working.
   Everything now runs under 30mm.
*/
$main30 = $cn30;
$pz30 = $cn30;

/* --------------------
   SAFE QUERY HELPERS
-------------------- */
function safe_query($conn, $sql)
{
    try {
        mysqli_query($conn, $sql);
    } catch (Throwable $e) {
        error_log("Ignored MySQL error: " . $e->getMessage());
    }
}

function column_exists($conn, $table, $column)
{
    try {
        $result = mysqli_query($conn, "SHOW COLUMNS FROM `$table` LIKE '$column'");
        return $result && mysqli_num_rows($result) > 0;
    } catch (Throwable $e) {
        return false;
    }
}

function add_column_if_missing($conn, $table, $column, $definition)
{
    if (!column_exists($conn, $table, $column)) {
        safe_query($conn, "ALTER TABLE `$table` ADD COLUMN `$column` $definition");
    }
}

/* --------------------
   BASIC TABLE / COLUMN SETUP
-------------------- */
safe_query(
    $main30,
    "CREATE TABLE IF NOT EXISTS messages (
        id INT AUTO_INCREMENT PRIMARY KEY,
        sender VARCHAR(100) NOT NULL,
        receiver VARCHAR(100) NOT NULL,
        message TEXT NOT NULL,
        type VARCHAR(20) NOT NULL DEFAULT 'public',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"
);

add_column_if_missing($main30, "register", "points", "INT NOT NULL DEFAULT 0");

safe_query(
    $main30,
    "CREATE TABLE IF NOT EXISTS puzzle_point_awards (
        id INT AUTO_INCREMENT PRIMARY KEY,
        puzzle_id INT NOT NULL,
        student_id INT NOT NULL,
        awarded_by_id INT NOT NULL,
        points INT NOT NULL,
        awarded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE KEY unique_puzzle_award (puzzle_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"
);

safe_query(
    $pz30,
    "CREATE TABLE IF NOT EXISTS puzzles (
        id INT AUTO_INCREMENT PRIMARY KEY,
        title VARCHAR(255) NOT NULL,
        description TEXT NULL,
        image VARCHAR(255) NOT NULL,
        created_by VARCHAR(100) NULL,
        created_by_id INT NULL,
        created_by_role VARCHAR(50) NULL,
        points_awarded TINYINT(1) NOT NULL DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"
);

safe_query(
    $pz30,
    "CREATE TABLE IF NOT EXISTS comments (
        id INT AUTO_INCREMENT PRIMARY KEY,
        puzzle_id INT NOT NULL,
        parent_id INT NULL,
        user_name VARCHAR(100) NOT NULL,
        role VARCHAR(50) NOT NULL,
        comment_text TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"
);

add_column_if_missing($pz30, "comments", "created_at", "TIMESTAMP DEFAULT CURRENT_TIMESTAMP");

safe_query(
    $pz30,
    "CREATE TABLE IF NOT EXISTS comment_reactions (
        id INT AUTO_INCREMENT PRIMARY KEY,
        comment_id INT NOT NULL,
        user_name VARCHAR(100) NOT NULL,
        reaction_type VARCHAR(10) NOT NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"
);

add_column_if_missing($pz30, "puzzles", "created_by_id", "INT NULL");
add_column_if_missing($pz30, "puzzles", "created_by_role", "VARCHAR(50) NULL");
add_column_if_missing($pz30, "puzzles", "points_awarded", "TINYINT(1) NOT NULL DEFAULT 0");

/* --------------------
   LOGIN + ROLE GUARD
-------------------- */
if (!isset($_SESSION['role'])) {
    header("Location: login.php");
    exit();
}

$role = $_SESSION['role'];

if (!in_array($role, ['admin', 'master', 'student'], true)) {
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
    $_SESSION['puzzle_flash'][] = [
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

function process_puzzle_image(string $field): array
{
    if (empty($_FILES[$field]['name'])) {
        return [
            'ok' => false,
            'error' => 'Puzzle image is required.'
        ];
    }

    if ($_FILES[$field]['error'] !== UPLOAD_ERR_OK) {
        return [
            'ok' => false,
            'error' => 'There was a problem uploading the puzzle image.'
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

    if (!is_dir('uploads')) {
        @mkdir('uploads', 0755, true);
    }

    $newName = "puzzle_" . bin2hex(random_bytes(8)) . "." . $ext;

    if (!move_uploaded_file($tmpName, "uploads/" . $newName)) {
        return [
            'ok' => false,
            'error' => 'Could not save uploaded puzzle image.'
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
   CURRENT USER ID
-------------------- */
$currentUserId = 0;

if (isset($_SESSION['Username'])) {
    $stmt = mysqli_prepare($main30, "SELECT ID FROM register WHERE Username = ? LIMIT 1");

    if ($stmt) {
        mysqli_stmt_bind_param($stmt, "s", $_SESSION['Username']);
        mysqli_stmt_execute($stmt);

        $result = mysqli_stmt_get_result($stmt);
        $userRow = mysqli_fetch_assoc($result);

        if ($userRow) {
            $currentUserId = (int)$userRow['ID'];
        }

        mysqli_stmt_close($stmt);
    }
}

$currentUser = $_SESSION['Name'] ?? 'User';

$redirectUser = intval($_GET['user'] ?? 0);
$redirectUrl = 'puzzle.php' . ($redirectUser > 0 ? '?user=' . $redirectUser : '');

/* --------------------
   ADMIN / MASTER: SEND MESSAGE
-------------------- */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['send_msg_action'])) {
    if (!valid_csrf()) {
        flash('failure', 'Invalid Request', 'Security token missing.');
        header("Location: " . $redirectUrl);
        exit();
    }

    if (!in_array($role, ['admin', 'master'], true)) {
        flash('failure', 'Denied', 'Only admin or master can send messages.');
        header("Location: " . $redirectUrl);
        exit();
    }

    $sender  = $_SESSION['Username'] ?? 'system';
    $message = trim($_POST['message_text'] ?? '');
    $target  = $_POST['msg_target'] ?? '';

    if ($message === '') {
        flash('warning', 'Empty Message', 'Message cannot be empty.');
        header("Location: " . $redirectUrl);
        exit();
    }

    if ($target === 'all') {
        $receiver = 'all';
        $type = 'public';

        $stmt = mysqli_prepare(
            $main30,
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
            header("Location: " . $redirectUrl);
            exit();
        }

        $check = mysqli_prepare(
            $main30,
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
                    $main30,
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

    header("Location: " . $redirectUrl);
    exit();
}

/* --------------------
   ADMIN / MASTER: AWARD POINTS
-------------------- */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['award_points_action'])) {
    if (!valid_csrf()) {
        flash('failure', 'Invalid Request', 'Security token missing.');
        header("Location: " . $redirectUrl);
        exit();
    }

    if (!in_array($role, ['admin', 'master'], true)) {
        flash('failure', 'Denied', 'Only admin or master can award points.');
        header("Location: " . $redirectUrl);
        exit();
    }

    $puzzleId = intval($_POST['award_puzzle_id'] ?? 0);
    $studentId = intval($_POST['award_student_id'] ?? 0);
    $points = intval($_POST['award_points'] ?? 10);
    $awardedById = $currentUserId;

    if ($puzzleId <= 0 || $studentId <= 0 || $points < 1 || $points > 100) {
        flash('warning', 'Invalid Request', 'Invalid award request.');
        header("Location: " . $redirectUrl);
        exit();
    }

    $checkPuzzle = mysqli_prepare(
        $pz30,
        "SELECT id
         FROM puzzles
         WHERE id = ? AND created_by_id = ? AND points_awarded = 0
         LIMIT 1"
    );

    if (!$checkPuzzle) {
        flash('failure', 'Award Failed', 'Database error.');
        header("Location: " . $redirectUrl);
        exit();
    }

    mysqli_stmt_bind_param($checkPuzzle, "ii", $puzzleId, $studentId);
    mysqli_stmt_execute($checkPuzzle);
    mysqli_stmt_store_result($checkPuzzle);

    if (mysqli_stmt_num_rows($checkPuzzle) === 0) {
        flash('warning', 'Award Failed', 'Puzzle already awarded or not found.');
        header("Location: " . $redirectUrl);
        exit();
    }

    mysqli_stmt_close($checkPuzzle);

    $checkStudent = mysqli_prepare(
        $main30,
        "SELECT ID
         FROM register
         WHERE ID = ? AND (role = 'student' OR role = 'user')
         LIMIT 1"
    );

    if (!$checkStudent) {
        flash('failure', 'Award Failed', 'Database error.');
        header("Location: " . $redirectUrl);
        exit();
    }

    mysqli_stmt_bind_param($checkStudent, "i", $studentId);
    mysqli_stmt_execute($checkStudent);
    mysqli_stmt_store_result($checkStudent);

    if (mysqli_stmt_num_rows($checkStudent) === 0) {
        flash('warning', 'Award Failed', 'Student not found.');
        header("Location: " . $redirectUrl);
        exit();
    }

    mysqli_stmt_close($checkStudent);

    $awardStmt = mysqli_prepare(
        $main30,
        "INSERT INTO puzzle_point_awards
        (puzzle_id, student_id, awarded_by_id, points)
        VALUES (?, ?, ?, ?)"
    );

    if ($awardStmt) {
        mysqli_stmt_bind_param(
            $awardStmt,
            "iiii",
            $puzzleId,
            $studentId,
            $awardedById,
            $points
        );

        if (mysqli_stmt_execute($awardStmt)) {
            $updatePuzzle = mysqli_prepare(
                $pz30,
                "UPDATE puzzles SET points_awarded = 1 WHERE id = ?"
            );

            if ($updatePuzzle) {
                mysqli_stmt_bind_param($updatePuzzle, "i", $puzzleId);
                mysqli_stmt_execute($updatePuzzle);
                mysqli_stmt_close($updatePuzzle);
            }

            $updatePoints = mysqli_prepare(
                $main30,
                "UPDATE register SET points = points + ? WHERE ID = ?"
            );

            if ($updatePoints) {
                mysqli_stmt_bind_param($updatePoints, "ii", $points, $studentId);
                mysqli_stmt_execute($updatePoints);
                mysqli_stmt_close($updatePoints);
            }

            flash('success', 'Points Awarded', $points . ' points awarded successfully.');
        } else {
            flash('warning', 'Award Failed', 'This puzzle has already been awarded.');
        }

        mysqli_stmt_close($awardStmt);
    } else {
        flash('failure', 'Award Failed', 'Database error.');
    }

    header("Location: " . $redirectUrl);
    exit();
}

/* --------------------
   UPLOAD PUZZLE
-------------------- */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['uploadPuzzle'])) {
    if (!valid_csrf()) {
        flash('failure', 'Invalid Request', 'Security token missing.');
        header("Location: " . $redirectUrl);
        exit();
    }

    if (!in_array($role, ['admin', 'master', 'student'], true)) {
        flash('failure', 'Denied', 'You are not allowed to upload puzzles.');
        header("Location: " . $redirectUrl);
        exit();
    }

    if ($role === 'student' && $currentUserId <= 0) {
        flash('failure', 'Upload Failed', 'Student account not found.');
        header("Location: " . $redirectUrl);
        exit();
    }

    $title = trim($_POST['title'] ?? '');
    $description = trim($_POST['description'] ?? '');

    if ($title === '') {
        flash('warning', 'Missing Title', 'Puzzle title is required.');
        header("Location: " . $redirectUrl);
        exit();
    }

    $upload = process_puzzle_image('image');

    if (!$upload['ok']) {
        flash('warning', 'Invalid Puzzle Image', $upload['error']);
        header("Location: " . $redirectUrl);
        exit();
    }

    $imageName = $upload['path'];
    $createdBy = $_SESSION['Name'] ?? 'User';

    $stmt = mysqli_prepare(
        $pz30,
        "INSERT INTO puzzles
        (title, description, image, created_by, created_by_id, created_by_role, points_awarded)
        VALUES (?, ?, ?, ?, ?, ?, 0)"
    );

    if ($stmt) {
        mysqli_stmt_bind_param(
            $stmt,
            "ssssis",
            $title,
            $description,
            $imageName,
            $createdBy,
            $currentUserId,
            $role
        );

        if (mysqli_stmt_execute($stmt)) {
            flash('success', 'Puzzle Added', 'Your puzzle has been published.');
        } else {
            flash('failure', 'Upload Failed', 'Could not save puzzle.');
        }

        mysqli_stmt_close($stmt);
    } else {
        flash('failure', 'Upload Failed', 'Database error.');
    }

    header("Location: " . $redirectUrl);
    exit();
}

/* --------------------
   DELETE PUZZLE
-------------------- */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['delete_puzzle'])) {
    if (!valid_csrf()) {
        flash('failure', 'Invalid Request', 'Security token missing.');
        header("Location: " . $redirectUrl);
        exit();
    }

    if (!in_array($role, ['admin', 'master'], true)) {
        flash('failure', 'Denied', 'Only admin or master can delete puzzles.');
        header("Location: " . $redirectUrl);
        exit();
    }

    $puzzleId = intval($_POST['puzzle_id'] ?? 0);

    if ($puzzleId <= 0) {
        flash('warning', 'Invalid Request', 'Invalid puzzle ID.');
        header("Location: " . $redirectUrl);
        exit();
    }

    $stmt = mysqli_prepare($pz30, "SELECT image FROM puzzles WHERE id = ? LIMIT 1");

    if (!$stmt) {
        flash('failure', 'Delete Failed', 'Database error.');
        header("Location: " . $redirectUrl);
        exit();
    }

    mysqli_stmt_bind_param($stmt, "i", $puzzleId);
    mysqli_stmt_execute($stmt);

    $result = mysqli_stmt_get_result($stmt);
    $puzzle = mysqli_fetch_assoc($result);

    mysqli_stmt_close($stmt);

    if ($puzzle) {
        $commentIdsStmt = mysqli_prepare($pz30, "SELECT id FROM comments WHERE puzzle_id = ?");

        if ($commentIdsStmt) {
            mysqli_stmt_bind_param($commentIdsStmt, "i", $puzzleId);
            mysqli_stmt_execute($commentIdsStmt);

            $commentIdsResult = mysqli_stmt_get_result($commentIdsStmt);

            while ($commentRow = mysqli_fetch_assoc($commentIdsResult)) {
                $reactionDelete = mysqli_prepare(
                    $pz30,
                    "DELETE FROM comment_reactions WHERE comment_id = ?"
                );

                if ($reactionDelete) {
                    mysqli_stmt_bind_param($reactionDelete, "i", $commentRow['id']);
                    mysqli_stmt_execute($reactionDelete);
                    mysqli_stmt_close($reactionDelete);
                }
            }

            mysqli_stmt_close($commentIdsStmt);
        }

        $deleteComments = mysqli_prepare($pz30, "DELETE FROM comments WHERE puzzle_id = ?");

        if ($deleteComments) {
            mysqli_stmt_bind_param($deleteComments, "i", $puzzleId);
            mysqli_stmt_execute($deleteComments);
            mysqli_stmt_close($deleteComments);
        }

        $deletePuzzle = mysqli_prepare($pz30, "DELETE FROM puzzles WHERE id = ?");

        if ($deletePuzzle) {
            mysqli_stmt_bind_param($deletePuzzle, "i", $puzzleId);
            mysqli_stmt_execute($deletePuzzle);
            mysqli_stmt_close($deletePuzzle);
        }

        if (!empty($puzzle['image']) && file_exists("uploads/" . $puzzle['image'])) {
            @unlink("uploads/" . $puzzle['image']);
        }

        flash('success', 'Puzzle Deleted', 'Puzzle removed successfully.');
    } else {
        flash('failure', 'Delete Failed', 'Puzzle not found.');
    }

    header("Location: " . $redirectUrl);
    exit();
}

/* --------------------
   SUBMIT COMMENT / REPLY
-------------------- */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['submitComment'])) {
    if (!valid_csrf()) {
        flash('failure', 'Invalid Request', 'Security token missing.');
        header("Location: " . $redirectUrl);
        exit();
    }

    $puzzleId = intval($_POST['puzzle_id'] ?? 0);
    $parentId = !empty($_POST['parent_id']) ? intval($_POST['parent_id']) : null;
    $commentText = trim($_POST['comment_text'] ?? '');

    if ($puzzleId <= 0 || $commentText === '') {
        flash('warning', 'Invalid Comment', 'Comment cannot be empty.');
        header("Location: " . $redirectUrl);
        exit();
    }

    $stmt = mysqli_prepare(
        $pz30,
        "INSERT INTO comments (puzzle_id, parent_id, user_name, role, comment_text)
        VALUES (?, ?, ?, ?, ?)"
    );

    if ($stmt) {
        mysqli_stmt_bind_param(
            $stmt,
            "iisss",
            $puzzleId,
            $parentId,
            $currentUser,
            $role,
            $commentText
        );

        if (mysqli_stmt_execute($stmt)) {
            flash('success', 'Comment Posted', 'Your comment has been added.');
        } else {
            flash('failure', 'Comment Failed', 'Could not post comment.');
        }

        mysqli_stmt_close($stmt);
    } else {
        flash('failure', 'Comment Failed', 'Database error.');
    }

    header("Location: " . $redirectUrl);
    exit();
}

/* --------------------
   REACT TO COMMENT
-------------------- */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['react'])) {
    if (!valid_csrf()) {
        flash('failure', 'Invalid Request', 'Security token missing.');
        header("Location: " . $redirectUrl);
        exit();
    }

    if (!in_array($role, ['admin', 'master'], true)) {
        flash('failure', 'Denied', 'Only admin or master can react.');
        header("Location: " . $redirectUrl);
        exit();
    }

    $allowedReactions = ['👍', '🧠', '🎯'];
    $reactionType = $_POST['react'] ?? '';
    $commentId = intval($_POST['comment_id'] ?? 0);

    if (!in_array($reactionType, $allowedReactions, true) || $commentId <= 0) {
        flash('warning', 'Invalid Reaction', 'Invalid reaction request.');
        header("Location: " . $redirectUrl);
        exit();
    }

    $check = mysqli_prepare(
        $pz30,
        "SELECT id FROM comment_reactions WHERE comment_id = ? AND user_name = ? LIMIT 1"
    );

    if ($check) {
        mysqli_stmt_bind_param($check, "is", $commentId, $currentUser);
        mysqli_stmt_execute($check);
        mysqli_stmt_store_result($check);

        if (mysqli_stmt_num_rows($check) > 0) {
            $update = mysqli_prepare(
                $pz30,
                "UPDATE comment_reactions SET reaction_type = ? WHERE comment_id = ? AND user_name = ?"
            );

            if ($update) {
                mysqli_stmt_bind_param($update, "sis", $reactionType, $commentId, $currentUser);
                mysqli_stmt_execute($update);
                mysqli_stmt_close($update);
            }
        } else {
            $insert = mysqli_prepare(
                $pz30,
                "INSERT INTO comment_reactions (comment_id, user_name, reaction_type) VALUES (?, ?, ?)"
            );

            if ($insert) {
                mysqli_stmt_bind_param($insert, "iss", $commentId, $currentUser, $reactionType);
                mysqli_stmt_execute($insert);
                mysqli_stmt_close($insert);
            }
        }

        mysqli_stmt_close($check);
    }

    header("Location: " . $redirectUrl);
    exit();
}

/* --------------------
   FETCH PUZZLES
-------------------- */
$filterUserId = intval($_GET['user'] ?? 0);
$puzzles = [];

try {
    if ($filterUserId > 0) {
        $stmt = mysqli_prepare(
            $pz30,
            "SELECT * FROM puzzles WHERE created_by_id = ? ORDER BY id DESC"
        );

        if ($stmt) {
            mysqli_stmt_bind_param($stmt, "i", $filterUserId);
            mysqli_stmt_execute($stmt);

            $result = mysqli_stmt_get_result($stmt);

            while ($row = mysqli_fetch_assoc($result)) {
                $puzzles[] = $row;
            }

            mysqli_stmt_close($stmt);
        } else {
            $result = mysqli_query($pz30, "SELECT * FROM puzzles ORDER BY id DESC");

            if ($result) {
                while ($row = mysqli_fetch_assoc($result)) {
                    $puzzles[] = $row;
                }
            }
        }
    } else {
        $result = mysqli_query($pz30, "SELECT * FROM puzzles ORDER BY id DESC");

        if ($result) {
            while ($row = mysqli_fetch_assoc($result)) {
                $puzzles[] = $row;
            }
        }
    }
} catch (Throwable $e) {
    error_log("Puzzle fetch error: " . $e->getMessage());
    $puzzles = [];
}

$flashes = $_SESSION['puzzle_flash'] ?? [];
unset($_SESSION['puzzle_flash']);

$currentRole = $role;
?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Chess Puzzles</title>

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
            min-height: 220px;
            display: flex;
            align-items: center;
            justify-content: center;
            background: #ffffff;
            transition: 0.3s;
        }

        .add-card:hover {
            background: #f1fcf6;
        }

        .card-img-top {
            height: 200px;
            object-fit: contain;
            background-color: #f8f9fa;
            border-bottom: 1px solid #dee2e6;
            cursor: zoom-in;
            transition: opacity 0.2s;
        }

        .card-img-top:hover {
            opacity: 0.9;
        }

        .badge-username {
            font-size: 0.75rem;
            background: #e9ecef;
            color: #495057;
            padding: 3px 6px;
            border-radius: 4px;
        }

        .comment-box {
            background-color: #f8f9fa;
            border-radius: 6px;
            padding: 8px 12px;
            margin-bottom: 6px;
        }

        .reply-box {
            background-color: #ffffff;
            border-left: 3px solid #0d6efd;
            border-radius: 4px;
            padding: 6px 10px;
            margin-left: 25px;
            margin-top: 4px;
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

        .reaction-btn {
            border: none;
            background: transparent;
            padding: 0;
            font-size: 0.9rem;
        }
    </style>
</head>

<body class="bg-light">

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

    <button class="btn btn-sm btn-info m-2" onclick="window.location.href='ani1.php'">
        <i class="bi bi-house-up-fill"></i> Home
    </button>

    <ul class="nav nav-tabs d-flex w-100 m-2" id="myTab" role="tablist">
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
            <button class="nav-link active">
                <i class="bi bi-puzzle-fill"></i> Daily Puzzles
            </button>
        </li>


        <?php if (in_array($currentRole, ['admin', 'master'], true)): ?>
            <li class="nav-item ms-auto">
                <button class="btn btn-outline-primary btn-sm mt-1 me-2"
                    data-bs-toggle="modal"
                    data-bs-target="#messageModal">
                    <i class="bi bi-chat-dots-fill"></i> Send Message
                </button>
            </li>
        <?php endif; ?>

        <?php if ($currentRole === 'admin'): ?>
            <li class="nav-item">
                <button class="nav-link" onclick="window.location.href='studentProfile.php'">
                    <i class="bi bi-person-fill"></i> Student Profile
                </button>
            </li>
        <?php endif; ?>

        <?php if ($currentRole !== 'guest'): ?>
            <li class="nav-item <?php echo in_array($currentRole, ['admin', 'master'], true) ? '' : 'ms-auto'; ?>">
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
                        <strong><?php echo e($_SESSION['Name'] ?? 'Guest'); ?></strong>
                    </p>

                    <span class="badge bg-success mb-2">
                        <?php echo e(ucfirst($currentRole ?: 'guest')); ?>
                    </span>

                    <br>

                    <button class="btn btn-sm btn-danger w-100"
                        onclick="window.location.href='puzzle.php?logout=1'">
                        <i class="bi bi-person-fill-dash"></i> Logout
                    </button>
                </li>
            </ul>
        </li>
    </ul>

    <div class="container-fluid px-4">
        <?php if ($filterUserId > 0): ?>
            <div class="alert alert-info d-flex justify-content-between align-items-center">
                <span>Showing puzzles shared by student ID: <?php echo $filterUserId; ?></span>

                <a href="puzzle.php" class="btn btn-sm btn-secondary">
                    Show All Puzzles
                </a>
            </div>
        <?php endif; ?>

        <div class="row">
            <?php if (in_array($role, ['admin', 'master', 'student'], true)): ?>
                <div class="col-xl-3 col-lg-4 col-md-6 mb-4">
                    <div class="card h-100 add-card shadow-sm"
                        data-bs-toggle="modal"
                        data-bs-target="#addUploadModal">
                        <div class="text-center text-success p-3">
                            <i class="bi bi-plus-circle-fill fs-1"></i>
                            <h5 class="fw-bold mt-2">Upload New Puzzle</h5>
                        </div>
                    </div>
                </div>
            <?php endif; ?>

            <?php if (empty($puzzles)): ?>
                <div class="col-12">
                    <div class="alert alert-info text-center">No puzzles found.</div>
                </div>
            <?php endif; ?>

            <?php foreach ($puzzles as $puzzle): ?>
                <?php
                $puzzleId = (int)$puzzle['id'];
                $puzzleTitle = e($puzzle['title']);

                $canAward =
                    in_array($role, ['admin', 'master'], true)
                    && empty($puzzle['points_awarded'])
                    && !empty($puzzle['created_by_id']);

                if (
                    $canAward &&
                    isset($puzzle['created_by_role']) &&
                    $puzzle['created_by_role'] !== '' &&
                    !in_array($puzzle['created_by_role'], ['student', 'user'], true)
                ) {
                    $canAward = false;
                }
                ?>

                <div class="col-xl-3 col-lg-4 col-md-6 mb-4">
                    <div class="card h-100 shadow border-0">
                        <img src="uploads/<?php echo e($puzzle['image']); ?>"
                            class="card-img-top puzzle-preview-img"
                            alt="Chess Puzzle"
                            data-title="<?php echo $puzzleTitle; ?>"
                            onerror="this.onerror=null; this.src='https://placehold.co/600x400/ececec/909090?text=Puzzle+Image+Missing';">

                        <div class="card-body d-flex flex-column pb-2">
                            <h5 class="card-title fw-bold text-dark"><?php echo $puzzleTitle; ?></h5>

                            <p class="card-text text-muted small flex-grow-1">
                                <?php echo e($puzzle['description']); ?>
                            </p>

                            <div class="d-flex justify-content-between align-items-center mt-2 mb-2">
                                <span class="badge-username">
                                    <i class="bi bi-pen"></i> <?php echo e($puzzle['created_by']); ?>
                                </span>

                                <?php if (in_array($role, ['admin', 'master'], true)): ?>
                                    <form method="POST"
                                        style="display:inline;"
                                        onsubmit="return confirm('Delete this puzzle permanently?');">
                                        <input type="hidden" name="csrf_token" value="<?php echo e($_SESSION['csrf_token']); ?>">
                                        <input type="hidden" name="delete_puzzle" value="1">
                                        <input type="hidden" name="puzzle_id" value="<?php echo $puzzleId; ?>">

                                        <button type="submit" class="btn btn-link text-danger btn-sm p-0 text-decoration-none">
                                            <i class="bi bi-trash3-fill"></i> Delete
                                        </button>
                                    </form>
                                <?php endif; ?>
                            </div>

                            <?php if (!empty($puzzle['points_awarded'])): ?>
                                <span class="badge bg-success mb-2">Points Awarded</span>
                            <?php endif; ?>

                            <?php if ($canAward): ?>
                                <form method="POST" class="d-flex gap-1 mb-2">
                                    <input type="hidden" name="csrf_token" value="<?php echo e($_SESSION['csrf_token']); ?>">
                                    <input type="hidden" name="award_puzzle_id" value="<?php echo $puzzleId; ?>">
                                    <input type="hidden" name="award_student_id" value="<?php echo (int)$puzzle['created_by_id']; ?>">

                                    <input type="number"
                                        name="award_points"
                                        min="1"
                                        max="100"
                                        value="10"
                                        class="form-control form-control-sm"
                                        style="width: 80px;">

                                    <button type="submit" name="award_points_action" class="btn btn-sm btn-warning">
                                        Award
                                    </button>
                                </form>
                            <?php endif; ?>

                            <hr class="my-2">

                            <div class="comments-section mt-1">
                                <h6 class="fw-bold text-secondary small mb-2">
                                    <i class="bi bi-chat-dots"></i> Discussions
                                </h6>

                                <div class="comments-wrapper overflow-auto class-comments mb-2" style="max-height: 200px;">
                                    <?php
                                    $commentStmt = mysqli_prepare(
                                        $pz30,
                                        "SELECT * FROM comments WHERE puzzle_id = ? AND parent_id IS NULL ORDER BY id ASC"
                                    );

                                    if ($commentStmt) {
                                        mysqli_stmt_bind_param($commentStmt, "i", $puzzleId);
                                        mysqli_stmt_execute($commentStmt);

                                        $commentResult = mysqli_stmt_get_result($commentStmt);

                                        if (mysqli_num_rows($commentResult) === 0) {
                                            echo '<p class="text-muted muted small italic text-center my-2">No analysis yet.</p>';
                                        }

                                        while ($comment = mysqli_fetch_assoc($commentResult)) {
                                            $commentId = (int)$comment['id'];

                                            $reactions = ['👍' => 0, '🧠' => 0, '🎯' => 0];

                                            $reactionStmt = mysqli_prepare(
                                                $pz30,
                                                "SELECT reaction_type, COUNT(*) AS qty
                                             FROM comment_reactions
                                             WHERE comment_id = ?
                                             GROUP BY reaction_type"
                                            );

                                            if ($reactionStmt) {
                                                mysqli_stmt_bind_param($reactionStmt, "i", $commentId);
                                                mysqli_stmt_execute($reactionStmt);

                                                $reactionResult = mysqli_stmt_get_result($reactionStmt);

                                                while ($rx = mysqli_fetch_assoc($reactionResult)) {
                                                    if (isset($reactions[$rx['reaction_type']])) {
                                                        $reactions[$rx['reaction_type']] = (int)$rx['qty'];
                                                    }
                                                }

                                                mysqli_stmt_close($reactionStmt);
                                            }

                                            $commentDate = '';
                                            if (!empty($comment['created_at'])) {
                                                $timestamp = strtotime($comment['created_at']);
                                                if ($timestamp !== false) {
                                                    $commentDate = date('M d, H:i', $timestamp);
                                                }
                                            }
                                    ?>

                                            <div class="comment-box shadow-sm border-start border-success border-2">
                                                <div class="d-flex justify-content-between">
                                                    <strong class="small text-primary">
                                                        <?php echo e($comment['user_name']); ?>

                                                        <span class="badge bg-secondary text-white style-font" style="font-size:0.55rem;">
                                                            <?php echo e(strtoupper($comment['role'])); ?>
                                                        </span>
                                                    </strong>

                                                    <span class="text-muted" style="font-size:0.65rem;">
                                                        <?php echo e($commentDate); ?>
                                                    </span>
                                                </div>

                                                <p class="mb-1 text-dark small-text style-font-body" style="font-size:0.85rem;">
                                                    <?php echo e($comment['comment_text']); ?>
                                                </p>

                                                <div class="d-flex align-items-center gap-2 my-1">
                                                    <?php if (in_array($role, ['admin', 'master'], true)): ?>
                                                        <?php foreach (['👍', '🧠', '🎯'] as $reactionType): ?>
                                                            <form method="POST" class="d-inline">
                                                                <input type="hidden" name="csrf_token" value="<?php echo e($_SESSION['csrf_token']); ?>">
                                                                <input type="hidden" name="comment_id" value="<?php echo $commentId; ?>">
                                                                <input type="hidden" name="react" value="<?php echo e($reactionType); ?>">

                                                                <button type="submit" class="reaction-btn text-decoration-none text-reset small">
                                                                    <?php echo e($reactionType); ?>
                                                                    <span class="badge text-dark bg-light">
                                                                        <?php echo $reactions[$reactionType]; ?>
                                                                    </span>
                                                                </button>
                                                            </form>
                                                        <?php endforeach; ?>

                                                        <button class="btn btn-link btn-sm p-0 ms-auto text-primary"
                                                            style="font-size: 0.75rem;"
                                                            onclick="toggleReply('reply-form-<?php echo $commentId; ?>')">
                                                            <i class="bi bi-reply-fill"></i> Reply
                                                        </button>
                                                    <?php else: ?>
                                                        <span class="small opacity-75">
                                                            👍 <span class="badge text-dark bg-light"><?php echo $reactions['👍']; ?></span>
                                                        </span>

                                                        <span class="small opacity-75">
                                                            🧠 <span class="badge text-dark bg-light"><?php echo $reactions['🧠']; ?></span>
                                                        </span>

                                                        <span class="small opacity-75">
                                                            🎯 <span class="badge text-dark bg-light"><?php echo $reactions['🎯']; ?></span>
                                                        </span>
                                                    <?php endif; ?>
                                                </div>

                                                <div id="reply-form-<?php echo $commentId; ?>" style="display:none;" class="mt-2">
                                                    <form method="POST" class="d-flex gap-1">
                                                        <input type="hidden" name="csrf_token" value="<?php echo e($_SESSION['csrf_token']); ?>">
                                                        <input type="hidden" name="puzzle_id" value="<?php echo $puzzleId; ?>">
                                                        <input type="hidden" name="parent_id" value="<?php echo $commentId; ?>">

                                                        <input type="text"
                                                            name="comment_text"
                                                            class="form-control form-control-sm"
                                                            placeholder="Write reply..."
                                                            required>

                                                        <button type="submit" name="submitComment" class="btn btn-primary btn-sm px-2">
                                                            <i class="bi bi-send"></i>
                                                        </button>
                                                    </form>
                                                </div>
                                            </div>

                                            <?php
                                            $replyStmt = mysqli_prepare(
                                                $pz30,
                                                "SELECT * FROM comments WHERE parent_id = ? ORDER BY id ASC"
                                            );

                                            if ($replyStmt) {
                                                mysqli_stmt_bind_param($replyStmt, "i", $commentId);
                                                mysqli_stmt_execute($replyStmt);

                                                $replyResult = mysqli_stmt_get_result($replyStmt);

                                                while ($reply = mysqli_fetch_assoc($replyResult)) {
                                                    $replyDate = '';
                                                    if (!empty($reply['created_at'])) {
                                                        $timestamp = strtotime($reply['created_at']);
                                                        if ($timestamp !== false) {
                                                            $replyDate = date('M d, H:i', $timestamp);
                                                        }
                                                    }
                                            ?>

                                                    <div class="reply-box shadow-sm">
                                                        <div class="d-flex justify-content-between">
                                                            <strong class="text-primary" style="font-size:0.75rem;">
                                                                <i class="bi bi-arrow-return-right text-muted"></i>
                                                                <?php echo e($reply['user_name']); ?>

                                                                <span class="badge bg-info text-dark" style="font-size:0.5rem;">
                                                                    <?php echo e(strtoupper($reply['role'])); ?>
                                                                </span>
                                                            </strong>

                                                            <span class="text-muted" style="font-size:0.6rem;">
                                                                <?php echo e($replyDate); ?>
                                                            </span>
                                                        </div>

                                                        <p class="mb-0 text-secondary" style="font-size:0.8rem;">
                                                            <?php echo e($reply['comment_text']); ?>
                                                        </p>
                                                    </div>

                                    <?php
                                                }

                                                mysqli_stmt_close($replyStmt);
                                            }
                                        }

                                        mysqli_stmt_close($commentStmt);
                                    }
                                    ?>
                                </div>

                                <form method="POST" class="mt-2 d-flex gap-1">
                                    <input type="hidden" name="csrf_token" value="<?php echo e($_SESSION['csrf_token']); ?>">
                                    <input type="hidden" name="puzzle_id" value="<?php echo $puzzleId; ?>">

                                    <input type="text"
                                        name="comment_text"
                                        class="form-control form-control-sm"
                                        placeholder="Post analysis or FEN..."
                                        required>

                                    <button type="submit" name="submitComment" class="btn btn-success btn-sm">
                                        <i class="bi bi-chat-left-text-fill"></i>
                                    </button>
                                </form>
                            </div>
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

    <div class="modal fade" id="addUploadModal" tabindex="-1" aria-hidden="true">
        <div class="modal-dialog modal-dialog-centered">
            <div class="modal-content">
                <form method="POST" enctype="multipart/form-data" data-loading="1">
                    <div class="modal-header bg-success text-white">
                        <h5 class="modal-title">
                            <i class="bi bi-upload"></i> Distribute Chess Puzzle
                        </h5>

                        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                    </div>

                    <div class="modal-body">
                        <input type="hidden" name="csrf_token" value="<?php echo e($_SESSION['csrf_token']); ?>">
                        <input type="hidden" name="uploadPuzzle" value="1">

                        <div class="mb-3">
                            <label class="form-label fw-bold">Title</label>
                            <input type="text"
                                name="title"
                                class="form-control"
                                placeholder="e.g., Mate in 3 Moves"
                                required>
                        </div>

                        <div class="mb-3">
                            <label class="form-label fw-bold">Description / Instructions</label>
                            <textarea name="description"
                                class="form-control"
                                rows="3"
                                placeholder="Describe the conditions or source configuration..."></textarea>
                        </div>

                        <div class="mb-3">
                            <label class="form-label fw-bold">Puzzle Image File</label>
                            <input type="file" name="image" class="form-control" accept="image/*" required>
                            <div class="form-text">Supports PNG, JPG, JPEG, WEBP and GIF formats. Max 2MB.</div>
                        </div>
                    </div>

                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                        <button type="submit" class="btn btn-success">
                            <i class="bi bi-cloud-arrow-up-fill"></i> Deploy Puzzle
                        </button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <div class="modal fade" id="imageLightboxModal" tabindex="-1" aria-hidden="true">
        <div class="modal-dialog modal-dialog-centered modal-lg">
            <div class="modal-content bg-transparent border-0 shadow-none">
                <div class="modal-header border-0 pb-0 justify-content-between bg-dark text-white rounded-top">
                    <h5 class="modal-title" id="lightboxModalLabel">Chess Puzzle Preview</h5>
                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                </div>

                <div class="modal-body text-center p-0 bg-white rounded-bottom border">
                    <img src=""
                        id="lightboxTargetImage"
                        class="img-fluid w-100"
                        style="max-height: 80vh; object-fit: contain;"
                        alt="Enlarged Puzzle">
                </div>
            </div>
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
        function toggleReply(id) {
            const element = document.getElementById(id);

            if (!element) {
                return;
            }

            element.style.display = element.style.display === 'none' ? 'block' : 'none';
        }

        document.addEventListener('DOMContentLoaded', function() {
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

            document.querySelectorAll('form[data-loading]').forEach(function(form) {
                form.addEventListener('submit', function(e) {
                    if (!form.checkValidity()) {
                        return;
                    }

                    e.preventDefault();

                    startLoadingQuote();

                    setTimeout(function() {
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
                    }, 1000);
                });
            }

            document.addEventListener('click', function(event) {
                const image = event.target.closest('.puzzle-preview-img');

                if (!image) {
                    return;
                }

                const targetImageSrc = image.src;
                const puzzleTitleText = image.dataset.title;

                const lightboxImage = document.getElementById('lightboxTargetImage');
                const lightboxLabel = document.getElementById('lightboxModalLabel');

                if (!lightboxImage || !lightboxLabel) {
                    return;
                }

                lightboxImage.src = targetImageSrc;
                lightboxLabel.textContent = puzzleTitleText || 'View Puzzle';

                const imageLightbox = new bootstrap.Modal(document.getElementById('imageLightboxModal'));
                imageLightbox.show();
            });
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