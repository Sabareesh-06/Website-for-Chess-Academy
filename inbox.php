<?php
session_start();
mysqli_report(MYSQLI_REPORT_OFF);

$cn30 = mysqli_connect("localhost", "root", "", "30mm");
if (!$cn30) { error_log("DB connect failed: " . mysqli_connect_error()); die("Database unavailable."); }
mysqli_set_charset($cn30, "utf8mb4");

if (!isset($_SESSION['role'], $_SESSION['Username'])) { header("Location: login.php"); exit(); }
$role = trim($_SESSION['role']);
$currentUser = trim($_SESSION['Username']);
if ($role === 'guest') { header("Location: ani1.php"); exit(); }

if (empty($_SESSION['csrf_token'])) { $_SESSION['csrf_token'] = bin2hex(random_bytes(32)); }

/* ---------- HELPERS ---------- */
function e($value): string { return htmlspecialchars($value ?? '', ENT_QUOTES, 'UTF-8'); }
function q($conn, $v): string { return "'" . mysqli_real_escape_string($conn, $v) . "'"; }
function valid_csrf(): bool { return isset($_POST['csrf_token'], $_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $_POST['csrf_token']); }
function flash(string $t, string $m): void { $_SESSION['inbox_flash'] = ['type' => $t, 'message' => $m]; }
function normalize_date(string $d): string { $d = trim($d); if ($d === '') return ''; $ts = strtotime($d); return ($ts === false) ? '' : date('Y-m-d', $ts); }

function can_delete_message(string $role, string $me, array $msg): bool {
    if (!empty($msg['is_deleted'])) return false;
    $sender = $msg['sender'] ?? ''; $senderRole = $msg['sender_role'] ?? '';
    $own = strcasecmp(trim($sender), trim($me)) === 0;
    if ($role === 'admin') return true;
    if ($role === 'master') return $own || in_array($senderRole, ['student', 'user'], true);
    if ($role === 'student') return $own;
    return false;
}

function build_redirect_url(array $p): string {
    $q = [];
    if (!empty($p['current_text_search'])) $q['text_search'] = $p['current_text_search'];
    if (!empty($p['current_username_search'])) $q['username_search'] = $p['current_username_search'];
    if (!empty($p['current_from_date'])) $q['from_date'] = $p['current_from_date'];
    if (!empty($p['current_to_date'])) $q['to_date'] = $p['current_to_date'];
    return empty($q) ? 'inbox.php' : 'inbox.php?' . http_build_query($q);
}

mysqli_query($cn30, "CREATE TABLE IF NOT EXISTS messages (
 id INT AUTO_INCREMENT PRIMARY KEY,
 sender VARCHAR(100) NOT NULL,
 receiver VARCHAR(100) NOT NULL,
 message TEXT NOT NULL,
 type VARCHAR(20) NOT NULL DEFAULT 'private',
 created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
 is_deleted TINYINT(1) NOT NULL DEFAULT 0,
 deleted_by VARCHAR(100) NULL,
 deleted_at TIMESTAMP NULL DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci");
/* Fix collation mismatch between messages and register tables */
@mysqli_query($cn30, "ALTER TABLE messages CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci");
@mysqli_query($cn30, "ALTER TABLE register CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci");

/* ---------- DELETE ---------- */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['delete_message'])) {
    if (!valid_csrf()) { flash('failure', 'Security token missing.'); header("Location: inbox.php"); exit(); }
    $id = intval($_POST['message_id'] ?? 0);
    if ($id <= 0) { flash('warning', 'Invalid message.'); header("Location: " . build_redirect_url($_POST)); exit(); }

    $lk = mysqli_prepare($cn30, "SELECT m.*, r.role AS sender_role FROM messages m LEFT JOIN register r ON r.Username = m.sender WHERE m.id = ? LIMIT 1");
    mysqli_stmt_bind_param($lk, "i", $id); mysqli_stmt_execute($lk);
    $msg = mysqli_fetch_assoc(mysqli_stmt_get_result($lk)); mysqli_stmt_close($lk);

    if (!$msg) { flash('warning', 'Message not found.'); header("Location: " . build_redirect_url($_POST)); exit(); }
    if (!empty($msg['is_deleted'])) { flash('warning', 'Already deleted.'); header("Location: " . build_redirect_url($_POST)); exit(); }
    if (!can_delete_message($role, $currentUser, $msg)) { flash('failure', 'Not allowed to delete this message.'); header("Location: " . build_redirect_url($_POST)); exit(); }

    $up = mysqli_prepare($cn30, "UPDATE messages SET is_deleted=1, deleted_by=?, deleted_at=NOW() WHERE id=? AND is_deleted=0");
    mysqli_stmt_bind_param($up, "si", $currentUser, $id);
    flash(mysqli_stmt_execute($up) && mysqli_stmt_affected_rows($up) > 0 ? 'success' : 'failure',
          mysqli_stmt_affected_rows($up) > 0 ? 'Message deleted successfully.' : 'Could not delete message.');
    mysqli_stmt_close($up);
    header("Location: " . build_redirect_url($_POST)); exit();
}

/* ---------- SEND ---------- */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['send_inbox_message'])) {
    if (!valid_csrf()) { flash('failure', 'Security token missing.'); header("Location: inbox.php"); exit(); }
    $text = trim($_POST['message_text'] ?? '');
    $target = $_POST['target'] ?? 'individual';
    if ($text === '') { flash('warning', 'Message cannot be empty.'); header("Location: inbox.php"); exit(); }

    if ($target === 'all') {
        if (!in_array($role, ['admin', 'master'], true)) { flash('failure', 'Only admin/master can announce.'); header("Location: inbox.php"); exit(); }
        $st = mysqli_prepare($cn30, "INSERT INTO messages (sender, receiver, message, type, created_at) VALUES (?, 'all', ?, 'public', NOW())");
        mysqli_stmt_bind_param($st, "ss", $currentUser, $text);
        flash(mysqli_stmt_execute($st) ? 'success' : 'failure', 'Announcement sent to all students.');
        mysqli_stmt_close($st);
        header("Location: inbox.php"); exit();
    }

    $receiver = trim($_POST['receiver'] ?? '');
    if ($receiver === '') { flash('warning', 'Please enter a receiver username.'); header("Location: inbox.php"); exit(); }
    if (strcasecmp($receiver, $currentUser) === 0) { flash('warning', 'You cannot message yourself.'); header("Location: inbox.php"); exit(); }

    $ck = mysqli_prepare($cn30, "SELECT Username FROM register WHERE LOWER(TRIM(Username)) = LOWER(TRIM(?)) LIMIT 1");
    mysqli_stmt_bind_param($ck, "s", $receiver); mysqli_stmt_execute($ck);
    $rr = mysqli_fetch_assoc(mysqli_stmt_get_result($ck)); mysqli_stmt_close($ck);
    if (!$rr) { flash('warning', 'Username not found.'); header("Location: inbox.php"); exit(); }
    $receiver = $rr['Username'];

    $st = mysqli_prepare($cn30, "INSERT INTO messages (sender, receiver, message, type, created_at) VALUES (?, ?, ?, 'private', NOW())");
    mysqli_stmt_bind_param($st, "sss", $currentUser, $receiver, $text);
    flash(mysqli_stmt_execute($st) ? 'success' : 'failure', 'Message sent successfully.');
    mysqli_stmt_close($st);
    header("Location: inbox.php"); exit();
}

/* ---------- SEARCH / FILTER ---------- */
$textSearch = trim($_GET['text_search'] ?? '');
$usernameSearch = trim($_GET['username_search'] ?? '');
$fromDate = normalize_date($_GET['from_date'] ?? '');
$toDate = normalize_date($_GET['to_date'] ?? '');
if ($fromDate !== '' && $toDate !== '' && $fromDate > $toDate) { $t = $fromDate; $fromDate = $toDate; $toDate = $t; }
$likeText = '%' . addcslashes($textSearch, '%_') . '%';
$likeUser = '%' . addcslashes($usernameSearch, '%_') . '%';

$fetchError = '';

/* shared filter builder (returns SQL fragment) */
function filter_sql($cn30, $textSearch, $likeText, $usernameSearch, $likeUser, $fromDate, $toDate, $userColForUserSearch) {
    $s = '';
    if ($textSearch !== '') $s .= " AND LOWER(m.message) LIKE LOWER(" . q($cn30, $likeText) . ")";
    if ($usernameSearch !== '') $s .= " AND LOWER(TRIM($userColForUserSearch)) LIKE LOWER(" . q($cn30, $likeUser) . ")";
    if ($fromDate !== '' && $toDate !== '') $s .= " AND DATE(m.created_at) BETWEEN " . q($cn30, $fromDate) . " AND " . q($cn30, $toDate);
    elseif ($fromDate !== '') $s .= " AND DATE(m.created_at) >= " . q($cn30, $fromDate);
    elseif ($toDate !== '') $s .= " AND DATE(m.created_at) <= " . q($cn30, $toDate);
    return $s;
}

/* ---------- FETCH RECEIVED ---------- */
$receivedMessages = [];
$sql = "SELECT m.*, r.role AS sender_role FROM messages m
        LEFT JOIN register r ON r.Username = m.sender
        WHERE (LOWER(TRIM(m.receiver)) = LOWER(TRIM(" . q($cn30, $currentUser) . ")) OR LOWER(TRIM(m.receiver)) = 'all')"
        . filter_sql($cn30, $textSearch, $likeText, $usernameSearch, $likeUser, $fromDate, $toDate, 'm.sender')
        . " ORDER BY m.created_at DESC, m.id DESC LIMIT 200";
$res = mysqli_query($cn30, $sql);
if ($res) { while ($r = mysqli_fetch_assoc($res)) $receivedMessages[] = $r; }
else { $fetchError .= "RECEIVED QUERY ERROR: " . mysqli_error($cn30) . " "; }

/* ---------- FETCH SENT ---------- */
$sentMessages = [];
$sql = "SELECT m.*, r.role AS sender_role FROM messages m
        LEFT JOIN register r ON r.Username = m.sender
        WHERE LOWER(TRIM(m.sender)) = LOWER(TRIM(" . q($cn30, $currentUser) . "))"
        . filter_sql($cn30, $textSearch, $likeText, $usernameSearch, $likeUser, $fromDate, $toDate, 'm.receiver')
        . " ORDER BY m.created_at DESC, m.id DESC LIMIT 200";
$res = mysqli_query($cn30, $sql);
if ($res) { while ($r = mysqli_fetch_assoc($res)) $sentMessages[] = $r; }
else { $fetchError .= "SENT QUERY ERROR: " . mysqli_error($cn30) . " "; }

/* ---------- FETCH ALL (staff) ---------- */
$allMessages = [];
$isStaff = in_array($role, ['admin', 'master'], true);
if ($isStaff) {
    $sql = "SELECT m.*, r.role AS sender_role FROM messages m
            LEFT JOIN register r ON r.Username = m.sender
            WHERE 1=1"
            . filter_sql($cn30, $textSearch, $likeText, $usernameSearch, $likeUser, $fromDate, $toDate, 'm.sender')
            . " ORDER BY m.created_at DESC, m.id DESC LIMIT 200";
    $res = mysqli_query($cn30, $sql);
    if ($res) { while ($r = mysqli_fetch_assoc($res)) $allMessages[] = $r; }
    else { $fetchError .= "ALL QUERY ERROR: " . mysqli_error($cn30) . " "; }
}

$flash = $_SESSION['inbox_flash'] ?? null;
unset($_SESSION['inbox_flash']);
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Inbox</title>
<link rel="stylesheet" href="bootstrap/css/bootstrap.min.css">
<link rel="stylesheet" href="bootstrap/icons/font/bootstrap-icons.css">
<link rel="stylesheet" href="notiflix/notiflix-3.2.7.min.css">
<script src="bootstrap/js/bootstrap.bundle.min.js"></script>
<script src="notiflix/notiflix-3.2.7.min.js"></script>
<style>
body{background:#f8f9fa}.message-box{max-height:450px;overflow-y:auto}.message-item{border-radius:8px}
.announcement-badge,.private-badge,.deleted-badge{font-size:.7rem}
</style>
</head>
<body>
<div class="container py-4">
<div class="d-flex justify-content-between align-items-center mb-4">
<h4 class="mb-0"><i class="bi bi-inbox-fill"></i> Inbox</h4>
<div>
<span class="badge bg-dark me-2">Logged in as: <?php echo e($currentUser); ?> (<?php echo e($role); ?>)</span>
<button class="btn btn-sm btn-info" onclick="window.location.href='ani1.php'"><i class="bi bi-house-door-fill"></i> Home</button>
</div>
</div>

<?php if ($fetchError !== ''): ?>
<div class="alert alert-danger small"><?php echo e($fetchError); ?></div>
<?php endif; ?>

<div class="card shadow-sm mb-4">
<div class="card-header bg-dark text-white"><i class="bi bi-search"></i> Search &amp; Filter Messages</div>
<div class="card-body">
<form method="GET" class="row g-2">
<div class="col-md-3"><label class="form-label small mb-1">Search by Text</label>
<input type="text" name="text_search" value="<?php echo e($textSearch); ?>" class="form-control" placeholder="Search message text..."></div>
<div class="col-md-3"><label class="form-label small mb-1">Search by Username</label>
<input type="text" name="username_search" value="<?php echo e($usernameSearch); ?>" class="form-control" placeholder="Search username..."></div>
<div class="col-md-2"><label class="form-label small mb-1">From Date</label>
<input type="date" name="from_date" value="<?php echo e($fromDate); ?>" class="form-control"></div>
<div class="col-md-2"><label class="form-label small mb-1">To Date</label>
<input type="date" name="to_date" value="<?php echo e($toDate); ?>" class="form-control"></div>
<div class="col-md-2 d-flex align-items-end">
<button type="submit" class="btn btn-primary me-2"><i class="bi bi-search"></i> Apply</button>
<a href="inbox.php" class="btn btn-secondary">Clear</a>
</div>
</form>
</div>
</div>

<div class="row">
<div class="col-lg-4 mb-4">
<div class="card shadow-sm">
<div class="card-header bg-primary text-white"><i class="bi bi-send-fill"></i> Send Message</div>
<div class="card-body">
<form method="POST">
<input type="hidden" name="send_inbox_message" value="1">
<input type="hidden" name="csrf_token" value="<?php echo e($_SESSION['csrf_token']); ?>">
<?php if ($isStaff): ?>
<div class="mb-3"><label class="form-label fw-bold">Send To</label>
<select name="target" id="target" class="form-select">
<option value="individual">Individual Username</option>
<option value="all">All Students (Announcement)</option>
</select></div>
<?php else: ?>
<input type="hidden" name="target" value="individual">
<?php endif; ?>
<div class="mb-3" id="receiverWrap"><label class="form-label fw-bold">Receiver Username</label>
<input type="text" name="receiver" id="receiver" class="form-control" placeholder="Enter username" autocomplete="off"></div>
<div class="mb-3"><label class="form-label fw-bold">Message</label>
<textarea name="message_text" class="form-control" rows="4" placeholder="Write your message..." required></textarea></div>
<button type="submit" class="btn btn-primary w-100"><i class="bi bi-send"></i> Send</button>
</form>
</div>
</div>
</div>

<div class="col-lg-8 mb-4">
<div class="card shadow-sm">
<div class="card-header bg-success text-white"><i class="bi bi-envelope-open-fill"></i> Received Messages (for <?php echo e($currentUser); ?>)</div>
<div class="card-body message-box">
<?php if (empty($receivedMessages)): ?>
<div class="alert alert-info text-center mb-0">No received messages found.</div>
<?php else: ?>
<div class="list-group list-group-flush">
<?php foreach ($receivedMessages as $msg): ?>
<?php
$isAnn = ($msg['receiver'] === 'all' || ($msg['type'] ?? '') === 'public');
$isDel = !empty($msg['is_deleted']);
$canDel = can_delete_message($role, $currentUser, $msg);
$mDate = !empty($msg['created_at']) ? date('d M Y, h:i A', strtotime($msg['created_at'])) : '';
$dDate = !empty($msg['deleted_at']) ? date('d M Y, h:i A', strtotime($msg['deleted_at'])) : '';
?>
<div class="list-group-item message-item mb-2 border <?php echo $isDel ? 'border-secondary' : ($isAnn ? 'border-warning' : 'border-primary'); ?>">
<div class="d-flex justify-content-between align-items-start">
<div><strong>From: <?php echo e($msg['sender']); ?></strong>
<?php if ($isDel): ?><span class="badge bg-secondary deleted-badge">Deleted</span>
<?php elseif ($isAnn): ?><span class="badge bg-warning text-dark announcement-badge">Announcement</span>
<?php else: ?><span class="badge bg-primary private-badge">Private</span><?php endif; ?></div>
<small class="text-muted"><?php echo e($mDate); ?></small>
</div>
<?php if ($isDel): ?>
<div class="alert alert-secondary mt-2 mb-0 small"><i class="bi bi-trash-fill"></i> This message was deleted by <strong><?php echo e($msg['deleted_by'] ?? 'unknown'); ?></strong> on <strong><?php echo e($dDate ?: 'unknown time'); ?></strong>.</div>
<?php else: ?>
<p class="mb-2 mt-2"><?php echo nl2br(e($msg['message'])); ?></p>
<?php endif; ?>
<?php if ($canDel): ?>
<form method="POST" class="text-end">
<input type="hidden" name="delete_message" value="1">
<input type="hidden" name="csrf_token" value="<?php echo e($_SESSION['csrf_token']); ?>">
<input type="hidden" name="message_id" value="<?php echo (int)$msg['id']; ?>">
<input type="hidden" name="current_text_search" value="<?php echo e($textSearch); ?>">
<input type="hidden" name="current_username_search" value="<?php echo e($usernameSearch); ?>">
<input type="hidden" name="current_from_date" value="<?php echo e($fromDate); ?>">
<input type="hidden" name="current_to_date" value="<?php echo e($toDate); ?>">
<button type="submit" class="btn btn-sm btn-outline-danger" onclick="return confirm('Delete this message?');"><i class="bi bi-trash"></i> Delete</button>
</form>
<?php endif; ?>
</div>
<?php endforeach; ?>
</div>
<?php endif; ?>
</div>
</div>
</div>
</div>

<?php if ($isStaff): ?>
<div class="row">
<div class="col-12 mb-4">
<div class="card shadow-sm">
<div class="card-header bg-dark text-white"><i class="bi bi-chat-square-text-fill"></i> All Messages (Admin/Master view)</div>
<div class="card-body message-box">
<?php if (empty($allMessages)): ?>
<div class="alert alert-info text-center mb-0">No messages in the system yet.</div>
<?php else: ?>
<div class="list-group list-group-flush">
<?php foreach ($allMessages as $msg): ?>
<?php
$isAnn = ($msg['receiver'] === 'all' || ($msg['type'] ?? '') === 'public');
$isDel = !empty($msg['is_deleted']);
$canDel = can_delete_message($role, $currentUser, $msg);
$mDate = !empty($msg['created_at']) ? date('d M Y, h:i A', strtotime($msg['created_at'])) : '';
$dDate = !empty($msg['deleted_at']) ? date('d M Y, h:i A', strtotime($msg['deleted_at'])) : '';
?>
<div class="list-group-item message-item mb-2 border <?php echo $isDel ? 'border-secondary' : 'border-dark'; ?>">
<div class="d-flex justify-content-between align-items-start">
<div><strong><?php echo e($msg['sender']); ?></strong> <i class="bi bi-arrow-right mx-1"></i> <strong><?php echo $msg['receiver'] === 'all' ? 'All Students' : e($msg['receiver']); ?></strong>
<?php if ($isDel): ?><span class="badge bg-secondary deleted-badge">Deleted</span>
<?php elseif ($isAnn): ?><span class="badge bg-warning text-dark announcement-badge">Announcement</span>
<?php else: ?><span class="badge bg-primary private-badge">Private</span><?php endif; ?></div>
<small class="text-muted"><?php echo e($mDate); ?></small>
</div>
<?php if ($isDel): ?>
<div class="alert alert-secondary mt-2 mb-0 small"><i class="bi bi-trash-fill"></i> This message was deleted by <strong><?php echo e($msg['deleted_by'] ?? 'unknown'); ?></strong> on <strong><?php echo e($dDate ?: 'unknown time'); ?></strong>.</div>
<?php else: ?>
<p class="mb-2 mt-2"><?php echo nl2br(e($msg['message'])); ?></p>
<?php endif; ?>
<?php if ($canDel): ?>
<form method="POST" class="text-end">
<input type="hidden" name="delete_message" value="1">
<input type="hidden" name="csrf_token" value="<?php echo e($_SESSION['csrf_token']); ?>">
<input type="hidden" name="message_id" value="<?php echo (int)$msg['id']; ?>">
<input type="hidden" name="current_text_search" value="<?php echo e($textSearch); ?>">
<input type="hidden" name="current_username_search" value="<?php echo e($usernameSearch); ?>">
<input type="hidden" name="current_from_date" value="<?php echo e($fromDate); ?>">
<input type="hidden" name="current_to_date" value="<?php echo e($toDate); ?>">
<button type="submit" class="btn btn-sm btn-outline-danger" onclick="return confirm('Delete this message?');"><i class="bi bi-trash"></i> Delete</button>
</form>
<?php endif; ?>
</div>
<?php endforeach; ?>
</div>
<?php endif; ?>
</div>
</div>
</div>
</div>
<?php endif; ?>

<div class="row">
<div class="col-12">
<div class="card shadow-sm">
<div class="card-header bg-secondary text-white"><i class="bi bi-send-check-fill"></i> Sent Messages (by <?php echo e($currentUser); ?>)</div>
<div class="card-body message-box">
<?php if (empty($sentMessages)): ?>
<div class="alert alert-info text-center mb-0">No sent messages found.</div>
<?php else: ?>
<div class="list-group list-group-flush">
<?php foreach ($sentMessages as $msg): ?>
<?php
$isAnn = ($msg['receiver'] === 'all' || ($msg['type'] ?? '') === 'public');
$isDel = !empty($msg['is_deleted']);
$canDel = can_delete_message($role, $currentUser, $msg);
$mDate = !empty($msg['created_at']) ? date('d M Y, h:i A', strtotime($msg['created_at'])) : '';
$dDate = !empty($msg['deleted_at']) ? date('d M Y, h:i A', strtotime($msg['deleted_at'])) : '';
?>
<div class="list-group-item message-item mb-2 border <?php echo $isDel ? 'border-secondary' : ($isAnn ? 'border-warning' : 'border-primary'); ?>">
<div class="d-flex justify-content-between align-items-start">
<div><strong>To: <?php echo $msg['receiver'] === 'all' ? 'All Students' : e($msg['receiver']); ?></strong>
<?php if ($isDel): ?><span class="badge bg-secondary deleted-badge">Deleted</span>
<?php elseif ($isAnn): ?><span class="badge bg-warning text-dark announcement-badge">Announcement</span>
<?php else: ?><span class="badge bg-primary private-badge">Private</span><?php endif; ?></div>
<small class="text-muted"><?php echo e($mDate); ?></small>
</div>
<?php if ($isDel): ?>
<div class="alert alert-secondary mt-2 mb-0 small"><i class="bi bi-trash-fill"></i> This message was deleted by <strong><?php echo e($msg['deleted_by'] ?? 'unknown'); ?></strong> on <strong><?php echo e($dDate ?: 'unknown time'); ?></strong>.</div>
<?php else: ?>
<p class="mb-2 mt-2"><?php echo nl2br(e($msg['message'])); ?></p>
<?php endif; ?>
<?php if ($canDel): ?>
<form method="POST" class="text-end">
<input type="hidden" name="delete_message" value="1">
<input type="hidden" name="csrf_token" value="<?php echo e($_SESSION['csrf_token']); ?>">
<input type="hidden" name="message_id" value="<?php echo (int)$msg['id']; ?>">
<input type="hidden" name="current_text_search" value="<?php echo e($textSearch); ?>">
<input type="hidden" name="current_username_search" value="<?php echo e($usernameSearch); ?>">
<input type="hidden" name="current_from_date" value="<?php echo e($fromDate); ?>">
<input type="hidden" name="current_to_date" value="<?php echo e($toDate); ?>">
<button type="submit" class="btn btn-sm btn-outline-danger" onclick="return confirm('Delete this message?');"><i class="bi bi-trash"></i> Delete</button>
</form>
<?php endif; ?>
</div>
<?php endforeach; ?>
</div>
<?php endif; ?>
</div>
</div>
</div>
</div>
</div>

<script>
function toggleReceiverField(){
var t=document.getElementById('target'),w=document.getElementById('receiverWrap'),r=document.getElementById('receiver');
if(!t||!w||!r)return;
if(t.value==='all'){w.style.display='none';r.required=false;}else{w.style.display='block';r.required=true;}
}
document.addEventListener('DOMContentLoaded',function(){
var t=document.getElementById('target');
if(t){t.addEventListener('change',toggleReceiverField);toggleReceiverField();}
<?php if ($flash): ?>
var ft=<?php echo json_encode(in_array($flash['type'] ?? '', ['success','failure','warning','info'], true) ? $flash['type'] : 'info'); ?>;
var fm=<?php echo json_encode($flash['message'] ?? '', JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_QUOT|JSON_HEX_AMP); ?>;
if(fm&&window.Notiflix&&Notiflix.Notify){ if(typeof Notiflix.Notify[ft]==='function'){Notiflix.Notify[ft](fm);}else{Notiflix.Notify.info(fm);} }
<?php endif; ?>
});
</script>
</body>
</html>