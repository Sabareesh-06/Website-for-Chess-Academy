<?php
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action_type_js'] ?? ($_POST['action_type'] ?? '');
    $action = trim($action);

    if ($action === 'login') {
        header("Location: login.php");
        exit();
    }

    if ($action === 'register') {
        header("Location: register.php");
        exit();
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>My Website</title>

    <link rel="stylesheet" href="Rutu2.css">
    <link rel="stylesheet" href="bootstrap/css/bootstrap.min.css">
    <link rel="stylesheet" href="bootstrap/icons/font/bootstrap-icons.css">

    <!-- Notiflix -->
    <link rel="stylesheet" href="notiflix/notiflix-3.2.7.min.css">
    <script src="notiflix/notiflix-3.2.7.min.js"></script>
</head>
<body>

<form method="post" id="loadingForm" action="">
    <!-- Used when JavaScript submits the form -->
    <input type="hidden" name="action_type_js" id="action_type_js" value="">

    <div class="one">
        <div class="card" style="width: 18rem;">
            <img src="images/chess.jpeg" class="card-img-top img-fluid" alt="Chess Academy">

            <div class="card-body text-center">
                <h5 class="card-title">Do you have an account?</h5>

                <button type="submit" name="action_type" value="login"
                        class="btn btn-primary"
                        onclick="return runLoading('login');">
                    <i class="bi bi-arrow-right"></i> Login
                </button>

                <!--
                <button type="submit" name="action_type" value="register"
                        class="btn btn-primary mt-2"
                        onclick="return runLoading('register');">
                    <i class="bi bi-person-check"></i> Register
                </button>
                -->
            </div>
        </div>
    </div>

    <noscript>
        <div class="alert alert-warning m-3">
            Please enable JavaScript to use the loading animation.
        </div>
    </noscript>
</form>

<script>
window.addEventListener('pageshow', function(event) {
    if (event.persisted) {
        if (window.Notiflix) {
            Notiflix.Loading.remove();
        }
        return;
    }

    const navigationEntries = window.performance.getEntriesByType("navigation");

    if (
        navigationEntries.length > 0 &&
        navigationEntries[0].type === "back_forward"
    ) {
        if (window.Notiflix) {
            Notiflix.Loading.remove();
        }
    }
});

function runLoading(target) {
    const actionInput = document.getElementById('action_type_js');
    const loadingForm = document.getElementById('loadingForm');

    if (!loadingForm) {
        return true;
    }

    if (actionInput) {
        actionInput.value = target;
    }

    if (!window.Notiflix) {
        return true;
    }

    let loadingMessage = 'Please wait...';

    Notiflix.Loading.pulse(loadingMessage, {
        backgroundColor: 'rgba(0,0,0,0.6)',
        svgColor: '#c6e400',
        messageColor: '#ffffff',
        messageFontSize: '18px',
        svgSize: '70px'
    });

    setTimeout(function() {
        loadingForm.submit();
    }, 800);

    return false;
}
</script>

</body>
</html>