<?php
session_start();

// Check if user is logged in already
if (isset($_SESSION['id'])) {
    header('Location: /index.php');
}

// Handle a submitted log in form
if (isset($_POST['username']) && isset($_POST['password'])) {
    // Check if variables are empty
    if (!empty($_POST['username']) && !empty($_POST['password'])) {    
        include_once 'includes/db_connect.php';
        
        // Check if username:password is correct
        $res = pg_prepare($db_conn, "login_query", 'SELECT id, username, is_activated::int, is_admin::int FROM users WHERE username=$1 AND password=$2');
        $res = pg_execute($db_conn, "login_query", array($_POST['username'], md5($db_salt . $_POST['password'])));
        
        if (pg_num_rows($res) == 1) {
            // Check if account is activated
            $row = pg_fetch_row($res);
            if ((bool)$row[2]) {
                // User is logged in
                $_SESSION['id'] = $row[0];
                $_SESSION['username'] = $row[1];
                $_SESSION['is_admin'] = $row[3];

                // Redirect to home page
                header('Location: /index.php');
            } else {
                $alert = "Account is not activated yet";
            }
        } else {
            $alert = "Username or password is incorrect.";
        }
    } else {
        $alert = "Please fill in both username and password.";
    }
}
?>

<html>
    <head>
        <title>BroScience : Log In</title>
        <?php include_once 'includes/header.php'; ?>
    </head>
    <body>
        <?php include_once 'includes/navbar.php'; ?>
        <div class="uk-container uk-container-xsmall">
            <form class="uk-form-stacked" method="POST" action="login.php">
                <fieldset class="uk-fieldset">
                    <legend class="uk-legend">Log In</legend>
                    <?php
                    // Display any alerts
                    if (isset($alert)) {
                    ?>
                    <div uk-alert class="uk-alert-<?php if(isset($alert_type)){echo $alert_type;}else{echo 'danger';} ?>">
                            <a class="uk-alert-close" uk-close></a>
                            <?=$alert?>
                        </div>
                    <?php
                    }
                    ?>
                    <div class="uk-margin">
                        <input name="username" class="uk-input" placeholder="Username">
                    </div>
                    <div class="uk-margin">
                        <input name="password" class="uk-input" type="password" placeholder="Password">
                    </div>
                    <div class="uk-margin">
                        <button class="uk-button uk-button-default" type="submit">Log in</button>
                    </div>
                    <div class="uk-margin">
                        <a href="register.php">Create an account</a>
                    </div>
                </fieldset>
            </form>
        </div>
    </body>
</html>