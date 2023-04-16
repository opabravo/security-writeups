<?php
session_start();

// Check if user is logged in already
if (isset($_SESSION['id'])) {
    header('Location: /index.php');
}

// Handle a submitted register form
if (isset($_POST['username']) && isset($_POST['email']) && isset($_POST['password']) && isset($_POST['password-confirm'])) {
    // Check if variables are empty
    if (!empty($_POST['username']) && !empty($_POST['email']) && !empty($_POST['password']) && !empty($_POST['password-confirm'])) {
        // Check if passwords match
        if (strcmp($_POST['password'], $_POST['password-confirm']) == 0) {
            // Check if email is too long
            if (strlen($_POST['email']) <= 100) {
                // Check if email is valid
                if (filter_var($_POST['email'], FILTER_VALIDATE_EMAIL)) {
                    // Check if username is valid
                    if (strlen($_POST['username']) <= 100) {
                        // Check if user exists already    
                        include_once 'includes/db_connect.php';

                        $res = pg_prepare($db_conn, "check_username_query", 'SELECT id FROM users WHERE username = $1');
                        $res = pg_execute($db_conn, "check_username_query", array($_POST['username']));
                        
                        if (pg_num_rows($res) == 0) {
                            // Check if email is registered already
                            $res = pg_prepare($db_conn, "check_email_query", 'SELECT id FROM users WHERE email = $1');
                            $res = pg_execute($db_conn, "check_email_query", array($_POST['email']));

                            if (pg_num_rows($res) == 0) {
                                // Create the account
                                include_once 'includes/utils.php';
                                $activation_code = generate_activation_code();
                                $res = pg_prepare($db_conn, "check_code_unique_query", 'SELECT id FROM users WHERE activation_code = $1');
                                $res = pg_execute($db_conn, "check_code_unique_query", array($activation_code));

                                if (pg_num_rows($res) == 0) {
                                    $res = pg_prepare($db_conn, "create_user_query", 'INSERT INTO users (username, password, email, activation_code) VALUES ($1, $2, $3, $4)');
                                    $res = pg_execute($db_conn, "create_user_query", array($_POST['username'], md5($db_salt . $_POST['password']), $_POST['email'], $activation_code));

                                    // TODO: Send the activation link to email
                                    $activation_link = "https://broscience.htb/activate.php?code={$activation_code}";

                                    $alert = "Account created. Please check your email for the activation link.";
                                    $alert_type = "success";
                                } else {
                                    $alert = "Failed to generate a valid activation code, please try again.";
                                }
                            } else {
                                $alert = "An account with this email already exists.";
                            }
                        }
                        else {
                            $alert = "Username is already taken.";
                        }
                    } else {
                        $alert = "Maximum username length is 100 characters.";
                    }
                } else {
                    $alert = "Please enter a valid email address.";
                }
            } else {
                $alert = "Maximum email length is 100 characters.";
            }
        } else {
            $alert = "Passwords do not match.";
        }
    } else {
        $alert = "Please fill all fields in.";
    }
}
?>

<html>
    <head>
        <title>BroScience : Register</title>
        <?php include_once 'includes/header.php'; ?>
    </head>
    <body>
        <?php include_once 'includes/navbar.php'; ?>
        <div class="uk-container uk-container-xsmall">
            <form class="uk-form-stacked" method="POST" action="register.php">
                <fieldset class="uk-fieldset">
                    <legend class="uk-legend">Register</legend>
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
                        <input name="email" class="uk-input" type="email" placeholder="Email">
                    </div>
                    <div class="uk-margin">
                        <input name="password" class="uk-input" type="password" placeholder="Password">
                    </div>
                    <div class="uk-margin">
                        <input name="password-confirm" class="uk-input" type="password" placeholder="Repeat password">
                    </div>
                    <div class="uk-margin">
                        <button class="uk-button uk-button-default" type="submit">Register</button>
                    </div>
                </fieldset>
            </form>
        </div>
    </body>
</html>