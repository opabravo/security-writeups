<?php
session_start();

// Is it a proper request?
if (isset($_GET['id'])) {
    if (!empty($_GET['id'])) {
        if (filter_var($_GET['id'], FILTER_VALIDATE_INT)) {
            include_once 'includes/db_connect.php';
            $res = pg_prepare($db_conn, "get_user_query", 'SELECT username, email, is_activated::int, is_admin::int, date_created FROM users WHERE id = $1');
            $res = pg_execute($db_conn, "get_user_query", array($_GET['id']));

            if (pg_num_rows($res) > 0) {
                $row = pg_fetch_row($res);
            } else {
                $alert = "No user with that ID";
            }
        } else {
            $alert = "Invalid ID value";
        }
    } else {
        $alert = "Empty ID value";
    }
} else {
    $alert = "Missing ID value";
}
?>

<html>
    <head>
        <title>BroScience : <?php if (isset($row)) {echo htmlspecialchars($row[0],ENT_QUOTES,'UTF-8');} else {echo "View user";}?></title>
        <?php 
        include_once 'includes/header.php';
        include_once 'includes/utils.php';
        $theme = get_theme();
        ?>
        <link rel="stylesheet" href="styles/<?=$theme?>.css">
    </head>
    <body class="<?=get_theme_class($theme)?>">
        <?php include_once 'includes/navbar.php'; ?>
        <div class="uk-container uk-container-xsmall">
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
            if (isset($row)) {
            ?>
                <h1 class="uk-heading-small"><?=htmlspecialchars($row[0],ENT_QUOTES,'UTF-8')?></h1>
                <!-- TODO: Avatars -->
                <dl class="uk-description-list">
                    <dt>Member since</dt>
                    <dd><?=rel_time($row[4])?></dd>
                    <dt>Email Address</dt>
                    <dd><?=$row[1]?></dd>
                    <dt>Total exercises posted</dt>
                    <dd>
                        <?php
                        $res = pg_prepare($db_conn, "get_num_exercises_query", 'SELECT COUNT(*) FROM exercises WHERE author_id = $1');
                        $res = pg_execute($db_conn, "get_num_exercises_query", array($_GET['id']));
                        $row2 = pg_fetch_row($res);
                        echo $row2[0];
                        ?>
                    </dd>
                    <dt>Total comments posted</dt>
                    <dd>
                        <?php
                        $res = pg_prepare($db_conn, "get_num_comments_query", 'SELECT COUNT(*) FROM comments WHERE author_id = $1');
                        $res = pg_execute($db_conn, "get_num_comments_query", array($_GET['id']));
                        $row3 = pg_fetch_row($res);
                        echo $row3[0];
                        ?>
                    </dd>
                    <dt>Is activated</dt>
                    <dd>
                        <?=(bool)$row[2]?'Yes':'No'?>
                    </dd>
                    <dt>Is admin</dt>
                    <dd>
                        <?=(bool)$row[3]?'Yes':'No'?>
                    </dd>
                </dl>
            <?php 
                // Check if we are logged in
                if (isset($_SESSION['id'])) {
                    if ($_SESSION['id'] === $_GET['id'] || $_SESSION['is_admin']) {
                        // We are logged in as this user, add the edit form
                        ?>
                        <hr>
                        <form class="uk-form-stacked" method="POST" action="update_user.php">
                            <fieldset class="uk-fieldset">
                                <legend class="uk-legend">Edit User</legend>
                                <div class="uk-margin">
                                    <input name="username" class="uk-input" type="text" placeholder="New username">
                                </div>
                                <div class="uk-margin">
                                    <input name="email" class="uk-input" type="email" placeholder="New email">
                                </div>
                                <div class="uk-margin">
                                    <input name="password" class="uk-input" placeholder="New password">
                                </div>
                                <div class="uk-margin">
                                    <button class="uk-button uk-button-default" type="submit">Update</button>
                                </div>
                                <input type="hidden" name="id" value="<?=$_GET['id']?>">
                            </fieldset>
                        </form>
                        <?php
                    }
                }
            }
            ?>
        </div>
    </body>
</html>