<?php
session_start();

if (isset($_GET['id'])) {
    if (!empty($_GET['id'])) {
        if (filter_var($_GET['id'], FILTER_VALIDATE_INT)) {
            include_once 'includes/db_connect.php';

            $res = pg_prepare($db_conn, "get_exercise_query", 'SELECT exercises.id, username, title, image, content, exercises.date_created, users.id FROM exercises JOIN users ON author_id = users.id WHERE exercises.id=$1');
            $res = pg_execute($db_conn, "get_exercise_query", array($_GET['id']));
                        
            if (pg_num_rows($res) > 0) {     
                $row = pg_fetch_row($res);
            } else {
                $alert = "No exercise with that ID";
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
        <title>BroScience : <?php if (isset($row)) {echo $row[2];} else {echo "View exercise";}?></title>
        <?php 
        include_once 'includes/header.php';
        include_once 'includes/utils.php';
        $theme = get_theme();
        ?>
        <link rel="stylesheet" href="styles/<?=$theme?>.css">
    </head>
    <body class="<?=get_theme_class($theme)?>">
        <?php include_once 'includes/navbar.php'; ?>
        <div class="uk-container uk-margin uk-container-xsmall">
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
                <article class="uk-article">
                    <h1 class="uk-article-title"><?=$row[2]?></h1>
                    <p class="uk-article-meta">Written <?=rel_time($row[5])?> by <a class="uk-link-text" href="user.php?id=<?=$row[6]?>"><?=$row[1]?></a></p>
                    <div class="uk-background-contain uk-background-muted uk-height-medium uk-panel uk-flex uk-flex-center uk-flex-middle" style="background-image: url(includes/img.php?path=<?=$row[3]?>);"></div>
                    <p><?=$row[4]?></p>
                </article>
                <hr>
                <form action="/comment.php" method="POST">
                    <fieldset class="uk-fieldset">
                        <legend class="uk-legend">Add a comment</legend>
                        <div class="uk-margin">
                            <textarea name="content" class="uk-textarea" rows="5" placeholder="Write something nice..." required></textarea>
                        </div>
                        <div class="uk-margin">
                            <button class="uk-button uk-button-default" type="submit">Post comment</button>
                        </div>
                        <input type="hidden" name="exercise_id" value="<?=$row[0]?>"/>
                    </fieldset>
                </form>
                <?php
                $res = pg_prepare($db_conn, "get_comments_query", 'SELECT users.username, comments.date_created, content, users.id FROM comments JOIN users ON users.id = comments.author_id WHERE exercise_id = $1 ORDER BY comments.date_created DESC');
                $res = pg_execute($db_conn, "get_comments_query", array($row[0]));
                            
                if (pg_num_rows($res) > 0) {     
                    while ($row = pg_fetch_row($res)) {
                        ?>
                        <article class="uk-comment">
                            <header class="uk-comment-header">
                                <div class="uk-grid-medium uk-flex-middle" uk-grid>
                                    <div class="uk-width-expand">
                                        <h4 class="uk-comment-title uk-margin-remove"><a class="uk-link-text" href="user.php?id=<?=$row[3]?>"><?=htmlspecialchars($row[0],ENT_QUOTES,'UTF-8')?></a></h4>
                                        <p class="uk-comment-meta uk-margin-remove-top"><?=rel_time($row[1])?></p>
                                    </div>
                                </div>
                            </header>
                            <div class="uk-comment-body">
                                <p><?=htmlspecialchars($row[2],ENT_QUOTES,'UTF-8')?></p>
                            </div>
                        </article>
                        <br>
                        <?php
                    }
                } else {
                    ?>
                    <div class="uk-alert" uk-alert>
                        <a class="uk-alert-close" uk-close></a>
                        <p>There are no comments yet</p>
                    </div>
                    <?php
                }
            }
            ?>
        </div>
    </body>
</html>