<?php
session_start();
?>

<html>
    <head>
        <title>BroScience : Home</title>
        <?php 
        include_once 'includes/header.php';
        include_once 'includes/utils.php';
        $theme = get_theme();
        ?>
        <link rel="stylesheet" href="styles/<?=$theme?>.css">
    </head>
    <body class="<?=get_theme_class($theme)?>">
        <?php include_once 'includes/navbar.php'; ?>
        <div class="uk-container uk-margin">
            <!-- TODO: Search bar -->
            <?php
            include_once 'includes/db_connect.php';
                    
            // Load exercises
            $res = pg_query($db_conn, 'SELECT exercises.id, username, title, image, SUBSTRING(content, 1, 100), exercises.date_created, users.id FROM exercises JOIN users ON author_id = users.id');
            if (pg_num_rows($res) > 0) {
                echo '<div class="uk-child-width-1-2@s uk-child-width-1-3@m" uk-grid>';
                while ($row = pg_fetch_row($res)) {
                    ?>
                    <div>
                        <div class="uk-card uk-card-default <?=(strcmp($theme,"light"))?"uk-card-secondary":""?>">
                            <div class="uk-card-media-top">
                                <img src="includes/img.php?path=<?=$row[3]?>" width="600" height="600" alt="">
                            </div>
                            <div class="uk-card-body">
                                <a href="exercise.php?id=<?=$row[0]?>" class="uk-card-title"><?=$row[2]?></a>
                                <p><?=$row[4]?>... <a href="exercise.php?id=<?=$row[0]?>">keep reading</a></p>
                            </div>
                            <div class="uk-card-footer">
                                <p class="uk-text-meta">Written by <a class="uk-link-text" href="user.php?id=<?=$row[6]?>"><?=htmlspecialchars($row[1],ENT_QUOTES,'UTF-8')?></a> <?=rel_time($row[5])?></p>
                            </div>
                        </div>
                    </div>
                    
                    <?php
                }
                echo '</div>';
            } 
            ?>
        </div>
    </body>
</html>