<?php
include_once "includes/utils.php";
?>

<nav class="uk-navbar-container uk-margin uk-navbar-transparent <?=get_theme_class()?>">
    <div class="uk-container uk-container-expand">
        <div class="uk-navbar" uk-navbar>
            <div class="uk-navbar-left">
                <a href="/" class="uk-navbar-item uk-logo">BroScience</a>
            </div>
            <div class="uk-navbar-right">
                <?php
                // Check if user is logged in
                if (isset($_SESSION['id'])) {
                    echo '<div class="uk-navbar-item"><a href="swap_theme.php" class="uk-link-text"><span uk-icon="icon: paint-bucket"></span></a></div>';
                    echo "<div class=\"uk-navbar-item\">Logged in as <a class=\"uk-link-text\" href=\"user.php?id={$_SESSION['id']}\"><b>".htmlspecialchars($_SESSION['username'],ENT_QUOTES,'UTF-8')."</b></a></div>";
                    echo '<ul class="uk-navbar-nav"><li><a href="logout.php">Log Out</a></li></ul>';
                } else {
                    echo '<ul class="uk-navbar-nav"><li><a href="login.php">Log In</a></li></ul>';
                }
                ?>
            </div>
        </div>
    </div>
</nav>