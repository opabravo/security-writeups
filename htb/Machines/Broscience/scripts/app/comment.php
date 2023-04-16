<?php
session_start();

// Check if user is not logged in
if (!isset($_SESSION['id'])) {
    header('Location: /login.php');
    echo "Not logged in";
    die();
}

// Check that all parameters are filled out
if (!isset($_POST['content']) || !isset($_POST['exercise_id'])) {
    header('Location: /index.php');
    echo "Missing parameters";
    die();
}

// Check that parameters are not empty
if (empty($_POST['content']) || empty($_POST['exercise_id'])) {
    header('Location: /index.php');
    echo "Empty parameters";
    die();
}

// Add the comment
include_once 'includes/db_connect.php';

$res = pg_prepare($db_conn, "add_comment_query", 'INSERT INTO comments (exercise_id, author_id, content) VALUES ($1, $2, $3)');
$res = pg_execute($db_conn, "add_comment_query", array($_POST['exercise_id'], $_SESSION['id'], $_POST['content']));

header("Location: /exercise.php?id={$_POST['exercise_id']}");
echo "Comment posted";
?>