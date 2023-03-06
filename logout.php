<?php
// Destroy the logged-in sessions and redirect the user to the login page.

session_start();
session_destroy();
// Redirect to the login page:
header('Location: index.html');

?>