<?php
$servername = "localhost";
$username = "root";
$password = ""; 
$dbname = "user_database";
$conn = new mysqli($servername, $username, $password, $dbname);


if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}


if ($_SERVER["REQUEST_METHOD"] == "POST") {
    if (isset($_POST['action'])) {
        if ($_POST['action'] == 'register') {

            $name = trim($_POST['register-name']);
            $email = trim($_POST['register-email']);
            $password = password_hash(trim($_POST['register-password']), PASSWORD_BCRYPT); 

            $sql = "INSERT INTO users (name, email, password) VALUES (?, ?, ?)";
            $stmt = $conn->prepare($sql);
            $stmt->bind_param("sss", $name, $email, $password);

            if ($stmt->execute()) {
                echo "Registration successful!";
            } else {
                echo "Error: " . $stmt->error;
            }
            $stmt->close();
        } elseif ($_POST['action'] == 'login') {

            $email = trim($_POST['login-email']);
            $password = trim($_POST['login-password']);


            $sql = "SELECT password FROM users WHERE email = ?";
            $stmt = $conn->prepare($sql);
            $stmt->bind_param("s", $email);
            $stmt->execute();
            $stmt->bind_result($hashed_password);
            $stmt->fetch();

            if ($hashed_password && password_verify($password, $hashed_password)) {
                echo "Login successful!";
            } else {
                echo "Invalid email or password.";
            }
            $stmt->close();
        }
    }
}

$conn->close();
?>
