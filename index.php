<?php

require("config/config.php");

////////////////////
///DB CONNECTION
////////////////////


//MYSQL SETUP
mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);
$mysqli = new mysqli($mysql_host, $mysql_user, $mysql_passwd, $mysql_db);

// Check connection
if ($mysqli -> connect_errno) {
  echo "Failed to connect to MySQL: " . $mysqli -> connect_error;
  exit();
}


////////////////////
///FUNCTIONS
////////////////////

function bot_detected()
{
  return (
    isset($_SERVER['HTTP_USER_AGENT'])
    && preg_match('/bot|crawl|slurp|spider|mediapartners/i', $_SERVER['HTTP_USER_AGENT'])
  );
}


function base64url_encode($data) {

  return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');

}


function base64url_decode($data) {

  return base64_decode(str_pad(strtr($data, '-_', '+/'), strlen($data) % 4, '=', STR_PAD_RIGHT));

}

function generate_key_1()
{
    // Create The First Key
    $key1=base64url_encode(openssl_random_pseudo_bytes(32));
    return $key1;
}

function generate_key_2()
{
    // Create The Second Key
    $key2=base64url_encode(openssl_random_pseudo_bytes(64));
    return $key2;
}

function generate_code()
{
    // Create The First Key
    $code=base64url_encode(openssl_random_pseudo_bytes(32));
    return $code;
}


function secured_encrypt($data,$key1,$key2)
{
    $first_key = base64url_decode($key1);
    $second_key = base64url_decode($key2);    
    
    $method = "aes-256-cbc";    
    $iv_length = openssl_cipher_iv_length($method);
    $iv = openssl_random_pseudo_bytes($iv_length);
    
    $first_encrypted = openssl_encrypt($data,$method,$first_key, OPENSSL_RAW_DATA ,$iv);    
    $second_encrypted = hash_hmac('sha3-512', $first_encrypted, $second_key, TRUE);
    
    $output = base64url_encode($iv.$second_encrypted.$first_encrypted);    
    return $output;        
}

function secured_decrypt($input,$key1,$key2)
{
    $first_key = base64url_decode($key1);
    $second_key = base64url_decode($key2);            
    $mix = base64url_decode($input);
    
    $method = "aes-256-cbc";    
    $iv_length = openssl_cipher_iv_length($method);
    
    $iv = substr($mix,0,$iv_length);
    $second_encrypted = substr($mix,$iv_length,64);
    $first_encrypted = substr($mix,$iv_length+64);
    
    $data = openssl_decrypt($first_encrypted,$method,$first_key,OPENSSL_RAW_DATA,$iv);
    $second_encrypted_new = hash_hmac('sha3-512', $first_encrypted, $second_key, TRUE);
    
    if (hash_equals($second_encrypted,$second_encrypted_new))
        return $data;
    
    return false;
}

function display_headers($project_title)
{
    echo "
<html>
<head>
<title>$project_title</title>
<style>
body {
color: white;
background-color: black;
font-family: system-ui;
}
.tooltip {
  position: relative;
  display: inline-block;
}

.tooltip .tooltiptext {
  visibility: hidden;
  width: 140px;
  background-color: #555;
  color: #fff;
  text-align: center;
  border-radius: 6px;
  padding: 5px;
  position: absolute;
  z-index: 1;
  bottom: 150%;
  left: 50%;
  margin-left: -75px;
  opacity: 0;
  transition: opacity 0.3s;
}

.tooltip .tooltiptext::after {
  content: '';
  position: absolute;
  top: 100%;
  left: 50%;
  margin-left: -5px;
  border-width: 5px;
  border-style: solid;
  border-color: #555 transparent transparent transparent;
}

.tooltip:hover .tooltiptext {
  visibility: visible;
  opacity: 1;
}

textarea,textarea:focus
{
 font-size: 14px;
 overflow: hidden;
 width: 30%;
 padding: 12px 20px;
  box-sizing: border-box;
  border: 4px solid #47110d;
  border-radius: 4px;
  background-color: #f8f8f8;
  resize: none; 
  outline: none !important;
  box-shadow: 0 0 10px #642e2a;
}

.button {
  background-color: #ef3d30;
  border: none;
  color: white;
  padding: 10px 20px;
  text-align: center;
  text-decoration: none;
  display: inline-block;
  font-size: 14px;
border-radius: 8px;
}

.button:hover
{
  background-color: #47110d;
  border: none;
  color: white;
  padding: 10px 20px;
  text-align: center;
  text-decoration: none;
  display: inline-block;
  font-size: 14px;
 border-radius: 8px;
}


</style>

<body>
<center>
<br>
<img src='supertechguy-avatar-redeagle.svg' width='100px'>
<br>
";
}

function display_footers()
{
    echo "
<script>
function copylink() {
  var copyText = document.getElementById('link');
  copyText.select();
  copyText.setSelectionRange(0, 99999);
  navigator.clipboard.writeText(copyText.value);
  
  var tooltip = document.getElementById('myTooltip');
  tooltip.innerHTML = 'Copied link to clipboard';
}
function copypasswd() {
  var copyText = document.getElementById('passwd');
  copyText.select();
  copyText.setSelectionRange(0, 99999);
  navigator.clipboard.writeText(copyText.value);
  
  var tooltip = document.getElementById('myTooltip');
  tooltip.innerHTML = 'Copied password to clipboard';
}

function outlink() {
  var tooltip = document.getElementById('myTooltip');
  tooltip.innerHTML = 'Copy link to clipboard';
}
function outpasswd() {
  var tooltip = document.getElementById('myTooltip');
  tooltip.innerHTML = 'Copy password to clipboard';
}
</script>


</body>
</html>
";
}

function display_form()
{
    echo "<br>
<h1>Enter password to encrypt and send</h1>
<form method='POST' action='index.php?action=encrypt'>
  <textarea id='passwd' name='passwd' rows='5' cols='60' autofocus></textarea><br><br>
  <input class='button' type='submit' value='Generate Link'>
</form>
";
}

function display_link($link)
{
    echo "<br>
<h1>Send this link to the recipient</h1>
  <textarea id='link' name='link' rows='5' cols='60' autofocus>$link</textarea></p>
<div class='tooltip'>
<button class='button' onclick='copylink()' onmouseout='outlink()'>
  <span class='tooltiptext' id='myTooltip'>Copy to clipboard</span>
  Copy Link
  </button>
</div>
<input class='button' type='button' onclick=\"location.href='index.php';\" value='Reset' />

";
}

function display_passwd($passwd)
{
    echo "<br>
<h1>Your password is:</h1>
  <textarea id='passwd' name='passwd' rows='5' cols='60' autofocus>$passwd</textarea><br><br>
  <p>This page will only be accessable once, you must copy the password now</p>
  <p style='color:red'>[Data Destroyed]</p>
<div class='tooltip'>
<button class='button' onclick='copypasswd()' onmouseout='outpasswd()'>
  <span class='tooltiptext' id='myTooltip'>Copy to clipboard</span>
  Copy Password
  </button>
</div>
  <input class='button' type='button' onclick=\"location.href='index.php';\" value='Reset' />

";
}


function display_error()
{
    echo "<br>
  <p style='color:red'>[ERROR]</p>
  <input class='button' type='button' onclick=\"location.href='index.php';\" value='Reset' />
";
}


////////////////////
///ENV VARS
////////////////////

//CONTROL
$action=$_GET['action'];

//ENCRYPT
$passwd=$_POST['passwd'];

//DECRYPT
$key1=$_GET['key1'];
$key2=$_GET['key2'];
$id=mysqli_real_escape_string($mysqli,$_GET['id']);
$code=mysqli_real_escape_string($mysqli,$_GET['code']);

/////////////////////
///MAIN RUNTIME CODE
/////////////////////

if (bot_detected())
{
    echo "
<html>
<head>
<title>$project_title</title>
<body>
<h1>$project_title</h1>
</body>
</html>
";
}
else
{
    display_headers($project_title);
    switch($action)
    {
    case "encrypt":
        $key1=generate_key_1();
        $key2=generate_key_2();
        $code=generate_code();
        $encrypted_passwd=secured_encrypt($passwd,$key1,$key2);
        $result=mysqli_query($mysqli,"insert into passwds(code,passwd) values ('$code','$encrypted_passwd');");
        $id=mysqli_insert_id($mysqli);
        $link="$project_url/index.php?action=decrypt&id=$id&key1=$key1&key2=$key2&code=$code";
        display_link($link);
        break;
    case "decrypt":
        $query="select passwd from passwds where id='$id' and code='$code';";
        $result=$mysqli->query($query);
        $row=$result->fetch_array(MYSQLI_BOTH);
        $total=$result -> num_rows;
        if ($total==1)
        {
            $encrypted_passwd=$row['passwd'];
            $passwd=secured_decrypt($encrypted_passwd,$key1,$key2);
            $query="delete from passwds where id='$id' and code='$code';";
            $result=$mysqli->query($query);
            display_passwd($passwd);
        }
        else
        {
            display_error();
        }
        break;
    default:
        display_form();
    }
    
    display_footers();
}

?>
