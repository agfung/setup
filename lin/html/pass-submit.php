<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML Basic 1.0//EN"
    "http://www.w3.org/TR/xhtml-basic/xhtml-basic10.dtd">

<?php
// Magic quotes be gone!
set_magic_quotes_runtime(0);
function array_stripslashes(&$array) {
	while (list($key) = each($array)) {
		if (is_array($array[$key])) {
			array_stripslashes($array[$key]);
		} else {
			$array[$key] = stripslashes($array[$key]);
		}
	}
}
if (get_magic_quotes_gpc ()) {
	array_stripslashes($_POST);
	array_stripslashes($_GET);
	array_stripslashes($_COOKIE);
}

require_once('passwordmaker_class.php');
?>
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<title>PasswordMaker</title>
</head>
<body>

<?php 
$alg = explode('_', $_POST['alg']);
$sha256_bug = false;
if (count($alg) > 1 && $alg[1] == 'v6') {
	$trim = false;
	$_POST['charset'] = '0123456789abcdef';
} elseif (count($alg) > 1 && $alg[1] == 'v151') {
	$sha256_bug = true;
} else {
	$trim = true;
}
$alg = $alg[0];
echo 'Password is:&nbsp;<input type="text" size="10" value="' .
  htmlspecialchars(generatepassword($alg,
  $_POST['mpw'],
  $_POST['url'] . $_POST['user'] . $_POST['mod'],
  $_POST['leet'],
  $_POST['level'],
  $_POST['len'],
  $_POST['charset'],
  $_POST['prefix'],
  $_POST['suffix'],
  $trim, $sha256_bug)) . '"/>';
  
if (isset($_POST['verbose'])) {
  echo 'Master PW: ' . $_POST['mpw'] . "<br/>";  
  echo 'algorithm: ' . $_POST['alg'] . "<br/>";
  echo 'url: ' . $_POST['url'] . "<br/>";
  echo 'username: ' . $_POST['user'] . "<br/>";
  echo 'modifier: ' . $_POST['mod'] . "<br/>";
  echo 'leet: ' . $_POST['leet'] . "<br/>";
  echo 'level: ' . $_POST['level'] . "<br/>";
  echo 'length: ' . $_POST['len'] . "<br/>";
  echo 'characters: ' . $_POST['charset'] . "<br/>";
  echo 'prefix: ' . $_POST['prefix'] . "<br/>";
  echo 'suffix: ' . $_POST['suffix'];
}?>
</body>
</html>
