<?php
/*
  PasswordMaker - Creates and manages passwords
  Copyright (C) 2005-2006 Eric H. Jung and LeahScape, Inc.
  http://passwordmaker.org/
  grimholtz@yahoo.com

  This library is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or (at
  your option) any later version.

  This library is distributed in the hope that it will be useful, but WITHOUT
  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
  FITNESSFOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
  for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with this library; if not, write to the Free Software Foundation,
  Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
  
  Written by Miquel Burns and Eric H. Jung
*/

define('LEET_NONE', 0);
define('LEET_BEFORE', 1);
define('LEET_AFTER', 2);
define('LEET_BOTH', 3);
// $data = $url.$username.$modifier
function generatepassword($hashAlgorithm, $key, $data, $whereToUseL33t, $l33tLevel, $passwordLength, $charset, $prefix, $suffix, $trim = true, $sha256_bug = true) {
	global $PasswordMaker_l33t, $PasswordMaker_SHA256, $PasswordMaker_SHA1, $PasswordMaker_MD4, $PasswordMaker_MD5, $PasswordMaker_RIPEMD160;
	// Never *ever, ever* allow the charset's length<2 else
	// the hash algorithms will run indefinitely
	if (strlen($charset) < 2)
		return "";
	
	// apply l33t before the algorithm?
	if ($whereToUseL33t == LEET_BOTH || $whereToUseL33t == LEET_BEFORE) {
		$key = $PasswordMaker_l33t->convert($l33tLevel, $key);
		if ($usingHMAC) {
			$data = $PasswordMaker_l33t->convert($l33tLevel, $data); // new for 0.3; 0.2 didn't apply l33t to _data_ for HMAC algorithms
		}
	}
	
	// for non-hmac algorithms, the key is master pw and url concatenated
	$usingHMAC = strpos($hashAlgorithm, "hmac") !== false;
	
	// apply the algorithm
	$password = '';
	$count = 0;
	$tkey = $key; // Copy of the key so we don't interfer with it.
	/**/
	while (strlen($password) < $passwordLength && count < 1000) {
		$key = ($count++) ? $tkey."\n".$count: $tkey;
		if (!$usingHMAC)
			$data = $key.$data;
		switch($hashAlgorithm) {
		case "sha256":
			$password .= $PasswordMaker_SHA256->any_sha256($data, $charset, $trim);
			break;
		case "hmac-sha256":
			$password .= $PasswordMaker_SHA256->any_hmac_sha256($key, $data, $charset, $trim, $sha256_bug);
			break;
		case "sha1":
			$password .= $PasswordMaker_SHA1->any_sha1($data, $charset, $trim);
			break;
		case "hmac-sha1":
			$password .= $PasswordMaker_SHA1->any_hmac_sha1($key, $data, $charset, $trim);
			break;
		case "md4":
			$password .= $PasswordMaker_MD4->any_md4($data, $charset, $trim);
			break;
		case "hmac-md4":
			$password .= $PasswordMaker_MD4->any_hmac_md4($key, $data, $charset, $trim);
			break;
		case "md5":
			$password .= $PasswordMaker_MD5->any_md5($data, $charset, $trim);
			break;
		case "hmac-md5":
			$password .= $PasswordMaker_MD5->any_hmac_md5($key, $data, $charset, $trim);
			break;
		case "rmd160":
			$password .= $PasswordMaker_RIPEMD160->any_rmd160($data, $charset, $trim);
			break;
		case "hmac-rmd160":
			$password .= $PasswordMaker_RIPEMD160->any_hmac_rmd160($key, $data, $charset, $trim);
			break;
		}
		if (!$password) break; // Just in case something is wrong with the input
	}
	/**/
	// apply l33t after the algorithm?
	if ($whereToUseL33t == LEET_BOTH || $whereToUseL33t == LEET_AFTER)
		$password = $PasswordMaker_l33t->convert($l33tLevel, $password);/**/
	if ($prefix)
		$password = $prefix . $password;
	if ($suffix)
		$password = substr($password, 0, $passwordLength-strlen($suffix)) . $suffix;
	return substr($password, 0, $passwordLength);
}

class PasswordMaker_l33t {
	var $alphabet, $levels;
	function PasswordMaker_l33t() {
		for($i = 0; $i < 26; $i++) {
			$t = chr(ord('a') + $i);
			$t = "/$t/";
			$this->alphabet[] = $t;
		}
		$this->levels = Array(
			Array("4", "b", "c", "d", "3", "f", "g", "h", "i", "j", "k", "1", "m", "n", "0", "p", "9", "r", "s", "7", "u", "v", "w", "x", "y", "z"),
			Array("4", "b", "c", "d", "3", "f", "g", "h", "1", "j", "k", "1", "m", "n", "0", "p", "9", "r", "5", "7", "u", "v", "w", "x", "y", "2"),
			Array("4", "8", "c", "d", "3", "f", "6", "h", "'", "j", "k", "1", "m", "n", "0", "p", "9", "r", "5", "7", "u", "v", "w", "x", "'/", "2"),
			Array("@", "8", "c", "d", "3", "f", "6", "h", "'", "j", "k", "1", "m", "n", "0", "p", "9", "r", "5", "7", "u", "v", "w", "x", "'/", "2"),
			Array("@", "|3", "c", "d", "3", "f", "6", "#", "!", "7", "|<", "1", "m", "n", "0", "|>", "9", "|2", "$", "7", "u", "\\/", "w", "x", "'/", "2"),
			Array("@", "|3", "c", "|)", "&", "|=", "6", "#", "!", ",|", "|<", "1", "m", "n", "0", "|>", "9", "|2", "$", "7", "u", "\\/", "w", "x", "'/", "2"),
			Array("@", "|3", "[", "|)", "&", "|=", "6", "#", "!", ",|", "|<", "1", "^^", "^/", "0", "|*", "9", "|2", "5", "7", "(_)", "\\/", "\\/\\/", "><", "'/", "2"),
			Array("@", "8", "(", "|)", "&", "|=", "6", "|-|", "!", "_|", "|(", "1", "|\\/|", "|\\|", "()", "|>", "(,)", "|2", "$", "|", "|_|", "\\/", "\\^/", ")(", "'/", "\"/_"),
			Array("@", "8", "(", "|)", "&", "|=", "6", "|-|", "!", "_|", "|{", "|_", "/\\/\\", "|\\|", "()", "|>", "(,)", "|2", "$", "|", "|_|", "\\/", "\\^/", ")(", "'/", "\"/_"));
	}
	
	/**
	* Convert the string in _message_ to l33t-speak
	* using the l33t level specified by _leetLevel_.
	* l33t levels are 1-9 with 1 being the simplest
	* form of l33t-speak and 9 being the most complex.
	*
	* Note that _message_ is converted to lower-case if
	* the l33t conversion is performed.
	* Future versions can support mixed-case, if we need it.
	*
	* Using a _leetLevel_ <= 0 results in the original message
	* being returned.
	*
	*/
	function convert($leetLevel, $message) {
		if ($leetLevel > -1 && $leetLevel < 9) {
			$ret = strtolower($message);
			for ($item = 0; $item < count($this->alphabet); $item++) {
				$ret = preg_replace($this->alphabet[$item], $this->levels[$leetLevel][$item], $ret);
			}
			return $ret;
		}
		return $message;
	}
}
$PasswordMaker_l33t = new PasswordMaker_l33t;

// PHP function to emulate >>>
function _BF_SHR32 ($x, $bits) {
	if ($bits==0) return $x;
	if ($bits==32) return 0;
	$y = ($x & 0x7FFFFFFF) >> $bits;
	if (0x80000000 & $x) {
		$y |= (1<<(31-$bits));    
	}
	return $y;
}

// The lose type system of PHP makes this really iffy when values are close to
// or greater than 0x80000000 on 32-bit systems (Like all known public systems)
function unsigned_xor32 ($a, $b)  {
	$a1 = $a & 0x7FFF0000;
	$a2 = $a & 0x0000FFFF;
	$a3 = $a & 0x80000000;
	$b1 = $b & 0x7FFF0000;
	$b2 = $b & 0x0000FFFF;
	$b3 = $b & 0x80000000;
	$c = ($a3 != $b3) ? 0x80000000 : 0;
	return (($a1 ^ $b1) |($a2 ^ $b2)) + $c;
}

class PasswordMaker_HashUtils {
var $chrsz = 8;  /* bits per input character. 8 - ASCII; 16 - Unicode      */

	/*
	* Encode a string as utf-8.
	* For efficiency, this assumes the input is valid utf-16.
	*/
	function str2rstr_utf8 ($input) {
		$output = "";
		$i = -1;
		while (++$i < strlen($input)) {
			// Decode utf-16 surrogate pairs
			$x = ord($input{$i});
			$y = ($i + 1 < strlen($input)) ? ord($input{$i + 1}) : 0;
			if (0xD800 <= $x && $x <= 0xDBFF && 0xDC00 <= $y && $y <= 0xDFFF) {
				$x = 0x10000 + (($x & 0x03FF) << 10) + ($y & 0x03FF);
				$i++;
			}
			
			// Encode output as utf-8
			if($x <= 0x7F)
				$output .= chr($x);
			else if($x <= 0x7FF)
				$output .= chr(0xC0 | (_BF_SHR32($x , 6 ) & 0x1F),
					0x80 | ( $x         & 0x3F));
			else if($x <= 0xFFFF)
				$output .= chr(0xE0 | (_BF_SHR32($x , 12) & 0x0F),
					0x80 | (_BF_SHR32($x , 6 ) & 0x3F),
					0x80 | ( $x         & 0x3F));
			else if($x <= 0x1FFFFF)
				$output .= chr(0xF0 | (_BF_SHR32($x , 18) & 0x07),
					0x80 | (_BF_SHR32($x , 12) & 0x3F),
					0x80 | (_BF_SHR32($x , 6 ) & 0x3F),
					0x80 | ( $x         & 0x3F));
		}
		return $output;
	}

	/*
	* Convert a raw string to an array of little-endian words
	* Characters >255 have their high-byte silently ignored.
	*/
	function rstr2binl($input) {
		for($i = 0; $i < strlen($input) * 8; $i += 8) {
			if (!isset($output[$i>>5])) $output[$i>>5] = 0;
			$output[$i>>5] |= (ord($input{$i/8}) & 0xFF) << ($i%32);
		}
		return $output;
	}
		
	/*
	* Convert an array of little-endian words to a string
	*/
	function binl2rstr($input) {
		$output = '';
		for ($i = 0; $i < count($input) * 32; $i += 8)
			$output .= chr(_BF_SHR32($input[$i>>5] , ($i % 32)) & 0xFF);
		return $output;
	}
		
	/*
	* Convert a raw string to an arbitrary string encoding
	* Set $trim to false for keeping leading zeros
	*/
	function rstr2any($input, $encoding, $trim = true) {
		$divisor = strlen($encoding);
		$remainders = Array();
		
		/* Convert to an array of 16-bit big-endian values, forming the dividend */
		// pad this
		$dividend = array_pad(array(), ceil(strlen($input) / 2), 0);
		$inp = $input; // Because Miquel is a lazy twit and didn't want to do a search and replace
		for($i = 0; $i < count($dividend); $i++) {
			$dividend[$i] = (ord($inp{$i * 2}) << 8) | ord($inp{$i * 2 + 1});
		}
		
		$full_length = ceil((float)strlen($input) * 8
			/ (log(strlen($encoding)) / log(2)));
		/*
		* Repeatedly perform a long division. The binary array forms the dividend,
		* the length of the encoding is the divisor. Once computed, the quotient
		* forms the dividend for the next step. We stop when the dividend is zero.
		* All remainders are stored for later use.
		*/
		if ($trim) {
			while(count($dividend) > 0) {
				$quotient = Array();
				$x = 0;
				for($i = 0; $i < count($dividend); $i++) {
					$x = ($x << 16) + $dividend[$i];
					$q = floor($x / $divisor);
					$x -= $q * $divisor;
					if(count($quotient) > 0 || $q > 0)
						$quotient[count($quotient)] = $q;
				}
				$remainders[count($remainders)] = $x;
				//$remainders[$j] = $x;
				$dividend = $quotient;
			}
		} else {
			for($j = 0; $j < $full_length; $j++) {
				$quotient = Array();
				$x = 0;
				for($i = 0; $i < count($dividend); $i++) {
					$x = ($x << 16) + $dividend[$i];
					$q = floor($x / $divisor);
					$x -= $q * $divisor;
					if(count($quotient) > 0 || $q > 0)
						$quotient[count($quotient)] = $q;
				}
				$remainders[$j] = $x;
				$dividend = $quotient;
			}
		}
		
		/* Convert the remainders to the output string */
		$output = "";
		for($i = count($remainders) - 1; $i >= 0; $i--)
			$output .= $encoding{$remainders[$i]};
		
		return $output;
	}

///===== big endian =====\\\

	/*
	* Convert a raw string to an array of big-endian words
	* Characters >255 have their high-byte silently ignored.
	*/
	function rstr2binb($input) {
		$output = array_pad(array(), strlen($input) >> 2, 0);
		for ($i = 0; $i < strlen($input) * 8; $i += 8) {
			if (!isset($output[$i>>5])) $output[$i>>5] = 0;
			$output[$i>>5] |= (ord($input{$i / 8}) & 0xFF) << (24 - $i %32);
		}
		return $output;
	}
		
	/*
	* Convert an array of big-endian words to a string
	*/
	function binb2rstr($input) {
		$output = '';
		for($i = 0; $i < count($input) * 32; $i += 8)
			$output .= chr(_BF_SHR32($input[$i>>5] , (24 - $i % 32)) & 0xFF);
		return $output;
	}
		
	/*
	* Bitwise rotate a 32-bit number to the left.
	*/
	function bit_rol ($num, $cnt) {
		return ($num << $cnt) | _BF_SHR32($num , (32 - $cnt));
	}
		
	/*
	* Add integers, wrapping at 2^32. This uses 16-bit operations internally
	* to work around bugs in some JS interpreters.
	*/
	function safe_add ($x, $y) {
		$lsw = ($x & 0xFFFF) + ($y & 0xFFFF);
		$msw = ($x >> 16) + ($y >> 16) + ($lsw >> 16);
		return ($msw << 16) | ($lsw & 0xFFFF);
	}
}
$PasswordMaker_HashUtils = new PasswordMaker_HashUtils;

class PasswordMaker_MD5 {
	function any_md5($s, $e, $t = true) {
		global $PasswordMaker_HashUtils;
		if (function_exists('mhash'))
			return $PasswordMaker_HashUtils->rstr2any(mhash(MHASH_MD5, $s), $e, $t);
		return $PasswordMaker_HashUtils->rstr2any(pack('H*', md5($s)), $e, $t);
	}
	
	function any_hmac_md5($k, $d, $e, $t = true) {
		global $PasswordMaker_HashUtils;
		if (function_exists('mhash'))
			return $PasswordMaker_HashUtils->rstr2any(mhash(MHASH_MD5, $d, $k), $e, $t);
		$b = 64; // byte length for md5
		if (strlen($k) > $b) {
			$k = pack("H*",md5($k));
		}
		$k  = str_pad($k, $b, chr(0x00));
		$ipad = str_pad('', $b, chr(0x36));
		$opad = str_pad('', $b, chr(0x5c));
		$ipad = $k ^ $ipad ;
		$opad = $k ^ $opad;
		return $PasswordMaker_HashUtils->rstr2any(pack('H*', md5($opad  . pack("H*",md5($ipad . $d)))), $e, $t);
	}
}
$PasswordMaker_MD5 = new PasswordMaker_MD5;

class PasswordMaker_MD4 {
	function any_hmac_md4($k, $d, $e, $t = true) {
		global $PasswordMaker_HashUtils;
		if (function_exists('mhash'))
			return $PasswordMaker_HashUtils->rstr2any(mhash(MHASH_MD4, $d, $k), $e, $t);
		return $PasswordMaker_HashUtils->rstr2any($this->rstr_hmac_md4($PasswordMaker_HashUtils->str2rstr_utf8($k), $PasswordMaker_HashUtils->str2rstr_utf8($d)), $e, $t);
	}

	function any_md4 ($s, $e, $t = true) {
		global $PasswordMaker_HashUtils;
		if (function_exists('mhash'))
			return $PasswordMaker_HashUtils->rstr2any(mhash(MHASH_MD4, $s), $e, $t);
		return $PasswordMaker_HashUtils->rstr2any($this->rstr_md4($PasswordMaker_HashUtils->str2rstr_utf8($s)), $e, $t);
	}
	
	/*
	* Calculate the MD4 of a raw string
	*/
	function rstr_md4 ($s) {
		global $PasswordMaker_HashUtils;
		return $PasswordMaker_HashUtils->binl2rstr($this->binl_md4($PasswordMaker_HashUtils->rstr2binl($s), strlen($s) * $PasswordMaker_HashUtils->chrsz));
	}
	
	/*
	* Calculate the MD4 of an array of little-endian words, and a bit length
	*/
	function binl_md4 ($x, $len) {
		global $PasswordMaker_HashUtils;
		// append padding
		$l1 = $len >> 5;
		$l2 = (_BF_SHR32(($len + 64) , 9) << 4) + 14;
		$x = array_pad($x, max($l1, $l2), 0);
		$x[$l1] |= 0x80 << ($len % 32);
		$x[$l2] = $len;
		
		$a =  1732584193;
		$b = -271733879;
		$c = -1732584194;
		$d =  271733878;
		
		for ($i = 0; $i < count($x); $i += 16) {
			$olda = $a;
			$oldb = $b;
			$oldc = $c;
			$oldd = $d;
			for ($j = 0; $j < 16; $j++) {
				if (!isset($x[$i+$j])) $x[$i+$j] = 0;
			}
			
			$a = $this->md4_ff($a, $b, $c, $d, $x[$i+ 0], 3 );
			$d = $this->md4_ff($d, $a, $b, $c, $x[$i+ 1], 7 );
			$c = $this->md4_ff($c, $d, $a, $b, $x[$i+ 2], 11);
			$b = $this->md4_ff($b, $c, $d, $a, $x[$i+ 3], 19);
			$a = $this->md4_ff($a, $b, $c, $d, $x[$i+ 4], 3 );
			$d = $this->md4_ff($d, $a, $b, $c, $x[$i+ 5], 7 );
			$c = $this->md4_ff($c, $d, $a, $b, $x[$i+ 6], 11);
			$b = $this->md4_ff($b, $c, $d, $a, $x[$i+ 7], 19);
			$a = $this->md4_ff($a, $b, $c, $d, $x[$i+ 8], 3 );
			$d = $this->md4_ff($d, $a, $b, $c, $x[$i+ 9], 7 );
			$c = $this->md4_ff($c, $d, $a, $b, $x[$i+10], 11);
			$b = $this->md4_ff($b, $c, $d, $a, $x[$i+11], 19);
			$a = $this->md4_ff($a, $b, $c, $d, $x[$i+12], 3 );
			$d = $this->md4_ff($d, $a, $b, $c, $x[$i+13], 7 );
			$c = $this->md4_ff($c, $d, $a, $b, $x[$i+14], 11);
			$b = $this->md4_ff($b, $c, $d, $a, $x[$i+15], 19);
			
			$a = $this->md4_gg($a, $b, $c, $d, $x[$i+ 0], 3 );
			$d = $this->md4_gg($d, $a, $b, $c, $x[$i+ 4], 5 );
			$c = $this->md4_gg($c, $d, $a, $b, $x[$i+ 8], 9 );
			$b = $this->md4_gg($b, $c, $d, $a, $x[$i+12], 13);
			$a = $this->md4_gg($a, $b, $c, $d, $x[$i+ 1], 3 );
			$d = $this->md4_gg($d, $a, $b, $c, $x[$i+ 5], 5 );
			$c = $this->md4_gg($c, $d, $a, $b, $x[$i+ 9], 9 );
			$b = $this->md4_gg($b, $c, $d, $a, $x[$i+13], 13);
			$a = $this->md4_gg($a, $b, $c, $d, $x[$i+ 2], 3 );
			$d = $this->md4_gg($d, $a, $b, $c, $x[$i+ 6], 5 );
			$c = $this->md4_gg($c, $d, $a, $b, $x[$i+10], 9 );
			$b = $this->md4_gg($b, $c, $d, $a, $x[$i+14], 13);
			$a = $this->md4_gg($a, $b, $c, $d, $x[$i+ 3], 3 );
			$d = $this->md4_gg($d, $a, $b, $c, $x[$i+ 7], 5 );
			$c = $this->md4_gg($c, $d, $a, $b, $x[$i+11], 9 );
			$b = $this->md4_gg($b, $c, $d, $a, $x[$i+15], 13);
			
			$a = $this->md4_hh($a, $b, $c, $d, $x[$i+ 0], 3 );
			$d = $this->md4_hh($d, $a, $b, $c, $x[$i+ 8], 9 );
			$c = $this->md4_hh($c, $d, $a, $b, $x[$i+ 4], 11);
			$b = $this->md4_hh($b, $c, $d, $a, $x[$i+12], 15);
			$a = $this->md4_hh($a, $b, $c, $d, $x[$i+ 2], 3 );
			$d = $this->md4_hh($d, $a, $b, $c, $x[$i+10], 9 );
			$c = $this->md4_hh($c, $d, $a, $b, $x[$i+ 6], 11);
			$b = $this->md4_hh($b, $c, $d, $a, $x[$i+14], 15);
			$a = $this->md4_hh($a, $b, $c, $d, $x[$i+ 1], 3 );
			$d = $this->md4_hh($d, $a, $b, $c, $x[$i+ 9], 9 );
			$c = $this->md4_hh($c, $d, $a, $b, $x[$i+ 5], 11);
			$b = $this->md4_hh($b, $c, $d, $a, $x[$i+13], 15);
			$a = $this->md4_hh($a, $b, $c, $d, $x[$i+ 3], 3 );
			$d = $this->md4_hh($d, $a, $b, $c, $x[$i+11], 9 );
			$c = $this->md4_hh($c, $d, $a, $b, $x[$i+ 7], 11);
			$b = $this->md4_hh($b, $c, $d, $a, $x[$i+15], 15);
			
			$a = $PasswordMaker_HashUtils->safe_add($a, $olda);
			$b = $PasswordMaker_HashUtils->safe_add($b, $oldb);
			$c = $PasswordMaker_HashUtils->safe_add($c, $oldc);
			$d = $PasswordMaker_HashUtils->safe_add($d, $oldd);
		}
		return array($a, $b, $c, $d);
	}
	
	/*
	* These functions implement the basic operation for each round of the
	* algorithm.
	*/
	function md4_cmn ($q, $a, $b, $x, $s, $t) {
		global $PasswordMaker_HashUtils;
		return $PasswordMaker_HashUtils->safe_add($PasswordMaker_HashUtils->bit_rol($PasswordMaker_HashUtils->safe_add($PasswordMaker_HashUtils->safe_add($a, $q), $PasswordMaker_HashUtils->safe_add($x, $t)), $s), $b);
	}
	function md4_ff ($a, $b, $c, $d, $x, $s) {
		global $PasswordMaker_HashUtils;
		return $this->md4_cmn(($b & $c) | ((~$b) & $d), $a, 0, $x, $s, 0);
	}
	function md4_gg ($a, $b, $c, $d, $x, $s) {
		global $PasswordMaker_HashUtils;
		return $this->md4_cmn(($b & $c) | ($b & $d) | ($c & $d), $a, 0, $x, $s, 1518500249);
	}
	function md4_hh ($a, $b, $c, $d, $x, $s) {
		global $PasswordMaker_HashUtils;
		return $this->md4_cmn(unsigned_xor32(unsigned_xor32($b, $c), $d), $a, 0, $x, $s, 1859775393);
	}
	
	/*
	* Calculate the HMAC-MD4 of a key and some data
	*/
	function rstr_hmac_md4 ($key, $data) {
		global $PasswordMaker_HashUtils;
		$bkey = $PasswordMaker_HashUtils->rstr2binl($key);
		if(count($bkey) > 16) $bkey = $this->binl_md4($bkey, strlen($key) * $PasswordMaker_HashUtils->chrsz);
		$bkey = array_pad($bkey, 16, 0);
		
		for ($i = 0; $i < 16; $i++) {
			$ipad[$i] = $bkey[$i] ^ 0x36363636;
			$opad[$i] = $bkey[$i] ^ 0x5C5C5C5C;
		}
		
		$hash = $this->binl_md4(array_merge($ipad, $PasswordMaker_HashUtils->rstr2binl($data)), 512 + strlen($data) * $PasswordMaker_HashUtils->chrsz);
		return $PasswordMaker_HashUtils->binl2rstr($this->binl_md4(array_merge($opad, $hash), 512 + 128));
	}
}
$PasswordMaker_MD4 = new PasswordMaker_MD4;

class PasswordMaker_RIPEMD160 {
	function any_rmd160($s, $e, $t = true) {
		global $PasswordMaker_HashUtils;
		if (function_exists('mhash'))
			return $PasswordMaker_HashUtils->rstr2any(mhash(MHASH_RIPEMD160 , $s), $e, $t);
		return $PasswordMaker_HashUtils->rstr2any($this->rstr_rmd160($PasswordMaker_HashUtils->str2rstr_utf8($s)), $e, $t);
	}
	
	function any_hmac_rmd160($k, $d, $e, $t = true) {
		global $PasswordMaker_HashUtils;
		if (function_exists('mhash'))
			return $PasswordMaker_HashUtils->rstr2any(mhash(MHASH_RIPEMD160, $d, $k), $e, $t);
		return $PasswordMaker_HashUtils->rstr2any($this->rstr_hmac_rmd160($PasswordMaker_HashUtils->str2rstr_utf8($k), $PasswordMaker_HashUtils->str2rstr_utf8($d)), $e, $t);
	}

	/*
	* Calculate the rmd160 of a raw string
	*/
	function rstr_rmd160($s) {
		global $PasswordMaker_HashUtils;
		return $PasswordMaker_HashUtils->binl2rstr($this->binl_rmd160($PasswordMaker_HashUtils->rstr2binl($s), strlen($s) * $PasswordMaker_HashUtils->chrsz));
	}
	
	/*
	* Calculate the HMAC-rmd160 of a key and some data (raw strings)
	*/
	function rstr_hmac_rmd160($key, $data) {
		global $PasswordMaker_HashUtils;
		$bkey = $PasswordMaker_HashUtils->rstr2binl($key);
		if(count($bkey) > 16) $bkey = $this->binl_md4($bkey, strlen($key) * $PasswordMaker_HashUtils->chrsz);
		$bkey = array_pad($bkey, 16, 0);
		
		for ($i = 0; $i < 16; $i++) {
			$ipad[$i] = $bkey[$i] ^ 0x36363636;
			$opad[$i] = $bkey[$i] ^ 0x5C5C5C5C;
		}
		
		$hash = $this->binl_rmd160(array_merge($ipad, $PasswordMaker_HashUtils->rstr2binl($data)), 512 + strlen($data) * 8);
		return $PasswordMaker_HashUtils->binl2rstr($this->binl_rmd160(array_merge($opad, $hash), 512 + 160));
	}
	
	/*
	* Calculate the RIPE-MD160 of an array of little-endian words, and a bit length.
	*/
	function binl_rmd160($x, $len) {
		global $PasswordMaker_HashUtils;
		// append padding
		$l1 = $len >> 5;
		$l2 = (_BF_SHR32(($len + 64), 9) << 4) + 14;
		$x = array_pad($x, max($l1, $l2), 0);
		$x[$l1] |= 0x80 << ($len % 32);
		$x[$l2] = $len;
		
		$h0 = 0x67452301;
		$h1 = 0xefcdab89;
		$h2 = 0x98badcfe;
		$h3 = 0x10325476;
		$h4 = 0xc3d2e1f0;
		
		for ($i = 0; $i < count($x); $i += 16) {
			$A1 = $h0;
			$B1 = $h1;
			$C1 = $h2;
			$D1 = $h3;
			$E1 = $h4;
			$A2 = $h0;
			$B2 = $h1;
			$C2 = $h2;
			$D2 = $h3;
			$E2 = $h4;
			$x = array_pad($x, $i + 16, 0);
			for ($j = 0; $j <= 79; ++$j) {
				$T = $PasswordMaker_HashUtils->safe_add($A1, $this->rmd160_f($j, $B1, $C1, $D1));
				$T = $PasswordMaker_HashUtils->safe_add($T, $x[$i + $this->rmd160_r1[$j]]);
				$T = $PasswordMaker_HashUtils->safe_add($T, $this->rmd160_K1($j));
				$T = $PasswordMaker_HashUtils->safe_add($PasswordMaker_HashUtils->bit_rol($T, $this->rmd160_s1[$j]), $E1);
				$A1 = $E1; $E1 = $D1; $D1 = $PasswordMaker_HashUtils->bit_rol($C1, 10); $C1 = $B1; $B1 = $T;
				$T = $PasswordMaker_HashUtils->safe_add($A2, $this->rmd160_f(79-$j, $B2, $C2, $D2));
				$T = $PasswordMaker_HashUtils->safe_add($T, $x[$i + $this->rmd160_r2[$j]]);
				$T = $PasswordMaker_HashUtils->safe_add($T, $this->rmd160_K2($j));
				$T = $PasswordMaker_HashUtils->safe_add($PasswordMaker_HashUtils->bit_rol($T, $this->rmd160_s2[$j]), $E2);
				$A2 = $E2; $E2 = $D2; $D2 = $PasswordMaker_HashUtils->bit_rol($C2, 10); $C2 = $B2; $B2 = $T;
			}
			$T = $PasswordMaker_HashUtils->safe_add($h1, $PasswordMaker_HashUtils->safe_add($C1, $D2));
			$h1 = $PasswordMaker_HashUtils->safe_add($h2, $PasswordMaker_HashUtils->safe_add($D1, $E2));
			$h2 = $PasswordMaker_HashUtils->safe_add($h3, $PasswordMaker_HashUtils->safe_add($E1, $A2));
			$h3 = $PasswordMaker_HashUtils->safe_add($h4, $PasswordMaker_HashUtils->safe_add($A1, $B2));
			$h4 = $PasswordMaker_HashUtils->safe_add($h0, $PasswordMaker_HashUtils->safe_add($B1, $C2));
			$h0 = $T;
		}
		return array($h0, $h1, $h2, $h3, $h4);
	}
	
	function rmd160_f($j, $x, $y, $z) {
		return (( 0 <= $j && $j <= 15) ? unsigned_xor32(unsigned_xor32($x, $y), $z) :
			((16 <= $j && $j <= 31) ? ($x & $y) | (~$x & $z) :
			((32 <= $j && $j <= 47) ? unsigned_xor32(($x | ~$y), $z) :
			((48 <= $j && $j <= 63) ? ($x & $z) | ($y & ~$z) :
			((64 <= $j && $j <= 79) ? unsigned_xor32($x, ($y | ~$z)) :
			"rmd160_f: j out of range")))));
	}
	
	function rmd160_K1($j) {
		return (( 0 <= $j && $j <= 15) ? 0x00000000 :
			((16 <= $j && $j <= 31) ? 0x5a827999 :
			((32 <= $j && $j <= 47) ? 0x6ed9eba1 :
			((48 <= $j && $j <= 63) ? 0x8f1bbcdc:
			((64 <= $j && $j <= 79) ? 0xa953fd4e:
			"rmd160_K1: j out of range")))));
	}
	
	function rmd160_K2($j) {
		return (( 0 <= $j && $j <= 15) ? 0x50a28be6 :
			((16 <= $j && $j <= 31) ? 0x5c4dd124 :
			((32 <= $j && $j <= 47) ? 0x6d703ef3 :
			((48 <= $j && $j <= 63) ? 0x7a6d76e9 :
			((64 <= $j && $j <= 79) ? 0x00000000 :
			"rmd160_K2: j out of range")))));
	}
	
	function PasswordMaker_RIPEMD160() {
		$this->rmd160_r1 = array(
			0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
			7,  4, 13,  1, 10,  6, 15,  3, 12,  0,  9,  5,  2, 14, 11,  8,
			3, 10, 14,  4,  9, 15,  8,  1,  2,  7,  0,  6, 13, 11,  5, 12,
			1,  9, 11, 10,  0,  8, 12,  4, 13,  3,  7, 15, 14,  5,  6,  2,
			4,  0,  5,  9,  7, 12,  2, 10, 14,  1,  3,  8, 11,  6, 15, 13
		);
		$this->rmd160_r2 = array(
			5, 14,  7,  0,  9,  2, 11,  4, 13,  6, 15,  8,  1, 10,  3, 12,
			6, 11,  3,  7,  0, 13,  5, 10, 14, 15,  8, 12,  4,  9,  1,  2,
			15,  5,  1,  3,  7, 14,  6,  9, 11,  8, 12,  2, 10,  0,  4, 13,
			8,  6,  4,  1,  3, 11, 15,  0,  5, 12,  2, 13,  9,  7, 10, 14,
			12, 15, 10,  4,  1,  5,  8,  7,  6,  2, 13, 14,  0,  3,  9, 11
		);
		$this->rmd160_s1 = array(
			11, 14, 15, 12,  5,  8,  7,  9, 11, 13, 14, 15,  6,  7,  9,  8,
			7,  6,  8, 13, 11,  9,  7, 15,  7, 12, 15,  9, 11,  7, 13, 12,
			11, 13,  6,  7, 14,  9, 13, 15, 14,  8, 13,  6,  5, 12,  7,  5,
			11, 12, 14, 15, 14, 15,  9,  8,  9, 14,  5,  6,  8,  6,  5, 12,
			9, 15,  5, 11,  6,  8, 13, 12,  5, 12, 13, 14, 11,  8,  5,  6
		);
		$this->rmd160_s2 = array(
			8,  9,  9, 11, 13, 15, 15,  5,  7,  7,  8, 11, 14, 14, 12,  6,
			9, 13, 15,  7, 12,  8,  9, 11,  7,  7, 12,  7,  6, 15, 13, 11,
			9,  7, 15, 11,  8,  6,  6, 14, 12, 13,  5, 14, 13, 13,  7,  5,
			15,  5,  8, 11, 14, 14,  6, 14,  6,  9, 12,  9, 12,  5, 15,  8,
			8,  5, 12,  9, 12,  5, 14,  6,  8, 13,  6,  5, 15, 13, 11, 11
		);
	}
	var $rmd160_r1;
	var $rmd160_r2;
	var $rmd160_s1;
	var $rmd160_s2;
}
$PasswordMaker_RIPEMD160 = new PasswordMaker_RIPEMD160;

class PasswordMaker_SHA1 {
	function any_sha1($s, $e, $t = true) {
		global $PasswordMaker_HashUtils;
		if (function_exists('mhash'))
			return $PasswordMaker_HashUtils->rstr2any(mhash(MHASH_SHA1 , $s), $e, $t);
		return $PasswordMaker_HashUtils->rstr2any(pack('H*', sha1($s)), $e, $t);
	}
	
	function any_hmac_sha1($k, $d, $e, $t = true) {
		global $PasswordMaker_HashUtils;
		if (function_exists('mhash'))
			return $PasswordMaker_HashUtils->rstr2any(mhash(MHASH_SHA1, $d, $k), $e, $t);
		$b = 64;
		if (strlen($k) > $b) {
			$k = pack('H*', sha1($k));
		}
		$k = str_pad($k, $b, chr(0x00));
		$ipad = str_pad('', $b, chr(0x36));
		$opad = str_pad('', $b, chr(0x5c));
		$ipad = $k ^ $ipad;
		$opad = $k ^ $opad;
		return $PasswordMaker_HashUtils->rstr2any(pack('H*', sha1($opad.pack('H*', sha1($ipad.$d)))), $e);
	}
}
$PasswordMaker_SHA1 = new PasswordMaker_SHA1;

class PasswordMaker_SHA256 {
	var $sha256_K;
	
	// Because there's a class array to set, here's the contrustor
	function PasswordMaker_SHA256() {
		$this->sha256_K = array(
			1116352408, 1899447441, -1245643825, -373957723, 961987163, 1508970993,
			-1841331548, -1424204075, -670586216, 310598401, 607225278, 1426881987,
			1925078388, -2132889090, -1680079193, -1046744716, -459576895, -272742522,
			264347078, 604807628, 770255983, 1249150122, 1555081692, 1996064986,
			-1740746414, -1473132947, -1341970488, -1084653625, -958395405, -710438585,
			113926993, 338241895, 666307205, 773529912, 1294757372, 1396182291,
			1695183700, 1986661051, -2117940946, -1838011259, -1564481375, -1474664885,
			-1035236496, -949202525, -778901479, -694614492, -200395387, 275423344,
			430227734, 506948616, 659060556, 883997877, 958139571, 1322822218,
			1537002063, 1747873779, 1955562222, 2024104815, -2067236844, -1933114872,
			-1866530822, -1538233109, -1090935817, -965641998
		);
	}

	function any_sha256 ($s, $e, $t = true){
		global $PasswordMaker_HashUtils;
		if (function_exists('mhash'))
			return $PasswordMaker_HashUtils->rstr2any(mhash(MHASH_SHA256 , $s), $e);
		return $PasswordMaker_HashUtils->rstr2any($this->rstr_sha256($PasswordMaker_HashUtils->str2rstr_utf8($s)), $e, $t);
	}
	
	function any_hmac_sha256 ($k, $d, $e, $t = true, $bug = true){
		global $PasswordMaker_HashUtils;
		if (function_exists('mhash') && !$bug)
			return $PasswordMaker_HashUtils->rstr2any(mhash(MHASH_SHA256, $d, $k), $e);
		return $PasswordMaker_HashUtils->rstr2any($this->rstr_hmac_sha256($PasswordMaker_HashUtils->str2rstr_utf8($k), $PasswordMaker_HashUtils->str2rstr_utf8($d), $bug), $e, $t);
	}
	
	/*
	* Calculate the sha256 of a raw string
	*/
	function rstr_sha256 ($s) {
		global $PasswordMaker_HashUtils;
		return $PasswordMaker_HashUtils->binb2rstr($this->binb_sha256($PasswordMaker_HashUtils->rstr2binb($s), strlen($s) * 8));
	}
	
	/*
	* Calculate the HMAC-sha256 of a key and some data (raw strings)
	*/
	function rstr_hmac_sha256($key, $data, $bug) {
		global $PasswordMaker_HashUtils;
		$bkey = $PasswordMaker_HashUtils->rstr2binb($key);
		if(count($bkey) > 16) $bkey = $this->binl_md4($bkey, strlen($key) * $PasswordMaker_HashUtils->chrsz);
		$bkey = array_pad($bkey, 16, 0);
		
		for ($i = 0; $i < 16; $i++) {
			$ipad[$i] = $bkey[$i] ^ 0x36363636;
			$opad[$i] = $bkey[$i] ^ 0x5C5C5C5C;
		}
		
		$hash = $this->binb_sha256(array_merge($ipad, $PasswordMaker_HashUtils->rstr2binb($data)), 512 + strlen($data) * 8);
		return $PasswordMaker_HashUtils->binb2rstr($this->binb_sha256(array_merge($opad, $hash), 512 + (($bug) ? 160 : 256))); // Is non-bug value correct?
	}
	
	/*
	* Main sha256 function, with its support functions
	*/
	function S($X, $n) {return  _BF_SHR32($X, $n ) | ($X << (32 - $n));}
	function R($X, $n) {return  _BF_SHR32($X, $n );}
	function Ch($x, $y, $z) {return unsigned_xor32(($x & $y), ((~$x) & $z));}
	function Maj($x, $y, $z) {return unsigned_xor32(unsigned_xor32(($x & $y), ($x & $z)), ($y & $z));}
	function Sigma0256($x) {return unsigned_xor32(unsigned_xor32($this->S($x, 2), $this->S($x, 13)) , $this->S($x, 22));}
	function Sigma1256($x) {return unsigned_xor32(unsigned_xor32($this->S($x, 6), $this->S($x, 11)), $this->S($x, 25));}
	function Gamma0256($x) {return unsigned_xor32(unsigned_xor32($this->S($x, 7), $this->S($x, 18)), $this->R($x, 3));}
	function Gamma1256($x) {return unsigned_xor32(unsigned_xor32($this->S($x, 17), $this->S($x, 19)), $this->R($x, 10));}
	function Sigma0512($x) {return unsigned_xor32(unsigned_xor32($this->S($x, 28), $this->S($x, 34)), $this->S($x, 39));}
	function Sigma1512($x) {return unsigned_xor32(unsigned_xor32($this->S($x, 14), $this->S($x, 18)), $this->S($x, 41));}
	function Gamma0512($x) {return unsigned_xor32(unsigned_xor32($this->S($x, 1), $this->S($x, 8)), $this->R($x, 7));}
	function Gamma1512($x) {return unsigned_xor32(unsigned_xor32($this->S($x, 19), $this->S($x, 61)), $this->R($x, 6));}
	
	function binb_sha256($m, $l) {
		global $PasswordMaker_HashUtils;
		$HASH = array(1779033703, -1150833019, 1013904242, -1521486534,
		1359893119, -1694144372, 528734635, 1541459225);
		$W = array_pad(array(), 64, 0);
		$l1 = $l >> 5;
		$l2 = (($l + 64 >> 9) << 4) + 15;
		
		// append padding
		$m = array_pad($m, max($l1, $l2), 0);
		$m[$l1] |= 0x80 << (24 - $l % 32);
		$m[$l2] = $l;
		
		for($i = 0; $i < count($m); $i += 16) {
			$a = $HASH[0];
			$b = $HASH[1];
			$c = $HASH[2];
			$d = $HASH[3];
			$e = $HASH[4];
			$f = $HASH[5];
			$g = $HASH[6];
			$h = $HASH[7];
			
			for($j = 0; $j < 64; $j++) {
				if ($j < 16) $W[$j] = $m[$j + $i];
				else $W[$j] = $PasswordMaker_HashUtils->safe_add($PasswordMaker_HashUtils->safe_add($PasswordMaker_HashUtils->safe_add($this->Gamma1256($W[$j - 2]), $W[$j - 7]),
					$this->Gamma0256($W[$j - 15])), $W[$j - 16]);
				
				$T1 = $PasswordMaker_HashUtils->safe_add($PasswordMaker_HashUtils->safe_add($PasswordMaker_HashUtils->safe_add($PasswordMaker_HashUtils->safe_add($h, $this->Sigma1256($e)), $this->Ch($e, $f, $g)),
					$this->sha256_K[$j]), $W[$j]);
				$T2 = $PasswordMaker_HashUtils->safe_add($this->Sigma0256($a), $this->Maj($a, $b, $c));
				
				$h = $g;
				$g = $f;
				$f = $e;
				$e = $PasswordMaker_HashUtils->safe_add($d, $T1);
				$d = $c;
				$c = $b;
				$b = $a;
				$a = $PasswordMaker_HashUtils->safe_add($T1, $T2);
			}
			
			$HASH[0] = $PasswordMaker_HashUtils->safe_add($a, $HASH[0]);
			$HASH[1] = $PasswordMaker_HashUtils->safe_add($b, $HASH[1]);
			$HASH[2] = $PasswordMaker_HashUtils->safe_add($c, $HASH[2]);
			$HASH[3] = $PasswordMaker_HashUtils->safe_add($d, $HASH[3]);
			$HASH[4] = $PasswordMaker_HashUtils->safe_add($e, $HASH[4]);
			$HASH[5] = $PasswordMaker_HashUtils->safe_add($f, $HASH[5]);
			$HASH[6] = $PasswordMaker_HashUtils->safe_add($g, $HASH[6]);
			$HASH[7] = $PasswordMaker_HashUtils->safe_add($h, $HASH[7]);
		}
		return $HASH;
	}

}
$PasswordMaker_SHA256 = new PasswordMaker_SHA256();
?>
