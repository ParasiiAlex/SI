<?php

include_once "AES.php";

class AESCounter
{
    public static function encrypt($textToEncrypt, $password, $nrBits)
    {
        /**
         * Marimea blocului care urmeaza a fi criptat
         * Pentru AES folosim 16 octeti
         */
        $blockSize = 16;

        /**
         * AES permite utilizarea cheilor de criptare cu dimensiuni de 128/192/256 biti.
         */
        if (!($nrBits == 128 || $nrBits == 192 || $nrBits == 256)) {
            return '';
        }

        /**
         * Folosim algoritmul AES pentru criptarea parolei cu care, mai apoi, vom cripta textul.
         */
        $nBytes = $nrBits / 8;
        $pwBytes = array();
        for ($i = 0; $i < $nBytes; $i++) {
            $pwBytes[$i] = ord(substr($password, $i, 1)) & 0xff;
        }
        $key = AES::encryptByteArray($pwBytes, AES::keyExpansion($pwBytes));
        $key = array_merge($key, array_slice($key, 0, $nBytes - 16));  // marim cheia pana la 16/24/32 de octeti

        /**
         * Avem nevoie de a initializa primii 8 octeti cu valori aleatorii, care vor fi unice pentru fiecare incercare de criptare.
         */
        $counterBlock = array();
        $nonce = floor(microtime(true) * 1000);
        $nonceMs = $nonce % 1000;
        $nonceSec = floor($nonce / 1000);
        $nonceRnd = floor(rand(0, 0xffff));

        for ($i = 0; $i < 2; $i++) {
            $counterBlock[$i] = self::unsignedRightShift($nonceMs, $i * 8) & 0xff;
        }
        for ($i = 0; $i < 2; $i++) {
            $counterBlock[$i + 2] = self::unsignedRightShift($nonceRnd, $i * 8) & 0xff;
        }
        for ($i = 0; $i < 4; $i++) {
            $counterBlock[$i + 4] = self::unsignedRightShift($nonceSec, $i * 8) & 0xff;
        }

        /**
         * Transformam din ASCII in caractere
         */
        $ctrTxt = '';
        for ($i = 0; $i < 8; $i++) {
            $ctrTxt .= chr($counterBlock[$i]);
        }

        /**
         * Generam un array din cheia cifrata, pe care-l vom folosi la criptarea textului.
         * La fiecare etapa de criptare vom folosi o anumita parte din cheie.
         */
        $keySchedule = AES::keyExpansion($key);

        $blockCount = ceil(strlen($textToEncrypt) / $blockSize);
        $ciphertxt = array();

        for ($b = 0; $b < $blockCount; $b++) {
            for ($c = 0; $c < 4; $c++) {
                $counterBlock[15 - $c] = self::unsignedRightShift($b, $c * 8) & 0xff;
            }
            for ($c = 0; $c < 4; $c++) {
                $counterBlock[15 - $c - 4] = self::unsignedRightShift($b / 0x100000000, $c * 8) & 0xff;
            }

            $cipherCntr = AES::encryptByteArray($counterBlock, $keySchedule);

            $blockLength = $b < $blockCount - 1 ? $blockSize : (strlen($textToEncrypt) - 1) % $blockSize + 1;
            $cipherByte = array();

            for ($i = 0; $i < $blockLength; $i++) {
                $cipherByte[$i] = $cipherCntr[$i] ^ ord(substr($textToEncrypt, $b * $blockSize + $i, 1));
                $cipherByte[$i] = chr($cipherByte[$i]);
            }
            $ciphertxt[$b] = implode('', $cipherByte);
        }

        $ciphertext = $ctrTxt.implode('', $ciphertxt);
        $ciphertext = base64_encode($ciphertext);

        return $ciphertext;
    }

    public static function decrypt($ciphertext, $password, $nrBits)
    {
        $blockSize = 16;
        if (!($nrBits == 128 || $nrBits == 192 || $nrBits == 256)) {
            return '';
        }
        $ciphertext = base64_decode($ciphertext);


        $nBytes = $nrBits / 8;
        $pwBytes = array();
        for ($i = 0; $i < $nBytes; $i++) {
            $pwBytes[$i] = ord(substr($password, $i, 1)) & 0xff;
        }
        $key = AES::encryptByteArray($pwBytes, AES::keyExpansion($pwBytes));
        $key = array_merge($key, array_slice($key, 0, $nBytes - 16));

        /**
         * Trebuie sa restabilim primii 8 octeti
         */
        $counterBlock = array();
        $ctrTxt = substr($ciphertext, 0, 8);
        for ($i = 0; $i < 8; $i++) {
            $counterBlock[$i] = ord(substr($ctrTxt, $i, 1));
        }

        $keySchedule = AES::keyExpansion($key);

        /**
         * Formam blocurile pentru a fi decriptate
         */
        $nBlocks = ceil((strlen($ciphertext) - 8) / $blockSize);
        $ct = array();
        for ($b = 0; $b < $nBlocks; $b++) {
            $ct[$b] = substr($ciphertext, 8 + $b * $blockSize, 16);
        }
        $ciphertext = $ct;

        /**
         * Decriptam textul.
         */
        $plaintxt = array();

        for ($b = 0; $b < $nBlocks; $b++) {
            for ($c = 0; $c < 4; $c++) {
                $counterBlock[15 - $c] = self::unsignedRightShift($b, $c * 8) & 0xff;
            }
            for ($c = 0; $c < 4; $c++) {
                $counterBlock[15 - $c - 4] = self::unsignedRightShift(($b + 1) / 0x100000000 - 1, $c * 8) & 0xff;
            }

            $cipherCntr = AES::encryptByteArray($counterBlock, $keySchedule);

            $plaintxtByte = array();
            for ($i = 0; $i < strlen($ciphertext[$b]); $i++) {
                $plaintxtByte[$i] = $cipherCntr[$i] ^ ord(substr($ciphertext[$b], $i, 1));
                $plaintxtByte[$i] = chr($plaintxtByte[$i]);
            }
            $plaintxt[$b] = implode('', $plaintxtByte);
        }

        $textToEncrypt = implode('', $plaintxt);

        return $textToEncrypt;
    }

    private static function unsignedRightShift($a, $b)
    {
        $a &= 0xffffffff;
        $b &= 0x1f;
        if ($a & 0x80000000 && $b > 0) {   // verificam daca bitul cel mai semnificativ este setat si numarul cu care facem shift este mai mare ca 0
            $a = ($a >> 1) & 0x7fffffff;   //   facem right-shift cu un bit one bit si stergem bitul cel mai semnificativ
            $a = $a >> ($b - 1);           //   scoatem ceea ce a ramas
        } else {
            $a = ($a >> $b);               //   facem right-shif in mod obisnuit cu $b pozitii
        }

        return $a;
    }
}