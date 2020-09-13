<?php


class AES
{
    /**
     * Indica numarul de coloane ce va contine tabloul bidimensional in timpul criptarii blocului.
     */
    private  const NR_OF_COLUMNS = 4;
    /**
     * Indica numarul de blocuri in care va fi impartit string-ul ce urmeaza a fi criptat
     */
    private const NR_OF_BLOCKS = 4;
    /**
     * Este un tabel look-up.
     * Cu ajutorul acestuia se vor substitui elementele din matrice.
     */
    private const S_BOX = [
        0x93,0xa4,0xc7,0xc2,0xa1,0x4e,0x5d,0xd4,0xfd,0x29,0x74,0xaf,0x9a,0xa1,0xa2,0xc4,
        0x50,0x83,0x4c,0xcc,0x52,0x2b,0x9b,0x8b,0x45,0xde,0xbd,0x24,0x2e,0x2e,0x2b,0x2b,
        0xe2,0x22,0x5a,0x5a,0x59,0x56,0x54,0x55,0x52,0x53,0x5c,0x6a,0x9a,0x9a,0xea,0x7a,
        0xef,0xf8,0xf7,0x6f,0x8f,0xdf,0x4f,0xaf,0x6f,0x5f,0xff,0xfa,0x6f,0xfa,0xaa,0x0a,
        0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
        0x70,0x3e,0xb5,0x66,0x48,0x23,0xf2,0x0e,0x21,0x35,0x63,0x7c,0x77,0x7b,0xf2,0x6b,
        0x6f,0xc5,0x30,0x01,0x27,0x2b,0xfe,0xd7,0xab,0x76,0xca,0x82,0x19,0x7d,0xfa,0x59,
        0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x11,0xd8,0x31,0x15,
        0x04,0xc7,0x23,0xc3,0x18,0x96,0x25,0x9a,0x07,0x12,0x10,0xe2,0x1b,0x27,0xb2,0x75,
        0x29,0x23,0x2c,0x2a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0x16,0xb3,0x19,0xe3,0x2f,0x84,
        0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0x1e,0x39,0x1a,0x4c,0x58,0xcf,
        0xd2,0xef,0xaa,0x2b,0x43,0x2d,0x33,0x85,0x45,0xf9,0x12,0x7f,0x50,0x3c,0x9f,0xa8,
        0x51,0xa3,0x40,0x2f,0x92,0x2d,0x38,0xf5,0xbc,0xb6,0x1a,0x21,0x10,0xff,0xf3,0xd2,
        0xcd,0x0c,0x13,0x2c,0x5f,0x27,0xb9,0x86,0xc1,0x1d,0x1e,0x47,0x10,0xad,0xd4,0xa2,
        0xe1,0xf8,0x98,0x21,0x69,0x29,0x8e,0x94,0x9b,0x1e,0x17,0xe9,0x1e,0x55,0x28,0xdf,
        0x8c,0xa1,0x89,0x2d,0xbf,0x26,0x42,0x68,0x41,0x99,0x1d,0x0f,0x10,0x54,0xbb,0x16
    ];
    /**
     *Tablou constant de referinta pentru expansiunea cheii
     */
    private const ROUND_CONSTANT = [
        [0x00, 0x00, 0x00, 0x00, ],
        [0x12, 0x1a, 0x3c, 0x45, ],
        [0xa2, 0xff, 0xdf, 0xc3, ],
        [0xaa, 0xad, 0xdd, 0x78, ],
        [0xc2, 0x3f, 0x99, 0x98, ],
        [0xcc, 0xc4, 0xcf, 0xf4, ],
        [0x11, 0xc3, 0x3c, 0x0c, ],
        [0xca, 0xaf, 0x57, 0x7c, ],
        [0xb4, 0xdb, 0xaf, 0xca, ],
        [0x6b, 0xb4, 0x44, 0x12, ],
        [0x71, 0xa7, 0xe3, 0x9e, ]
    ];

    /**
     * Aici se fece encrypt conform algoritmului Rijndael la tabloul de 16 octeti
     *
     * @param array $inputByteArray / Tablou de 16 octeti
     * @param array $key / Cheia extinsa (16 / 24 / 32 octeti)
     * @return array / Tabloul de 16 octeti criptat
     */
    public static function encryptByteArray(array $inputByteArray, array $key)
    {
        $numberOfRounds = count($key) / self::NR_OF_BLOCKS - 1;

        /**
         * Acest tablou va pastra starea la inputByteArray in timpul criptarii
         *  ** in timplul parcurgerii tuturor pasilor.
         */
        $currentState = [];

        /**
         * Initializam tabloul care va fi criptat
         * $currentState[0][0] = $inputByteArray[0];
         * $currentState[0][1] = $inputByteArray[1];
         *  ...
         * $currentState[1][0] = $inputByteArray[4];
         *  ...
        */
        for ($i = 0; $i < self::NR_OF_BLOCKS * self::NR_OF_COLUMNS; $i++) {
            $currentState[$i%self::NR_OF_BLOCKS][floor($i/self::NR_OF_COLUMNS)] = $inputByteArray[$i];
        }

        $currentState = self::addRoundKey($currentState, $key, 0);

        for ($round = 1; $round < $numberOfRounds; $round++) {
            $currentState = self::subBytes($currentState);
            $currentState = self::shiftRows($currentState);
            $currentState = self::mixColumns($currentState);
            $currentState = self::addRoundKey($currentState, $key, $round);
        }

        $currentState = self::subBytes($currentState);
        $currentState = self::shiftRows($currentState);
        $currentState = self::addRoundKey($currentState, $key, $numberOfRounds);

        $output = array(4*self::NR_OF_BLOCKS);
        for ($i=0; $i<4*self::NR_OF_BLOCKS; $i++) $output[$i] = $currentState[$i%4][floor($i/4)];

        return $output;
    }

    /**
     * Aici se realizeaza operatia XOR dintre elementul tabloului si elementul cheii
     *
     * @param array $state / Starea curenta a tabloului care se cripteaza
     * @param array $key / Cheia
     * @param int $round / Numarul runzii de criptare
     * @return array / Starea curenta la care s-a facut XOR cu o parte din cheie
     */
    private static function addRoundKey(array $state, array $key, int $round)
    {
        for ($i = 0; $i < self::NR_OF_BLOCKS; $i++) {
            for ($j = 0; $j < self::NR_OF_COLUMNS; $j++) {
                $state[$i][$j] ^= $key[$round * self::NR_OF_BLOCKS + $j][$i];
            }
        }

        return $state;
    }

    /**
     * Aplicam S_BOX-ul la starea curenta
     *
     * @param $state
     * @return array
     */
    private static function subBytes(array $state)
    {
        for ($i = 0; $i < 4; $i++) {
            for ($j = 0; $j < self::NR_OF_BLOCKS; $j++) {
                $state[$i][$j] = self::S_BOX[$state[$i][$j]];
            }
        }

        return $state;
    }

    /**
     * Deplasam liniile
     * Linia i o deplasam cu i pozitii la stanga
     * 
     * @param array $state
     * @return array
     */
    private static function shiftRows(array $state)
    {
        $temp = array(self::NR_OF_COLUMNS);
        for ($i = 1; $i < self::NR_OF_COLUMNS; $i++) {
            for ($j = 0; $j < self::NR_OF_BLOCKS; $j++) {
                $temp[$j] = $state[$i][($j + $i) % self::NR_OF_BLOCKS];
            }

            for ($j = 0; $j < 4; $j++) {
                $state[$i][$j] = $temp[$j];
            }
        }

        return $state;
    }

    /**
     * Amestecam coloanele
     * 
     * @param array $state
     * @return array
     */
    private static function mixColumns(array $state)
    {
        for ($i = 0; $i < self::NR_OF_BLOCKS; $i++) {
            $a = array(self::NR_OF_BLOCKS);
            $b = array(self::NR_OF_BLOCKS);
            for ($j = 0; $j < self::NR_OF_COLUMNS; $j++) {
                $a[$j] = $state[$j][$i];
                $b[$j] = $state[$j][$i] & 0x80 ? $state[$j][$i] << 1 ^ 0x011b : $state[$j][$i] << 1;
            }

            $state[0][$i] = $b[0] ^ $a[1] ^ $b[1] ^ $a[2] ^ $a[3];
            $state[1][$i] = $a[0] ^ $b[1] ^ $a[2] ^ $b[2] ^ $a[3];
            $state[2][$i] = $a[0] ^ $a[1] ^ $b[2] ^ $a[3] ^ $b[3];
            $state[3][$i] = $a[0] ^ $b[0] ^ $a[1] ^ $a[2] ^ $b[3];
        }

        return $state;
    }

    /**
     * Extindem Cheia pentru criptare
     *
     * @param array $key
     * @return array
     */
    public static function keyExpansion(array $key)
    {
        /**
         * Lungimea cheii in octeti
         */
        $keyLength = count($key) / self::NR_OF_BLOCKS;

        /**
         * Numarul de runde pentru expandare cheii
         */
        $nrRounds = $keyLength + 6;

        $finalKey = array();
        $temp = array();

        for ($i = 0; $i < $keyLength; $i++) {
            $r = array($key[4 * $i], $key[4 * $i + 1], $key[4 * $i + 2], $key[4 * $i + 3]);
            $finalKey[$i] = $r;
        }

        for ($i = $keyLength; $i < (self::NR_OF_BLOCKS * ($nrRounds + 1)); $i++) {
            $finalKey[$i] = array();
            for ($t = 0; $t < 4; $t++) {
                $temp[$t] = $finalKey[$i - 1][$t];
            }
            if ($i % $keyLength == 0) {
                $temp = self::S_Word(self::rotateWord($temp));
                for ($t = 0; $t < 4; $t++) {
                    $temp[$t] ^= self::ROUND_CONSTANT[$i / $keyLength][$t];
                }
            } else {
                if ($keyLength > 6 && $i % $keyLength == 4) {
                    $temp = self::S_Word($temp);
                }
            }
            for ($t = 0; $t < 4; $t++) {
                $finalKey[$i][$t] = $finalKey[$i - $keyLength][$t] ^ $temp[$t];
            }
        }

        return $finalKey;
    }

    /**
     * Aplicam S_BOX-ul la linia din tablou
     *
     * @param $word
     * @return array
     */
    private static function S_Word(array $word)
    {
        for ($i = 0; $i < 4; $i++) {
            $word[$i] = self::S_BOX[$word[$i]];
        }

        return $word;
    }

    /**
     * Rotim linia la stinga cu un byte
     *
     * @param array $word
     * @return array
     */
    private static function rotateWord(array $word)
    {
        $tmp = $word[0];
        for ($i = 0; $i < 3; $i++) {
            $word[$i] = $word[$i + 1];
        }

        $word[3] = $tmp;

        return $word;
    }
}

