/*
    1. KeyExpansion—round keys are derived from the cipher key using Rijndael's key schedule. AES requires a separate 128-bit round key block for each round plus one more.

    2. Initial round key addition:
        2.1 AddRoundKey—each byte of the state is combined with a block of the round key using bitwise xor.

    3. 9 rounds:
        3.1 SubBytes—a non-linear substitution step where each byte is replaced with another according to a lookup table.
        3.2 ShiftRows—a transposition step where the last three rows of the state are shifted cyclically a certain number of steps.
        3.3 MixColumns—a linear mixing operation which operates on the columns of the state, combining the four bytes in each column.
        3.4 AddRoundKey

    4. Final round (making 10 rounds in total):
        4.1 SubBytes
        4.2 ShiftRows
        4.3 AddRoundKey

    Links:
        https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
        https://ipfs.io/ipfs/QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco/wiki/Rijndael_mix_columns.html
        https://www.youtube.com/watch?v=gP4PqVGudtg
        https://kavaliro.com/wp-content/uploads/2014/03/AES.pdf
*/

package com.company;

import java.util.ArrayList;
import java.util.List;

import static com.company.Const.*;

class Aes {
    private static short[] text = new short[16];
    private static short[] key = new short[16];
    private static List<short[]> partialKeys = new ArrayList<>();

    // ENCRYPTION
    public static String encrypt(String strKey, String strText) {
        key = stringToMatrix(strKey.toCharArray());
        text = stringToMatrix(strText.toCharArray());

        addRoundKey(key);

        for (int i = 0; i < 9; i++) {
            subBytes();
            shiftRows();
            mixColumns();
            keyExpansion(i);
            addRoundKey(key);
        }

        subBytes();
        shiftRows();
        keyExpansion(9);
        addRoundKey(key);

        return toHexLine(text);
    }

    private static void keyExpansion(int rconIndex) {
        // w3; w3 shifted; w3 -> s-box; w3 ^ rcon
        short[] w3 = {
                (short) (Const.sBox[key[7]] ^ Const.rcon[rconIndex]),
                Const.sBox[key[11]],
                Const.sBox[key[15]],
                Const.sBox[key[3]]
        };

        // round key calculation
        for (int i = 0; i < 4; i++) {
            w3[0] = key[i] ^= w3[0];
            w3[1] = key[i + 4] ^= w3[1];
            w3[2] = key[i + 8] ^= w3[2];
            w3[3] = key[i + 12] ^= w3[3];
        }
    }

    private static void subBytes() {
        for (int i = 0; i < 16; i++) {
            text[i] = sBox[text[i]];
        }
    }

    private static void shiftRows() {
        short[] tmp = new short[16];

        tmp[0] = text[0];
        tmp[1] = text[1];
        tmp[2] = text[2];
        tmp[3] = text[3];

        tmp[4] = text[5];
        tmp[5] = text[6];
        tmp[6] = text[7];
        tmp[7] = text[4];

        tmp[8] = text[10];
        tmp[9] = text[11];
        tmp[10] = text[8];
        tmp[11] = text[9];

        tmp[12] = text[15];
        tmp[13] = text[12];
        tmp[14] = text[13];
        tmp[15] = text[14];

        text = tmp.clone();
    }

    private static void mixColumns() {
        short[] tmp = new short[16];

        tmp[0] = (short) (mul2[text[0]] ^ mul3[text[4]] ^ text[8] ^ text[12]);
        tmp[1] = (short) (mul2[text[1]] ^ mul3[text[5]] ^ text[9] ^ text[13]);
        tmp[2] = (short) (mul2[text[2]] ^ mul3[text[6]] ^ text[10] ^ text[14]);
        tmp[3] = (short) (mul2[text[3]] ^ mul3[text[7]] ^ text[11] ^ text[15]);

        tmp[4] = (short) (text[0] ^ mul2[text[4]] ^ mul3[text[8]] ^ text[12]);
        tmp[5] = (short) (text[1] ^ mul2[text[5]] ^ mul3[text[9]] ^ text[13]);
        tmp[6] = (short) (text[2] ^ mul2[text[6]] ^ mul3[text[10]] ^ text[14]);
        tmp[7] = (short) (text[3] ^ mul2[text[7]] ^ mul3[text[11]] ^ text[15]);

        tmp[8] = (short) (text[0] ^ text[4] ^ mul2[text[8]] ^ mul3[text[12]]);
        tmp[9] = (short) (text[1] ^ text[5] ^ mul2[text[9]] ^ mul3[text[13]]);
        tmp[10] = (short) (text[2] ^ text[6] ^ mul2[text[10]] ^ mul3[text[14]]);
        tmp[11] = (short) (text[3] ^ text[7] ^ mul2[text[11]] ^ mul3[text[15]]);

        tmp[12] = (short) (mul3[text[0]] ^ text[4] ^ text[8] ^ mul2[text[12]]);
        tmp[13] = (short) (mul3[text[1]] ^ text[5] ^ text[9] ^ mul2[text[13]]);
        tmp[14] = (short) (mul3[text[2]] ^ text[6] ^ text[10] ^ mul2[text[14]]);
        tmp[15] = (short) (mul3[text[3]] ^ text[7] ^ text[11] ^ mul2[text[15]]);

        text = tmp.clone();
    }

    private static void addRoundKey(short[] key) {
        for (int i = 0; i < 16; i++) {
            text[i] ^= key[i];
        }
    }

    // DECRYPTION
    public static String decrypt(String strKey, String strHexText) {
        key = stringToMatrix(strKey.toCharArray());
        text = stringToMatrix(hexStrToCharArr(strHexText));

        generateKeys();

        addRoundKey(partialKeys.get(10));
        invShiftRows();
        invSubBytes();

        for(int i = 9; i>= 1; i--) {
            addRoundKey(partialKeys.get(i));
            invMixColumns();
            invShiftRows();
            invSubBytes();
        }

        addRoundKey(partialKeys.get(0));

        return toTextLine(text);
    }

    private static void generateKeys() {
        partialKeys.add(key.clone());
        for (int i = 0; i < 10; i++) {
            keyExpansion(i);
            partialKeys.add(key.clone());
        }
    }

    private static void invSubBytes() {
        for (int i = 0; i < 16; i++) {
            text[i] = invSBox[text[i]];
        }
    }

    private static void invShiftRows() {
        short[] tmp = new short[16];

        tmp[0] = text[0];
        tmp[1] = text[1];
        tmp[2] = text[2];
        tmp[3] = text[3];

        tmp[4] = text[7];
        tmp[5] = text[4];
        tmp[6] = text[5];
        tmp[7] = text[6];

        tmp[8] = text[10];
        tmp[9] = text[11];
        tmp[10] = text[8];
        tmp[11] = text[9];

        tmp[12] = text[13];
        tmp[13] = text[14];
        tmp[14] = text[15];
        tmp[15] = text[12];

        text = tmp.clone();
    }

    private static void invMixColumns() {
        short[] tmp = new short[16];

        tmp[0] = (short) (mul14[text[0]] ^ mul11[text[4]] ^ mul13[text[8]] ^ mul9[text[12]]);
        tmp[1] = (short) (mul14[text[1]] ^ mul11[text[5]] ^ mul13[text[9]] ^ mul9[text[13]]);
        tmp[2] = (short) (mul14[text[2]] ^ mul11[text[6]] ^ mul13[text[10]] ^ mul9[text[14]]);
        tmp[3] = (short) (mul14[text[3]] ^ mul11[text[7]] ^ mul13[text[11]] ^ mul9[text[15]]);

        tmp[4] = (short) (mul9[text[0]] ^ mul14[text[4]] ^ mul11[text[8]] ^ mul13[text[12]]);
        tmp[5] = (short) (mul9[text[1]] ^ mul14[text[5]] ^ mul11[text[9]] ^ mul13[text[13]]);
        tmp[6] = (short) (mul9[text[2]] ^ mul14[text[6]] ^ mul11[text[10]] ^ mul13[text[14]]);
        tmp[7] = (short) (mul9[text[3]] ^ mul14[text[7]] ^ mul11[text[11]] ^ mul13[text[15]]);

        tmp[8] = (short) (mul13[text[0]] ^ mul9[text[4]] ^ mul14[text[8]] ^ mul11[text[12]]);
        tmp[9] = (short) (mul13[text[1]] ^ mul9[text[5]] ^ mul14[text[9]] ^ mul11[text[13]]);
        tmp[10] = (short) (mul13[text[2]] ^ mul9[text[6]] ^ mul14[text[10]] ^ mul11[text[14]]);
        tmp[11] = (short) (mul13[text[3]] ^ mul9[text[7]] ^ mul14[text[11]] ^ mul11[text[15]]);

        tmp[12] = (short) (mul11[text[0]] ^ mul13[text[4]] ^ mul9[text[8]] ^ mul14[text[12]]);
        tmp[13] = (short) (mul11[text[1]] ^ mul13[text[5]] ^ mul9[text[9]] ^ mul14[text[13]]);
        tmp[14] = (short) (mul11[text[2]] ^ mul13[text[6]] ^ mul9[text[10]] ^ mul14[text[14]]);
        tmp[15] = (short) (mul11[text[3]] ^ mul13[text[7]] ^ mul9[text[11]] ^ mul14[text[15]]);

        text = tmp.clone();
    }

    // UTILS
    private static String toHexLine(short[] array) {
        StringBuilder line = new StringBuilder();
        for (int j = 0; j < 4; j++) {
            for (int i = 0; i < 16; i += 4) {
                line.append(String.format("%02x", array[i + j])).append(" ");
            }
        }
        return line.toString();
    }

    private static String toTextLine(short[] array) {
        StringBuilder line = new StringBuilder();
        for (int j = 0; j < 4; j++) {
            for (int i = 0; i < 16; i += 4) {
                line.append((char) array[i + j]);
            }
        }
        return line.toString();
    }

    private static short[] stringToMatrix(char[] string) {
        string = cropArray(string);
        short[] array = new short[16];

        int k = 0;
        for (int j = 0; j < 4; j++) {
            for (int i = 0; i < 16; i += 4, k++) {
                array[k] = (short) string[i + j];
            }
        }

        return array;
    }

    private static char[] cropArray(char[] string) {
        char[] chars = new char[16];
        int len = string.length < 16 ? string.length : 16;
        System.arraycopy(string, 0, chars, 0, len);

        return chars;
    }

    private static char[] hexStrToCharArr(String hexText) {
        List<String> strNumbers = new ArrayList<>();
        char[] charArr = new char[16];

        hexText = hexText.replaceAll("\\s+","");

        for (int i = 0; i < hexText.length(); i+=2) {
            strNumbers.add(hexText.substring(i, i+ 2));
        }

        for (int i = 0; i < 16; i++) {
            charArr[i] = (char) Short.parseShort(strNumbers.get(i), 16);
        }

        return charArr;
    }
}
