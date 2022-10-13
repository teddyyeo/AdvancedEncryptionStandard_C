//2022 KU SMRT Assignment for ModernCrypto
#include "lookup.h"
#include <stdint.h>

typedef uint8_t AES_STATE_t[16];
typedef uint8_t AES128_KEY_t[16];
typedef uint8_t AES192_KEY_t[24];
typedef uint8_t AES256_KEY_t[32];
//Student Number & Name
char SUBMISSION_INFO[256] = "2021350010_여태욱";

//Prints state as hexadecimal
//Used for debugging
void print_state(AES_STATE_t P)
{
	for (int i = 0; i < 16; i++)
	{
		if (i%4 ==0)
			printf(" ");
		printf("%02x", P[i]);
	}
	puts("");
}

//XOR state with round key
void AddRoundKey(AES_STATE_t P, AES128_KEY_t K)
{
	for (int i = 0; i < 16; i++)
		P[i] = P[i] ^ K[i];
}

//Subtitution with sbox
void SubBytes(AES_STATE_t P)
{
	for (int i = 0; i < 16; i++)
		P[i] = sBox[P[i]];
}

//Inverse of SubBytes, using inverse sbox
void invSubBytes(AES_STATE_t P)
{
	for (int i = 0; i < 16; i++)
		P[i] = inv_sBox[P[i]];
}

//Used in KeyExpansion, subtitute word(4byte) by byte
unsigned int SubByteWord(uint32_t word)
{
	uint32_t ret = 0;
	for (int i = 0; i < 4; i++)
	{
		ret = ret << 8;
		ret = ret | sBox[(word >> (3-i)*8) & 0xFF];
	}
	return (ret);
}

//Shift state by row, implemented with lookup table(see lookup.h)
void ShiftRows(AES_STATE_t P)
{
	AES_STATE_t temp = {0,};
	for (int i = 0; i < 16; i++)
		temp[i] = P[i];
	for (int i = 0; i < 16; i++)
		P[i] = temp[shift[i]];
}

//inverse of shiftRows
void invShiftRows(AES_STATE_t P)
{
	AES_STATE_t temp = {0,};
	for (int i = 0; i < 16; i++)
		temp[i] = P[i];
	for (int i = 0; i < 16; i++)
		P[i] = temp[invShift[i]];
}

//MiXColunm, implemented with lookup table for speed
void MixCol(AES_STATE_t P)
{
	unsigned char temp[4] = {0,};

	for (int i = 0; i < 13; i += 4)
	{
		temp[0] = mul2[P[0 + i]] ^ mul3[P[1 + i]] ^      P[2 + i]  ^      P[3 + i];
		temp[1] =      P[0 + i]  ^ mul2[P[1 + i]] ^ mul3[P[2 + i]] ^      P[3 + i];
		temp[2] =      P[0 + i]  ^      P[1 + i]  ^ mul2[P[2 + i]] ^ mul3[P[3 + i]];
		temp[3] = mul3[P[0 + i]] ^      P[1 + i]  ^      P[2 + i]  ^ mul2[P[3 + i]];
		for (int j = 0; j < 4; j++)
			P[j + i] = temp[j];
	}
}

//Inverse of MiXColumn
void invMixCol(AES_STATE_t P)
{
	unsigned char temp[4] = {0,};

	for (int i = 0; i < 13; i += 4)
	{
		temp[0] = mul14[P[0 + i]] ^ mul11[P[1 + i]] ^ mul13[P[2 + i]] ^  mul9[P[3 + i]];
		temp[1] =  mul9[P[0 + i]] ^ mul14[P[1 + i]] ^ mul11[P[2 + i]] ^ mul13[P[3 + i]];
		temp[2] = mul13[P[0 + i]] ^  mul9[P[1 + i]] ^ mul14[P[2 + i]] ^ mul11[P[3 + i]];
		temp[3] = mul11[P[0 + i]] ^ mul13[P[1 + i]] ^  mul9[P[2 + i]] ^ mul14[P[3 + i]];
		for (int j = 0; j < 4; j++)
			P[j + i] = temp[j];
	}
}

//Rotation for KeyExpansion
unsigned int Rot(uint32_t key)
{
	uint32_t temp = key >> (3 * 8);
	key = key << 8;
	key = key | temp;
	return (key);
}

//Use in Key Expansion, take byte array of 4 and assign it to uint
uint32_t byte2word(uint8_t byte[])
{
	uint32_t ret = 0;
	for (int i = 0; i < 4; i++)
	{
		ret = ret << 8;
		ret = ret | byte[i];
	}
	return (ret);
}

//KeyExpansion, take Key, array of words, and Nk
void KeyExpand(unsigned char key[], unsigned int wordSet[], char Nk)
{
	unsigned int temp;
	for (int i = 0; i < Nk; i++)
		wordSet[i] = byte2word(&key[4*i]);;
	for (int i = Nk; i < 4 * (Nk + 7); i++)
	{
		temp = wordSet[i - 1];
		if (i % Nk == 0)
			temp = SubByteWord(Rot(temp)) ^ (rcon[i / Nk] << (24));
		wordSet[i] = wordSet[i - Nk] ^ temp;
	}
}

//KeyExapansion for 256bit key
//Although mostly the same with 128, 192bit key, it is separated
//If it is not a independent function, there will be a conditional statement
// in every loop of KeyExpansion checking for (Nk <= 6)
//This would make the program slower, hence the separation
void KeyExpand256(unsigned char key[], unsigned int wordSet[], char Nk)
{
	unsigned int temp;
	for (int i = 0; i < Nk; i++)
		wordSet[i] = byte2word(&key[4*i]);;
	for (int i = Nk; i < 4 * (Nk + 7); i++)
	{
		temp = wordSet[i - 1];
		if (i % Nk == 0)
			temp = SubByteWord(Rot(temp)) ^ (rcon[i / Nk] << (24));
		else if (i % Nk == 4)
			temp = SubByteWord(temp);
		wordSet[i] = wordSet[i - Nk] ^ temp;
	}
}

//Takes a word set and format it to a array of keys(16 byte char array)
void word2key(uint32_t wordSet[], AES128_KEY_t keySet[], uint8_t Nk)
{
	for (int j = 0; j < Nk; j++)
	{
		for (int i = 0; i < 16; i++)
			keySet[j][i] = (wordSet[i/4 + j*4] >> ((3 - (i%4)) * 8)) & 0xFF;
	}
}

//Encryption for 128bit key
AES128_KEY_t keySet128[11] = {{0,},};
void AES128_enc(AES_STATE_t C, AES_STATE_t P, AES128_KEY_t K128)
{
	//Initialize a wordSet to store the expanded key
	uint32_t wordSet[44] = {0,};
	KeyExpand(K128, wordSet, 4);

	//Initialize a keySet to store the foramtted keys
	word2key(wordSet, keySet128, 11);

	//Copy plaintext P into C
	for (int i = 0; i < 16; i++)
		C[i] = P[i];

	//Initial AddRoundKey with the first key
	AddRoundKey(C, keySet128[0]);

	//9 rounds of SubBytes -> ShiftRow -> MixColumn -> AddRoundKey
	for (int i = 1; i < 10; i++)
	{
		SubBytes(C);
		ShiftRows(C);
		MixCol(C);
		AddRoundKey(C, keySet128[i]);
	}

	//Final round without the MixColumn
	SubBytes(C);
	ShiftRows(C);
	AddRoundKey(C, keySet128[10]);
}

//Decryption for 128bit key
void AES128_dec(AES_STATE_t P, AES_STATE_t C, AES128_KEY_t K128)
{
	//Expanded key set is already calculated at encryption
	AddRoundKey(C, keySet128[10]);

	//Using inverse functions, 9 rounds of inverse
	for (int i = 9; i > 0; i--)
	{
		invShiftRows(C);
		invSubBytes(C);
		AddRoundKey(C, keySet128[i]);
		invMixCol(C);
	}

	//final round without mixCol
	invShiftRows(C);
	invSubBytes(C);
	AddRoundKey(C, keySet128[0]);

	for (int i = 0; i < 16; i++)
		P[i] = C[i];
}



AES128_KEY_t keySet192[13] = {{0,},};
void AES192_enc(AES_STATE_t C, AES_STATE_t P, AES192_KEY_t K192)
{
	uint32_t wordSet[56] = {0,};
	KeyExpand(K192, wordSet, 6);

	word2key(wordSet, keySet192, 13);

	for (int i = 0; i < 16; i++)
		C[i] = P[i];

	AddRoundKey(C, keySet192[0]);
	for (int i = 1; i < 12; i++)
	{
		SubBytes(C);
		ShiftRows(C);
		MixCol(C);
		AddRoundKey(C, keySet192[i]);
	}
	SubBytes(C);
	ShiftRows(C);
	AddRoundKey(C, keySet192[12]);
}


void AES192_dec(AES_STATE_t P, AES_STATE_t C, AES192_KEY_t K192)
{
	AddRoundKey(C, keySet192[12]);
	for (int i = 11; i > 0; i--)
	{
		invShiftRows(C);
		invSubBytes(C);
		AddRoundKey(C, keySet192[i]);
		invMixCol(C);
	}
	invShiftRows(C);
	invSubBytes(C);
	AddRoundKey(C, keySet192[0]);

	for (int i = 0; i < 16; i++)
		P[i] = C[i];
}

AES128_KEY_t keySet256[15] = {{0,},};
void AES256_enc(AES_STATE_t C, AES_STATE_t P, AES256_KEY_t K256)
{
	uint32_t wordSet[68] = {0,};
	KeyExpand256(K256, wordSet, 8);

	word2key(wordSet, keySet256, 15);

	for (int i = 0; i < 16; i++)
		C[i] = P[i];
	AddRoundKey(C, keySet256[0]);
	for (int i = 1; i < 14; i++)
	{
		SubBytes(C);
		ShiftRows(C);
		MixCol(C);
		AddRoundKey(C, keySet256[i]);
	}
	SubBytes(C);
	ShiftRows(C);
	AddRoundKey(C, keySet256[14]);
}


void AES256_dec(AES_STATE_t P, AES_STATE_t C, AES256_KEY_t K256)
{
	AddRoundKey(C, keySet256[14]);
	for (int i = 13; i > 0; i--)
	{
		invShiftRows(C);
		invSubBytes(C);
		AddRoundKey(C, keySet256[i]);
		invMixCol(C);
	}
	invShiftRows(C);
	invSubBytes(C);
	AddRoundKey(C, keySet256[0]);

	for (int i = 0; i < 16; i++)
		P[i] = C[i];
}
