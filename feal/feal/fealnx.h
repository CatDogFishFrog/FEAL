#pragma once

#include<cstdlib>
#include<memory>
#include <cstring>
#include <iostream>
#include<fstream>
using namespace std;
#define S0(x,y)Rot2((x)+(y))
#define S1(x,y)Rot2((x)+(y)+1)
const char CHIPPER_NAME[] = "FEAL-NX";
typedef struct {
	 int NRounds;
	unsigned char *KSchedule;
} *KeyScheduleType;

enum eChipperMode
{
	ecb,

};
typedef unsigned char DataBlockType[8];

class Feal{
public:
	KeyScheduleType NewKeySchedule(int Rounds, unsigned char *Key);
	void Encrypt(KeyScheduleType K, DataBlockType Plain);
	void Decrypt(KeyScheduleType K, DataBlockType Cipher);
	};
	
	struct sCryptorHeader
	{
		char chipperName[16];
		eChipperMode mode;
		long long fileLen;
		sCryptorHeader(char *cName, eChipperMode eMode, long long files);
		sCryptorHeader() {}
	};
	class cController {
	private:
		Feal crypt;
		int GetByteOfText(unsigned char *buf, ifstream &file);
		long long GetFileSize(ifstream &file);
	public:
		long long encrypt(unsigned char key[16], string src_filename, string dst_filename, eChipperMode cryptMode = ecb);
		long long decrypt(unsigned char key[16], string src_filename, string dst_filename);
	};