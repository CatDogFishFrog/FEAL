
#include "fealnx.h"

sCryptorHeader::sCryptorHeader(char *cName, eChipperMode eMode, long long files) {
	strcpy_s(chipperName, cName);
	mode = eMode;
	fileLen = files;
}

long long cController::GetFileSize(ifstream &file) {
	streamoff begin, end;
	long long size;
	begin = file.tellg();
	file.seekg(0, ios::end);
	end = file.tellg();
	size = end - begin;
	file.seekg(0, ios::beg);
	return size;
}

int cController::GetByteOfText(unsigned char *buf, ifstream &file) {
	int count = 0;
	char buf1;
	unsigned char currBytes[10] = "\0";
	while ((!file.eof()) && (count <  8)) {
		file.get(buf1);
		if (!file.eof()) {
			currBytes[count] = (unsigned char)buf1;
			count++;
		}
	}
	if (count == 0)
		return 0;
	if (count != 8) {
		srand(rand());
		while (count < 8) {
			currBytes[count] = unsigned char(rand() % 256);
			count++;
		}
	}
	for (int i = 0; i < 8; i++)
		buf[i] = currBytes[i];
	return 1;
}

long long cController::encrypt(unsigned char key[16], string src_filename, string dst_filename, eChipperMode cryptMode) {
	ifstream iSrcFile(src_filename.c_str(), ios::in | ios::_Nocreate | ios::binary);
	if (!iSrcFile) {
		throw "Исходного файла не существует!";
	}
	long long llFileSize = GetFileSize(iSrcFile);
	ofstream oDestFile(dst_filename.c_str(), ios::out | ios::binary);
	if (!oDestFile) {
		iSrcFile.close();
		throw "Невозможно создать файл для записи!";
	}
	unsigned char bTextBlock[100] = "\0";
	sCryptorHeader schHeader(const_cast<char*>(CHIPPER_NAME), cryptMode, llFileSize);
	oDestFile.write((char*)&schHeader, sizeof(schHeader));
	unsigned char KeyForEncrypt[16];
	for (int i = 0; i < 16; i++) {
		KeyForEncrypt[i] = key[i];
	}
	KeyScheduleType lc;
	while (iSrcFile) {
		if (GetByteOfText(bTextBlock, iSrcFile)) {
			lc= crypt.NewKeySchedule(32, KeyForEncrypt);
			crypt.Encrypt(lc, bTextBlock);
			oDestFile.write((const char*)bTextBlock, 8);
		}
	}
	iSrcFile.close();
	oDestFile.close();
	return llFileSize;
}


long long cController::decrypt(unsigned char key[16], string src_filename, string dst_filename) {
	ifstream iSrcFile(src_filename.c_str(), ios::in | ios::_Nocreate | ios::binary);
	if (!iSrcFile) {
		throw "Исходного файла не существует!";
	}
	sCryptorHeader schHeader;
	iSrcFile.read((char*)&schHeader, sizeof(schHeader));
	if (strcmp(schHeader.chipperName, CHIPPER_NAME) != 0) {
		iSrcFile.close();
		throw "Невозможно расшифровать криптограмму, использовался другой шифр!";
	}
	ofstream oDestFile(dst_filename.c_str(), ios::out | ios::binary);
	if (!oDestFile) {
		iSrcFile.close();
		throw "Невозможно создать файл для записи!";
	}
	unsigned char bTextBlock[100] = "\0", KeyForDecrypt[16];
	long long size = 0;
	for (int i = 0; i < 16; i++) {
		KeyForDecrypt[i] = key[i];
	}
	KeyScheduleType lc;
	while (!iSrcFile.eof()) {
		if (GetByteOfText(bTextBlock, iSrcFile)) {
			lc = crypt.NewKeySchedule(32, KeyForDecrypt);
			crypt.Encrypt(lc, bTextBlock);
			for (int i = 0; i < (8) && size < schHeader.fileLen; i++) {
				oDestFile.put(bTextBlock[i]);
				size++;
			}
		}
	}
	iSrcFile.close();
	oDestFile.close();
	return schHeader.fileLen;
}

void CalcFk(unsigned char Output[4], unsigned char Alpha[4],
	unsigned char Beta[4])
{
	unsigned char t1, t2;
	unsigned char Rot2(int A);

	t1 = Alpha[0] ^ Alpha[1];
	t2 = Alpha[2] ^ Alpha[3];
	t1 = S1(t1, t2 ^ Beta[0]);
	t2 = S0(t2, t1 ^ Beta[1]);
	Output[1] = t1;
	Output[2] = t2;
	Output[0] = S0(Alpha[0], t1 ^ Beta[2]);
	Output[3] = S1(Alpha[3], t2 ^ Beta[3]);
}

void  Feal ::Decrypt(KeyScheduleType K, DataBlockType Cipher)
{
	int Rounds;
	int i;
	unsigned char L[4], R[4], NewR[4];
	unsigned char *KP;
	unsigned char *Xor4(unsigned char A[4], unsigned char B[4]);
	unsigned char *F(unsigned char K[2], unsigned char R[4]);

	Rounds = K->NRounds;
	KP = K->KSchedule + 2 * Rounds;
	memmove(Xor4(KP + 8, Cipher), L, 4);
	memmove(Xor4(L, Xor4(KP + 12, Cipher + 4)), R, 4);
	for (i = 0; i < Rounds; ++i)
	{
		KP -= 2;
		memmove(Xor4(L, F(KP, R)), NewR, 4);
		memmove(R, L, 4);
		memmove(NewR, R, 4);
	}  
	KP = K->KSchedule + 2 * Rounds;
	memmove(Xor4(KP, R), Cipher, 4);
	memmove(Xor4(KP + 4, Xor4(R, L)), Cipher + 4, 4);
}

void  Feal:: Encrypt(KeyScheduleType K, DataBlockType Plain)
{
	int Rounds;
	int i;
	unsigned char L[4], R[4], NewR[4];
	unsigned char *KP;
	unsigned char *Xor4(unsigned char A[4], unsigned char B[4]);
	unsigned char *F(unsigned char K[2], unsigned char R[4]);

	KP = K->KSchedule;
	Rounds = K->NRounds;
	memmove(Xor4(KP + 2 * Rounds, Plain), L, 4);
	memmove(Xor4(L, Xor4(KP + 2 * Rounds + 4, Plain + 4)), R, 4);
	for (i = 0; i < Rounds; ++i, KP += 2)
	{
		memmove(Xor4(L, F(KP, R)), NewR, 4);
		memmove(R, L, 4);
		memmove(NewR, R, 4);
	}  
	memmove(Xor4(KP + 8, R), Plain, 4);
	memmove(Xor4(KP + 12, Xor4(R, L)), Plain + 4, 4);
}

unsigned char *F(unsigned char Beta[2], unsigned char Alpha[4])
{
	unsigned char t1, t2;
	static unsigned char Result[4];
	unsigned char Rot2(int A);

	t1 = Alpha[0] ^ Alpha[1] ^ Beta[0];
	t2 = Alpha[2] ^ Alpha[3] ^ Beta[1];
	t1 = S1(t1, t2);
	t2 = S0(t2, t1);
	Result[1] = t1;
	Result[2] = t2;
	Result[0] = S0(t1, Alpha[0]);
	Result[3] = S1(t2, Alpha[3]);
	return Result;
}

KeyScheduleType  Feal:: NewKeySchedule(int Rounds, unsigned char *Key)
{
	KeyScheduleType Result;
	int Step;
	unsigned char *KSP;
	unsigned char a[4], b[4], c[4], d[4];
	void CalcFk(unsigned char Output[4], unsigned char In1[4],
		unsigned char In2[4]);
	unsigned char *Xor4(unsigned char A[4], unsigned char B[4]);

	Result = (KeyScheduleType)malloc((sizeof(Result) + Rounds + 8) * 2);
	if (Result != NULL)
	{
		Result->NRounds = Rounds;
		Result->KSchedule = (unsigned char *)(Result + 1);
		memcpy(a, Key, 4);
		memcpy(b, Key + 4, 4);
		memcpy(c, Xor4(Key + 8, Key + 12), 4);
		memset(d, 0, 4);
		KSP = Result->KSchedule;
		for (Step = 0; Step < Rounds / 2 + 4; ++Step, KSP += 4)
		{
			switch (Step % 3)
			{
			case 0:
				CalcFk(KSP, a, Xor4(d, Xor4(b, c)));
				break;

			case 1:
				CalcFk(KSP, a, Xor4(d, Xor4(b, Key + 8)));
				break;

			case 2:
				CalcFk(KSP, a, Xor4(d, Xor4(b, Key + 12)));
				break;
			}
			memcpy(d, a, 4);
			memcpy(a, b, 4);
			memcpy(b, KSP, 4);
		}
	}
	return Result;
}

unsigned char Rot2(int X)
{
	 int First = 1;
	 unsigned char Result[256];

	if (First)
	{
		int i;

		for (i = 0; i < 256; ++i)
			Result[i] = (i << 2) + (i >> 6);
		First = 0;
	}

	return Result[X & 0xFF];
}

unsigned char *Xor4(unsigned char A[4], unsigned char B[4])

{
	static unsigned char Result[4];

	Result[0] = A[0] ^ B[0];
	Result[1] = A[1] ^ B[1];
	Result[2] = A[2] ^ B[2];
	Result[3] = A[3] ^ B[3];
	return Result;
}