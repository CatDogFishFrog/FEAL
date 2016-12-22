#include"fealnx.h"

int main(int argc, char *argv[]) {
	setlocale(LC_ALL, "Rus");
	if (argc == 1)
	{
		cout << "��������� �� ����� �������� ��� ����������!" << endl;
		exit(2);
	}
	if (argc < 5)
	{
		cout << "������� ���� ���������� ��� ������ ���������!\n";
		exit(3);
	}
	if (strcmp(argv[1], "-enc") != 0 && strcmp(argv[1], "-dec") != 0)
	{
		cout << "�������� ������ �������!\n� ��������� mode ����� ���� ������ enc ��� dec!" << endl;
		exit(4);
	}
	if (strlen(argv[2]) != 16)
	{
		cout << "�������� ������ �������!\n������ ����� ������ ���� ������ 8!" << endl;
		exit(5);
	}
	cController Chipper;
	long long result = 0;
	unsigned char ourKey[17] = "\0";
	for (int i = 0; i < 8; i++)
		ourKey[i] = (unsigned char)argv[2][i];
	try
	{
		switch (argv[1][1])
		{
		case 'e':
		{
			result = Chipper.encrypt(ourKey, argv[3], argv[4]);
			break;
		}
		case 'd':
		{
			result = Chipper.decrypt(ourKey, argv[3], argv[4]);
		}
		}
	}
	catch (const char eMsg[])
	{
		cout << "������: " << eMsg << endl;
		system("pause");
		return 1;
	}
	switch (argv[1][1])
	{
	case 'e':
	{
		cout << "���� ������� ����������.\n";
		break;
	}
	case 'd':
		cout << "���� ������� �����������.\n";
	}
	system("pause");
	return 0;
}
