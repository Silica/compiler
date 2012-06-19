#include "PSL/PSL.h"

#include <stdio.h>
#include <vector>

#include <windows.h>

typedef unsigned long dword;
using namespace PSL;

void compile(FILE *exe, const char *filename)
{
	PSLVM p;
	if (p.LoadScript(filename))
		return;

	string exename = filename;
	int period = exename.rfind('.');
	if (period > 0)
		exename /= period;
	exename += ".exe";
	FILE *fp = fopen(exename, "wb");
	if (!fp)
		return;
	fseek(exe, 0, SEEK_END);
	int end = ftell(exe);
	variable::buffer byte(end);
	fseek(exe, 0, SEEK_SET);
	fread(byte.get(), 1, end, exe);
	fwrite(byte.get(), 1, end, fp);
	p.WriteCompiledCode(fp);
	dword l = 0xDEADC0DE;
	fwrite(&end, 1, sizeof(dword), fp);
	fwrite(&l, 1, sizeof(dword), fp);

	fclose(fp);
}

bool compiled(FILE *exe)
{
	int i = sizeof(dword);
	fseek(exe, -i, SEEK_END);
	dword l;
	fread(&l, 1, sizeof(dword), exe);
	return l == 0xDEADC0DE;
}

class binarystring
{
public:
	static binarystring *New()	{return new binarystring();}

	binarystring()				{offset = 0;}
	void destructor()			{delete this;}
	void resize(size_t size)	{bin.resize(size);}
	void set(size_t size)		{offset = size;}

	void write_byte(unsigned char c)
	{
		bin[offset++] = c;
	}
	void write_word(unsigned short s)
	{
		unsigned short *p = reinterpret_cast<unsigned short*>(&bin[offset]);
		*p = s;
		offset += sizeof(unsigned short);
	}
	void write_dword(unsigned long l)
	{
		unsigned long *p = reinterpret_cast<unsigned long*>(&bin[offset]);
		*p = l;
		offset += sizeof(unsigned long);
	}
	std::vector<unsigned char> bin;
private:
	size_t offset;
};

void zero(FILE *fp, int n)
{
	for (int i = 0; i < n; i++)
		fputc(0, fp);
}

void write_exe(string filename, std::vector<unsigned char> *bin)
{
	size_t codesize = bin->size();
	size_t filesize = (codesize + 0x1FF)/0x200*0x200;
	size_t imagesize = (filesize + 0xFFF)/0x1000*0x1000;
	const char dos[] = {0x0E,0x1F,0xBA,0x0E,0x00,0xB4,0x09,0xCD,0x21,0xB8,0x01,0x4C,0xCD,0x21,0x44,0x4F,0x53,0x0D,0x0D,0x0A,0x24};
	IMAGE_DOS_HEADER dos_header = {'ZM', 0x90, 3, 0, 4, 0, 0xFFFF, 0, 0xB8, 0, 0, 0, 0x40, 0, {0}, 0, 0, {0}, sizeof(IMAGE_DOS_HEADER) + ((sizeof(dos)+15)/16)*16};
	IMAGE_NT_HEADERS32 nt_header = {'EP',
		{0x14C, 2, time(0), 0, 0, sizeof(IMAGE_OPTIONAL_HEADER32),
			IMAGE_FILE_RELOCS_STRIPPED|IMAGE_FILE_EXECUTABLE_IMAGE|IMAGE_FILE_32BIT_MACHINE},
		{0x10B, 1, 0,
			imagesize, // SizeOfCode
			0x1000, // SizeOfInitializedData
			0,0x2000,0x2000,
			0x1000, // BaseOfData
			0x400000,0x1000,0x200,4,0,0,0,4,0,0,
			0x2000+imagesize, // SizeOfImage
			0x200, // SizeOfHeaders
			0,IMAGE_SUBSYSTEM_WINDOWS_CUI,0,0x10000,0x1000,0,0,0,IMAGE_NUMBEROF_DIRECTORY_ENTRIES,{
				{0,0},
				{0x11A8,sizeof(IMAGE_IMPORT_DESCRIPTOR)},
				{0,0},
				{0,0},
				{0,0},
				{0,0},
				{0,0},
				{0,0},
				{0,0},
				{0,0},
				{0,0},
				{0,0},
				{0x11CC,8},
				{0,0},
				{0,0},
				{0,0},
			}
		}
	};

	IMAGE_SECTION_HEADER data_section = {".data", 0x200, 0x1000, 0x200, 4, 0, 0, 0, 0, IMAGE_SCN_CNT_INITIALIZED_DATA|IMAGE_SCN_MEM_READ|IMAGE_SCN_MEM_WRITE};
	IMAGE_SECTION_HEADER text_section = {".text", filesize, 0x2000, filesize, 0x200, 0, 0, 0, 0, IMAGE_SCN_CNT_CODE|IMAGE_SCN_MEM_EXECUTE|IMAGE_SCN_MEM_READ};

	if (FILE *fp = fopen(filename.c_str(), "wb"))
	{
		fwrite(&dos_header, sizeof(dos_header), 1, fp);
		fwrite(dos, sizeof(dos), 1, fp);
		if (int m = sizeof(dos) % 16)
			zero(fp, 16-m);
		fwrite(&nt_header, sizeof(nt_header), 1, fp);
		fwrite(&data_section, sizeof(data_section), 1, fp);
		fwrite(&text_section, sizeof(text_section), 1, fp);

		{
			IMAGE_IMPORT_DESCRIPTOR import_desc = {0x11CC, 0, 0, 0x11BC, 0x11CC};
			const char dllname[] = "msvcrt.dll";
			int table[3] = {
				0x11CC+sizeof(table)-2,
				0x11CC+sizeof(table)+7,
				0};

			fwrite(&import_desc, sizeof(IMAGE_IMPORT_DESCRIPTOR), 1, fp);
			fprintf(fp, "%s", dllname);
			zero(fp, 17-sizeof(dllname));
			fwrite(table, sizeof(table), 1, fp);
			fprintf(fp, "%s", "putchar");
			zero(fp, 2);
			fprintf(fp, "%s", "getchar");
		}

		fseek(fp, 0x200, SEEK_SET);
		for (int i = 0; i < bin->size(); i++)
		{
			fputc((*bin)[i], fp);
		}

		if (codesize < filesize)
		{
			fseek(fp, 0x200+filesize-1, SEEK_SET);
			fputc(0, fp);
		}

		fclose(fp);
	}
}

void execute(FILE *exe, variable &arg)
{
	int i = sizeof(dword) * 2;
	fseek(exe, -i, SEEK_END);
	dword l;
	int end = ftell(exe);
	fread(&l, 1, sizeof(dword), exe);
	fseek(exe, l, SEEK_SET);
	PSLVM p;
	if (p.LoadCompiledCode(exe, end - l))
		return;
	p.addClass<binarystring>("binarystring")
		("destructor", &binarystring::destructor)
		("resize", &binarystring::resize)
		("set", &binarystring::set)
		("write_byte", &binarystring::write_byte)
		("write_word", &binarystring::write_word)
		("write_dword", &binarystring::write_dword)
	;
	p.addFunction("new_binarystring", binarystring::New);
	p.addFunction("write_exe", &write_exe);
	variable lib;
	lib["putchar"] = 0x4011CC;
	lib["getchar"] = 0x4011D0;
	p.add("lib", lib);
	p.Run(arg);
}

int main(int argc, char **argv)
{
	FILE *exe = fopen(argv[0], "rb");
	if (!exe)
		return 1;

	if (!compiled(exe))
	{
		if (argc >= 2)
			compile(exe, argv[1]);
	}
	else
	{
		variable arg;
		for (int i = 0; i < argc; i++)
			arg[i] = argv[i];
		execute(exe, arg);
	}

	fclose(exe);
	return 0;
}
