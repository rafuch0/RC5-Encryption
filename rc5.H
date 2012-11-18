#ifndef RC5_H
#define RC5_H

#include <iostream>
#include <math.h>
#include <stdint.h>
#include <fstream>

using namespace std;

#define P16 0xb7e1
#define Q16 0x9e37
#define P32 0xb7e15163
#define Q32 0x9e3779b9
#define P64 0xb7e151628aed2a6bLL
#define Q64 0x9e3779b97f4a7c15LL

template <class T>
class rc5
{
	public:
		rc5(int wordSize, int argc, char *argv[]);
		~rc5();
	private:
		void rc5doit();			//Initiates Program
		void rc5userPrompt();		//Prompt
		void rc5init();			//Create MixKey matrices
		void rc5encrypt();		//Encrypt
		void rc5decrypt();		//Decrypt

		T ROTL(T x, T s);		//Template Class rotate left
		T ROTR(T x, T s);		//Right
		T MagicP();			//Get MagicP for wordsize
		T MagicQ();			//Get MagicQ for wordsize

		bool encryptBool;		//E/D?
		int w; //16,32,64 bits		//Word Size
		int r; //1-256			//Rounds
		int b; //1-256 bytes		//Key Length
		
		char tempKey[256];		//Input Key
		T *K;				//Key Matri
		T *S;				//Secret Key Matrix
		T *L;				//MixKey Matrix
		char inFile[128];		//Infile
		char outFile[128];		//Outfile
};

#include "rc5.cpp"

#endif
