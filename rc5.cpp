#ifndef RC5_CPP
#define RC5_CPP

#include <iostream>
#include <math.h>
#include <stdint.h>
#include <fstream>
#include <cassert>
#include <sys/stat.h>
#include <sys/time.h>
#include <string.h>
#include <cstdlib>

#define P16 0xb7e1
#define Q16 0x9e37
#define P32 0xb7e15163
#define Q32 0x9e3779b9
#define P64 0xb7e151628aed2a6bLL
#define Q64 0x9e3779b97f4a7c15LL

#define D true
#define D2 false

using namespace std;

template <class T>
T rc5<T>::MagicP()
{
	switch(w)
	{
		case 16:
		if(D)cout << "MagicP = " << (T) P16 << endl;
		return (T) P16;
		case 32:
		if(D)cout << "MagicP = " << (T) P32 << endl;
		return (T) P32;
		case 64:
		if(D)cout << "MagicP = " << (T) P64 << endl;
		return (T) P64;
	}
}

template <class T>
T rc5<T>::MagicQ()
{
        switch(w)
        {
                case 16:
		if(D)cout << "MagicQ = " << (T) Q16 << endl;
                return (T) Q16;
                case 32:
		if(D)cout << "MagicQ = " << (T) Q32 << endl;
                return (T) Q32;
                case 64:
		if(D)cout << "MagicQ = " << (T) Q64 << endl;
                return (T) Q64;
        }
}


template <class T>
T rc5<T>::ROTL(T x, T s)
{
	if(D2)cout << "\n ROTL: return = " << (T) (((x)<<(s&(w-1))) | ((x)>>(w-(s&(w-1))))) << endl;
	return (T) (((x)<<(s&(w-1))) | ((x)>>(w-(s&(w-1)))));
}

template <class T>
T rc5<T>::ROTR(T x, T s)
{
	if(D2)cout << "\n ROTR: return = " << (T) (((x)>>(s&(w-1))) | ((x)<<(w-(s&(w-1))))) << endl;
	return (T) (((x)>>(s&(w-1))) | ((x)<<(w-(s&(w-1)))));
}

template <class T>
rc5<T>::rc5(int wordSize,int argc, char *argv[])
{
	if(!(argc > 1))
	{
		w = wordSize;		//Interactive
		rc5userPrompt();
	}
	else				//Else Parse ARGV
	{
		encryptBool = true;
		if((*argv[1]) == 'd')
		{
			encryptBool = false;
		}

		cout << argv[1][0] << ",";

		strcpy(inFile,argv[2]);
		strcpy(outFile,argv[3]);

		w = atoi(argv[4]);
		cout << w << ",";
		r = atoi(argv[5]);
		cout << r << ",";
		b = atoi(argv[6]);
		cout << b << ",";
		strcpy(tempKey,argv[7]);
	}
	rc5init();			//Init
	rc5doit();			//Do Encrypt or Decrypt
}

template <class T>
void rc5<T>::rc5doit()
{
	if(encryptBool) rc5encrypt();	//Encrypt
	else rc5decrypt();		//Else Decrypt
}

template <class T>
void rc5<T>::rc5init()
{
        timeval tim;
        gettimeofday(&tim, NULL);
        double t1 = tim.tv_sec+(tim.tv_usec/1000000.0);		//Time

        int u = w/8;
        int c = (int)ceil((float)max(b,1)/(float)u);
        int t = 2*(r+1);

        int i;
        int j;

        K = new T[b];   //make sure key size is 1-256
        L = new T[c];
        S = new T[t];

	for(int z=0;z<b;z++)
	{
		K[z] = tempKey[z];
		if(D)cout << "\ntempkey[" << z << "] = " << tempKey[z] << " k[" << z << "] = " << K[z] << endl;
	}

	for(int z=0;z<c;z++)
	{
		L[z] = 0;
	}

        T A=0;
        T B=0;

        for(i=b-1,L[c-1]=0;i!=-1;i--)
        {
                L[i/u] = (L[i/u]<<8) + K[i];
		if(D)cout << "\nmix key L[" << i/u << "] = " << L[i/u] << endl;
        }

        for(i=1,S[0]=MagicP();i<t;i++)
        {
                S[i] = S[i-1]+MagicQ();
		if(D)cout << "\n Secret Key Seed S[" << i << "] = " << S[i] << endl;
        }

        for(int z=0,A=B=i=j=0;z<3*max(t,c);z++,i=(i+1)%t,j=(j+1)%c)
        {
                A = S[i] = ROTL((S[i] + A + B),3);
                B = L[j] = ROTL((L[j] + A + B),(A + B));
        }

        gettimeofday(&tim,NULL);
        double t2=tim.tv_sec+(tim.tv_usec/1000000.0);		//Time
        printf("%.6lf,", t2-t1);
}

template <class T>
rc5<T>::~rc5()
{
	delete[] K;		//Destructors
	delete[] S;
	delete[] L;
}


template <class T>
void rc5<T>::rc5encrypt()
{
        timeval tim;
        gettimeofday(&tim, NULL);				//Time
        double t1 = tim.tv_sec+(tim.tv_usec/1000000.0);

	int n;
	struct stat results;
	n = stat(inFile, &results);				//Get File Size for Padding
	if(D)cout << "Original File has " << results.st_size << " bytes!\n";

	T A = 0;
	T B = 0;

	ifstream text(inFile, ios::in | ios::binary);		//Binary
	ofstream cyph(outFile, ios::out | ios::binary);

	assert(text);						//File Exists

	int padRead = results.st_size % ((w*2)/8);		//Where to Pad
	int padVal = ((w*2)/8) - padRead;			//How Much Padding?

	for(int z=0;z<results.st_size;z+=2*(w/8))
	{
		if(z+((w*2)/8) > results.st_size)  //Reading last Blocks!
		{
			if(D)cout << "This should be the time to init the last blocks" << endl;
			if(D)cout << "PadRead = " << padRead << " PadVal = " << padVal << endl;
			if(padRead == 0)
			{
				if(D)cout << "Not Padding!  We shouldnt be here!" << endl;
				break;
			}
			if(padRead >= (w/8))	//If only B is to recieve padding
			{
				if(D)cout  << "Need to Read all of A, rest of B then pad B" << endl;
				A = 0;
				B = 0;
				text.read((char*)&A,sizeof(A));	//Read all of A
				if(D)cout << "Read A as: " << hex << A << endl;
				text.read((char*)&B,sizeof(char)*(padRead-(w/8))); //Read part of B
				if(D)cout << "Read B as: " << hex << B << endl;
				for(int i=0;i<((w/8)-(padRead-(w/8)));i++) //Pad remaining part of B with padVal for each nibble
				{
					B = B << 8;
					B |= padVal;
					if(D)cout << "B ShiftOR " << hex << B << endl;
				}
			}
			else
			{
				if(D)cout << "Need to read all padread into A, then Pad rest of A and All of B\n";
				A = 0;
				B = 0;
				text.read((char*)&A,padRead);
                                if(D)cout << "Read A as: " << hex << A << endl;
				for(int i=0;i<(padVal - (w/8));i++)	//Pad remaining part of A with padval and shifting by four nibbles
				{
					A = A << 8;
					A |= padVal;
                                        if(D)cout << "A ShiftOR " << hex << A << endl;
				}
				for(int i=0;i<(w/8);i++)
				{
					B = B << 8;
					B |= padVal;
                                        if(D)cout << "B ShiftOR " << hex << B << endl;
				}
			}
		}
		else
		{
			if(D)cout << "Normal Reading Procedure here" << endl;
			text.read((char*)&A,sizeof(A));
                        if(D)cout << "Read A as: " << hex << A << endl;                              
			text.read((char*)&B,sizeof(B));
                        if(D)cout << "Read B as: " << hex << B << endl;
		}

		if(D)cout << "Read Last two Blocks As: " << endl;
                if(D)cout << "Read A as: " << hex << A << endl;
		if(D)cout << "Read B as: " << hex << B << endl;


		A = A + S[0];
		B = B + S[1];
		for(int i=1;i<=r;i++)
		{
			A = ROTL((A^B),B) + S[2*i];
			B = ROTL((B^A),A) + S[2*i+1];
		}

		cyph.write((char*)&A,sizeof(A));		//Write Block
		cyph.write((char*)&B,sizeof(B));
	}

	text.close();
	cyph.close();

        gettimeofday(&tim,NULL);
        double t2=tim.tv_sec+(tim.tv_usec/1000000.0);		//Time
        printf("%.6lf", t2-t1);
}

template <class T>
void rc5<T>::rc5decrypt()
{
        timeval tim;
        gettimeofday(&tim, NULL);				//Time
        double t1 = tim.tv_sec+(tim.tv_usec/1000000.0);

        int n;
        struct stat results;
        n = stat(inFile, &results);				//Get Filesize for Padding
        if(D)cout << "Original File has " << results.st_size << " bytes!\n";
        if(D)cout << "May need to depad " << (w/8)*2 << " bytes!\n";

        T A = 0;
        T B = 0;

        ifstream cyph(inFile, ios::in | ios::binary);		//Binary Read
        ofstream text(outFile, ios::out | ios::binary);

        assert(cyph);

        for(int z=0;z<results.st_size;z+=2*(w/8))
        {
                cyph.read((char*)&A, sizeof(A));
       	        cyph.read((char*)&B, sizeof(B));

                for(int i=r;i>0;i--)
                {
       	                B = ROTR((B - S[2*i+1]),A)^A;
       	                A = ROTR((A - S[2*i]),B)^B;
                }

                B = B - S[1];
                A = A - S[0];

                if(D)cout << "Decrypted A as: " << hex << A << endl;
                if(D)cout << "Decrypted B as: " << hex << B << endl;

		if( (z+2*(w/8)) >= results.st_size)
		{
			if(D)cout << "Should be the Last Block Here!" << endl;
			int padVal = B&0xFF;
			if(D)cout << "Possible PadVal = " << hex << padVal << endl;

			int aBytes = (w/8);
			int bBytes = (w/8);

			if(padVal <= 2*(w/8)-1)
			{
				if(padVal >= (w/8))
				{
					for(int i=0;i<(w/8);i++)
					{
						if((B & 0xFF) == padVal)
						{
							B = B >> 8;
							if(D)cout << "B ShiftR " << hex << B << endl;
							bBytes--;
						}
						else
						{
							if(D)cout << "Houston we have a problem!  Pad Failed!" << endl;
						}
					}

					for(int i=0;i<padVal-(w/8);i++)
					{
						if((A & 0xFF) == padVal)
						{
							A = A >> 8;
							if(D)cout << "A shiftR " << hex << A << endl;
							aBytes--;
						}
						else
						{
							if(D)cout << "Houston we have a problem!  Pad Failed!" << endl;
						}
					}
				}
				else
				{
					for(int i=0;i<padVal;i++)
					{
						if((B & 0xFF) == padVal)
						{
							B = B >> 8;
							if(D)cout << "B ShiftR " << hex << B << endl;
							bBytes--;
						}
						else
						{
                                                        if(D)cout << "Houston we have a problem!  Pad Failed!" << endl;
						}
					}

				}

				text.write((char*)&A,sizeof(char)*aBytes);
				text.write((char*)&B,sizeof(char)*bBytes);
				if(D)cout << "Wrote " << aBytes << " bytes for A which = " << hex << A << endl;
	                        if(D)cout << "Wrote " << bBytes << " bytes for B which = " << hex << B << endl;
			}
			else
			{
				text.write((char*)&A,sizeof(A));
        	                text.write((char*)&B,sizeof(B));
			}
		}
		else
		{
		        text.write((char*)&A,sizeof(A));		//Write
        		text.write((char*)&B,sizeof(B));
		}
        }

        cyph.close();
        text.close();

        gettimeofday(&tim,NULL);
        double t2=tim.tv_sec+(tim.tv_usec/1000000.0);		//Time
        printf("%.6lf", t2-t1);
}

template <class T>
void rc5<T>::rc5userPrompt()
{
	char charInput[5]="";
	int  intInput=0;
	encryptBool = true;

	cin.getline(charInput,5);	

	while((charInput[0] != 'e') && (charInput[0] != 'd'))
	{
		cout << "Would you like to encrypt or decrypt? (e/d) ";
		cin.getline(charInput, 5);
	}

	switch(charInput[0])
	{
		case 'e':
			cout << "Please input the filename of the text: ";
			cin.getline(inFile, 128);
			cout << "Please input the filename to store the cypher text: ";
			cin.getline(outFile, 128);
		break;

		case 'd':
			cout << "Please input the filename of the cypher text: ";
			cin.getline(inFile, 128);
			cout << "Please enter the filename to store the text: ";
			cin.getline(outFile, 128);
			encryptBool = false;
		break;
	}

	cout << "Please Enter the Number of Rounds: (1-256) ";
	cin >> intInput;
	while((intInput < 1) || (intInput > 256))
	{
		cout << "\n(1-256)";
		cin >> intInput;
	}
	r = intInput;


	cout << "Please Enter your keysize: (1-256) ";
	cin >> intInput;
	while((intInput < 1) || (intInput > 256))
	{
		cout << "\n(1-256): ";
		cin >> intInput;
	}
	b = intInput;

	for(int i=0;i<256;i++)tempKey[i]=0;
	cin.getline(charInput,5);

	cout << "Please Enter the Secret Key of size " << b << " in ASCII: ";
	cin.getline(tempKey, 256, '\n');
}

#endif
