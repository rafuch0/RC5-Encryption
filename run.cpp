#include <iostream>
#include <stdint.h>
#include "rc5.H"

int main(int argc, char *argv[])
{
	int intInput=0;

	rc5<uint16_t> *myRC516;
	rc5<uint32_t> *myRC532;
	rc5<uint64_t> *myRC564;

	if(!(argc > 1))
	{
		cout << "RC5 Encryption/Decryption\n";
        	cout << "Please Enter the Wordsize: (16,32,64) ";
	        cin >> intInput;
	        while((intInput != 16) && (intInput != 32) && (intInput != 64))
        	{
                	cout << "\n(16,32,64)";
	                cin >> intInput;
	        }
	}
	else
	{
		if(argc != 8)
		{
			cout << "Usage:" << endl;
			cout << "./rc5 {e,d} <INFile> <OUTFile> {16,32,64} {1-256} {1-256} [KEY..]" << endl;
			cout << flush;
			return 0;
		}

		intInput = atoi(argv[4]);
	}

	switch(intInput)
	{
		case 16:
			myRC516 = new rc5<uint16_t>(intInput,argc, argv);
			delete myRC516;
		break;

		case 32:
                        myRC532 = new rc5<uint32_t>(intInput,argc,argv);
                        delete myRC532;
		break;

		case 64:
                        myRC564 = new rc5<uint64_t>(intInput,argc,argv);
                        delete myRC564;
		break;
	}

	cout << endl;
}
