//============================================================================
// Name        : testPocoWebServer.cpp
// Author      : 
// Version     :
// Copyright   : Your copyright notice
// Description : Hello World in C++, Ansi-style
//============================================================================



#include <iostream>
#include <string>
#include <vector>



#include <stdio.h>
#include <stdlib.h>

#include "FtpServerWrapper.cpp"


using namespace std;
using namespace PA_CG3000;




	int main(int argc, char** argv) {

		FtpServerWrapper wrapper;
		wrapper.run();

		exit(1);



	}


