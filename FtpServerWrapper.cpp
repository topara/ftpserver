/*
 * FtpServerConnection.cpp
 *
 *  Created on: Jun 27, 2016
 *      Author: root
 */

/*#include "FtpServerConnection.h"*/
#ifndef FTPSERVERWRAPPER_CPP_
#define FTPSERVERWRAPPER_CPP_
#include <iostream>
#include <thread>

/*
#include <string>
#include <exception>
#include <map>
#include <algorithm>
#include <vector>
#include <cctype>
#include <pwd.h>
#include <netinet/in.h>
#include <time.h>
#include <dirent.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
*/


/*
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <memory>
#include <sstream>
#include <vector>
#include <fstream>
#include <sys/statfs.h>
*/

/*#include "crc32.c"*/
#include "TCPAcceptor.h"
#include "TCPStream.h"
#include "FtpServerConnection.cpp"







namespace PA_CG3000 {

class FtpServerWrapper{
private:
	TCPAcceptor* acceptor = NULL;


public :
	FtpServerWrapper() {

	acceptor = new TCPAcceptor(21,std::string("").c_str());

}





	 void run()   {


		 if (acceptor->start() == 0) {

				while (1) {
					 TCPStream* stream = NULL;

					stream = acceptor->accept();


					if (stream != NULL) {
						try {





								std::thread handler([stream](){
									FtpServerConnection conn(stream);
									 std::thread tw1 = std::move(conn.MakeThread());
									 tw1.join();

								});
								handler.detach();



						}
								  catch(std::exception& e){
									  std::cerr << "Unknow excepion: " << e.what()<<std::endl ;

								  }
					}
				}
			}
		 else
		 {
			  std::cout << "Error openning " <<  std::endl;// ;
		 }


		std::cout << "Connection finished!" << std::endl << std::flush;
	}

	~FtpServerWrapper() {
		// TODO Auto-generated destructor stub
		acceptor->~TCPAcceptor();
	}
};
} /* namespace PA_CG3000 */
#endif
