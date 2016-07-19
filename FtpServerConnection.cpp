/*
 * FtpServerConnection.cpp
 *
 *  Created on: Jun 27, 2016
 *      Author: root
 */

/*#include "FtpServerConnection.h"*/
#ifndef FTPSERVERCONNECTION_CPP_
#define FTPSERVERCONNECTION_CPP_
#include <iostream>
#include <thread>

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
#include <chrono>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <memory>
#include <sstream>
#include <vector>
#include <fstream>
#include <sys/statfs.h>
#include <dirent.h>
//#include <filesystem>


/*#include "crc32.c"*/

#include "TCPStream.h"
#include "TCPAcceptor.h"
#include "TCPStream.h"
#include "TCPConnector.h"

#include <mutex>





#ifndef BSIZE
  #define BSIZE 1024
#endif
#ifndef PSIZE
  #define PSIZE 128
#endif
#define	ALLPERMS	(S_ISUID|S_ISGID|S_ISVTX|S_IRWXU|S_IRWXG|S_IRWXO)

namespace PA_CG3000 {


typedef unsigned long long ulonglong;
/* Command struct */
typedef struct Command
{
  std::string command;
  std::string arg;
} Command;

typedef enum conn_mode{ NORMAL, SERVER, CLIENT }conn_mode;

/* Commands enumeration */
typedef enum cmdlist
{
  ABOR, CWD, DELE, LIST, MDTM, MKD, NLST, PASS, PASV,
  PORT, PWD, QUIT, RETR, RMD, RNFR, RNTO, SITE, SIZE,
  STOR, TYPE, USER, NOOP, MODE, STRU, DIS
} cmdlist;


struct ToLong
{
    long operator()(std::string const &str) { return strtol(str.c_str(),NULL,10);  }
};



typedef struct Port
{
  int p1;
  int p2;
} Port;

typedef struct State
{
  /* Connection mode: NORMAL, SERVER, CLIENT */
  int mode;

  /* Is user loggd in? */
  bool logged_in;

  /* Is this username allowed? */
  bool username_ok;
  std::string username;

  /* Response message to client e.g. 220 Welcome */
  std::string message;
  /* current working directory for the session */
  std::string currentDirectory;

  /* the relative path with respect to the root directory */
   std::string currentRelativePath;

  /* Commander connection */
  int connection;

  //Poco::Net::ServerSocket* sock_pasv;

  /* Transfer process id */
  int tr_pid;

  /* Root directory for the client*/
  std::string root_dir;

  /* Server IP address*/
  std::string ip_addr_server;

  /* Client Ip address for Active mode*/
  std::string act_ip_addr;

  /* Client port for Active mode*/
  int act_port;

} State;

class FtpServerConnection{
private:
	const std::string welcomeMessage="220 WDLS Ftp Server 1.9 Welcome!\r\n";
	Command cmd ;
	State state ;
	std::map<std::string, cmdlist> mapComandList;
    std::string	usernames[3]{ "ftp","anonymous","wdls"};
    TCPStream* _stream;
  //  std::unique_ptr<std::thread> handlerThread;
    bool isOpen = true;
    bool isPasiveModeOn=false;
    std::mutex mu;
    void handleUserCommand(){

    		  if(inArray(cmd.arg)){
    		    state.username = cmd.arg;
    		    state.username_ok = true;
    		    state.message = "331 User name ok, need password\r\n";
    		  }else{
    		    state.message = "530 Invalid username\r\n";
    		  }
    		  sendCommand(state.message);

    }
    bool inArray(const std::string userName){
    		for(const std::string name: usernames )
    		{

    			if(name.compare(userName)==0){
    				return true;
    			}
    		}
    		return false;
    	}
    void setInitDir(){
    	 state.ip_addr_server=_stream->getServerIP();
    	 state.currentRelativePath="/";
			 if(state.ip_addr_server.compare("192.168.197.2")==0){
						state.root_dir = "/mnt/sdcard/cmc";
			  }else if(state.ip_addr_server.compare("192.168.197.1")==0){
				state.root_dir = "/mnt/sdcard/fplans";
			  }
			 //TODO: pending whe the ip is not from the subnet and exit here
			  else{

				//return 0;
			  }
			 state.currentDirectory=state.root_dir;
    }
    	void initSequence(){
    		 setInitDir();

    		  //  std::this_thread::sleep_for(std::chrono::seconds(5));
			 std::cout << "Root directory " << state.root_dir<<std::endl ;
			 mu.lock();
			chdir(state.root_dir.c_str());
			 mu.unlock();
			isOpen=true;
			sendCommand(welcomeMessage);



	}
    	unsigned long Crc32_ComputeBuf( unsigned long inCrc32, const void *buf, size_t bufLen )
    	{
    	    static const unsigned long crcTable[256] = {
    	   0x00000000,0x77073096,0xEE0E612C,0x990951BA,0x076DC419,0x706AF48F,0xE963A535,
    	   0x9E6495A3,0x0EDB8832,0x79DCB8A4,0xE0D5E91E,0x97D2D988,0x09B64C2B,0x7EB17CBD,
    	   0xE7B82D07,0x90BF1D91,0x1DB71064,0x6AB020F2,0xF3B97148,0x84BE41DE,0x1ADAD47D,
    	   0x6DDDE4EB,0xF4D4B551,0x83D385C7,0x136C9856,0x646BA8C0,0xFD62F97A,0x8A65C9EC,
    	   0x14015C4F,0x63066CD9,0xFA0F3D63,0x8D080DF5,0x3B6E20C8,0x4C69105E,0xD56041E4,
    	   0xA2677172,0x3C03E4D1,0x4B04D447,0xD20D85FD,0xA50AB56B,0x35B5A8FA,0x42B2986C,
    	   0xDBBBC9D6,0xACBCF940,0x32D86CE3,0x45DF5C75,0xDCD60DCF,0xABD13D59,0x26D930AC,
    	   0x51DE003A,0xC8D75180,0xBFD06116,0x21B4F4B5,0x56B3C423,0xCFBA9599,0xB8BDA50F,
    	   0x2802B89E,0x5F058808,0xC60CD9B2,0xB10BE924,0x2F6F7C87,0x58684C11,0xC1611DAB,
    	   0xB6662D3D,0x76DC4190,0x01DB7106,0x98D220BC,0xEFD5102A,0x71B18589,0x06B6B51F,
    	   0x9FBFE4A5,0xE8B8D433,0x7807C9A2,0x0F00F934,0x9609A88E,0xE10E9818,0x7F6A0DBB,
    	   0x086D3D2D,0x91646C97,0xE6635C01,0x6B6B51F4,0x1C6C6162,0x856530D8,0xF262004E,
    	   0x6C0695ED,0x1B01A57B,0x8208F4C1,0xF50FC457,0x65B0D9C6,0x12B7E950,0x8BBEB8EA,
    	   0xFCB9887C,0x62DD1DDF,0x15DA2D49,0x8CD37CF3,0xFBD44C65,0x4DB26158,0x3AB551CE,
    	   0xA3BC0074,0xD4BB30E2,0x4ADFA541,0x3DD895D7,0xA4D1C46D,0xD3D6F4FB,0x4369E96A,
    	   0x346ED9FC,0xAD678846,0xDA60B8D0,0x44042D73,0x33031DE5,0xAA0A4C5F,0xDD0D7CC9,
    	   0x5005713C,0x270241AA,0xBE0B1010,0xC90C2086,0x5768B525,0x206F85B3,0xB966D409,
    	   0xCE61E49F,0x5EDEF90E,0x29D9C998,0xB0D09822,0xC7D7A8B4,0x59B33D17,0x2EB40D81,
    	   0xB7BD5C3B,0xC0BA6CAD,0xEDB88320,0x9ABFB3B6,0x03B6E20C,0x74B1D29A,0xEAD54739,
    	   0x9DD277AF,0x04DB2615,0x73DC1683,0xE3630B12,0x94643B84,0x0D6D6A3E,0x7A6A5AA8,
    	   0xE40ECF0B,0x9309FF9D,0x0A00AE27,0x7D079EB1,0xF00F9344,0x8708A3D2,0x1E01F268,
    	   0x6906C2FE,0xF762575D,0x806567CB,0x196C3671,0x6E6B06E7,0xFED41B76,0x89D32BE0,
    	   0x10DA7A5A,0x67DD4ACC,0xF9B9DF6F,0x8EBEEFF9,0x17B7BE43,0x60B08ED5,0xD6D6A3E8,
    	   0xA1D1937E,0x38D8C2C4,0x4FDFF252,0xD1BB67F1,0xA6BC5767,0x3FB506DD,0x48B2364B,
    	   0xD80D2BDA,0xAF0A1B4C,0x36034AF6,0x41047A60,0xDF60EFC3,0xA867DF55,0x316E8EEF,
    	   0x4669BE79,0xCB61B38C,0xBC66831A,0x256FD2A0,0x5268E236,0xCC0C7795,0xBB0B4703,
    	   0x220216B9,0x5505262F,0xC5BA3BBE,0xB2BD0B28,0x2BB45A92,0x5CB36A04,0xC2D7FFA7,
    	   0xB5D0CF31,0x2CD99E8B,0x5BDEAE1D,0x9B64C2B0,0xEC63F226,0x756AA39C,0x026D930A,
    	   0x9C0906A9,0xEB0E363F,0x72076785,0x05005713,0x95BF4A82,0xE2B87A14,0x7BB12BAE,
    	   0x0CB61B38,0x92D28E9B,0xE5D5BE0D,0x7CDCEFB7,0x0BDBDF21,0x86D3D2D4,0xF1D4E242,
    	   0x68DDB3F8,0x1FDA836E,0x81BE16CD,0xF6B9265B,0x6FB077E1,0x18B74777,0x88085AE6,
    	   0xFF0F6A70,0x66063BCA,0x11010B5C,0x8F659EFF,0xF862AE69,0x616BFFD3,0x166CCF45,
    	   0xA00AE278,0xD70DD2EE,0x4E048354,0x3903B3C2,0xA7672661,0xD06016F7,0x4969474D,
    	   0x3E6E77DB,0xAED16A4A,0xD9D65ADC,0x40DF0B66,0x37D83BF0,0xA9BCAE53,0xDEBB9EC5,
    	   0x47B2CF7F,0x30B5FFE9,0xBDBDF21C,0xCABAC28A,0x53B39330,0x24B4A3A6,0xBAD03605,
    	   0xCDD70693,0x54DE5729,0x23D967BF,0xB3667A2E,0xC4614AB8,0x5D681B02,0x2A6F2B94,
    	   0xB40BBE37,0xC30C8EA1,0x5A05DF1B,0x2D02EF8D };
    	    unsigned long crc32;
    	    unsigned char *byteBuf;
    	    size_t i;

    	    /** accumulate crc32 for buffer **/
    	    crc32 = inCrc32 ^ 0xFFFFFFFF;
    	    byteBuf = (unsigned char*) buf;
    	    for (i=0; i < bufLen; i++) {
    	        crc32 = (crc32 >> 8) ^ crcTable[ (crc32 ^ byteBuf[i]) & 0xFF ];
    	    }
    	    return( crc32 ^ 0xFFFFFFFF );
    	}

    	/*----------------------------------------------------------------------------*\
    	 *  NAME:
    	 *     Crc32_ComputeFile() - compute CRC-32 value for a file
    	 *  DESCRIPTION:
    	 *     Computes the CRC-32 value for an opened file.
    	 *  ARGUMENTS:
    	 *     file - file pointer
    	 *     outCrc32 - (out) result CRC-32 value
    	 *  RETURNS:
    	 *     err - 0 on success or -1 on error
    	 *  ERRORS:
    	 *     - file errors
    	\*----------------------------------------------------------------------------*/
    	int Crc32_ComputeFile( FILE *file, unsigned long *outCrc32 )
    	{
    	#   define CRC_BUFFER_SIZE  8192
    	    unsigned char buf[CRC_BUFFER_SIZE];
    	    size_t bufLen;

    	    /** accumulate crc32 from file **/
    	    *outCrc32 = 0;
    	    while (1) {
    	        bufLen = fread( buf, 1, CRC_BUFFER_SIZE, file );
    	        if (bufLen == 0) {
    	            if (ferror(file)) {
    	                fprintf( stderr, "error reading file\n" );
    	                goto ERR_EXIT;
    	            }
    	            break;
    	        }
    	        *outCrc32 = Crc32_ComputeBuf( *outCrc32, buf, bufLen );
    	    }
    	    return( 0 );

    	    /** error exit **/
    	ERR_EXIT:
    	    return( -1 );
    	}
	void response(){
		isOpen=true;
		//std::cout<<"Handling command "<<trim(cmd.command)<< " Enum value:"<< mapComandList[trim(cmd.command)]<<std::endl;
		switch(mapComandList[cmd.command]){
		case cmdlist::USER:
			handleUserCommand();
			break;
		case cmdlist::PASS:
			handlePasswordCommand();
					break;
		case cmdlist::QUIT:
			handleQuitCommand();
			isOpen=false;
			break;
		case cmdlist::MODE:
			handleModeCommand();
			break;
		case cmdlist::STRU:
			handleStruCommand();
			break;
		case cmdlist::SIZE:
			handleSizeCommand();
			break;
		case cmdlist::LIST:
			handleListCommand();
			break;
		case cmdlist::RMD:
			handleRmdCommand();
			break;
		case cmdlist::PASV:
			handlePasvCommand();
			break;
		case cmdlist::PORT:
			handleFtpPortCommand();
			break;
		case cmdlist::TYPE:
			handleTypeCommand();
				break;
		case cmdlist::STOR:
			handleStorCommand();
			break;
		case cmdlist::SITE:
			handleSiteCommand();
			break;
		case cmdlist::CWD:
			//std::cout<<"Handling CWD command"<<std::endl;
			handleCwdCommand();
			break;
		case cmdlist::PWD:
			//std::cout<<"Handling PWD command"<<std::endl;
			handlePwdCommand();
					break;
		case cmdlist::MKD:
			handleMkdCommand();
							break;
		case cmdlist::DELE:
			handleDeleteCommand();
								break;
		case cmdlist::ABOR:
			handleAbortCommand();
				break;
		case cmdlist::RETR:
			handleRetrCommand();
						break;

		case NOOP:
			if(state.logged_in){
				state.message = "200 Nice to NOOP you!\r\n";
			}else{
				state.message = "530 Please login with USER and PASS.\r\n";
			}
			sendCommand(state.message);
			break;
		default:
			std::cout<<"500 Unknown command.\r\n";
			state.message = "500 Unknown command.\r\n";
			sendCommand(state.message);
			break;

		}

	}

	/** RETR command */
	void handleRetrCommand()
	{


	    //int connection;
	    int fd;
	    struct stat stat_buf;
	    int offset;
	    int remain_data;
	    int sent_total = 0;
	    int accsesInt;
	    if(state.logged_in){

	      /* Passive mode and Active mode */
	      if(state.mode == SERVER || state.mode == CLIENT){

	        char absFile[PSIZE];
	        //absFile = (char *)malloc(PSIZE);
	        memset(absFile,0,PSIZE);
	        std::string filePath;
	        if(cmd.arg.c_str()[0]=='/'){

	          //strcat(absFile,state.root_dir.c_str());
	          filePath=state.root_dir+cmd.arg;
	        }else
	        {
	        	filePath=state.currentDirectory +( state.currentDirectory.back()== '/' ?"":"/")+cmd.arg;
	        }
	        mu.lock();
	       // strcat(absFile,cmd.arg.c_str());


	        printf("File name: %s\n",filePath.c_str());
	        accsesInt = access(filePath.c_str(),R_OK);
	        fd = open(filePath.c_str(),O_RDONLY);
	        if(accsesInt==0 && fd>=0){
	          fstat(fd,&stat_buf);
	          mu.unlock();

	          state.message = "150 File status okay; about to open data connection.\r\n";

	          sendCommand(state.message);

			      offset = 0;
			      remain_data = stat_buf.st_size;
				  /*  while (((sent_total = sendfile(connection,fd,&offset,BSIZE)) > 0) && (remain_data > 0)) {
					    remain_data -= sent_total;
				    }*/
			      if(state.mode == CLIENT){
			    	  //std::cout<<"sending file: "<<std::string(absFile)<<std::endl;
			    	  sendFileToSocket(state.act_ip_addr, state.act_port, filePath,  stat_buf.st_size);
			    	  remain_data=0;
			      }else{
			    	//  sendFileToSocket(socket().address().toString(), 21,  std::string(absFile));

			      }
			      remain_data=0;
	    			/*if(sent_total==0){
	    				state.message = "550 Failed to read file.\r\n";
	    			}*/
	    			if(remain_data == 0){
	    				state.message = "226 File send OK.\r\n";
	    			}else {
	    				perror("ftp_retr:sendfile");
	    				//exit(EXIT_SUCCESS);
	    			}
	        }else{
	          state.message = "550 Failed to get file.\r\n";
	        }
	      }else{
	        state.message = "503 Please use PASV or PORT first.\r\n";
	      }
	    }else{
	      state.message = "530 Please login with USER and PASS.\r\n";
	    }

	    close(fd);
	    mu.unlock();
	    sendCommand(state.message);

	  state.mode = NORMAL;


	}


	/** Handle DELE command */
	void handleDeleteCommand()
	{
	  if(state.logged_in){
	    char fileName[PSIZE];
	    memset(fileName,0,PSIZE);
	    if(cmd.arg.c_str()[0]=='/'){
	      strcat(fileName,state.root_dir.c_str());
	    }
	    strcat(fileName,cmd.arg.c_str());
	    if(unlink(fileName)==-1){
	      state.message = "550 File unavailable.\r\n";
	    }else{
	      state.message = "250 Requested file action okay, completed.\r\n";
	    }
	  }else{
	    state.message = "530 Please login with USER and PASS.\r\n";
	  }
	  sendCommand( state.message);
	}

	void handleMkdCommand()
	{
	  if(state.logged_in){
	    char cwd[BSIZE];
	    char res[BSIZE];
	    memset(cwd,0,BSIZE);
	    memset(res,0,BSIZE);
	    getcwd(cwd,BSIZE);

	    /* TODO: check if directory already exists with chdir? */

	    /* Absolute path */
	    if(cmd.arg.c_str()[0]=='/'){
	      char absDir[PSIZE];
	      //absDir = (char *)malloc(PSIZE);
	      memset(absDir,0,PSIZE);
	      if(absDir!=NULL){
	        strcat(absDir,state.root_dir.c_str());
	        strcat(absDir,cmd.arg.c_str());
	        if(mkdir(absDir,S_IRWXU)==0){
	          strcat(res,"257 \"");
	          strcat(res,cmd.arg.c_str());
	          strcat(res,"\" directory created.\r\n");
	          state.message = std::string(res);
	        }else{
	          state.message = "550 Failed to create directory. Check path or permissions.\r\n";
	        }
	      }else{
	        state.message = "500 Internal error.\r\n";
	      }
	    }
	    /* Relative path */
	    else{
	      if(mkdir(cmd.arg.c_str(),S_IRWXU)==0){
	        sprintf(res,"257 \"%s\" directory created.\r\n",cmd.arg.c_str());
	        state.message =std::string( res);
	      }else{
	        state.message = "550 Failed to create directory.\r\n";
	      }
	    }
	  }else{
	    state.message = "500 Login with USER and PASS.\r\n";
	  }
	  sendCommand( state.message );
	}

	/** PWD command */
	void handlePwdCommand()
	{
		 std::string path(state.currentDirectory);
		 std::cout<<"Current directory: "<<state.currentDirectory<<std::endl;
		 if(state.logged_in){

		    if(state.currentDirectory.size()>0){
		    	std::string::size_type i = state.currentDirectory.find(state.root_dir);
		    	if (i != std::string::npos)
		    		path.erase(i, state.root_dir.length());
		    	if(path.back()=='/'){
		    		path=path.substr(0, path.length()-1);
		    	}
		      state.message = "257 \""+path+"/\"\r\n";

		    }else{
		      state.message = "550 Failed to get pwd.\r\n";
		    }
		  //  delete cwd;
		    sendCommand(state.message);
		  }
	}

	  bool pathIsOk(std::string path){
			DIR *pDir;
			bool pathOk=true;
			std::cout<<"Opening dir "<<std::endl;
			pDir = opendir (path.c_str());
			pathOk=pDir != NULL;
			if(pathOk){
				closedir (pDir);
			}
			std::cout<<"Dir opened "<<std::endl;
			return pathOk;
	  }
	/** CWD command */
	void handleCwdCommand()
	{
		// std::cout<<"Entering chdir, argument: "<<  cmd.arg<< " Length: "<< cmd.arg.size()<< std::endl;
		// std::cout<<"Current dir : "<< state.currentDirectory<<" Relative path:"<< state.currentRelativePath<< std::endl;
	  if(state.logged_in){
		  auto wDir=state.currentDirectory;
		  if( cmd.arg.compare("..") ==0){
			  auto pos=state.currentRelativePath.find_last_of('/');
			  if(state.currentRelativePath.compare("/")==0 || pos==std::string::npos){
				  state.message = "550 Permission denied.\r\n";
			  }else {
				  if(state.currentRelativePath.size()>1){
					  if( pos>1 ){
						//	 std::cout<<"New dir relative:"<< state.root_dir+"/"+state.currentRelativePath.substr(0,pos-1 )<< std::endl;
							 state.currentRelativePath=state.currentRelativePath.substr(0,pos-1 );
					  }else{
						  state.currentRelativePath='/';
					  }
					  state.currentDirectory=state.root_dir+   state.currentRelativePath;
					//  std::cout<<"New relative path: "<< state.currentRelativePath<< std::endl;
					  state.message = "250 Directory successfully changed.\r\n";
				  }

			  }
		  }
		  else{
				  bool pathOk=true;
				if(cmd.arg.front()  == '/'){

					wDir=state.root_dir+ cmd.arg;
					//std::cout<<"Trying to enter path   "<<wDir <<  std::endl;
					pathOk=pathIsOk(wDir);
					if(pathOk){
						state.currentRelativePath=cmd.arg;
					//	std::cout<<"New relative path: "<< state.currentRelativePath<< std::endl;
						state.message = "250 Directory successfully changed.\r\n";
						 state.currentDirectory=state.root_dir+   state.currentRelativePath;
					}else{
					//	std::cout<<"Path is not ok "<< std::endl;
						state.message = "550 Failed to change directory.\r\n";
					}


				}else{
					// std::cout<<"Validating: "<<state.root_dir+ state.currentRelativePath+ (state.currentRelativePath.back()=='/'?"":  "/")+cmd.arg<<std::endl;
					pathOk=pathIsOk(state.root_dir+state.currentRelativePath+ (state.currentRelativePath.back()=='/'?"":  "/")+cmd.arg);
					//std::cout<<"Dir validated "<<std::endl;
					if(pathOk){
						wDir+="/"+cmd.arg;
						state.currentRelativePath+= (state.currentRelativePath.back()=='/'?"":  "/")+cmd.arg;
						 state.currentDirectory=state.root_dir+   state.currentRelativePath;
						// std::cout<<"Current set directory: "<<state.currentDirectory<<std::endl;
					}
				   //std::cout<<"Working dir: "<<wDir<<" relative path: "<< 	state.currentRelativePath<<std::endl;
				}
				if(pathOk){//chdir(wDir.c_str())==0){
					//state.currentDirectory=wDir;
				  state.message = "250 Directory successfully changed.\r\n";
				}else{
				  state.message = "550 Failed to change directory.\r\n";
				}
			  }
	    }/*else{
	      state.message = "500 Internal error.\r\n";
	    }*/
	  else{
	    state.message = "500 Login with USER and PASS.\r\n";
	  }
	  sendCommand(state.message);

	}

	void handleSiteCommand(){
	  if(state.logged_in){
	    char site_cmd[15];
	    memset(site_cmd,0,15);
	    char site_args[PSIZE];
	    memset(site_args,0,PSIZE);

	    sscanf(cmd.arg.c_str(),"%s %s",site_cmd,site_args);

	    convertToUpperCase(site_cmd,sizeof(site_cmd));
	    std::cout<<"SITE: "<<site_cmd<<std::endl;
	    if(strcmp(site_cmd,"CRC")==0){
	      unsigned long crc32;
	      int err;
	      char absFile[PSIZE];
	      memset(absFile,0,PSIZE);
	      if(site_args[0]=='/'){
	        strcat(absFile,state.root_dir.c_str());
	      }
	      strcat(absFile,site_args);
	      FILE *fp = fopen(absFile,"r");
	      if(fp!=NULL){

	        err = Crc32_ComputeFile(fp, &crc32);

	        if(err == -1){
	          state.message = "550 Could not get file CRC.\r\n";
	        }else{
	          char crc_resp[25];
	          memset(crc_resp,0,25);
	          sprintf(crc_resp, "213 %lu\r\n", crc32);
	          state.message = std::string(crc_resp);
	        }
	        err = fclose(fp);
	        fp = NULL;
	      }else{
	        state.message = "550 Could not open file.\r\n";
	      }

	    }else if(strcmp(site_cmd,"INFO")==0){

	      struct statfs vfs;

	      if(statfs("/mnt/sdcard/", &vfs) == 0){

	        char result[BSIZE];
	        memset(result, 0, BSIZE);
	        char blocksAvl[50];
	        memset(blocksAvl,0,50);
	        ulonglong blckAvlr = ((vfs.f_bfree * vfs.f_bsize)/1024) - 1048576;
	        ulonglong blocksTotal = ((vfs.f_blocks * vfs.f_bsize)/1024) - 1048576;
	        if(blckAvlr <= 1048576 )
	          blckAvlr = 0;
	        ulonglong blocksUsed = blocksTotal - blckAvlr;
	        int usedPrc = (blocksUsed * 100)/blocksTotal;
	        sprintf(blocksAvl, "  %llu    %llu   %llu    %d%%\r\n", blocksTotal, blocksUsed, blckAvlr, usedPrc);

	        strcat(result,"214-CG200P Info:\r\n");
	        strcat(result,"CG200P Volume Label:\r\n");
	        strcat(result,"\r\n");
	        strcat(result,"\r\n");
	        strcat(result,"1k blocks    Used    Available   Use%\r\n");
	        strcat(result,blocksAvl);
	        strcat(result,"214 CG200P info complete\r\n");
	        state.message = std::string(result);

	      }else{
	        state.message ="502 Cannot get the available blocks.\r\n";
	      }
	    }else{
	      state.message = "500 Unknown command.\r\n";
	    }
	  }else{
	    state.message = "530 Please login with USER and PASS.\r\n";
	  }
	  sendCommand( state.message);
	}

	void convertToUpperCase(char *sPtr, int limit)
	{
	  int i = 0;
	  while(i < limit && sPtr[i] != '\0')
	  {
	    sPtr[i] = toupper(sPtr[i]);
	    i++;
	  }
	}
	/** Handle STOR command. TODO: check permissions. */
	void handleStorCommand()
	{
		 char absFile[PSIZE];

		memset(absFile,0,PSIZE);

		    if(cmd.arg.c_str()[0]=='/'){
			    char absFile[PSIZE];

			    	if(state.logged_in){
					  if(!(state.mode==SERVER)&&!(state.mode==CLIENT)){
						state.message = "503 Please use PASV or PORT first.\r\n";
					  }
					  /* Passive mode */
					  else{
						//  std::cout<< "Values Before : "<<state.act_port <<"Local add: "<<state.ip_addr_server <<std::endl;
						  state.message = "125 Data connection already open; transfer starting.\r\n";
						  sendCommand( state.message );
						  int bytesReceived =readFileFromSocket(state.ip_addr_server, state.act_port, std::string(absFile));

						  /* Internal error */
						  if(bytesReceived < 0){
							perror("ftp_stor: read error.");
							std::cerr << "ftp_stor: read error." <<std::endl ;
							exit(EXIT_SUCCESS);
						  }else{

							state.message = "226 File send OK.\r\n";
						  }

					  }
			    }else{
			      state.message = "530 Please login with USER and PASS.\r\n";
			    }

			    sendCommand(state.message);
		       strcat(absFile,state.root_dir.c_str());
		    }
		    strcat(absFile,cmd.arg.c_str());

		    if(state.logged_in){
		      if(!(state.mode==SERVER)&&!(state.mode==CLIENT)){
		        state.message = "503 Please use PASV or PORT first.\r\n";
		      }

		      /* Passive mode */
		      else{
		    	    std::cout<<"Client IP address: "<< state.act_ip_addr<< " Port: "<<state.act_port<<std::endl;
		    	    state.message = "125 Data connection already open; transfer starting.\r\n";
					 sendCommand(state.message);
				   int bytesReceived = readFileFromSocket(state.act_ip_addr, state.act_port,  std::string(absFile));


				  if(bytesReceived < 0){

					std::cerr << "ftp_stor: read error." <<std::endl ;
					exit(EXIT_FAILURE);
				  }else{

					state.message = "226 File send OK.\r\n";
				  }

		      }
		    }else{
		      state.message = "530 Please login with USER and PASS.\r\n";
		    }
		   // isOpen=true;
		    sendCommand(state.message);
		    state.mode = NORMAL;


	}

	int sendFileToSocket(std::string ipAddress, int port,  std::string fileName, long file_size){
		const unsigned int buff_size = 8192;
				 try{
					 	 	 TCPConnector connector;
					 		auto tcpStream2=connector.connect(state.act_ip_addr.c_str(), state.act_port );

					 		 auto filePath=state.currentDirectory +( state.currentDirectory.back()== '/' ?"":"/")+fileName;


				 			//std::cout << "Sending, path " << fileName<<" Size:"<<file_size<<std::endl;
				 			 char buffer[buff_size];

				 			 //int accsesInt = access(fileName.c_str(),R_OK);
				 			  FILE* fp = fopen(fileName.c_str(),"rb");// O_RDONLY);

				 			// std::cout << "Openning C" << fileName << std::endl;
				 			//std::cout << "Sending, path " << fileName<<" Size:"<<file_size<<std::endl;
				 			int r=1;
				 			int count=0;
				 			 while ( (r=fread(buffer, sizeof(char), buff_size, fp)) > 0) {
				 				//ftpserverc
				 				tcpStream2->send(buffer, r);
				 				memset(buffer, 0,buff_size );
				 				count+=r;

				 			 }
				 			//std::cout << "Sending.. " << r<<" count: "<< count <<".."<<std::endl;
				 			fflush(fp);
				 			 fclose(fp);



		 					tcpStream2->close();
		 					delete tcpStream2;
		 					//close(fp);
				 			 std::cout << "Done sending file " << fileName;


				 		}

				 	  catch(std::exception& e){
				 		  std::cerr << "Unknow excepion: " << e.what()<<std::endl ;

				 	  }
				 		return 0;

	}

	int readFileFromSocket(std::string ipAddress, int port,  std::string fileName){
		const int buff_size = 8192;

		 char incommingBuffer[buff_size];
		int bytesReceived = -1;
		 int nobytesReceived=0;//
		 // std::cout << "Root path: " << state.root_dir<<std::endl ;
		 auto filePath=state.currentDirectory +( state.currentDirectory.back()== '/' ?"":"/")+fileName;//+( state.currentDirectory.back()== "/" ?"":"/")
		//  std::cout << "Entering reading file: " << filePath<<std::endl ;
		try{
			 TCPConnector connector;
			 auto tcpStream2=connector.connect(state.act_ip_addr.c_str(), state.act_port,900 );
			  FILE *fp = fopen(filePath.c_str(),"w");
			  bool isOpenClient=true;
			while(isOpenClient){
				 bytesReceived =tcpStream2->receive(incommingBuffer, sizeof(incommingBuffer),10);
				nobytesReceived+=bytesReceived;
				if(bytesReceived>0){
					  fwrite(incommingBuffer,1,bytesReceived,fp);
				}
				isOpenClient=bytesReceived>0;
		   }
			 fflush(fp);
			tcpStream2->close();
			delete tcpStream2;
		}

	  catch(std::exception& e){
		  std::cerr << "Unknow excepion: " << e.what()<<std::endl ;

	  }
		return nobytesReceived;
	}
	/** ABOR command */
	void handleAbortCommand()
	{
	  if(state.logged_in){
	    state.message = "226 Closing data connection.\r\n";
	    state.message = "225 Data connection open; no transfer in progress.\r\n";
	  }else{
	    state.message = "530 Please login with USER and PASS.\r\n";
	  }
	  sendCommand(state.message);

	}
	 /* Generate random port for passive mode
	 * @param state Client state
	 */
	void gen_port(Port& port)
	{
	  srand(time(NULL));
	  port.p1 = 128 + (rand() % 64);
	  port.p2 = rand() % 0xff;

	}

	/** PASV command */
	void handlePasvCommand()
	{
	  if(state.logged_in){
		  std::cout <<"Entering passive mode: "<< state.act_ip_addr<<std::endl;
		  auto address= _stream->getPeerIP();// socket().peerAddress().host().toString();
		   Port port ;
	    std::vector<std::string> numbers;
	    gen_port(port);

		  std::stringstream ss(address);
		  while( ss.good() )
		  {
			  std::string substr;
			  getline( ss, substr, '.' );

			  numbers.push_back (substr);
		  }
	    state.act_port=(256*port.p1)+port.p2;
	    //state.act_ip_addr=socket().peerAddress().host().toString();
	    state.act_ip_addr=_stream->getPeerIP();
	    std::stringstream ss2;
	    ss2 <<  state.act_port;

	    state.message ="227 Entering Passive Mode ("+numbers[0]+","+numbers[1]+","+numbers[2]+","+numbers[3]+","+ ss2.str() +")\r\n";
	    state.mode = SERVER;

	    isPasiveModeOn=true;
	    std::cout <<"Entering passive mode: "<< state.act_ip_addr<<std::endl;

	    //delete port;
	  }else{
	    state.message = "530 Please login with USER and PASS.\r\n";

	  }
	  sendCommand(state.message);
	}
	/** Handle RMD */
	void handleRmdCommand()
	{
	  if(!state.logged_in){
	    state.message = "530 Please login first.\r\n";
	  }else{
	    char fileName[PSIZE];
	    memset(fileName,0,PSIZE);
	    if(cmd.arg.data() [0]=='/'){
	      strcat(fileName,state.root_dir.c_str());
	    }
	    strcat(fileName,cmd.arg.c_str());
	    if(rmdir(fileName)==0){
	      state.message = "250 Requested file action okay, completed.\r\n";
	    }else{
	      state.message = "550 Cannot delete directory.\r\n";
	    }
	  }
	  sendCommand(state.message);

	}
	void  handleModeCommand(){
	  if(state.logged_in){
	    state.message = "200 Change mode successfully.\r\n";
	  }else{
	    state.message = "530 Please login with USER and PASS.\r\n";
	  }
	  sendCommand(state.message);
	}

	/** Handle SIZE (RFC 3659) */
	void handleSizeCommand()
	{
	  if(state.logged_in){
	    struct stat statbuf;
	    char filesize[128];
	    memset(filesize,0,128);

	    char fileName[PSIZE];
	    memset(fileName,0,PSIZE);
	    if(cmd.arg.data()[0]=='/'){
	      strcat(fileName,state.root_dir.c_str());
	    }
	    strcat(fileName,cmd.arg.c_str());
	    /* Success */
	    if(stat(fileName,&statbuf)==0){
	      sprintf(filesize, "213 %9jd\r\n", (intmax_t)statbuf.st_size);
	      state.message = filesize;
	    }else{
	      state.message = "550 Could not get file size.\r\n";
	    }
	  }else{
	    state.message = "530 Please login with USER and PASS.\r\n";
	  }

	  sendCommand(state.message);

	}

	void handleStruCommand (){
	  if(state.logged_in){
	    state.message = "200 Set stru successfully.\r\n";
	  }else{
	    state.message = "530 Please login with USER and PASS.\r\n";
	  }
	  sendCommand(state.message);
	}


	void handleListCommand()
	{
	  if(state.logged_in){
	    struct dirent *entry;
	    struct stat statbuf;
	    struct tm *time;
	    char timebuff[80];
	    std::string path(state.currentDirectory);

	    time_t rawtime;


	    /* Just chdir to specified path */
	    //EBC pending to fix this
	    /*if(cmd.arg.size()>0&& cmd.arg.front() !='-'){

	      if(cmd.arg.back()=='/' && cmd.arg.length()==1){
	    	  path=state.root_dir;
	      }else{
	    	  path=state.root_dir+(cmd.arg.back()=='/'?"":"/") +cmd.arg;

	      }

	    }else{
	    	if(path.back()=='/'){
				state.currentDirectory=state.currentDirectory.substr(0, state.currentDirectory.length()-1);
				path=state.currentDirectory;
	    	}
	    }*/




	   // std::cout<<"Directory: "<<   path<< " Argument:"<<cmd.arg<< std::endl;
	    mu.lock();
	   // std::cout<<"Locking done!!!"<<  std::endl;
	   auto res= chdir(path.c_str());
	   if(res<0){
		   mu.unlock();
		   //std::cout<<"Dir or file does not exist!!!"<<  std::endl;
		   state.message = "550 Failed to open directory.\r\n";
	   }else{
	    DIR *dp = opendir(path.c_str());
	  //  std::cout<<"Chdir done!!!"<<  std::endl;

	    std::vector<std::string> list;
	    if(dp==NULL){
	      state.message = "550 Failed to open directory.\r\n";
	    }else{
	      if(state.mode == SERVER || state.mode == CLIENT){

	       // connection = get_connection_mode(state);
	        state.message = "150 File status okay; about to open data connection.\r\n";
	        while((entry=readdir(dp)) != NULL){
	          if(stat(entry->d_name,&statbuf)==-1){
	            fprintf(stderr, "FTP: Error reading file stats...\n");
	          }else{
	        	  // std::cout<<"Directory: "<< entry->d_name<<std::endl;
					if(strcmp(entry->d_name, ".")!=0 && strcmp(entry->d_name,"..")!=0){
					  char *perms =(char *) malloc(9);
					  memset(perms,0,9);

					  /* Convert time_t to tm struct */
					  rawtime = statbuf.st_mtime;
					  time = localtime(&rawtime);
					  strftime(timebuff,80,"%b %d %H:%M",time);
					  str_perm((statbuf.st_mode & ALLPERMS), perms);
					  char buffer[BSIZE];
					  memset(buffer,0,BSIZE);
					  sprintf(buffer,
							   "%c%s %5d %4d %4d %9jd %s %s\r\n",
							   (entry->d_type==DT_DIR)?'d':'-',
							   perms,statbuf.st_nlink,
							   statbuf.st_uid,
							   statbuf.st_gid,
							   (intmax_t)statbuf.st_size,
							   timebuff,
							   entry->d_name);

					   list.push_back(std::string(buffer));

					}
	          }

	        }
			sendCommand(state.message);
	        state.message = "226 Directory send OK.\r\n";
	        if(state.mode == SERVER){
				 for(auto const& str : list){
					sendCommand(str);
				}

	       }else{
					sendDataClientMode(list);

	       	 }
	        state.mode = NORMAL;
	      }else{
	        state.message = "503 Please use PASV or PORT first.\r\n";
	      }
	    }
	    closedir(dp);
	    chdir(state.root_dir.c_str());
	    mu.unlock();
	  }
	  }
	  else{
	  	    state.message = "530 Please login with USER and PASS.\r\n";
	  	  }
	  state.mode = NORMAL;
	  sendCommand(state.message);

	}

	void sendDataClientMode(std::vector<std::string> list){



			try{
					TCPConnector connector;
					auto tcpStream2=connector.connect(state.act_ip_addr.c_str(), state.act_port,900 );
					for(auto const& str : list){
						tcpStream2->send(str.data(), (int)str.size());

					}
					tcpStream2->close();
					delete tcpStream2;

			}
			 catch(std::exception& e){
							  std::cerr << "Unknow excepion: " << e.what()<<std::endl ;
			 }


	}



	void handleFtpPortCommand(){
	  if(state.logged_in){
	    if(cmd.arg.size()>0){
	      std::vector<std::string> numbers;
	      std::stringstream ss(cmd.arg);
	      long port[2];

	      while( ss.good() )
	      {
	          std::string substr;
	          getline( ss, substr, ',' );
	          numbers.push_back (substr);
	      }
	      port[0] = strtol( numbers[4].c_str(),NULL,10);
	      port[1] = strtol( numbers[5].c_str(),NULL,10);

	      state.act_ip_addr =  numbers [0] +"." + numbers[1]+"."+ numbers[2]+"."+ numbers[3];
	      state.act_port=(port[0] * 256) + port[1];

	      state.message ="200 PORT Command successful.\r\n";

	      state.mode = CLIENT;

	    }else{
	      state.message = "501 No arguments in PORT command.\r\n";
	    }
	  }else{
	    state.message = "530 Please login with USER and PASS.\r\n";
	    //printf("%s",state.message);
	  }
	  sendCommand(state.message);
	}

	/**
	 * Handle TYPE command.
	 * BINARY only at the moment.
	 */
	void handleTypeCommand()
	{
	  if(state.logged_in){
	    if(cmd.arg.c_str()[0]=='I'){
	      state.message = "200 Switching to Binary mode.\r\n";
	    }else if(cmd.arg.c_str()[0]=='A'){

	      /* Type A must be always accepted according to RFC */
	      state.message = "200 Switching to ASCII mode.\r\n";
	    }else{
	      state.message = "504 Command not implemented for that parameter.\r\n";
	    }
	  }else{
	    state.message = "530 Please login with USER and PASS.\r\n";
	  }
	  sendCommand(state.message);
	}

	/**
	 * Converts permissions to string. e.g. rwxrwxrwx
	 * @param perm Permissions mask
	 * @param str_perm Pointer to string representation of permissions
	 */
	void str_perm(int perm, char *str_perm)
	{
	  int curperm = 0;
	//  int flag = 0;
	  int read, write, exec;

	  /* Flags buffer */
	  char fbuff[3];

	  read = write = exec = 0;

	  int i;
	  for(i = 6; i>=0; i-=3){
	    /* Explode permissions of user, group, others; starting with users */
	    curperm = ((perm & ALLPERMS) >> i ) & 0x7;

	    memset(fbuff,0,3);
	    /* Check rwx flags for each*/
	    read = (curperm >> 2) & 0x1;
	    write = (curperm >> 1) & 0x1;
	    exec = (curperm >> 0) & 0x1;

	    sprintf(fbuff,"%c%c%c",read?'r':'-' ,write?'w':'-', exec?'x':'-');
	    strcat(str_perm,fbuff);

	  }
	}


	/** QUIT command */
	void handleQuitCommand()
	{
	  state.message = "221 Goodbye, closing connection.\r\n";
	  sendCommand(state.message);
	  isOpen=false;

	}
	void handlePasswordCommand(){
		if(state.username_ok){
		    state.logged_in = true;
		    state.message = "230 User logged in\r\n";
		  }else{
		    state.message = "500 Invalid username or password\r\n";
		  }
		sendCommand(state.message);
	}
	void sendCommand(const std::string message){

		try {
			 _stream->send(message.c_str(), message.size());
		}
		catch(std::exception& e){
									  std::cerr << "Unknow excepion: " << e.what()<<std::endl ;
					 }
	}

	void parse_command(const std::string data){
			auto cmdString= data.substr(0,4);
			if(cmdString.back()=='\r' || cmdString.back()=='\n'){
				cmdString= cmdString.substr(0, cmdString.length()-1);
			}
			std::cout<<"Data:"<<data<<std::endl;
			//data=trim(data);
			cmd.arg.clear();
			cmd.command.clear();
			std::transform(cmdString.begin(), cmdString.end(),cmdString.begin(), ::toupper);

			std::vector<std::string> result;
			stringstream ss(data);
			while( ss.good() )
			{
				std::string substr;
				getline( ss, substr, ' ' );
				result.push_back( substr );
			}

			cmd.command=trim(cmdString);
			if(result.size()==2){//data.size()>7){//result.size()>1){//
				auto res=result[result.size()-1];
				cmd.arg=res.erase(res.length()-2);

			}else if(result.size()>2){
				for(int i=1;i<result.size();i++){
									cmd.arg.append(result[i]+" ");
				}
				cmd.arg=trim(cmd.arg);
				cmd.arg=cmd.arg.erase(cmd.arg.size()-2);
				std::cout<<"ARG:"<<cmd.arg<<std::endl;

			}


		 }

	inline std::string trim(std::string str)
	{
		str.erase(0, str.find_first_not_of(' '));       //prefixing spaces
		str.erase(str.find_last_not_of(' ')+1);         //surfixing spaces
		return str;
	}


	/**
	 * Creates socket on specified port and starts listening to this socket
	 * @param port Listen on this port
	 * @return int File descriptor for new socket
	 */
	void createSocket(int port)
	{



	}







public :

	/*template<typename T>
	void removeSubstrs(basic_string<T>& s,
	                   const basic_string<T>& p) {
	   basic_string<T>::size_type n = p.length();

	   for (basic_string<T>::size_type i = s.find(p);
	        i != basic_string<T>::npos;
	        i = s.find(p))
	      s.erase(i, n);
	}*/

	 void ftpHandler(){
		 try{
			char incommingBuffer[BSIZE];

			  ssize_t len;

			std::cout << "Running Client " << _stream->getPeerIP()<< std::endl;

			initSequence();
			while ((len = _stream->receive(incommingBuffer, sizeof(incommingBuffer),3600)) > 0   ) {
				std::cout <<"raw data:"<<incommingBuffer<<std::endl;
				std::string s( reinterpret_cast< char const* >(incommingBuffer) ) ;
				std::cout << "User "<< ((state.username.size()==0)?"unknown":state.username)<<" sent command: "<< s ;
				std::cout <<std::endl;
				parse_command(s);
				  response();
				memset( incommingBuffer,0,BSIZE);
				  if(!isOpen)
					  break;
			}

			_stream->close();

		  }
		 catch(std::exception& e){
			 	 std::cerr<<"Error: "<< e.what()<<std::endl;
		 }
	 }

	FtpServerConnection(TCPStream* stream ) {
		mapComandList.insert(std::pair<std::string,cmdlist>("ABOR",cmdlist::ABOR));
		mapComandList.insert(std::pair<std::string,cmdlist>("CWD",cmdlist::CWD));
		mapComandList.insert(std::pair<std::string,cmdlist>("DELE",cmdlist::DELE));
		mapComandList.insert(std::pair<std::string,cmdlist>("LIST",cmdlist::LIST));
		mapComandList.insert(std::pair<std::string,cmdlist>("MDTM",cmdlist::MDTM));
		mapComandList.insert(std::pair<std::string,cmdlist>("MKD",cmdlist::MKD));
		mapComandList.insert(std::pair<std::string,cmdlist>("XMKD",cmdlist::MKD));
		mapComandList.insert(std::pair<std::string,cmdlist>("NLST",cmdlist::NLST));
		mapComandList.insert(std::pair<std::string,cmdlist>("PASS",cmdlist::PASS));
		mapComandList.insert(std::pair<std::string,cmdlist>("PASV",cmdlist::PASV));
		mapComandList.insert(std::pair<std::string,cmdlist>("PORT",cmdlist::PORT));
		mapComandList.insert(std::pair<std::string,cmdlist>("PWD",cmdlist::PWD));
		mapComandList.insert(std::pair<std::string,cmdlist>("XPWD",cmdlist::PWD));
		mapComandList.insert(std::pair<std::string,cmdlist>("QUIT",cmdlist::QUIT));
		mapComandList.insert(std::pair<std::string,cmdlist>("RETR",cmdlist::RETR));
		mapComandList.insert(std::pair<std::string,cmdlist>("RMD",cmdlist::RMD));
		mapComandList.insert(std::pair<std::string,cmdlist>("RNFR",cmdlist::RNFR));
		mapComandList.insert(std::pair<std::string,cmdlist>("RNTO",cmdlist::RNTO));
		mapComandList.insert(std::pair<std::string,cmdlist>("SITE",cmdlist::SITE));
		mapComandList.insert(std::pair<std::string,cmdlist>("SIZE",cmdlist::SIZE));
		mapComandList.insert(std::pair<std::string,cmdlist>("STOR",cmdlist::STOR));
		mapComandList.insert(std::pair<std::string,cmdlist>("TYPE",cmdlist::TYPE));
		mapComandList.insert(std::pair<std::string,cmdlist>("USER",cmdlist::USER));
		mapComandList.insert(std::pair<std::string,cmdlist>("NOOP",cmdlist::NOOP));
		mapComandList.insert(std::pair<std::string,cmdlist>("MODE",cmdlist::MODE));
		mapComandList.insert(std::pair<std::string,cmdlist>("STRU",cmdlist::STRU));
		mapComandList.insert(std::pair<std::string,cmdlist>("DIS",cmdlist::DIS));
		//std::lock_guard<std::mutex> guard(mu);
		_stream=stream;
		 state.ip_addr_server=_stream->getServerIP();
		 std::cout << "Server IP " << state.ip_addr_server << std::endl;

    }

	std::thread MakeThread() {

	      return std::thread( [this] {

	    	  this->ftpHandler();
	      } );
	    }


	~FtpServerConnection() {
		_stream->close();
		delete _stream;
		//std::cout << "Liberating memory " <<  std::endl;
	}
};
} /* namespace PA_CG3000 */
#endif
