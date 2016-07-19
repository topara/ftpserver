/*
 * TCPStream.h
 *
 *  Created on: Jul 7, 2016
 *      Author: root
 */

#ifndef TCPSTREAM_H_
#define TCPSTREAM_H_


#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string>
 #include <sys/ioctl.h>
#include <sstream>

namespace PA_CG3000 {
using namespace std;
class TCPStream {

	 int     m_sd;
	    string  m_peerIP;
	    int     m_peerPort;
	    std::string m_serverIP;


	    /*----------------------------------------------------------------------
	     Portable function to set a socket into nonblocking mode.
	     Calling this on a socket causes all future read() and write() calls on
	     that socket to do only as much as they can immediately, and return
	     without waiting.
	     If no data can be read or written, they return -1 and set errno
	     to EAGAIN (or EWOULDBLOCK).
	     Thanks to Bjorn Reese for this code.
	    ----------------------------------------------------------------------*/
	    inline int setNonblocking(int fd)
	    {
	        int flags;

	        /* If they have O_NONBLOCK, use the Posix way to do it */
	    #if defined(O_NONBLOCK)
	        /* Fixme: O_NONBLOCK is defined but broken on SunOS 4.1.x and AIX 3.2.5. */
	        if (-1 == (flags = fcntl(fd, F_GETFL, 0)))
	            flags = 0;
	        return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
	    #else
	        /* Otherwise, use the old way of doing it */
	        flags = 1;
	        return ioctl(fd, FIONBIO, &flags);
	    #endif
	    }

public:
	    friend class TCPAcceptor;
	        friend class TCPConnector;
	        void close();
	        ~TCPStream();

	        ssize_t send(const char* buffer, size_t len);
	        ssize_t receive(char* buffer, size_t len, int timeout=0);

	        string getPeerIP();
	        int    getPeerPort();

	        enum {
	            connectionClosed = 0,
	            connectionReset = -1,
	            connectionTimedOut = -2
	        };
	        std::string getServerIP() const;
	        //void getServerIP(int* ip);


private:
	        template <typename T>
			 std:: string NumberToString ( T Number )
			  {
				 std::ostringstream ss;
				 ss << Number;
				 return ss.str();
			  }
	    bool waitForReadEvent(int timeout);
	    void calculateServerIP( int *ip);
	       TCPStream(int sd, struct sockaddr_in* address);
	       TCPStream();
	       TCPStream(const TCPStream& stream);



};

} /* namespace PA_CG3000 */

#endif /* TCPSTREAM_H_ */
