/*
 * TCPAcceptor.h
 *
 *  Created on: Jul 7, 2016
 *      Author: root
 */

#ifndef TCPACCEPTOR_H_
#define TCPACCEPTOR_H_
#include <string>
#include <netinet/in.h>
#include <stdio.h>
#include <arpa/inet.h>
#include "TCPStream.h"
 #include <sys/ioctl.h>
#include <iostream>
namespace PA_CG3000 {

class TCPAcceptor {

	 int    m_lsd;
	    int    m_port;
	    string m_address;
	    bool   m_listening;

	  public:
	    TCPAcceptor(int port, const char* address="");
	    ~TCPAcceptor();

	    int        start();
	    TCPStream* accept();

	  private:


	    TCPAcceptor() {}

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
};

} /* namespace PA_CG3000 */

#endif /* TCPACCEPTOR_H_ */
