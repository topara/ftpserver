/*
 * TCPStream.cpp
 *
 *  Created on: Jul 7, 2016
 *      Author: root
 */
#include <arpa/inet.h>
#include "TCPStream.h"

namespace PA_CG3000 {

TCPStream::TCPStream(int sd, struct sockaddr_in* address) : m_sd(sd) {
    char ip[50];
    //setNonblocking(m_sd);
    inet_ntop(PF_INET, (struct in_addr*)&(address->sin_addr.s_addr), ip, sizeof(ip)-1);
    m_peerIP = ip;
    m_peerPort = ntohs(address->sin_port);
    int ip2[4];
    calculateServerIP(ip2);
    m_serverIP=NumberToString<int>( ip2[0])+"."+NumberToString<int>( ip2[1])+"."+NumberToString<int>( ip2[2])+"."+NumberToString<int>( ip2[3]);
}

TCPStream::~TCPStream()
{
    ::close(m_sd);
}

ssize_t TCPStream::send(const char* buffer, size_t len)
{
    return write(m_sd, buffer, len);
}

ssize_t TCPStream::receive(char* buffer, size_t len, int timeout)
{
    if (timeout <= 0) return read(m_sd, buffer, len);

    if (waitForReadEvent(timeout) == true)
    {
    //	std::cout<<"Reading bytes"<<std::endl;
        return read(m_sd, buffer, len);
    }
    return connectionTimedOut;

}

std::string TCPStream::getServerIP() const{
	return m_serverIP;
}
/**
   * Get ip where client connected to
   * @param sock Commander socket connection
   * @param ip Result ip array (length must be 4 or greater)
   * result IP array e.g. {127,0,0,1}
 */
   void TCPStream::calculateServerIP( int *ip)
  {
	socklen_t addr_size = sizeof(struct sockaddr_in);
	struct sockaddr_in addr;
	getsockname(m_sd, (struct sockaddr *)&addr, &addr_size);
	int host,i;

	host = (addr.sin_addr.s_addr);
	for(i=0; i<4; i++){
	  ip[i] = (host>>i*8)&0xff;
	}
  }
string TCPStream::getPeerIP()
{
    return m_peerIP;
}

int TCPStream::getPeerPort()
{
    return m_peerPort;
}
void TCPStream::close(){
	::shutdown(m_sd,::SHUT_WR);
	::close(m_sd);
}


bool TCPStream::waitForReadEvent(int timeout)
{
    fd_set sdset;
    struct timeval tv;

    tv.tv_sec = timeout;
    tv.tv_usec = 0;
    FD_ZERO(&sdset);
    FD_SET(m_sd, &sdset);
    if (select(m_sd+1, &sdset, NULL, NULL, &tv) > 0)
    {
        return true;
    }
    return false;
}
} /* namespace PA_CG3000 */
