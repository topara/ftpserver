/*
 * TCPAcceptor.cpp
 *
 *  Created on: Jul 7, 2016
 *      Author: root
 */

#include "TCPAcceptor.h"

namespace PA_CG3000 {
TCPAcceptor::TCPAcceptor(int port, const char* address)
    : m_lsd(0), m_port(port), m_address(address), m_listening(false) {}

TCPAcceptor::~TCPAcceptor()
{
    if (m_lsd > 0) {
        close(m_lsd);
    }
}

int TCPAcceptor::start()
{
    if (m_listening == true) {
        return 0;
    }

    m_lsd = socket(PF_INET, SOCK_STREAM, 0);
    struct sockaddr_in address;

    memset(&address, 0, sizeof(address));
    address.sin_family = PF_INET;
    address.sin_port = htons(m_port);
    if (m_address.size() > 0) {
        inet_pton(PF_INET, m_address.c_str(), &(address.sin_addr));
    }
    else {
        address.sin_addr.s_addr = INADDR_ANY;
    }

    int optval = 1;
    setsockopt(m_lsd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof optval);


    int result = bind(m_lsd, (struct sockaddr*)&address, sizeof(address));
    if (result != 0) {
        perror("bind() failed");
        return result;
    }
   // freeaddrinfo(address);
  //  setNonblocking(m_lsd);
    result = listen(m_lsd, 5);
    if (result != 0) {
        perror("listen() failed");
        return result;
    }
    m_listening = true;

    return result;
}




TCPStream* TCPAcceptor::accept()
{
    if (m_listening == false) {
        return NULL;
    }

    struct sockaddr_in address;
    socklen_t len = sizeof(address);
    memset(&address, 0, sizeof(address));
    int sd = ::accept(m_lsd, (struct sockaddr*)&address, &len);

    if (sd < 0) {
        perror("accept() failed");
        return NULL;
    }
   // setNonblocking(m_lsd);
    return new TCPStream(sd, &address);
}

} /* namespace PA_CG3000 */
