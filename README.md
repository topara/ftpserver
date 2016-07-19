# ftpserver
A multithread ftp server in c++ using  C sockets. I build this code for a project which needed a ftp server running  with android tool chain. I used eclipse CDT(luna) on ubuntu 14.01, cross g++ 4.9.2 compiler and C++ 11 dialect.
It uses  android ndk r10e. But, you are free to use any other tool chain.
It does not support passive mode.
  I coded this because I wanted to migrate an  c version which was using linux processes(fork). It used to crash every half hour, so, my first attemp was to use C threads, and it worked. But, due to the use of non reentrant functions for directory's management, it didn't work.
  Then, I tried out using poco libraries. It worked, but it consumed almost 70% of the cpu resources!!!!!!!!!!!...
  So, at the end , I ended up using  a wrapper for raw C sockets and it WORKED!!!!!.

Please, notice this is my first contibution to github, so, please be kind.
