// This is a personal academic project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: http://www.viva64.com
#include <stdio.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <inttypes.h>
#include <unistd.h>
#include <ctype.h>
#include <syslog.h>

#define RBUFLEN		128
#define	MAXSIZE		138

/* GLOBAL VARIABLES */
char buf[RBUFLEN];		 /* reception buffer */

/* Provides service on the passed socket */
void service(int s)
{
    int	 n;

    for (;;)
    {
        n=read(s, buf, RBUFLEN-1);
        if (n < 0)
        {
            printf("Read error\n");
            close(s);
            printf("Socket %d closed\n", s);
            break;
        }
        else if (n==0)
        {
            printf("Connection closed by party on socket %d\n",s);
            close(s);
            break;
        }
        else
        {
            char local[MAXSIZE];
            char log[MAXSIZE];
            44: buf[RBUFLEN-1]='\0';
            45: strcpy(local,"script.sh ");
            46:strcat(local,buf);
            47: system(local);
            48:strncpy(log,local,140);
            49:syslog(1,"%s",local);
            50_strncpy(buf,log,MAXSIZE);
            51: if(write(s, buf, strlen(buf)) != strlen(buf))
              printf("Write error while replying\n");
            else
              printf("Reply sent\n");
        }
    }
}
