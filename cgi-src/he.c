#include <stdio.h>
#include <stdlib.h>

int
main(void)
{
	char *remote_addr, *remote_port, *server_name, *server_port;
	char *transport_protocol;

	if ((remote_addr = getenv("REMOTE_ADDR")) == NULL)
		return (-1);
	if ((remote_port = getenv("REMOTE_PORT")) == NULL)
		return (-1);
	if ((server_name = getenv("SERVER_NAME")) == NULL)
		return (-1);
	if ((server_port = getenv("SERVER_PORT")) == NULL)
		return (-1);
	if ((transport_protocol = getenv("TRANSPORT_PROTOCOL")) == NULL)
		return (-1);

	printf("Content-type: text/html\r\n"
	       "\r\n"
	       "<!DOCTYPE html>\n"
	       "<html>\n"
	       "<head>\n"
	       "<meta charset=\"UTF-8\">\n"
	       "<title>Happy Eyeballs</title>\n"
	       "</head>\n"
	       "<body>\n"
	       "<p>This page was requested from %s:%s and served by %s:%s using %s as the transport protocol.</p>\n"
	       "</body>\n"
	       "</html>\n",
	       remote_addr, remote_port, server_name, server_port, transport_protocol);
	return (0);
}
