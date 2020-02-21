/*-
 * Copyright (c) 2017 Michael Tuexen
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int
main(void)
{
	char *remote_addr, *remote_port, *server_name, *server_port;
	char *transport_protocol;
	char *fastopen;
	char *tcp_timestamp, *tcp_sack, *tcp_window_scaling, *tcp_ecn;

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
	fastopen = getenv("FASTOPEN");
	tcp_timestamp = getenv("TCP_TIMESTAMPS");
	tcp_sack = getenv("TCP_SACK");
	tcp_window_scaling = getenv("TCP_WINDOW_SCALING");
	tcp_ecn = getenv("TCP_ECN");

	printf("Content-type: text/html\r\n"
	       "\r\n"
	       "<!DOCTYPE html>\n"
	       "<html>\n"
	       "<head>\n"
	       "<meta charset=\"UTF-8\">\n"
	       "<title>Happy Eyeballs</title>\n"
	       "</head>\n"
	       "<body>\n"
	       "<p>This page was requested from %s:%s and served by %s:%s using %s as the transport protocol.</p>\n",
	       remote_addr, remote_port, server_name, server_port, transport_protocol);
	if (fastopen != NULL)
		printf("<p>Fast open was%s used.</p>\n",
		       strcmp(fastopen, "YES") != 0 ? " not" : "");
	if (tcp_timestamp != NULL) {
		printf("<p>TCP timestamp support was%s negotiated.</p>\n",
		       strcmp(tcp_timestamp, "YES") != 0 ? " not" : "");
	}
	if (tcp_sack != NULL) {
		printf("<p>TCP SACK support was%s negotiated.</p>\n",
		       strcmp(tcp_sack, "YES") != 0 ? " not" : "");
	}
	if (tcp_window_scaling != NULL) {
		printf("<p>TCP window scaling was%s negotiated.</p>\n",
		       strcmp(tcp_window_scaling, "YES") != 0 ? " not" : "");
	}
	if (tcp_ecn != NULL) {
		printf("<p>TCP ECN support was%s negotiated.</p>\n",
		       strcmp(tcp_ecn, "YES") != 0 ? " not" : "");
	}
	printf("</body>\n"
	       "</html>\n");
	return (0);
}
