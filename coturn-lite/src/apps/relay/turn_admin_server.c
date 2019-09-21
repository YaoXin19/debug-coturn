/*
 * Copyright (C) 2011, 2012, 2013 Citrix Systems
 *
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
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <limits.h>
#include <ifaddrs.h>
#include <getopt.h>
#include <locale.h>
#include <libgen.h>

#include <pthread.h>

#include <signal.h>

//#include "libtelnet.h"

#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/resource.h>

#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <event2/http.h>

#include "userdb.h"
#include "mainrelay.h"

#include "ns_turn_utils.h"

#include "ns_turn_server.h"
#include "ns_turn_maps.h"

#include "apputils.h"

#include "turn_admin_server.h"

//#include "http_server.h"

#include "dbdrivers/dbdriver.h"

//#include "tls_listener.h"

///////////////////////////////

struct admin_server adminserver;

int use_cli = 1;

ioa_addr cli_addr;
int cli_addr_set = 0;

int cli_port = CLI_DEFAULT_PORT;

char cli_password[CLI_PASSWORD_LENGTH] = "";

int cli_max_output_sessions = DEFAULT_CLI_MAX_OUTPUT_SESSIONS;


int use_web_admin = 0;

ioa_addr web_admin_addr;
int web_admin_addr_set = 0;

int web_admin_port = WEB_ADMIN_DEFAULT_PORT;

///////////////////////////////

struct cli_session {
	evutil_socket_t fd;
	int auth_completed;
	size_t cmds;
	struct bufferevent *bev;
	ioa_addr addr;
//	telnet_t *ts;
	FILE* f;
	char realm[STUN_MAX_REALM_SIZE+1];
	char origin[STUN_MAX_ORIGIN_SIZE+1];
	realm_params_t *rp;
};

///////////////////////////////

#define CLI_PASSWORD_TRY_NUMBER (5)


struct toggleable_command {
	const char *cmd;
	vintp data;
};

struct toggleable_command tcmds[] = {
				{"stale-nonce",&turn_params.stale_nonce},
				{"stun-only",&turn_params.stun_only},
				{"no-stun",&turn_params.no_stun},
				{"secure-stun",&turn_params.secure_stun},
				{"no-udp-relay",&turn_params.no_udp_relay},
				{"no-tcp-relay",&turn_params.no_tcp_relay},
				{"no-multicast-peers",&turn_params.no_multicast_peers},
				{"allow-loopback-peers",&turn_params.allow_loopback_peers},
				{"mobility",&turn_params.mobility},
				{NULL,NULL}
};

static void cliserver_input_handler(struct evconnlistener *l, evutil_socket_t fd,
				struct sockaddr *sa, int socklen, void *arg)
{
	UNUSED_ARG(l);
	UNUSED_ARG(arg);
	UNUSED_ARG(socklen);

	addr_debug_print(adminserver.verbose, (ioa_addr*)sa,"CLI connected to");

	struct cli_session *clisession = (struct cli_session*)turn_malloc(sizeof(struct cli_session));
	ns_bzero(clisession,sizeof(struct cli_session));

	clisession->rp = get_realm(NULL);

	set_socket_options_fd(fd, TCP_SOCKET, sa->sa_family);

	clisession->fd = fd;

	addr_cpy(&(clisession->addr),(ioa_addr*)sa);

	clisession->bev = bufferevent_socket_new(adminserver.event_base,
					fd,
					TURN_BUFFEREVENTS_OPTIONS);
	debug_ptr_add(clisession->bev);
	//bufferevent_setcb(clisession->bev, cli_socket_input_handler_bev, NULL,
	//		cli_eventcb_bev, clisession);
	bufferevent_setwatermark(clisession->bev, EV_READ|EV_WRITE, 0, BUFFEREVENT_HIGH_WATERMARK);
	bufferevent_enable(clisession->bev, EV_READ); /* Start reading. */

//	clisession->ts = telnet_init(cli_telopts, cli_telnet_event_handler, 0, clisession);

/*	if(!(clisession->ts)) {
		const char *str = "Cannot open telnet session\n";
		addr_debug_print(adminserver.verbose, (ioa_addr*)sa,str);
		close_cli_session(clisession);
	} else {
	  print_str_array(clisession, CLI_GREETING_STR);
//	  telnet_printf(clisession->ts,"\n");
//	  telnet_printf(clisession->ts,"Type '?' for help\n");
	  if(cli_password[0]) {
	    const char* ipwd="Enter password: ";
//	    telnet_printf(clisession->ts,"%s\n",ipwd);
	  } else {
	    type_cli_cursor(clisession);
	  }
	}*/
}

static void web_admin_input_handler(ioa_socket_handle s, int event_type,
                                 ioa_net_data *in_buffer, void *arg, int can_resume) {
	UNUSED_ARG(event_type);
	UNUSED_ARG(can_resume);
	UNUSED_ARG(arg);

	int to_be_closed = 0;

	int buffer_size = (int)ioa_network_buffer_get_size(in_buffer->nbh);
	if (buffer_size > 0) {
		
		SOCKET_TYPE st = get_ioa_socket_type(s);
		
		if(is_stream_socket(st)) {
			if(is_http((char*)ioa_network_buffer_data(in_buffer->nbh), buffer_size)) {
				const char *proto = "HTTP";
				ioa_network_buffer_data(in_buffer->nbh)[buffer_size] = 0;
				if(st == TLS_SOCKET) {
					proto = "HTTPS";
					set_ioa_socket_app_type(s, HTTPS_CLIENT_SOCKET);

					TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s: %s (%s %s) request: %s\n", __FUNCTION__, proto, get_ioa_socket_cipher(s), get_ioa_socket_ssl_method(s), (char*)ioa_network_buffer_data(in_buffer->nbh));

					TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s socket to be detached: 0x%lx, st=%d, sat=%d\n", __FUNCTION__,(long)s, get_ioa_socket_type(s), get_ioa_socket_app_type(s));

					ioa_socket_handle new_s = detach_ioa_socket(s);
					if(new_s) {
						TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s new detached socket: 0x%lx, st=%d, sat=%d\n", __FUNCTION__,(long)new_s, get_ioa_socket_type(new_s), get_ioa_socket_app_type(new_s));
	
						send_https_socket(new_s);
					}
					to_be_closed = 1;
					
				} else {
					set_ioa_socket_app_type(s, HTTP_CLIENT_SOCKET);
					if(adminserver.verbose) {
						TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s: %s request: %s\n", __FUNCTION__, proto, (char*)ioa_network_buffer_data(in_buffer->nbh));
					}
//					handle_http_echo(s);
				}
			}
		}
	}

	if (to_be_closed) {
		if(adminserver.verbose) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
						  "%s: web-admin socket to be closed in client handler: s=0x%lx\n", __FUNCTION__, (long)s);
		}
		set_ioa_socket_tobeclosed(s);
	}
}


void setup_admin_thread(void)
{
	adminserver.event_base = turn_event_base_new();
	super_memory_t* sm = new_super_memory_region();
	adminserver.e = create_ioa_engine(sm, adminserver.event_base, turn_params.listener.tp, turn_params.relay_ifname, turn_params.relays_number, turn_params.relay_addrs,
				turn_params.default_relays, turn_params.verbose
	#if !defined(TURN_NO_HIREDIS)
				,turn_params.redis_statsdb
	#endif
		);

	if(use_web_admin) {
		// Support encryption on this ioa engine
		// because the web-admin needs HTTPS
		set_ssl_ctx(adminserver.e, &turn_params);
	}
    
	TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"IO method (admin thread): %s\n",event_base_get_method(adminserver.event_base));

	{
		struct bufferevent *pair[2];

		bufferevent_pair_new(adminserver.event_base, TURN_BUFFEREVENTS_OPTIONS, pair);

		adminserver.in_buf = pair[0];
		adminserver.out_buf = pair[1];

		bufferevent_setcb(adminserver.in_buf, admin_server_receive_message, NULL, NULL, &adminserver);
		bufferevent_enable(adminserver.in_buf, EV_READ);
	}

	{
		struct bufferevent *pair[2];

		bufferevent_pair_new(adminserver.event_base, TURN_BUFFEREVENTS_OPTIONS, pair);

		adminserver.https_in_buf = pair[0];
		adminserver.https_out_buf = pair[1];

		bufferevent_setcb(adminserver.https_in_buf, https_admin_server_receive_message, NULL, NULL, &adminserver);
		bufferevent_enable(adminserver.https_in_buf, EV_READ);
	}

    
	// Setup the web-admin server
	if(use_web_admin) {
		if(!web_admin_addr_set) {
			if(make_ioa_addr((const u08bits*)WEB_ADMIN_DEFAULT_IP, 0, &web_admin_addr) < 0) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Cannot set web-admin address %s\n", WEB_ADMIN_DEFAULT_IP);
				return;
			}
		}
	
		addr_set_port(&web_admin_addr, web_admin_port);
	
		char saddr[129];
		addr_to_string_no_port(&web_admin_addr,(u08bits*)saddr);

//        tls_listener_relay_server_type *tls_service = NULL;
//		tls_listener_relay_server_type *tls_service = create_tls_listener_server(turn_params.listener_ifname, saddr, web_admin_port, turn_params.verbose, adminserver.e, send_socket_to_admin_server, NULL);
	
/*		if (tls_service == NULL) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,"Cannot create web-admin listener\n");
			return;
		}*/
	
		addr_debug_print(adminserver.verbose, &web_admin_addr, "web-admin listener opened on ");
	}
    
	if(use_cli) {
		if(!cli_addr_set) {
			if(make_ioa_addr((const u08bits*)CLI_DEFAULT_IP,0,&cli_addr)<0) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,"Cannot set cli address %s\n",CLI_DEFAULT_IP);
				return;
			}
		}

		addr_set_port(&cli_addr,cli_port);

		adminserver.listen_fd = socket(cli_addr.ss.sa_family, ADMIN_STREAM_SOCKET_TYPE, ADMIN_STREAM_SOCKET_PROTOCOL);
		if (adminserver.listen_fd < 0) {
			perror("socket");
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,"Cannot open CLI socket\n");
			return;
		}

		if(addr_bind(adminserver.listen_fd,&cli_addr,1,1,TCP_SOCKET)<0) {
			perror("Cannot bind CLI socket to addr");
			char saddr[129];
			addr_to_string(&cli_addr,(u08bits*)saddr);
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,"Cannot bind CLI listener socket to addr %s\n",saddr);
			socket_closesocket(adminserver.listen_fd);
			return;
		}

		socket_tcp_set_keepalive(adminserver.listen_fd,TCP_SOCKET);

		socket_set_nonblocking(adminserver.listen_fd);

		adminserver.l = evconnlistener_new(adminserver.event_base,
			  cliserver_input_handler, &adminserver,
			  LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE,
			  1024, adminserver.listen_fd);

		if(!(adminserver.l)) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,"Cannot create CLI listener\n");
			socket_closesocket(adminserver.listen_fd);
			return;
		}

		addr_debug_print(adminserver.verbose, &cli_addr,"CLI listener opened on ");
	}

	adminserver.sessions = ur_map_create();
}

void admin_server_receive_message(struct bufferevent *bev, void *ptr)
{
	UNUSED_ARG(ptr);

	struct turn_session_info *tsi = (struct turn_session_info*)turn_malloc(sizeof(struct turn_session_info));
	turn_session_info_init(tsi);
	int n = 0;
	struct evbuffer *input = bufferevent_get_input(bev);

	while ((n = evbuffer_remove(input, tsi, sizeof(struct turn_session_info))) > 0) {
		if (n != sizeof(struct turn_session_info)) {
			fprintf(stderr,"%s: Weird CLI buffer error: size=%d\n",__FUNCTION__,n);
			continue;
		}

		ur_map_value_type t = 0;
		if (ur_map_get(adminserver.sessions, (ur_map_key_type)tsi->id, &t) && t) {
			struct turn_session_info *old = (struct turn_session_info*)t;
			turn_session_info_clean(old);
			turn_free(old,sizeof(struct turn_session_info));
			ur_map_del(adminserver.sessions, (ur_map_key_type)tsi->id, NULL);
		}

		if(tsi->valid) {
			ur_map_put(adminserver.sessions, (ur_map_key_type)tsi->id, (ur_map_value_type)tsi);
			tsi = (struct turn_session_info*)turn_malloc(sizeof(struct turn_session_info));
			turn_session_info_init(tsi);
		} else {
			turn_session_info_clean(tsi);
		}
	}

	if(tsi) {
		turn_session_info_clean(tsi);
		turn_free(tsi,sizeof(struct turn_session_info));
	}
}

int send_turn_session_info(struct turn_session_info* tsi)
{
	int ret = -1;

	if(tsi) {
		struct evbuffer *output = bufferevent_get_output(adminserver.out_buf);
		if(output) {
			if(evbuffer_add(output,tsi,sizeof(struct turn_session_info))>=0) {
				ret = 0;
			}
		}
	}

	return ret;
}

/////////// HTTPS /////////////

enum _AS_FORM {
	AS_FORM_LOGON,
	AS_FORM_LOGOUT,
	AS_FORM_PC,
	AS_FORM_HOME,
	AS_FORM_TOGGLE,
	AS_FORM_UPDATE,
	AS_FORM_PS,
	AS_FORM_USERS,
	AS_FORM_SS,
	AS_FORM_OS,
	AS_FORM_OAUTH,
	AS_FORM_OAUTH_SHOW_KEYS,
	AS_FORM_UNKNOWN
};

typedef enum _AS_FORM AS_FORM;

#define HR_USERNAME "uname"
#define HR_PASSWORD "pwd"
#define HR_PASSWORD1 "pwd1"
#define HR_REALM "realm"
#define HR_ADD_USER "add_user"
#define HR_ADD_REALM "add_user_realm"
#define HR_ADD_SECRET "add_secret"
#define HR_ADD_ORIGIN "add_origin"
#define HR_CLIENT_PROTOCOL "cprotocol"
#define HR_USER_PATTERN "puser"
#define HR_MAX_SESSIONS "maxsess"
#define HR_CANCEL_SESSION "cs"
#define HR_DELETE_USER "du"
#define HR_DELETE_REALM "dr"
#define HR_DELETE_SECRET "ds"
#define HR_DELETE_ORIGIN "do"
#define HR_DELETE_IP "dip"
#define HR_DELETE_IP_REALM "dipr"
#define HR_DELETE_IP_KIND "dipk"
#define HR_ADD_IP "aip"
#define HR_ADD_IP_REALM "aipr"
#define HR_ADD_IP_KIND "aipk"
#define HR_UPDATE_PARAMETER "togglepar"
#define HR_ADD_OAUTH_KID "oauth_kid"
#define HR_ADD_OAUTH_REALM "oauth_realm"
#define HR_ADD_OAUTH_TS "oauth_ts"
#define HR_ADD_OAUTH_LT "oauth_lt"
#define HR_ADD_OAUTH_IKM "oauth_ikm"
#define HR_ADD_OAUTH_TEA "oauth_tea"
#define HR_DELETE_OAUTH_KID "oauth_kid_del"
#define HR_OAUTH_KID "kid"

struct form_name {
	AS_FORM form;
	const char* name;
};

static struct form_name form_names[] = {
				{AS_FORM_LOGON,"/logon"},
				{AS_FORM_LOGOUT,"/logout"},
				{AS_FORM_PC,"/pc"},
				{AS_FORM_HOME,"/home"},
				{AS_FORM_TOGGLE,"/toggle"},
				{AS_FORM_UPDATE,"/update"},
				{AS_FORM_PS,"/ps"},
				{AS_FORM_USERS,"/us"},
				{AS_FORM_SS,"/ss"},
				{AS_FORM_OS,"/os"},
				{AS_FORM_OAUTH,"/oauth"},
				{AS_FORM_OAUTH_SHOW_KEYS,"/oauth_show_keys"},
				{AS_FORM_UNKNOWN,NULL}
};

#define admin_title "TURN Server (https admin connection)"
#define __bold_admin_title "<b>TURN Server</b><br><i>https admin connection</i><br>\r\n"
#define bold_admin_title get_bold_admin_title()

static ioa_socket_handle current_socket = NULL;

static char *get_bold_admin_title(void)
{
	static char sbat[1025];
	STRCPY(sbat,__bold_admin_title);
	if(current_socket && current_socket->special_session) {
		struct admin_session* as = (struct admin_session*)current_socket->special_session;
		if(as->as_ok) {
			if(as->as_login[0]) {
				char *dst=sbat+strlen(sbat);
				snprintf(dst,ADMIN_USER_MAX_LENGTH*2+2," admin user: <b><i>%s</i></b><br>\r\n",as->as_login);
			}
			if(as->as_realm[0]) {
				char *dst=sbat+strlen(sbat);
				snprintf(dst,STUN_MAX_REALM_SIZE*2," admin session realm: <b><i>%s</i></b><br>\r\n",as->as_realm);
			} else if(as->as_eff_realm[0]) {
				char *dst=sbat+strlen(sbat);
				snprintf(dst,STUN_MAX_REALM_SIZE*2," admin session realm: <b><i>%s</i></b><br>\r\n",as->as_eff_realm);
			}
		}
	}
	return sbat;
}

static int is_as_ok(ioa_socket_handle s) {
	return (s && s->special_session &&
			((struct admin_session*)s->special_session)->as_ok);
}

static int is_superuser(void) {
	return (is_as_ok(current_socket) &&
			(!((struct admin_session*)current_socket->special_session)->as_realm[0]));
}

static char* current_realm(void) {
	if(current_socket && current_socket->special_session && ((struct admin_session*)current_socket->special_session)->as_ok) {
		return ((struct admin_session*)current_socket->special_session)->as_realm;
	} else {
		static char bad_realm[1025] = "_ERROR:UNKNOWN_REALM__";
		return bad_realm;
	}
}

static char* current_eff_realm(void) {
	char* r = current_realm();
	if(r && r[0]) return r;
	else if(current_socket && current_socket->special_session && ((struct admin_session*)current_socket->special_session)->as_ok) {
		return ((struct admin_session*)current_socket->special_session)->as_eff_realm;
	} else {
		static char bad_eff_realm[1025] = "_ERROR:UNKNOWN_REALM__";
		return bad_eff_realm;
	}
}

void https_admin_server_receive_message(struct bufferevent *bev, void *ptr)
{
	/*UNUSED_ARG(ptr);

	ioa_socket_handle s= NULL;
	int n = 0;
	struct evbuffer *input = bufferevent_get_input(bev);

	while ((n = evbuffer_remove(input, &s, sizeof(s))) > 0) {
		if (n != sizeof(s)) {
			fprintf(stderr,"%s: Weird HTTPS CLI buffer error: size=%d\n",__FUNCTION__,n);
			continue;
		}

		register_callback_on_ioa_socket(adminserver.e, s, IOA_EV_READ, https_input_handler, NULL, 0);

		handle_https(s,NULL);
	}*/
}

void send_https_socket(ioa_socket_handle s) {
	struct evbuffer *output = bufferevent_get_output(adminserver.https_out_buf);
	if(output) {
		evbuffer_add(output,&s,sizeof(s));
	}
}

///////////////////////////////
