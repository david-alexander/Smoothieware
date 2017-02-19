/*
 * Copyright (c) 2005, Swedish Institute of Computer Science
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
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file is part of the uIP TCP/IP stack
 */
#ifndef __MDNS_H__
#define __MDNS_H__

#include "timer.h"
#include "pt.h"
#include "stdlib.h"

#define MDNS_PORT 5353

struct mdns_state {
  struct pt pt;
  struct uip_udp_conn *conn_recv;
  struct uip_udp_conn *conn_send;
  char* hostname;
  size_t hostname_len;
  char* srv_hostname;
  size_t srv_hostname_len;
  char* srv_instance;
  size_t srv_instance_len;
  char send_response;
  char send_srv_response;
  char send_ptr_response;
  char send_txt_response;
  const char* response_packet;
  size_t response_packet_len;
  const char* srv_response_packet;
  size_t srv_response_packet_len;
  const char* ptr_response_packet;
  size_t ptr_response_packet_len;
  const char* txt_response_packet;
  size_t txt_response_packet_len;
};

#ifdef __cplusplus
extern "C" {
#endif

void mdns_init(const void *mac_addr, int mac_len, char *hostname, char *srv_hostname);

void mdns_appcall();

#ifdef __cplusplus
}
#endif


#endif /* __MDNS_H__ */
