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

#include <stdio.h>
#include <string.h>

#include "mdns.h"

#include "uip.h"
#include "timer.h"
#include "pt.h"

#if UIP_CONF_UDP

#define ntohl(a) ((((a) >> 24) & 0x000000FF) | (((a) >> 8) & 0x0000FF00) | (((a) << 8) & 0x00FF0000) | (((a) << 24) & 0xFF000000))
static struct mdns_state s __attribute__ ((section ("AHBSRAM1")));

// Response packet structure = part1 + hostname + part2 + 4-byte IP address

static char mdns_response_packet_part1[] = {
    0x00, 0x00, // tid = 0
    0x84, 0x00, // flags = 0x8400
    0x00, 0x00, // questions = 0
    0x00, 0x01, // answers = 0
    0x00, 0x00, // authorities = 0
    0x00, 0x00, // additional = 0
};

static char mdns_response_packet_part2[] = {
    0x00, 0x01, // type = A
    0x80, 0x01, // class = IN, cache flush = true
    0x00, 0x00, 0x78, 0x00, // TTL = 30720
    0x00, 0x04, // length = 4
};

struct mdns_msg {
    u16_t tid;
    u16_t flags;
    u16_t nquestion;
    u16_t nanswer;
    u16_t nauthority;
    u16_t nadditional;
};

/*---------------------------------------------------------------------------*/
static void handle_msg()
{
    if (uip_len >= sizeof(struct mdns_msg))
    {
        struct mdns_msg *m = (struct mdns_msg*)uip_appdata;

        int i;
        char* pos = (char*)(m + 1);
        for (i = 0; i < ntohs(m->nquestion); i++)
        {
            char* hostname_start = pos;

            while (1)
            {
                char label_len = *pos;
                pos += label_len + 1;

                if (label_len == 0)
                {
                    break;
                }
            }

            if ((pos - hostname_start) == s.hostname_len && memcmp(hostname_start, s.hostname, s.hostname_len) == 0)
            {
                s.send_response = 1;
                break;
            }
        }
    }
}
/*---------------------------------------------------------------------------*/
static
PT_THREAD(handle_mdns())
{
    PT_BEGIN(&s.pt);

    while (1)
    {
        if (uip_udp_conn == s.conn_recv)
        {
            if (uip_newdata())
            {
                handle_msg(s);
            }
        }
        else
        {
            if (s.send_response)
            {
                memcpy(uip_appdata, s.response_packet, s.response_packet_len);
                uip_gethostaddr((uip_ipaddr_t*)((char*)uip_appdata + s.response_packet_len));
                uip_len = s.response_packet_len + sizeof(uip_ipaddr_t);

                uip_send(uip_appdata, uip_len);

                s.send_response = 0;
            }
        }

        PT_YIELD(&s.pt);
    }

    PT_END(&s.pt);
}
/*---------------------------------------------------------------------------*/
void
mdns_init(const void *mac_addr, int mac_len, char *hostname)
{
    s.hostname_len = strlen(hostname) + 2;
    s.hostname = (char*)malloc(s.hostname_len);

    char current_label_len = 0;
    char* h = hostname;

    char* current_label_start = s.hostname;
    char* next_label_char = s.hostname + 1;

    for (; 1; h++)
    {
        if (*h == '.' || *h == '\0')
        {
            *current_label_start = current_label_len;
            current_label_start += current_label_len + 1;
            next_label_char = current_label_start + 1;
            current_label_len = 0;

            if (*h == '\0')
            {
                *current_label_start = 0;
                break;
            }
        }
        else
        {
            *next_label_char = *h;
            current_label_len++;
            next_label_char++;
        }
    }

    s.response_packet_len = sizeof(mdns_response_packet_part1) + s.hostname_len + sizeof(mdns_response_packet_part2);
    char* response_packet = (char*)malloc(s.response_packet_len);
    s.response_packet = response_packet;

    memcpy(response_packet, mdns_response_packet_part1, sizeof(mdns_response_packet_part1));
    memcpy(response_packet + sizeof(mdns_response_packet_part1), s.hostname, s.hostname_len);
    memcpy(response_packet + sizeof(mdns_response_packet_part1) + s.hostname_len, mdns_response_packet_part2, sizeof(mdns_response_packet_part2));

    s.send_response = 0;

    uip_ipaddr_t recv_addr;
    uip_ipaddr(recv_addr, 255, 255, 255, 255);
    s.conn_recv = uip_udp_new(&recv_addr, HTONS(0));
    if (s.conn_recv != NULL) {
        uip_udp_bind(s.conn_recv, HTONS(MDNS_PORT));
    }

    uip_ipaddr_t send_addr;
    uip_ipaddr(send_addr, 224, 0, 0, 251);
    s.conn_send = uip_udp_new(&send_addr, HTONS(MDNS_PORT));
    if (s.conn_send != NULL) {
        uip_udp_bind(s.conn_send, HTONS(MDNS_PORT));
    }

    PT_INIT(&s.pt);
}
/*---------------------------------------------------------------------------*/
void
mdns_appcall()
{
    handle_mdns();
}
/*---------------------------------------------------------------------------*/

#endif
