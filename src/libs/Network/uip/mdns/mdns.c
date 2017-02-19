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
//                          OR part1 + hostname + part2_PTR + 2-byte length + target hostname
//                          OR part1 + hostname + part2_SRV + 2-byte length + part3_SRV + target hostname

static char mdns_response_packet_part1[] = {
    0x00, 0x00, // tid = 0
    0x84, 0x00, // flags = 0x8400
    0x00, 0x01, // questions = 1
    //0x00, 0x01, // answers = 0
    //0x00, 0x00, // authorities = 0
    //0x00, 0x00, // additional = 0
};

static char mdns_response_packet_part1_noquestion[] = {
    0x00, 0x00, // tid = 0
    0x84, 0x00, // flags = 0x8400
    0x00, 0x00, // questions = 0
    //0x00, 0x01, // answers = 0
    //0x00, 0x00, // authorities = 0
    //0x00, 0x00, // additional = 0
};

static char mdns_response_packet_part2[] = {
    0x00, 0x01, // type = A
    0x80, 0x01, // class = IN, cache flush = true
    0x00, 0x00, 0x78, 0x00, // TTL = 30720
    0x00, 0x04, // length = 4
};

static char mdns_response_packet_part2_PTR[] = {
    0x00, 0x0c, // type = PTR
    0x00, 0x01, // class = IN, cache flush = false
    0x00, 0x00, 0x78, 0x00 // TTL = 30720
};

static char mdns_response_packet_part2_SRV[] = {
    0x00, 0x21, // type = SRV
    0x00, 0x01, // class = IN, cache flush = false
    0x00, 0x00, 0x78, 0x00 // TTL = 30720
};

static char mdns_response_packet_part2_TXT[] = {
    0x00, 0x10, // type = TXT
    0x00, 0x01, // class = IN, cache flush = false
    0x00, 0x00, 0x78, 0x00 // TTL = 30720
};

static char mdns_response_packet_part3_SRV[] = {
    0x00, 0x00, // priority
    0x00, 0x00, // weight
    0x00, 0x50 // port = 80
};

struct mdns_msg {
    u16_t tid;
    u16_t flags;
    u16_t nquestion;
    u16_t nanswer;
    u16_t nauthority;
    u16_t nadditional;
};

static char question_buf[1024];
static int question_len = 0;

/*---------------------------------------------------------------------------*/
static void store_question(char const* hostname_start, char const* hostname_end)
{
    char const* question_start = hostname_start;
    char const* question_end = hostname_end + 4;

    question_len = question_end - question_start;
    memcpy(question_buf, question_start, question_len);
}
/*---------------------------------------------------------------------------*/
static char* parse_hostname(char* buffer, char** out_buffer_end, char const* hostname_start, char const* message)
{
    char* buffer_pos = buffer;

    char* pos = hostname_start;

    while (1)
    {
        char label_len = *pos;

        if (label_len & 0xC0)
        {
            unsigned short offset = ntohs(*(short*)pos);
            offset &= ~0xC000;
            parse_hostname(buffer_pos, &buffer_pos, &message[offset], message);
            pos += 2;
            break;
        }
        else
        {
            memcpy(buffer_pos, pos, label_len + 1);
            buffer_pos += label_len + 1;

            pos += label_len + 1;   
        }

        if (label_len == 0)
        {
            break;
        }
    }

    if (out_buffer_end)
    {
        *out_buffer_end = buffer_pos;
    }

    return pos;
}

static void handle_msg()
{
    if (uip_len >= sizeof(struct mdns_msg))
    {
        struct mdns_msg *m = (struct mdns_msg*)uip_appdata;

        int i;
        char* pos = (char*)(m + 1);
        for (i = 0; i < ntohs(m->nquestion); i++)
        {
            char hostname_buffer[1024];
            char* hostname_start = pos;
            char* hostname_buffer_end;
            pos = parse_hostname(hostname_buffer, &hostname_buffer_end, hostname_start, (char*)m);

            short record_type = ntohs(*(short*)pos);

            int hostname_buffer_len = hostname_buffer_end - hostname_buffer;

            if (hostname_buffer_len == s.hostname_len && memcmp(hostname_buffer, s.hostname, s.hostname_len) == 0)
            {
                s.send_response = 1;
                //store_question(hostname_start, pos);
                ///break;
            }

            if (s.srv_hostname && hostname_buffer_len == s.srv_hostname_len && memcmp(hostname_buffer, s.srv_hostname, s.srv_hostname_len) == 0)
            {
                s.send_ptr_response = 1;
                //store_question(hostname_start, pos);
                //break;
            }

            if (record_type == 33 && s.srv_hostname && hostname_buffer_len == s.srv_instance_len && memcmp(hostname_buffer, s.srv_instance, s.srv_instance_len) == 0)
            {
                s.send_srv_response = 1;
                //store_question(hostname_start, pos);
                //break;
            }

            if (record_type == 16 && s.srv_hostname && hostname_buffer_len == s.srv_instance_len && memcmp(hostname_buffer, s.srv_instance, s.srv_instance_len) == 0)
            {
                s.send_txt_response = 1;
                //store_question(hostname_start, pos);
                //break;
            }

            pos += 4;
        }
    }
}
/*---------------------------------------------------------------------------*/
static char* response_pos;
static short* response_nanswers;
static void init_response_packet()
{
    response_pos = uip_appdata;

    memcpy(response_pos, mdns_response_packet_part1_noquestion, sizeof(mdns_response_packet_part1_noquestion));
    response_pos += sizeof(mdns_response_packet_part1_noquestion);

    response_nanswers = (short*)response_pos;
    *response_nanswers = 0;
    response_pos += sizeof(short);

    *(short*)response_pos = 0;
    response_pos += sizeof(short);

    *(short*)response_pos = 0;
    response_pos += sizeof(short);
}
static void add_to_response_packet(char const* data, int length)
{
    (*response_nanswers)++;
    memcpy(response_pos, data, length);
    response_pos += length;
}
static void send_response_packet()
{
    if (*response_nanswers > 0)
    {
        *response_nanswers = HTONS(*response_nanswers);
        uip_len = response_pos - (char*)uip_appdata;
        uip_send(uip_appdata, uip_len);
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
            if (debug_len > 0)
            {
                memcpy(uip_appdata, debug_buf, debug_len);
                uip_len = debug_len;
                uip_send(uip_appdata, uip_len);

                debug_len = 0;
            }

            init_response_packet();

            if (s.send_response)
            {
                uip_gethostaddr((uip_ipaddr_t*)((char*)s.response_packet + s.response_packet_len - sizeof(uip_ipaddr_t)));
                add_to_response_packet(s.response_packet, s.response_packet_len);

                s.send_response = 0;
            }

            if (s.send_srv_response)
            {
                add_to_response_packet(s.srv_response_packet, s.srv_response_packet_len);

                s.send_srv_response = 0;
            }

            if (s.send_ptr_response)
            {
                add_to_response_packet(s.ptr_response_packet, s.ptr_response_packet_len);

                s.send_ptr_response = 0;
            }

            if (s.send_txt_response)
            {
                add_to_response_packet(s.txt_response_packet, s.txt_response_packet_len);

                s.send_txt_response = 0;
            }

            send_response_packet();
        }

        PT_YIELD(&s.pt);
    }

    PT_END(&s.pt);
}
/*---------------------------------------------------------------------------*/
void
mdns_convert_hostname(char **output, int *output_len, char const *hostname)
{
    if (hostname)
    {
        *output_len = strlen(hostname) + 2;
        *output = (char*)malloc(*output_len);

        char current_label_len = 0;
        char* h = hostname;

        char* current_label_start = *output;
        char* next_label_char = *output + 1;

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
    }
    else
    {
        *output = NULL;
        *output_len = 0;
    }
}
/*---------------------------------------------------------------------------*/
void
mdns_init(const void *mac_addr, int mac_len, char *hostname, char *srv_hostname)
{
    char dummy_txt[] = { 1, 42 };

    char* fully_qualified_hostname = malloc(strlen(hostname) + strlen(".local") + 1);
    sprintf(fully_qualified_hostname, "%s.local", hostname);

    char* srv_instance_name = malloc(strlen(hostname) + strlen(".") + strlen(srv_hostname));
    sprintf(srv_instance_name, "%s.%s", hostname, srv_hostname);

    mdns_convert_hostname(&s.hostname, &s.hostname_len, fully_qualified_hostname);
    mdns_convert_hostname(&s.srv_hostname, &s.srv_hostname_len, srv_hostname);
    mdns_convert_hostname(&s.srv_instance, &s.srv_instance_len, srv_instance_name);

    s.response_packet_len = /*sizeof(mdns_response_packet_part1) + */s.hostname_len + sizeof(mdns_response_packet_part2) + sizeof(uip_ipaddr_t);
    char* response_packet = (char*)malloc(s.response_packet_len);
    s.response_packet = response_packet;

    //memcpy(response_packet, mdns_response_packet_part1, sizeof(mdns_response_packet_part1));
    memcpy(response_packet /*+ sizeof(mdns_response_packet_part1)*/, s.hostname, s.hostname_len);
    memcpy(response_packet /*+ sizeof(mdns_response_packet_part1)*/ + s.hostname_len, mdns_response_packet_part2, sizeof(mdns_response_packet_part2));

    short srv_rdata_len_network_order = HTONS(s.hostname_len + 6);
    short ptr_rdata_len_network_order = HTONS(s.srv_instance_len);
    short txt_rdata_len_network_order = HTONS(sizeof(dummy_txt));

    s.srv_response_packet_len = /*sizeof(mdns_response_packet_part1) + */s.srv_instance_len + sizeof(mdns_response_packet_part2_SRV) + sizeof(srv_rdata_len_network_order) + sizeof(mdns_response_packet_part3_SRV) + s.hostname_len;
    char* srv_response_packet = (char*)malloc(s.srv_response_packet_len);
    s.srv_response_packet = srv_response_packet;

    //memcpy(srv_response_packet, mdns_response_packet_part1, sizeof(mdns_response_packet_part1));
    memcpy(srv_response_packet /*+ sizeof(mdns_response_packet_part1)*/, s.srv_instance, s.srv_instance_len);
    memcpy(srv_response_packet /*+ sizeof(mdns_response_packet_part1)*/ + s.srv_instance_len, mdns_response_packet_part2_SRV, sizeof(mdns_response_packet_part2_SRV));
    memcpy(srv_response_packet /*+ sizeof(mdns_response_packet_part1)*/ + s.srv_instance_len + sizeof(mdns_response_packet_part2_SRV), &srv_rdata_len_network_order, sizeof(srv_rdata_len_network_order));
    memcpy(srv_response_packet /*+ sizeof(mdns_response_packet_part1)*/ + s.srv_instance_len + sizeof(mdns_response_packet_part2_SRV) + sizeof(srv_rdata_len_network_order), mdns_response_packet_part3_SRV, sizeof(mdns_response_packet_part3_SRV));
    memcpy(srv_response_packet /*+ sizeof(mdns_response_packet_part1)*/ + s.srv_instance_len + sizeof(mdns_response_packet_part2_SRV) + sizeof(srv_rdata_len_network_order) + sizeof(mdns_response_packet_part3_SRV), s.hostname, s.hostname_len);

    s.ptr_response_packet_len = /*sizeof(mdns_response_packet_part1) + */s.srv_hostname_len + sizeof(mdns_response_packet_part2_SRV) + sizeof(ptr_rdata_len_network_order) + s.srv_instance_len;
    char* ptr_response_packet = (char*)malloc(s.ptr_response_packet_len);
    s.ptr_response_packet = ptr_response_packet;

    //memcpy(ptr_response_packet, mdns_response_packet_part1, sizeof(mdns_response_packet_part1));
    memcpy(ptr_response_packet /*+ sizeof(mdns_response_packet_part1)*/, s.srv_hostname, s.srv_hostname_len);
    memcpy(ptr_response_packet /*+ sizeof(mdns_response_packet_part1)*/ + s.srv_hostname_len, mdns_response_packet_part2_PTR, sizeof(mdns_response_packet_part2_PTR));
    memcpy(ptr_response_packet /*+ sizeof(mdns_response_packet_part1)*/ + s.srv_hostname_len + sizeof(mdns_response_packet_part2_PTR), &ptr_rdata_len_network_order, sizeof(ptr_rdata_len_network_order));
    memcpy(ptr_response_packet /*+ sizeof(mdns_response_packet_part1)*/ + s.srv_hostname_len + sizeof(mdns_response_packet_part2_PTR) + sizeof(ptr_rdata_len_network_order), s.srv_instance, s.srv_instance_len);


    s.txt_response_packet_len = /*sizeof(mdns_response_packet_part1) + */s.srv_instance_len + sizeof(mdns_response_packet_part2_TXT) + sizeof(txt_rdata_len_network_order) + sizeof(dummy_txt);
    char* txt_response_packet = (char*)malloc(s.txt_response_packet_len);
    s.txt_response_packet = txt_response_packet;

    //memcpy(txt_response_packet, mdns_response_packet_part1, sizeof(mdns_response_packet_part1));
    memcpy(txt_response_packet /*+ sizeof(mdns_response_packet_part1)*/, s.srv_instance, s.srv_instance_len);
    memcpy(txt_response_packet /*+ sizeof(mdns_response_packet_part1)*/ + s.srv_instance_len, mdns_response_packet_part2_TXT, sizeof(mdns_response_packet_part2_TXT));
    memcpy(txt_response_packet /*+ sizeof(mdns_response_packet_part1)*/ + s.srv_instance_len + sizeof(mdns_response_packet_part2_TXT), &txt_rdata_len_network_order, sizeof(txt_rdata_len_network_order));
    memcpy(txt_response_packet /*+ sizeof(mdns_response_packet_part1)*/ + s.srv_instance_len + sizeof(mdns_response_packet_part2_TXT) + sizeof(ptr_rdata_len_network_order), &dummy_txt, sizeof(dummy_txt));

    s.send_response = 0;
    s.send_srv_response = 0;
    s.send_ptr_response = 0;
    s.send_txt_response = 0;

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
