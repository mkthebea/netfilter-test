#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <libnet.h>
#include <string.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

char* htodrop;
int drop = 0;

/* find successful: return start address of the string to find
 * failed to find: return NULL
 * string to find is '\0': return start address of "packet"
 */
char* strnstr(unsigned char* packet, unsigned char* host, size_t len) {
	size_t	i;

	if (host[0] == '\0')
		return ((char *)packet);
	while (*packet != '\0' && len-- > 0)
	{
		i = 0;
		while (*(packet + i) == *(host + i) && i < len)
		{
			i++;
			if (*(host + i) == '\0')
				return ((char *)packet);
		}
		packet++;
	}
	return (0);
}

/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi;
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]);
	}

	mark = nfq_get_nfmark(tb);
	if (mark)
		printf("mark=%u ", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
		printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		printf("physoutdev=%u ", ifi);

	ret = nfq_get_payload(tb, &data);
	if (ret >= 0) {
		printf("payload_len=%d\n", ret);
		struct libnet_ipv4_hdr* iphdr;
		struct libnet_tcp_hdr* tcphdr;
		iphdr = (struct libnet_ipv4_hdr*) data;
		tcphdr = (struct libnet_tcp_hdr*) (data + (iphdr->ip_hl) * 4);
		if(iphdr->ip_p == 0x06 && ntohs(tcphdr->th_dport) == 80) {
			char* http = (char*)(data + (iphdr->ip_hl) * 4 + (tcphdr->th_off) * 4);
			if(strnstr(http, htodrop, strlen(http)))
				drop = 1;
			else
				drop = 0;
		}
		else
			drop = 0;
	}
	fputc('\n', stdout);

	return id;
}
/*
int should_drop(struct nfq_data *tb) {	
	struct libnet_ipv4_hdr* iphdr;
	struct libnet_tcp_hdr* tcphdr;
	int ret;
	unsigned char *data;
	ret = nfq_get_payload(tb, &data);
	if(ret >= 0) {
		iphdr = (struct libnet_ipv4_hdr*) data;
		if(iphdr->ip_p != 0x06)		//if not tcp
			return 0;
		tcphdr = (struct libnet_tcp_hdr*) (data + (iphdr->ip_hl) * 4);
		if(strnstr((char*)(tcphdr + (tcphdr->th_off) * 4), htodrop, iphdr->ip_len - iphdr->ip_hl - tcphdr->th_off))
			return 1;	
	}
	return 0;
}
*/
static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	u_int32_t id = print_pkt(nfa);
	printf("entering callback\n");
	
	if(drop) {
		printf("[PACKET DROPPED] %s\n", htodrop);
		return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
	}
	else {
		printf("[PACKET ACCEPTED]\n");
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
	}
}

int main(int argc, char **argv)
{
	if(argc != 2) {
		printf("syntax : netfilter-test <host>\nsample : netfilter-test test.gilgil.net\n");
		return -1;
	}	
	
	htodrop = argv[1];
	
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}

