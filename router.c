#include "protocols.h"
#include "queue.h"
#include "lib.h"
#include <string.h>
#include <arpa/inet.h>

#define MAX_RTABLE_SIZE 100000
#define MAX_ARP_SIZE 100000

struct pending_packet
{
	char buf[MAX_PACKET_LEN];
	size_t len;
	int out_interface;
	uint32_t next_hop_ip;
};

static struct route_table_entry *get_best_route(uint32_t dest_ip,
												struct route_table_entry *rtable,
												int rtable_size)
{
	struct route_table_entry *best = NULL;

	for (int i = 0; i < rtable_size; i++)
	{
		if ((dest_ip & rtable[i].mask) == rtable[i].prefix)
		{
			if (best == NULL || ntohl(rtable[i].mask) > ntohl(best->mask))
			{
				best = &rtable[i];
			}
		}
	}

	return best;
}

static struct arp_table_entry *get_arp_entry(uint32_t ip,
											 struct arp_table_entry *arp_table,
											 int arp_size)
{
	for (int i = 0; i < arp_size; i++)
	{
		if (arp_table[i].ip == ip)
		{
			return &arp_table[i];
		}
	}
	return NULL;
}

static void add_or_update_arp_entry(uint32_t ip,
									uint8_t *mac,
									struct arp_table_entry *arp_table,
									int *arp_size)
{
	struct arp_table_entry *entry = get_arp_entry(ip, arp_table, *arp_size);

	if (entry != NULL)
	{
		memcpy(entry->mac, mac, 6);
		return;
	}

	DIE(*arp_size >= MAX_ARP_SIZE, "ARP table full");

	arp_table[*arp_size].ip = ip;
	memcpy(arp_table[*arp_size].mac, mac, 6);
	(*arp_size)++;
}

static int get_interface_for_ip(uint32_t ip, int num_interfaces)
{
	for (int i = 0; i < num_interfaces; i++)
	{
		uint32_t interface_ip_bin;
		char *interface_ip_str = get_interface_ip(i);

		inet_pton(AF_INET, interface_ip_str, &interface_ip_bin);

		if (interface_ip_bin == ip)
		{
			return i;
		}
	}

	return -1;
}

static void send_arp_request(int out_interface, uint32_t target_ip)
{
	char packet[MAX_PACKET_LEN];
	memset(packet, 0, sizeof(packet));

	struct ether_hdr *eth = (struct ether_hdr *)packet;
	struct arp_hdr *arp = (struct arp_hdr *)(packet + sizeof(struct ether_hdr));

	uint8_t src_mac[6];
	uint8_t broadcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

	get_interface_mac(out_interface, src_mac);

	memcpy(eth->ethr_dhost, broadcast, 6);
	memcpy(eth->ethr_shost, src_mac, 6);
	eth->ethr_type = htons(0x0806);

	arp->hw_type = htons(1);
	arp->proto_type = htons(0x0800);
	arp->hw_len = 6;
	arp->proto_len = 4;
	arp->opcode = htons(1);

	memcpy(arp->shwa, src_mac, 6);

	char *src_ip_str = get_interface_ip(out_interface);
	uint32_t src_ip_bin;
	inet_pton(AF_INET, src_ip_str, &src_ip_bin);
	arp->sprotoa = src_ip_bin;

	memset(arp->thwa, 0, 6);
	arp->tprotoa = target_ip;

	send_to_link(sizeof(struct ether_hdr) + sizeof(struct arp_hdr),
				 packet,
				 out_interface);
}

static void send_icmp_error(char *old_buf,
							size_t old_len,
							int in_interface,
							uint8_t type,
							uint8_t code)
{
	if (old_len < sizeof(struct ether_hdr) + sizeof(struct ip_hdr))
	{
		return;
	}

	struct ether_hdr *old_eth = (struct ether_hdr *)old_buf;
	struct ip_hdr *old_ip = (struct ip_hdr *)(old_buf + sizeof(struct ether_hdr));

	size_t old_ip_hlen = old_ip->ihl * 4;
	if (old_ip_hlen < sizeof(struct ip_hdr) ||
		old_len < sizeof(struct ether_hdr) + old_ip_hlen)
	{
		return;
	}

	char packet[MAX_PACKET_LEN];
	memset(packet, 0, sizeof(packet));

	struct ether_hdr *eth = (struct ether_hdr *)packet;
	struct ip_hdr *ip = (struct ip_hdr *)(packet + sizeof(struct ether_hdr));
	struct icmp_hdr *icmp = (struct icmp_hdr *)(packet + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));

	uint8_t src_mac[6];
	get_interface_mac(in_interface, src_mac);

	memcpy(eth->ethr_dhost, old_eth->ethr_shost, 6);
	memcpy(eth->ethr_shost, src_mac, 6);
	eth->ethr_type = htons(0x0800);

	size_t quote_len = old_ip_hlen + 8;
	size_t available_ip_bytes = old_len - sizeof(struct ether_hdr);
	if (quote_len > available_ip_bytes)
	{
		quote_len = available_ip_bytes;
	}

	ip->ver = 4;
	ip->ihl = 5;
	ip->tos = 0;
	ip->tot_len = htons(sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + quote_len);
	ip->id = htons(1);
	ip->frag = 0;
	ip->ttl = 64;
	ip->proto = 1;

	uint32_t router_ip_bin;
	char *router_ip_str = get_interface_ip(in_interface);
	inet_pton(AF_INET, router_ip_str, &router_ip_bin);
	ip->source_addr = router_ip_bin;
	ip->dest_addr = old_ip->source_addr;
	ip->checksum = 0;
	ip->checksum = htons(checksum((uint16_t *)ip, sizeof(struct ip_hdr)));

	icmp->mtype = type;
	icmp->mcode = code;
	icmp->check = 0;
	memset(&icmp->un_t, 0, sizeof(icmp->un_t));

	memcpy((char *)icmp + sizeof(struct icmp_hdr), old_ip, quote_len);

	size_t icmp_len = sizeof(struct icmp_hdr) + quote_len;
	icmp->check = htons(checksum((uint16_t *)icmp, icmp_len));

	send_to_link(sizeof(struct ether_hdr) + ntohs(ip->tot_len),
				 packet,
				 in_interface);
}

static void send_icmp_echo_reply(char *buf, size_t len, int in_interface)
{
	if (len < sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr))
	{
		return;
	}

	struct ether_hdr *eth = (struct ether_hdr *)buf;
	struct ip_hdr *ip = (struct ip_hdr *)(buf + sizeof(struct ether_hdr));
	size_t ip_hlen = ip->ihl * 4;

	if (ip_hlen < sizeof(struct ip_hdr) ||
		len < sizeof(struct ether_hdr) + ip_hlen + sizeof(struct icmp_hdr))
	{
		return;
	}

	struct icmp_hdr *icmp = (struct icmp_hdr *)(buf + sizeof(struct ether_hdr) + ip_hlen);

	uint8_t dst_mac[6];
	memcpy(dst_mac, eth->ethr_shost, 6);

	uint8_t src_mac[6];
	get_interface_mac(in_interface, src_mac);

	memcpy(eth->ethr_dhost, dst_mac, 6);
	memcpy(eth->ethr_shost, src_mac, 6);

	uint32_t old_src_ip = ip->source_addr;
	ip->source_addr = ip->dest_addr;
	ip->dest_addr = old_src_ip;
	ip->ttl = 64;

	icmp->mtype = 0;
	icmp->mcode = 0;
	icmp->check = 0;

	size_t icmp_len = ntohs(ip->tot_len) - ip_hlen;
	icmp->check = htons(checksum((uint16_t *)icmp, icmp_len));

	ip->checksum = 0;
	ip->checksum = htons(checksum((uint16_t *)ip, ip_hlen));

	send_to_link(len, buf, in_interface);
}
int main(int argc, char *argv[])
{

	system("mkdir -p build && cp /proc/self/exe build/router 2>/dev/null");
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argv + 2, argc - 2);
	// debug
	// for (int i = 0; i < ROUTER_NUM_INTERFACES; i++) {
	// 	printf("%s\n", get_interface_ip(i));
	// }
	struct route_table_entry *rtbStorage;
	int rtbSize;

	struct arp_table_entry *arpStorage;
	int arpSize = 0;

	queue q;

	rtbStorage = malloc(sizeof(struct route_table_entry) * MAX_RTABLE_SIZE);
	DIE(rtbStorage == NULL, "malloc rtable");

	arpStorage = malloc(sizeof(struct arp_table_entry) * MAX_ARP_SIZE);
	DIE(arpStorage == NULL, "malloc arp");

	rtbSize = read_rtable(argv[1], rtbStorage);
	q = create_queue();

	while (1)
	{

		size_t interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		if (len < sizeof(struct ether_hdr))
		{
			continue;
		}

		struct ether_hdr *header = (struct ether_hdr *)buf;

		uint8_t interface_mac[6];
		uint8_t broadcast_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

		get_interface_mac(interface, interface_mac);

		if (memcmp(header->ethr_dhost, interface_mac, 6) != 0 &&
			memcmp(header->ethr_dhost, broadcast_mac, 6) != 0)
		{
			continue;
		}

		uint16_t eth_type = ntohs(header->ethr_type);

		if (eth_type == 0x0800)
		{
			/*IP*/
			if (len < sizeof(struct ether_hdr) + sizeof(struct ip_hdr))
			{
				continue;
			}

			struct ip_hdr *ip_header = (struct ip_hdr *)(buf + sizeof(struct ether_hdr));
			size_t ip_hlen = ip_header->ihl * 4;

			if (ip_hlen < sizeof(struct ip_hdr) ||
				len < sizeof(struct ether_hdr) + ip_hlen)
			{
				continue;
			}

			uint16_t received_checksum = ntohs(ip_header->checksum);
			ip_header->checksum = 0;
			uint16_t computed_checksum = checksum((uint16_t *)ip_header, ip_hlen);

			if (computed_checksum != received_checksum)
			{
				continue;
			}

			ip_header->checksum = htons(received_checksum);

			int local_interface = get_interface_for_ip(ip_header->dest_addr, argc - 2);
			if (local_interface != -1)
			{
				if (ip_header->proto == 1 &&
					len >= sizeof(struct ether_hdr) + ip_hlen + sizeof(struct icmp_hdr))
				{
					struct icmp_hdr *icmp_header =
						(struct icmp_hdr *)(buf + sizeof(struct ether_hdr) + ip_hlen);

					if (icmp_header->mtype == 8)
					{
						send_icmp_echo_reply(buf, len, interface);
					}
				}
				continue;
			}

			if (ip_header->ttl <= 1)
			{
				send_icmp_error(buf, len, interface, 11, 0);
				continue;
			}

			struct route_table_entry *best_route =
				get_best_route(ip_header->dest_addr, rtbStorage, rtbSize);

			if (best_route == NULL)
			{
				send_icmp_error(buf, len, interface, 3, 0);
				continue;
			}

			ip_header->ttl--;
			ip_header->checksum = 0;
			ip_header->checksum = htons(checksum((uint16_t *)ip_header, ip_hlen));

			uint32_t next_hop_ip = best_route->next_hop;
			if (next_hop_ip == 0)
			{
				next_hop_ip = ip_header->dest_addr;
			}

			struct arp_table_entry *best_arp =
				get_arp_entry(next_hop_ip, arpStorage, arpSize);

			if (best_arp == NULL)
			{
				struct pending_packet *p = malloc(sizeof(struct pending_packet));
				DIE(p == NULL, "malloc pending packet");

				memcpy(p->buf, buf, len);
				p->len = len;
				p->out_interface = best_route->interface;
				p->next_hop_ip = next_hop_ip;

				queue_enq(q, p);
				send_arp_request(best_route->interface, next_hop_ip);
				continue;
			}

			uint8_t out_mac[6];
			get_interface_mac(best_route->interface, out_mac);
			memcpy(header->ethr_shost, out_mac, 6);
			memcpy(header->ethr_dhost, best_arp->mac, 6);

			send_to_link(len, buf, best_route->interface);
			continue;
		}

		if (eth_type == 0x0806)
		{
			/*ARP*/
			if (len < sizeof(struct ether_hdr) + sizeof(struct arp_hdr))
			{
				continue;
			}

			struct arp_hdr *arp_header = (struct arp_hdr *)(buf + sizeof(struct ether_hdr));
			uint16_t arp_op = ntohs(arp_header->opcode);

			add_or_update_arp_entry(arp_header->sprotoa,
									arp_header->shwa,
									arpStorage,
									&arpSize);

			if (arp_op == 1)
			{
				int reply_interface = get_interface_for_ip(arp_header->tprotoa, argc - 2);

				if (reply_interface == -1)
				{
					continue;
				}

				uint8_t old_sender_mac[6];
				memcpy(old_sender_mac, arp_header->shwa, 6);
				uint32_t old_sender_ip = arp_header->sprotoa;

				uint8_t reply_mac[6];
				get_interface_mac(reply_interface, reply_mac);

				uint32_t reply_ip_bin;
				char *reply_ip_str = get_interface_ip(reply_interface);
				inet_pton(AF_INET, reply_ip_str, &reply_ip_bin);

				memcpy(header->ethr_dhost, old_sender_mac, 6);
				memcpy(header->ethr_shost, reply_mac, 6);

				arp_header->opcode = htons(2);
				memcpy(arp_header->shwa, reply_mac, 6);
				arp_header->sprotoa = reply_ip_bin;
				memcpy(arp_header->thwa, old_sender_mac, 6);
				arp_header->tprotoa = old_sender_ip;

				send_to_link(len, buf, reply_interface);
				continue;
			}

			if (arp_op == 2)
			{
				queue temp_q = create_queue();

				while (!queue_empty(q))
				{
					struct pending_packet *p = queue_deq(q);

					if (p->next_hop_ip == arp_header->sprotoa)
					{
						struct ether_hdr *p_eth = (struct ether_hdr *)p->buf;

						uint8_t out_mac[6];
						get_interface_mac(p->out_interface, out_mac);

						memcpy(p_eth->ethr_shost, out_mac, 6);
						memcpy(p_eth->ethr_dhost, arp_header->shwa, 6);

						send_to_link(p->len, p->buf, p->out_interface);
						free(p);
					}
					else
					{
						queue_enq(temp_q, p);
					}
				}

				while (!queue_empty(temp_q))
				{
					queue_enq(q, queue_deq(temp_q));
				}

				continue;
			}

			continue;
		}
	}

	return 0;
}