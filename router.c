#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <arpa/inet.h>
#include <string.h>
struct route_table_entry *rtable;
int rtable_len;
struct arp_table_entry *mac_table;
int mac_table_len;

struct route_table_entry *get_best_route(uint32_t ip_dest)
{
	/*
	 * Functie facuta initial, care cauta in tabela de routare
	 * intrarea potrivita, in cazul in care sunt mai multe prefixe
	 * ce se potrivesc extrage intarrea cu amsca cea mai mare
	 * (este luata din lab-ul 4 si nu mai este folsoita acum)
	 */
	struct route_table_entry *aux = NULL;
	for (int i = 0; i < rtable_len; i++)
	{
		if (rtable[i].prefix == (ip_dest & rtable[i].mask))
		{
			if (aux == NULL)
				aux = rtable + i;
			else if (aux->mask < rtable[i].mask)
				aux = rtable + i;
		}
	}
	// printf("\nRez%u   ,   %u ,%u , %u", rtable[29426].prefix, (ip_dest & rtable[29426].mask), ip_dest, rtable[29426].mask);
	return aux;
}
struct arp_table_entry *get_mac_entry(uint32_t ip_dest)
{
	/*
	 * Functie ce extrage din tabela arp intrarea
	 * care are ip-ul asociat, ip-ului dat ca parametru
	 * (tot luata din scheletul de lab), intoarce null dac anu gaseste
	 */
	struct arp_table_entry *aux = NULL;
	for (int i = 0; i < mac_table_len; i++)
	{
		if (mac_table[i].ip == ip_dest)
		{
			return mac_table + i;
		}
	}
	return aux;
}
void seteaza_mac_dst_broadcast(struct ether_header *header)
{
	/*
	 * Functie cu care setez mac-ul destinatie al header-ului ethernet
	 * in mod de broadcast
	 */
	for (int i = 0; i < 6; i++)
	{
		header->ether_dhost[i] = 255;
	}
}
void seteaza_mac_src(struct ether_header *header, uint8_t *mac_nou)
{
	/*
	 *Functie cu care setez mac-ul sursa din header-ul ethernet cu un
	 *mac nou, dat ca parametru
	 */
	for (int i = 0; i < 6; i++)
	{
		header->ether_shost[i] = mac_nou[i];
	}
}
void seteaza_mac_dst(struct ether_header *header, uint8_t *mac_nou)
{
	/*
	 *Functie cu care setez mac-ul destinatie din header-ul ethernet
	 * al pachetului cu un mac nou, dat ca parametru
	 */
	for (int i = 0; i < 6; i++)
	{
		header->ether_dhost[i] = mac_nou[i];
	}
}
void seteaza_mac_src_hdr_arp(uint8_t *mac, uint8_t *mac_nou)
{
	/*
	 *Functie cu care setez mac-ul sursa din header-ul arp cu un
	 *mac nou, ambele fiind date ca parametrii
	 */
	for (int i = 0; i < 6; i++)
	{
		mac[i] = mac_nou[i];
	}
}
void reverse_mac_eth_hdr(struct ether_header *eth_hdr)
{
	/*
	 * Functie cu care inversez adresele mac din headerul ethernet
	 * atunci cand este nevoie sa trimit pachetul inapoi
	 */
	uint8_t aux;
	for (int i = 0; i < 6; i++)
	{
		aux = eth_hdr->ether_dhost[i];
		eth_hdr->ether_dhost[i] = eth_hdr->ether_shost[i];
		eth_hdr->ether_shost[i] = aux;
	}
}
void pregatire_trimitire_reply_echo(struct ether_header *eth_hdr, struct iphdr *ip_hdr, struct icmphdr *icmp_hdr)
{
	/*
	 * Functie in care pregatesc mesajul icmp primit sa il trimit inapoi ca reply
	 */
	icmp_hdr->type = 0;
	icmp_hdr->code = 0;
	uint32_t aux = ip_hdr->daddr;
	ip_hdr->daddr = ip_hdr->saddr;
	ip_hdr->saddr = aux;
	icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr)));
	reverse_mac_eth_hdr(eth_hdr);
}
void pregatire_trimitere_ttl_sau_unreachable(char *buf, struct ether_header *eth_hdr, struct iphdr *ip_hdr, struct icmphdr *icmp_hdr, uint32_t ipul_meu, int tip_eroare)
{
	/*
	 * Functie in care pregatesc mesaj de eroare icmp pentru ttl<1 sau nu este gasit urmatorul host
	 * catre care sa se faca forward. Pregatesc mesajul de la coada la cap. Intai setez cei 64 de biti
	 * formati din 8 biti  din payload-ul primit + 8 ai headerului ip primit, iar apoi setez tipul
	 * pachetului icmp in functie de tipul erorii. Apoi setez si restul de campuri si adrese corespunzator.
	 */
	memcpy(buf + sizeof(struct ether_header) + 2 * sizeof(struct iphdr) + 8, ip_hdr + sizeof(struct iphdr), 8);
	memcpy(buf + sizeof(struct ether_header) + sizeof(struct iphdr) + 8, ip_hdr, sizeof(struct iphdr));
	if (tip_eroare == 0)
		icmp_hdr->type = 11;
	else
		icmp_hdr->type = 3;
	icmp_hdr->code = 0;
	ip_hdr->daddr = ip_hdr->saddr;
	ip_hdr->saddr = htonl(ipul_meu);
	ip_hdr->ttl = 64;
	ip_hdr->protocol = 1;
	ip_hdr->tot_len = htons(sizeof(struct iphdr) * 2 + 8 + 8);
	icmp_hdr->checksum = 0;
	icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, sizeof(struct iphdr) + 16));
	ip_hdr->check = 0;
	ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));
	reverse_mac_eth_hdr(eth_hdr);
}
void trimitere_cerere_arp(uint8_t *mac_src, uint32_t ip_target, uint32_t ip_interfata, int interfata_de_trimis)
{
	/*
	 * Functie in care trimit o cerere arp. Aici construiesc mesajul de la 0.
	 * Imi aloc un char * in care construiesc mesajul si apoi incep sa completez intai
	 * headerul ethernet cu detaliile primite ca parametru, mac-ul destinatie fiind aici broadcast,
	 * iar tirpul mesajului arp. Apoi completez si headerul arp corespunzator ca in exemplul dat in enunt
	 * si trimit mesajul.
	 */
	char *mesaj_nou = calloc(MAX_PACKET_LEN, sizeof(char));
	int len_mesaj_nou = sizeof(struct ether_header) + sizeof(struct arp_header);
	struct ether_header *eth_nou = (struct ether_header *)(mesaj_nou);
	eth_nou->ether_type = htons(0x0806);
	seteaza_mac_dst_broadcast(eth_nou);
	seteaza_mac_src(eth_nou, mac_src);
	struct arp_header *arp_nou = (struct arp_header *)(mesaj_nou + sizeof(struct ether_header));
	arp_nou->htype = htons(1);
	arp_nou->ptype = htons(0x0800);
	arp_nou->hlen = 6;
	arp_nou->plen = 4;
	arp_nou->op = htons(1);
	seteaza_mac_src_hdr_arp(arp_nou->sha, mac_src);
	arp_nou->spa = htonl(ip_interfata);
	// se poate sa trb sa modific, de verificat (htonl)
	for (int i = 0; i < 6; i++)
	{
		arp_nou->tha[i] = 0;
	}
	arp_nou->tpa = ip_target;
	send_to_link(interfata_de_trimis, mesaj_nou, len_mesaj_nou);
}
void addaugare_entry_tabela_arp(struct arp_header *arp_hdr)
{
	/*
	 * Functie cu care adaug in tabela arp o noua intrare
	 * primita la un arp request
	 */
	mac_table[mac_table_len].ip = arp_hdr->spa;
	for (int i = 0; i < 6; i++)
		mac_table[mac_table_len].mac[i] = arp_hdr->sha[i];
	mac_table_len++;
}
void reverse_arp_request_to_reply_and_send(struct ether_header *eth_hdr, struct arp_header *arp_hdr, uint8_t *mac_interfata, int interfata, uint32_t ipul_meu)
{
	/*
	 * Functie cu care convertesc un mesaj arp request primit, la un reply
	 * schimband campurile necesare, trimitandu-l inapoi.
	 */
	reverse_mac_eth_hdr(eth_hdr);
	seteaza_mac_src(eth_hdr, mac_interfata);
	arp_hdr->op = htons(2);
	arp_hdr->tpa = arp_hdr->spa;
	for (int i = 0; i < 6; i++)
		arp_hdr->tha[i] = arp_hdr->sha[i];
	seteaza_mac_src_hdr_arp(arp_hdr->sha, mac_interfata);
	arp_hdr->spa = htonl(ipul_meu);
	send_to_link(interfata, (char *)eth_hdr, sizeof(struct ether_header) + sizeof(struct arp_header));
}

int main(int argc, char *argv[])
{
	setvbuf(stdout, NULL, _IONBF, 0);
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);
	uint8_t *mac_interfata = (uint8_t *)malloc(6 * sizeof(uint8_t));
	uint8_t *mac_interfata_pt_arp = (uint8_t *)malloc(6 * sizeof(uint8_t));
	uint8_t *mac_interfata_trimis_pachet = (uint8_t *)malloc(6 * sizeof(uint8_t));
	struct Trie *trie = creaza_Trie_nou();
	rtable = malloc(80000 * sizeof(struct route_table_entry));
	rtable_len = read_rtable(argv[1], rtable, trie);
	mac_table = malloc(10 * sizeof(struct arp_table_entry));
	mac_table_len = 0;
	queue coada = queue_create();
	// mac_table_len = parse_arp_table("arp_table.txt", mac_table);
	while (1)
	{

		int interface;
		size_t len;
		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");
		// intai extrag headerul ethernet, pt ca el exista mereu
		struct ether_header *eth_hdr = (struct ether_header *)buf;
		get_interface_mac(interface, mac_interfata);
		int ok = 1;
		/* aici extrag ip-ul interfeti pe care a venit pachetul, pe care il convertesc in host order
		   https://linux.die.net/man/3/inet_network
		   De aici am luat informatiile despre aceasta functie. M-am gandit ca trebuie sa existe ceva
		   care sa converteasca un char * in numar
		*/
		uint32_t ipul_meu = inet_network(get_interface_ip(interface));
		// verific daca pachetul trebuia sa ajunga la acest router.
		for (int i = 0; i < 6; i++)
		{
			if (eth_hdr->ether_dhost[i] != mac_interfata[i])
				ok = 0;
		}
		if (ok == 0)
		{
			// in cazul in care nu are mac-ul interfetei, verific daca este cumva broadcast
			ok = 1;
			uint8_t byte_broadcast = 255;
			for (int i = 0; i < 6; i++)
				if (eth_hdr->ether_dhost[i] != byte_broadcast)
					ok = 0;
		}
		if (ok == 1)
		{
			// inseamna ca e pt noi
			if (ntohs(eth_hdr->ether_type) == 0x0800)
			{
				// protocol ip
				struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));
				int pachet_ok = 1;
				// salvez checksumul primit
				uint16_t checksum_primit = ntohs(ip_hdr->check);
				ip_hdr->check = 0;
				// verific sa aiba checksumul la fel
				if (checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)) != checksum_primit)
				{
					pachet_ok = 0;
				}
				if (pachet_ok == 1)
				{

					if (ip_hdr->ttl == 0 || ip_hdr->ttl == 1)
					{
						// aici trb sa trimit tle

						pachet_ok = 0;
						struct icmphdr *icmp_hdr = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));
						pregatire_trimitere_ttl_sau_unreachable(buf, eth_hdr, ip_hdr, icmp_hdr, ipul_meu, 0);
						send_to_link(interface, buf, sizeof(struct ether_header) + sizeof(struct iphdr) * 2 + 16);
					}
					else
					{
						// decrementez ttl-ul
						ip_hdr->ttl -= 1;
					}
					if (pachet_ok == 1)
					{
						// trebuie forward
						//	printf("ip meu:%u  ,  ip mesaj: %u", ipul_meu, htonl(ip_hdr->daddr));
						if (ntohl(ip_hdr->daddr) == ipul_meu)
						{
							// aici ajung pt reply echo de pe router
							struct icmphdr *icmp_hdr = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));
							pregatire_trimitire_reply_echo(eth_hdr, ip_hdr, icmp_hdr);
							ip_hdr->check = 0;
							ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));
							send_to_link(interface, buf, len);
						}
						else
						{
							// struct route_table_entry *aux = get_best_route(ip_hdr->daddr);
							struct route_table_entry *aux = cauta_ip_in_trie(trie, ip_hdr->daddr);
							if (aux == NULL)
							{
								struct icmphdr *icmp_hdr = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));
								pregatire_trimitere_ttl_sau_unreachable(buf, eth_hdr, ip_hdr, icmp_hdr, ipul_meu, 1);
								// pregatire_trimitere_unreachable(buf, ipul_meu, interface, len);
								send_to_link(interface, buf, sizeof(struct ether_header) + sizeof(struct iphdr) * 2 + 16);
							}
							else
							{
								struct arp_table_entry *aux2 = get_mac_entry(aux->next_hop);
								if (aux2 == NULL)
								{
									// trb bagat in queue si trimis arp request
									uint32_t ip_interfata_de_trimis = inet_network(get_interface_ip(aux->interface));
									ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));
									char *mere = malloc(len * sizeof(char));
									memcpy(mere, buf, len);
									queue_enq(coada, (void *)mere);
									get_interface_mac(aux->interface, mac_interfata_pt_arp);
									trimitere_cerere_arp(mac_interfata_pt_arp, aux->next_hop, ip_interfata_de_trimis, aux->interface);
								}
								else
								{
									// aici totul e ok si trimitem pachetul
									ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));
									get_interface_mac(aux->interface, mac_interfata_trimis_pachet);
									seteaza_mac_src(eth_hdr, mac_interfata_trimis_pachet);
									// seteaza_mac_src(eth_hdr, mac_interfata);
									seteaza_mac_dst(eth_hdr, aux2->mac);
									send_to_link(aux->interface, buf, len);
								}
							}
						}
					}
				}
			}
			else if (ntohs(eth_hdr->ether_type) == 0x0806)
			{
				// arp
				struct arp_header *arp_primit = (struct arp_header *)(buf + sizeof(struct ether_header));
				if (ntohs(arp_primit->op) == 2)
				{
					if (htonl(ipul_meu) == arp_primit->tpa)
					{
						// e reply pt mn
						addaugare_entry_tabela_arp(arp_primit);
						queue coada_aux = queue_create();
						while (queue_empty(coada) == 0)
						{
							char *pachet = (char *)(queue_deq(coada));
							struct ether_header *eth_hdr_coada = (struct ether_header *)(pachet);
							struct iphdr *ip_hdr_coada = (struct iphdr *)(pachet + sizeof(struct ether_header));
							// struct route_table_entry *aux_coada = get_best_route(ip_hdr_coada->daddr);
							struct route_table_entry *aux_coada = cauta_ip_in_trie(trie, ip_hdr_coada->daddr);
							struct arp_table_entry *aux2_coada = get_mac_entry(aux_coada->next_hop);
							if (aux2_coada != NULL)
							{
								seteaza_mac_dst(eth_hdr_coada, aux2_coada->mac);
								get_interface_mac(aux_coada->interface, mac_interfata_trimis_pachet);
								seteaza_mac_src(eth_hdr_coada, mac_interfata_trimis_pachet);
								send_to_link(aux_coada->interface, pachet, sizeof(struct ether_header) + ntohs(ip_hdr_coada->tot_len));
							}
							else
							{
								// bag in coada secundara
								queue_enq(coada_aux, (void *)pachet);
							}
						}
						while (queue_empty(coada_aux) == 0)
						{
							// apoi golesc coada secundara creata in coada veche
							char *pachet = (char *)(queue_deq(coada_aux));
							queue_enq(coada, (void *)pachet);
						}
					}
				}
				else
				{
					// i guess e request
					reverse_arp_request_to_reply_and_send(eth_hdr, arp_primit, mac_interfata, interface, ipul_meu);
				}
			}
		}

		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */
	}
	free(mac_interfata);
	free(mac_interfata_trimis_pachet);
	free(mac_interfata_pt_arp);
	free(rtable);
	free(mac_table);
}
