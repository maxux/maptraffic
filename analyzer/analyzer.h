#ifndef MAPANALYZER_H
	#define MAPANALYZER_H
	
	#define SNAP_LEN	1514	/* ethernet */
	#define FILTER		"scr port not 1441 or dst port not 1441"

	void diep(char *str);
	void diepcap(char *func, char *str);
	
	void callback(u_char *user, const struct pcap_pkthdr *h, const u_char *buff);
#endif
