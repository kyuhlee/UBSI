#include <stdio.h>
#include <string.h>
#include <string>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/syscall.h>

#include <sys/un.h>
#include <linux/ax25.h>
#include <linux/ipx.h>
#include <linux/atm.h>
#include <linux/x25.h>
#include <linux/netlink.h>

#include "UBSI_utils.h"

using namespace std;

void loadBar(long x, long n, int r, int w)
{
#ifdef DEBUGANY
		return;
#endif
 // Only update r times.
//    if ( x % (n/r +1) != 0 ) return;
 
    // Calculuate the ratio of complete-to-incomplete.
    float ratio = x/(float)n;
    int   c     = ratio * w;
 
    // Show the percentage complete.
    printf("%3d%% [", (int)(ratio*100) );
 
    // Show the load bar.
    for (int x=0; x<c; x++)
       printf("=");
 
    for (int x=c; x<w; x++)
       printf(" ");
 
    // ANSI Control codes to go back to the
    // previous line and clear it.
    printf("]\n\033[F\033[J");
}

string convert_time(time_t t, unsigned int mil)
{
		string str;
		
		if(t == 0) return string();
		str = string(ctime(&t));
		if(str[str.size()-1] == '\n') str[str.size()-1] = '\0';
		
		return string(str);
		char tmp[16];
		sprintf(tmp, "%u", mil);
		return string(str + "." + tmp);
}

int extract_time(char *s, time_t *t, unsigned int *mil)
{
		char *ptr;

		ptr = strchr(s, '(');
		if (ptr) {
				*t = strtoul(ptr+1, NULL, 10);
				ptr = strchr(ptr, '.');
				*mil = strtoul(ptr+1, NULL, 10);
				return 1;
		}
		return 0;
}


size_t hexstr_to_bytes(uint8_t *dest, size_t n, const char *src)
{
		const char *pos = src;
		size_t i;
		for (i = 0; i < n && (pos[0] != '\0' && pos[1] != '\0'); i++) {
				sscanf(pos, "%2hhx", &dest[i]);
				pos += 2 * sizeof(pos[0]);
		}
		return i;
}

char *sockaddr_to_str(const struct sockaddr *sa, char *s, size_t n)
{
		size_t len;

		switch (sa->sa_family) {
				case AF_INET:
						inet_ntop(AF_INET, &(((struct sockaddr_in *)sa)->sin_addr), 
										s, n);
						len = strlen(s);
						snprintf(s+len, n-len, ":%d", 
										((struct sockaddr_in *)sa)->sin_port);
						break;

				case AF_INET6:
						inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)sa)->sin6_addr), 
										s, n);
						len = strlen(s);
						snprintf(s+len, n-len, ":%d", 
										((struct sockaddr_in6 *)sa)->sin6_port);
						break;

				default:
						strncpy(s, "Unknown AF", n);
						return NULL;
		}

		return s;
}

string extract_sockaddr(char *ss, const char *needle, int size)
{
		char parse_sock[256];
		char *s = strstr(ss, needle);
		s += size;

		char temp[1024], addr[128];
		int family;
		char *ptr;
  char cwd[1024];

		ptr = strstr(s, "\n");
		if(ptr != NULL) *ptr='\0';

		int r = readlink("/proc/self/exe", cwd, 1024);

		for(int i = r; i > 0; i--)
		{
				if(cwd[i] == '/') {
						cwd[i] = '\0';
						break;
				}
		}

				//	ptr = strstr(s+16, "0000");
	//	if(ptr != NULL) *ptr = '\0';
		//printf("s = %s\n", s);
		//sprintf(temp, "perl %s -s %s",parse_sock, s);
		sprintf(temp, "perl %s/parse_sock.pl -s %s", cwd, s);
		FILE *pe = popen(temp, "r");
		fscanf(pe, "%d %s\n", &family, addr);
		pclose(pe);

		if(family == 1) {
				ptr = strstr(s+16, "0000");
				if(ptr != NULL) *ptr = '\0';
				sprintf(temp, "perl %s/parse_sock.pl -s %s", cwd, s);
				pe = popen(temp, "r");
				fscanf(pe, "%d %s\n", &family, addr);
				pclose(pe);
				//printf("sockaddr %s --> %s\n", s, addr);
				return string(addr);
		}
		
		if(family <= 2) {
				//printf("sockaddr %s --> %s\n", s, addr);
				return string(addr);
		}

		uint8_t bytes[128] = {0,};
		struct sockaddr *sa = NULL;
		char str[128] = {0,};
		size_t i, sz;

		//ptr = strstr(s, "\n");
		//if(ptr != NULL) *ptr='\0';
		sz = hexstr_to_bytes(bytes, sizeof(bytes)/sizeof(bytes[0]), s);

		sa = (struct sockaddr *)bytes;

		//if(sockaddr_to_str(sa, str, sizeof(str)/sizeof(str[0])) == NULL) return handle_empty_sock(s);
		sockaddr_to_str(sa, str, sizeof(str)/sizeof(str[0]));
		//printf("sockaddr %s --> %s\n", s, str);
		return string(str);
}

string extract_string(char *s, const char *needle)
{
		char *ptr;

		ptr = strstr(s, needle);

		if(ptr)
		{
				ptr+=strlen(needle);
				if(ptr[0] == '"') ptr++;
				int i=0;
				while(ptr[i] != ' ' && ptr[i] != '\n' && ptr[i] != '\0')
				{
						i++;
				}
				if(i == 0) return string();
				if(ptr[i-1] == '"') i--;

				return string(ptr, i);
		}
		return string();
}

int extract_long(char *s, const char *needle, long *store)
{
		char *ptr;

		ptr = strstr(s, needle);

		//if(ptr && sscanf(ptr+size, "%ld", store) > 0) return 1;
		if(ptr)
		{
				*store = strtol(ptr+strlen(needle), NULL, 10);
				return 1;
		}

		return 0;
}

int extract_hex_int(char *s, const char *needle, int *store)
{
		char *ptr;

		ptr = strstr(s, needle);

		//if(ptr && sscanf(ptr+size, "%ld", store) > 0) return 1;
		if(ptr)
		{
				*store = strtol(ptr+strlen(needle), NULL, 16);
				return 1;
		}

		return 0;
}
int extract_int(char *s, const char *needle, int *store)
{
		char *ptr;

		ptr = strstr(s, needle);

		//if(ptr && sscanf(ptr+size, "%ld", store) > 0) return 1;
		if(ptr)
		{
				*store = strtol(ptr+strlen(needle), NULL, 10);
				return 1;
		}

		return 0;
}

int extract_hex_long(char *s, const char *needle, long *store)
{
		char *ptr;

		ptr = strstr(s, needle);

		//if(ptr && sscanf(ptr+size, "%ld", store) > 0) return 1;
		if(ptr)
		{
				*store = strtol(ptr+strlen(needle), NULL, 16);
				return 1;
		}

		return 0;
}

bool get_succ(char *buf)
{
		char *ptr;
		char succ[16];
		int i=0;

		ptr = strstr(buf, " success=");
		if(ptr == NULL) {
				//printf("PTR NULL: %s\n", buf);
				return false;
		}
		ptr+=9;

		for(i=0; ptr[i] != ' '; i++)
		{
				succ[i] = ptr[i];
		}
		succ[i] = '\0';
		//printf("success = %s: %s", succ, buf);
		if(strncmp(succ, "yes", 3) == 0) return true;
		else false;
}

int get_fd(int sysno, char *buf)
{
		int fd;

		switch(sysno) {
				case SYS_read:
				case SYS_readv:
				case SYS_pread64:
				case SYS_preadv:
				case SYS_recvfrom:
				case SYS_recvmsg:
				case SYS_connect:
				case SYS_getpeername:

				case SYS_write:
				case SYS_writev:
				case SYS_pwrite64:
				case SYS_pwritev:
				case SYS_sendto:
				case SYS_sendmsg:
						extract_hex_int(buf, " a0=", &fd);
						break;

				case SYS_accept:
						extract_int(buf, " ret=", &fd);
						break;
		}
		return fd;
}

bool is_read(int sysno)
{
		if(sysno == SYS_read) return true;
		if(sysno == SYS_readv) return true;
		if(sysno == SYS_pread64) return true;
		if(sysno == SYS_preadv) return true;
//		if(sysno == SYS_recvfrom) return true;
//		if(sysno == SYS_recvmsg) return true;
//		if(sysno == SYS_accept) return true;
//		if(sysno == SYS_connect) return true;
//		if(sysno == SYS_getpeername) return true;
		//if(sysno == SYS_open && logentry.success) return true; // for pine file attachment

		return false;
}

bool is_write(int sysno)
{
		if(sysno == SYS_write) return true;
		if(sysno == SYS_writev) return true;
		if(sysno == SYS_pwrite64) return true;
		if(sysno == SYS_pwritev) return true;
//		if(sysno == SYS_sendto) return true;
//		if(sysno == SYS_sendmsg) return true;
//		if(sysno == SYS_link) return true;

		return false;
}

bool is_socket(int sysno)
{
		if(sysno == SYS_sendto) return true;
		if(sysno == SYS_sendmsg) return true;

		return false;
}

bool is_file_create(int sysno)
{
		//if(sysno == SYS_open) return true;
		//if(sysno == SYS_openat) return true;
		if(sysno == SYS_creat) return true;
		if(sysno == SYS_link) return true;
		if(sysno == SYS_linkat) return true;

		return false;
}

bool is_file_delete(int sysno)
{
		if(sysno == SYS_unlink) return true;
		if(sysno == SYS_unlinkat) return true;

		return false;
}

bool is_file_rename(int sysno)
{
		if(sysno == SYS_rename) return true;
		if(sysno == SYS_renameat) return true;

		return false;
}

bool is_fork_or_clone(int sysno)
{
		if(sysno == SYS_clone) return true;
		if(sysno == SYS_fork) return true;
		if(sysno == SYS_vfork) return true;

		return false;
}

bool is_exec(int sysno)
{
		if(sysno == SYS_execve) return true;

		return false;
}

char *fam_i2s(unsigned short sa_family)
{
		char *fam = (char*) malloc(sizeof(char)*10);
		
		switch(sa_family) {
				case AF_UNSPEC:
						strcpy(fam, "unspec\0");
						break;

				case AF_UNIX:
						strcpy(fam, "unix\0");
						break;

				case AF_INET:
						strcpy(fam, "ipv4\0");
						break;

				case AF_AX25:
						strcpy(fam, "ax25\0");
						break;

				case AF_IPX:
						strcpy(fam, "ipx\0");
						break;

				case AF_APPLETALK:
						strcpy(fam, "appletalk\0");
						break;

				case AF_NETROM:
						strcpy(fam, "netrom\0");
						break;

				case AF_BRIDGE:
						strcpy(fam, "bridge\0");
						break;

/*				case AF_AAL5:
						strcpy(fam, "aal5\0");
						break;
*/
				case AF_X25:
						strcpy(fam, "x25\0");
						break;

				case AF_INET6:
						strcpy(fam, "ipv6\0");
						break;

				case AF_NETLINK:
						strcpy(fam, "netlink\0");
						break;

				case AF_ATMPVC:
						strcpy(fam, "atmpvc\0");
						break;

			 default:
						return NULL;

		}

		return fam;
}

static unsigned char x2c(const unsigned char *buf)
{
        static const char AsciiArray[17] = "0123456789ABCDEF";
        char *ptr;
        unsigned char total=0;

        ptr = (char*) strchr(AsciiArray, (char)toupper(buf[0]));
        if (ptr)
                total = (unsigned char)(((ptr-AsciiArray) & 0x0F)<<4);
        ptr = (char*) strchr(AsciiArray, (char)toupper(buf[1]));
        if (ptr)
                total += (unsigned char)((ptr-AsciiArray) & 0x0F);

        return total;
}

char *au_unescape(char *buf)
{
		int olen, len, i;
		char saved, *str, *ptr = buf;

		/* Find the end of the name */
		if (*ptr == '(') {
				ptr = strchr(ptr, ')');
				if (ptr == NULL)
						return NULL;
				else
						ptr++;
		} else {
				while (isxdigit(*ptr))
						ptr++;
		}
		// Make the buffer based on size of original buffer.
		// This is in case we have unexpected non-hex digit
		// that causes truncation of the conversion and passes
		// back a buffer that is not sized on the expectation of
		// strlen(buf) / 2.
		olen = strlen(buf);
		str = (char*) malloc(olen+1);

		//saved = *ptr;
		//*ptr = 0;
		strcpy(str, buf);
		str[olen-1] = '\0';
		//*ptr = saved;

		/* See if its '(null)' from the kernel */
		if (*buf == '(')
				return str;

		/* We can get away with this since the buffer is 2 times
			* bigger than what we are putting there.
			*/
		len = strlen(str);
		if (len < 2) {
				free(str);
				return NULL;
		}
		ptr = str;
		for (i=0; i<len; i+=2) {
				*ptr = x2c((unsigned char *)&str[i]);
				ptr++;
		}
		*ptr = 0;
		len = ptr - str - 1;
		olen /= 2;
		// Because *ptr is 0, writing another 0 to it doesn't hurt anything
		if (olen > len)
				memset(ptr, 0, olen - len);

		return str;
}


void get_sockaddr(const char *val, char *family_t, char *addr_t, char *port_t)
{
		size_t slen;
		int rc = 0;
		const struct sockaddr *saddr;
		char name[NI_MAXHOST], serv[NI_MAXSERV];
		const char *host;
		char *out = NULL;
		const char *str;

		/*if(family) free(family);
		if(addr) free(addr);
		if(port) free(port);
		*/

		char *family = NULL;
		char *addr = NULL;
		char *port = NULL;

/*
		char family[16], ip[16], port[16];

		strcpy(family, "fd.sockfamily=\0");
		if(isServer) {
				strcpy(ip, "fd.sip=\0");
				strcpy(port, "fd.sport=\0");
		} else {
				strcpy(ip, "fd.cip=\0");
				strcpy(port, "fd.cport=\0");
		}
*/

		slen = strlen(val)/2;
		host = au_unescape((char *)val);

		if (host == NULL) {
				if (asprintf(&out, "malformed-host(%s)", val) < 0)
						out = NULL;
				family_t[0] = 0;
				addr_t[0] = 0;
				port_t[0] = 0;
				return;
		}
		saddr = (struct sockaddr *)host;

		str = fam_i2s(saddr->sa_family);
		if (str == NULL) {
				if (asprintf(&out, "unknown-family(%d)", saddr->sa_family) < 0)
				out = NULL;
				strcpy(family_t, "unknown");
				addr_t[0] = 0;
				port_t[0] = 0;
				free((char *)host);
				return;
		}

		// Now print address for some families
		switch (saddr->sa_family) {
				case AF_LOCAL:
						{
								const struct sockaddr_un *un =
										(struct sockaddr_un *)saddr;
								if (un->sun_path[0])
								{
										asprintf(&family, "%s", str);
										asprintf(&addr, "path:%s", un->sun_path);
								}
								else {// abstract name
										asprintf(&family, "%s", str);
										asprintf(&addr, "path:%.108s", &un->sun_path[1]);
								}
						}
						break;
				case AF_INET:
						if (slen < sizeof(struct sockaddr_in)) {
								asprintf(&family, "%s", str);
								asprintf(&addr, "too_short");
								break;
						}
						slen = sizeof(struct sockaddr_in);
						if (getnameinfo(saddr, slen, name, NI_MAXHOST, serv,
												NI_MAXSERV, NI_NUMERICHOST |
												NI_NUMERICSERV) == 0 ) {

										asprintf(&family, "%s", str);
										asprintf(&addr, "%s", name);
										asprintf(&port, "%s", serv);
						} else {
								asprintf(&family, "%s", str);
								asprintf(&addr, "error");
						}
						break;
				case AF_AX25:
						{
								const struct sockaddr_ax25 *x =
										(struct sockaddr_ax25 *)saddr;

										asprintf(&family, "%s", str);
										asprintf(&addr, "call:%c%c%c%c%c%c%c",
												x->sax25_call.ax25_call[0],
												x->sax25_call.ax25_call[1],
												x->sax25_call.ax25_call[2],
												x->sax25_call.ax25_call[3],
												x->sax25_call.ax25_call[4],
												x->sax25_call.ax25_call[5],
												x->sax25_call.ax25_call[6]);
						}
						break;
				case AF_IPX:
						{
								const struct sockaddr_ipx *ip =
										(struct sockaddr_ipx *)saddr;

										asprintf(&family, "%s", str);
										asprintf(&addr, "ipx-net:%u", ip->sipx_network);
										asprintf(&port, "%d", ip->sipx_port);
						}
						break;
				case AF_ATMPVC:
						{
								const struct sockaddr_atmpvc* at =
										(struct sockaddr_atmpvc *)saddr;
										asprintf(&family, "%s", str);
										asprintf(&addr, "%d", at->sap_addr.itf);
						}
						break;
				case AF_X25:
						{
								const struct sockaddr_x25* x =
										(struct sockaddr_x25 *)saddr;
										asprintf(&family, "%s", str);
										asprintf(&addr, "%.15s", x->sx25_addr.x25_addr);
						}
						break;
				case AF_INET6:
						if (slen < sizeof(struct sockaddr_in6)) {
										asprintf(&family, "%s", str);
										asprintf(&addr, "too_short");
								break;
						}
						slen = sizeof(struct sockaddr_in6);
						if (getnameinfo(saddr, slen, name, NI_MAXHOST, serv,
												NI_MAXSERV, NI_NUMERICHOST |
												NI_NUMERICSERV) == 0 ) {

										asprintf(&family, "%s", str);
										asprintf(&addr, "%s", name);
										asprintf(&port, "%s", serv);
						} else {
										asprintf(&family, "%s", str);
										asprintf(&addr, "error");
						}
						break;
				case AF_NETLINK:
						{
								const struct sockaddr_nl *n =
										(struct sockaddr_nl *)saddr;

										asprintf(&family, "%s", str);
										asprintf(&addr, "netlink_family:%u", n->nl_family);
										asprintf(&port, "netlink_pid:%u", n->nl_pid);
						}
						break;
				default:
						rc = asprintf(&family, "unsupported");
		}
		free((char *)host);

		if(family) strncpy(family_t, family, 256);
	 else family_t[0] = 0;

		if(addr) strncpy(addr_t, addr, 256);
	 else addr_t[0] = 0;

		if(port) strncpy(port_t, port, 256);
		else port_t[0] = 0;
		//return out;
}


