#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <time.h>
#include <signal.h>
#include <err.h>


#define READ_FD		6
#define WRITE_FD	7

#define USAGE		"usage: %s [-eV] [-l login] [-n nick] [-k env] " \
			"[-c status] [-d dir] [--] group\n"

#define PKT_SZ		256
#define OUT_SZ		PKT_SZ * 2
#define DATE_LEN	21
#define DAY		(60 * 60 * 24)


struct chat {
	int in;
	char name[PKT_SZ];
	char path[PATH_MAX];
	struct chat *next;
	time_t last;
};


void close_chat(const char *);
void close_chats(void);
int handle_input(struct chat *);
int handle_server(void);
struct chat *init_chat(const char *);
int log_in(char *, char *, char *, char *, char *);
int mkdirr(char *);
struct chat *open_chat(const char *);
void ping(void);
void pong(void);
int print_chat(char *, char *);
void print_command(char *);
void send_command(char *);
int send_msg(int, char *);
void soft_quit(int);


struct chat *chats = NULL;
time_t ts = 0;
char *cmd_out = NULL;
ssize_t cmd_len = 0;
char root[PATH_MAX];
char *group = NULL;
char *nick = NULL;
int quit = -1;
int extension = PKT_SZ - 1;


void
close_chat(const char *name)
{
	struct chat *c, *p;

	/* This does not close group */
	for (c = chats; c->next; c = c->next) {
		if (name == c->next->name || strncmp(name, c->next->name,
					PKT_SZ)) {
			p = c->next;
			c->next = c->next->next;
			close(p->in);
			free(p);
			return;
		}
	}

}


void
close_chats(void)
{
	struct chat *c, *p;
	char infile[PATH_MAX];

	for (c = chats; c; c = p) {
		p = c->next;
		close(c->in);
		(void)snprintf(infile, PATH_MAX, "%s/in", c->path);
		unlink(infile);
		free(c);
	}
}


int
handle_input(struct chat *c)
{
	char buf[PIPE_BUF];
	char tbuf[PIPE_BUF * 2];
	char out[OUT_SZ];
	size_t i;
	char *bufp, *arg;
	char path[PATH_MAX];

	for (i = 0; i < PIPE_BUF; i++) {
		if (read(c->in, buf + i, 1) != 1) {
			close(c->in);
			(void)snprintf(path, PATH_MAX, "%s/in", c->path);
			if ((c->in = open(path, O_RDONLY | O_NONBLOCK, 0)) ==
					-1)
				close_chat(c->name);
			return 0;
		}
		if (buf[i] == '\n') {
			buf[i] = '\0';
			break;
		}
	}

	if (c == chats) {
		if (strncmp(buf, ":m ", 3) == 0) {
			snprintf(tbuf, sizeof(tbuf), "m\001%s", buf + 3);
			send_msg('h', tbuf);
			(void)snprintf(out, OUT_SZ, "%s: %s", nick, arg);
			print_chat(bufp, out);
		} else if (strncmp(buf, ":c ", 3) == 0) {
			send_command(buf + 3);
		} else if (strncmp(buf, ":p", 3) == 0) {
			ping();
		} else if (strncmp(buf, ":q", 3) == 0) {
			quit = 0;
		} else {
			send_msg('b', buf);
			(void)snprintf(out, OUT_SZ, "%s: %s", nick, buf);
			print_chat(c->name, out);
		}
	} else {
		snprintf(tbuf, PIPE_BUF * 2, "m%s %s", c->name, buf);
		send_msg('h', tbuf);
		(void)snprintf(out, OUT_SZ, "%s: %s", nick, buf);
		print_chat(c->name, out);
	}

	return 0;
}


int
handle_server(void)
{
	char buf[PKT_SZ + 1], out[OUT_SZ], *bufp, name[PKT_SZ], *arg;
	ssize_t len;

	if ((len = read(READ_FD, buf, PKT_SZ)) < 0 || len > PKT_SZ)
		return -1;

	if (len == 0)
		return 0;

	if (buf[len - 1] != '\0')
		buf[len] = '\0';
	bufp = buf + 1;

	(void)strlcpy(name, chats->name, PKT_SZ);

	if ((arg = strchr(buf, '\001')) != NULL)
		*arg++ = '\0';

	switch (*bufp++) {
		case 'c':
			(void)strlcpy(name, chats->name, PKT_SZ);
			/* FALLTHROUGH */
		case 'b':
			if (arg == NULL)
				return -1;
			snprintf(out, OUT_SZ, "%s: %s", bufp, arg);
			break;
		case 'd':
			if (arg == NULL)
				return -1;
			snprintf(out, OUT_SZ, "<server> %s: %s", bufp, arg);
			break;
		case 'e':
			snprintf(out, OUT_SZ, "ERROR: %s", bufp);
			break;
		case 'f':
			if (arg == NULL)
				return -1;
			snprintf(out, OUT_SZ, "<SERVER> %s: %s", bufp, arg);
			break;
		case 'a':
		case 'h':
		case 'j':
			return -1;
		case 'n':
			return 0;
		case 'g':
			return quit = 0;
		case 'i':
			print_command(bufp);
			return 0;
		case 'k':
			snprintf(out, OUT_SZ, "%s beeped you!", bufp);
			return 0;
		case 'l':
			if (*bufp != '\0')
				return send_msg('m', bufp);
			else
				return send_msg('m', NULL);
		case 'm':
			pong();
			return 0;
		default:
			return -1;
	}
	return print_chat(name, out);
}


struct chat *
init_chat(const char *name)
{
	struct chat *c;
	char infile[PATH_MAX];
	char outfile[PATH_MAX];
	int fd;

	if (strnlen(name, PKT_SZ) >= PKT_SZ) {
		errno = ENAMETOOLONG;
		return NULL;
	}

	if ((c = malloc(sizeof(struct chat))) == NULL)
		return NULL;

	c->last = 0;

	if (strncmp(name, "", 1) == 0)
		(void)snprintf(c->name, PKT_SZ, "#%s", group);
	else
		(void)strlcpy(c->name, name, PKT_SZ);

	if (snprintf(c->path, PATH_MAX, "%s/%s", root, c->name) >= PATH_MAX) {
		errno = ENAMETOOLONG;
		free(c);
		return NULL;
	}

	if (mkdir(c->path, S_IRWXU) == -1 && errno != EEXIST) {
		free(c);
		return NULL;
	}

	(void)snprintf(infile, PATH_MAX, "%s/in", c->path);
	if (snprintf(outfile, PATH_MAX, "%s/out", c->path) >= PATH_MAX) {
		errno = ENAMETOOLONG;
		free(c);
		return NULL;
	}

	if (access(infile, F_OK) == -1 && mkfifo(infile, S_IRUSR | S_IWUSR) ==
			-1 && errno != EEXIST) {
		free(c);
		return NULL;
	}

	if ((c->in = open(infile, O_RDONLY | O_NONBLOCK, 0)) == -1) {
		free(c);
		return NULL;
	}

	/* create output file and close it immediately */
	close(open(outfile, O_WRONLY | O_CREAT | O_APPEND, S_IRUSR | S_IWUSR));

	c->next = NULL;
	
	return c;
}


int
log_in(char *login, char *nick, char *group, char *password, char *status)
{
	char buf[PKT_SZ];

	/* < protocol packet */
	if (read(READ_FD, buf, PKT_SZ) == -1)
		return -1;

	/* > login packer */
	(void)snprintf(buf, PKT_SZ, "%s\001%s\001%s\001login\001%s\001%s",
			login, nick, group, password, status);
	if (send_msg('a', buf) == -1)
		return -1;

	/* < login OK packet */
	if (read(READ_FD, buf, 256) == -1)
		return -1;

	if (buf[0] != 2 || buf[1] != 'a') {
		errno = ECONNREFUSED;
		return -1;
	}

	return 0;
}


int
loop(void)
{
	int maxfd;
	fd_set fds;
	struct chat *c;

	signal(SIGTERM, soft_quit);
	signal(SIGHUP, soft_quit);
	signal(SIGINT, soft_quit);

	if ((chats = init_chat("")) == NULL)
		return -1;

	for (;;) {
		maxfd = READ_FD;
		FD_ZERO(&fds);
		FD_SET(READ_FD, &fds);

		for (c = chats; c; c = c->next) {
			FD_SET(c->in, &fds);
			if (c->in > maxfd)
				maxfd = c->in;
		}
		if (select(maxfd + 1, &fds, NULL, NULL, NULL) == -1) {
			if (errno == EINTR && quit == -1)
				continue;
			else
				return quit;
		}

		if (FD_ISSET(READ_FD, &fds) && handle_server() == -1)
			return -1;

		for (c = chats; c; c = c->next)
			if (FD_ISSET(c->in, &fds) && handle_input(c) == -1)
				return -1;

		if (quit == 0)
			break;
	}
	return 0;
}


struct chat *
open_chat(const char *name)
{
	struct chat *c = chats;
	
	for (c = chats;; c = c->next) {
		if (name == c->name || strncmp(name, c->name, PKT_SZ) == 0)
			return c;
		if (c->next == NULL)
			return (c->next = init_chat(name));
	}

	return NULL;
}


void
ping(void)
{
	if (ts != 0 && ts != (time_t)-1) {
		print_chat(chats->name, "ERROR: ping already sent");
		return;
	}
	send_msg('l', NULL);
	if (time(&ts) == (time_t)-1)
		print_chat(chats->name, "ERROR: time() failed");
}


void
pong(void)
{
	time_t nts;
	char buf[PKT_SZ];

	if (time(&nts) == (time_t)-1) {
		print_chat(chats->name, "ERROR: time() failed");
		ts = 0;
		return;
	}

	if (nts - ts > 0)
		(void)snprintf(buf, PKT_SZ, "ping: %ds", (int)(nts - ts));
	else
		(void)snprintf(buf, PKT_SZ, "ping: less then a second!");
	print_chat(chats->name, buf);
	ts = 0;
}


int
print_chat(char *name, char *msg)
{
	struct chat *c = open_chat(name);
	time_t t;
	char ts[DATE_LEN];
	char file[PATH_MAX];
	int fd;

	if (snprintf(file, PATH_MAX, "%s/out", c->path) >= PATH_MAX)
		return -1;

	fd = open(file, O_WRONLY | O_APPEND, S_IRUSR | S_IWUSR);
	if (fd == -1)
		return -1;

	if ((t = time(NULL)) == (time_t)-1)
		return -1;
	if (t / DAY != c->last / DAY)
		strftime(ts, DATE_LEN, "%F\n%T", localtime(&t));
	else
		strftime(ts, DATE_LEN, "%T", localtime(&t));
	c->last = t;

	(void)dprintf(fd, "%s %s\n", ts, msg);

	return close(fd);
}


void
print_command(char *command)
{
	char *rank, *nick, *pidle, *pdate, *user, *host, *group, *topic;
	unsigned long idle;
	char unit;
	time_t date;
	char buf[PKT_SZ], datebuf[PKT_SZ], *p;

	if (strncmp(command, "wl", 2) != 0) {
		p = strchr(command, '\001');
		if (p == NULL)
			goto cleanup;
		*p++ = '\0';
		rank = p;

		p = strchr(p, '\001');
		if (p == NULL)
			goto cleanup;
		*p++ = '\0';
		nick = p;

		p = strchr(p, '\001');
		if (p == NULL)
			goto cleanup;
		*p++ = '\0';
		pidle = p;

		p = strchr(p, '\001');
		if (p == NULL)
			goto cleanup;
		*p++ = '\0';

		p = strchr(p, '\001');
		if (p == NULL)
			goto cleanup;
		*p++ = '\0';
		pdate = p;

		p = strchr(p, '\001');
		if (p == NULL)
			goto cleanup;
		*p++ = '\0';
		user = p;

		p = strchr(p, '\001');
		if (p == NULL)
			goto cleanup;
		*p++ = '\0';
		host = p;

		idle = strtoul(pidle, NULL, 10);
		unit = 's';
		if (idle > 600) {
			idle /= 60;
			unit = 'm';
			if (idle > 600) {
				idle /= 60;
				unit = 'h';
				if (idle > 600) {
					idle /= 60;
					unit = 'd';
					if (idle > 14) {
						idle /= 7;
						unit = 'w';
					}
				}
			}
		}

		date = (time_t)strtoull(pdate, NULL, 10);
		(void)strftime(datebuf, PKT_SZ, "%F %R", localtime(&date));

		cmd_len += snprintf(buf, PKT_SZ, "%s%s (%ld%c idle, %s %s@%s\n",
				rank, nick, idle, unit, datebuf, user, host);
		if ((p = realloc(cmd_out, cmd_len)) == NULL)
			goto cleanup;

		strlcpy(cmd_out, buf, cmd_len);
		return;
	} else if (strncmp(command, "wg", 2)) {
		p = strchr(command, '\001');
		if (p == NULL)
			goto cleanup;
		*p++ = '\0';
		group = p;

		p = strchr(p, '\001');
		if (p == NULL)
			goto cleanup;
		*p++ = '\0';
		topic = p;

		cmd_len += snprintf(buf, PKT_SZ, "Group: %s, topic: %s\n",
				group, topic);
		if ((p = realloc(cmd_out, cmd_len)) == NULL)
			goto cleanup;

		strlcpy(cmd_out, buf, cmd_len);
		return;
	} else if (strncmp(command, "co", 2)) {
		topic = strchr(command, '\001');
		if (topic == NULL)
			goto cleanup;
		topic++;
		for (p = strchr(topic, '\001'); (p); p = strchr(p, '\001'))
			*p++ = ' ';

		cmd_out += snprintf(buf, PKT_SZ, "%s\n", topic);
		if ((p = realloc(cmd_out, cmd_len)) == NULL)
			goto cleanup;

		strlcpy(cmd_out, buf, cmd_len);
		return;
	} else if (strncmp(command, "ec", 2)) {
		print_chat(chats->name, cmd_out);
	}
cleanup:
	free(cmd_out);
	cmd_len = 0;
}


void
send_command(char *cmd)
{
	int i;

	if (cmd_len != 0) {
		print_chat(chats->name, "ERROR: another command in progress");
		return;
	}

	for (i = 0; i < PKT_SZ && cmd[i] != '\0'; i++)
		if (cmd[i] == ' ')
			cmd[i] = '\001';

	if (i < PKT_SZ)
		(void)send_msg('h', cmd);
	else
		print_chat(chats->name, "ERROR: command too long");
}

int
send_msg(int type, char *cmd)
{
	char msg[PKT_SZ], *base = msg;
	size_t len, rem;
	int msgs = 0;

	*base++ = 'L';
	*base++ = type;
	*base = '\0';
	if (cmd != NULL && (len = strlcat(msg, cmd, PKT_SZ)) > PKT_SZ) {
		if (!(type == 'b' || (type == 'h' && *cmd == 'm'))) {
			errno = EMSGSIZE;
			return -1;
		}
		if (extension) {
			if (type == 'h' && *cmd == 'm') {
				if ((base = strchr(base, ' ')) == NULL) {
					errno = EINVAL;
					return -1;
				}
				base++;
			}
			rem = strnlen(base, PKT_SZ - (base - msg));
		} else {
			base = msg + 1;
			rem = PKT_SZ - 2;
		}

		do {
			msg[0] = extension;
			if (write(WRITE_FD, msg, PKT_SZ) == -1)
				return -1;
			msgs++;
		} while (strlcpy(base, cmd += rem, rem) > rem);
		len = strnlen(msg, PKT_SZ);
	}
	msg[0] = len - 1;
	if (write(WRITE_FD, msg, len) == -1)
		return -1;
	return ++msgs;
}


void
soft_quit(int signal)
{
	(void)signal;
	quit = 0;
}


int
main(int argc, char **argv)
{
	extern char *optarg;
	extern int optind;
	char prefix[PATH_MAX];
	char *login = NULL;
	char *password = "";
	char *host;
	char *status = "";
	int c;
	struct passwd *pw;

	if ((pw = getpwuid(getuid())) == NULL)
		err(1, NULL);
	login = pw->pw_name;
	(void)snprintf(prefix, PATH_MAX, "%s/%s", pw->pw_dir, "icb");

	while ((c = getopt(argc, argv, "c:d:ehk:l:n:V")) != -1) {
		switch (c) {
			case 'c':
				status = optarg;
				break;
			case 'd':
				if (realpath(optarg, prefix) == NULL)
					err(1, NULL);
				break;
			case 'e':
				extension = 0;
				break;
			case 'h':
				fprintf(stdout, USAGE, getprogname());
				return 0;
			case 'l':
				login = optarg;
				break;
			case 'k':
				if ((password = getenv(optarg)) == NULL)
					err(1, NULL);
				break;
			case 'n':
				nick = optarg;
				break;
			case 'V':
				fprintf(stdout, "icb " VERSION "\n");
				return 0;
			default:
				fprintf(stderr, USAGE, getprogname());
				return 1;
		}
	}
	argc -= optind;
	argv += optind;

	if (!argc--) {
		fprintf(stderr, USAGE, getprogname());
		return 1;
	}
	group = *argv++;

	if (argc) {
		fprintf(stderr, USAGE, getprogname());
		return 1;
	}

	if ((host = getenv("TCPREMOTEHOST")) == NULL) {
		host = getenv("TCPREMOTEIP");
		if (strlen(host) == 0)
			errx(1, "remote hostname unknown");
		if (strcmp(host, "127.0.0.1") != strcmp(host, "::1"))
			host = "localhost";
	}

	if (nick == NULL)
		nick = login;

	if (log_in(login, nick, group, password, status) == -1)
		err(1, NULL);

	if (mkdir(prefix, S_IRWXU) == -1 && errno != EEXIST)
		err(1, "%s", prefix);

	if (snprintf(root, PATH_MAX, "%s/%s", prefix, host) >= PATH_MAX)
		errx(1, "%s", strerror(ENAMETOOLONG));

	if (mkdir(root, S_IRWXU) == -1 && errno != EEXIST)
		err(1, "%s", root);

	if (loop() == -1)
		err(1, NULL);

	close_chats();

	return 0;
}
