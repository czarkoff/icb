`icb` — Internet Citizen's Band client

SYNOPSIS
========

`icb [-eV] [-c status] [-d dir] [-i type] [-k env] [-l login] [-n nick] group`

DESCRIPTION
===========

`icb` is a minimalistic FIFO- and filesystem-based Internet Citizen's Band (ICB)
client. It creates an *icb* directory with subdirectory for ICB server, where
subdirectries for group and nick name directories. In the leaf directories a
FIFO file *in* and and normal file *out* are placed. The *in* file is used to
communicate with the server and the *out* file contains the chat log. For every
nick name there will be new *in* and *out* files. The basic idea of this is to
be able to communicate with an ICB server with basic command line tools.

`icb` lacks its own networking support. It relies on UCSPI-compliant network
client instead.

The following flags are available:

| Flag | Description |
| :--- | :--- |
| `-c status` | If login will result in creation of a group, set its status to *status*. |
| `-d dir` | Use *dir* instead of default *~/icb* for program's directory tree. |
| `-e` | Use “exteded packets” extension to ICB protocol. In this mode `icb` will not split message into smaller messages, but will send it in multiple packets with length 0. |
| `-i types` | Ignore ICB packets of specified *types*. |
| `-k env` | Get ICB account's password from *env* environment variable. |
| `-l login` | Use *login* for login name when connecting. Defaults to system user name. |
| `-n nick` | Set nick name to *nick*. Defaults to login name. |
| `-V` | Show version information and exit. |

Following commands are interpreted specially when recieved from group FIFO:

| Command | Description |
| :--- | :--- |
| **:m** *user* | Send personal message to *user*. |
| **:c** *command* | Send *command* to server. |
| **:p** | Ping server. |
| **:q** | Quit chat. |

EXAMPLES
========

Connect to local ICB server and enter group ‘users’, send public message
followed by a private message to ‘root’:

```sh
$ tcpopen localhost icb icb users 
$ echo hello, world! > ~/icb/localhost/ 
$ echo :m root hi > ~/icb/localhost/
```

SEE ALSO
========

[ii](http://tools.suckless.org/ii/),
[tcpclient](http://cr.yp.to/ucspi-tcp/tcpclient.html).

CAVEATS
=======

 -  ICB is not a well-defined protocol. Things may not work properly in all
    cases.  Use with care.
 -  Due to program design and limitations of ICB protocol one `icb` instance can
    only deal with one group.
