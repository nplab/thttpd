/* config.h - configuration defines for thttpd and libhttpd
**
** Copyright © 1995,1998,1999,2000,2001 by Jef Poskanzer <jef@acme.com>.
** All rights reserved.
**
** Redistribution and use in source and binary forms, with or without
** modification, are permitted provided that the following conditions
** are met:
** 1. Redistributions of source code must retain the above copyright
**    notice, this list of conditions and the following disclaimer.
** 2. Redistributions in binary form must reproduce the above copyright
**    notice, this list of conditions and the following disclaimer in the
**    documentation and/or other materials provided with the distribution.
**
** THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
** ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
** IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
** ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
** FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
** DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
** OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
** HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
** LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
** OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
** SUCH DAMAGE.
*/

#ifndef _CONFIG_H_
#define _CONFIG_H_


/* The following configuration settings are sorted in order of decreasing
** likelihood that you'd want to change them - most likely first, least
** likely last.
**
** In case you're not familiar with the convention, "#ifdef notdef"
** is a Berkeleyism used to indicate temporarily disabled code.
** The idea here is that you re-enable it by just moving it outside
** of the ifdef.
*/

/* CONFIGURE: CGI, define this if you want to compile CGI source code
** CGI programs are executed only if there is also a valid CGI pattern
** (which may be set at compile time by CGI_PATTERN or, better,
**  at run-time using the -c command line flag or
**  cgipat directive in external configuration file).
** Undefine this if you definitively don't use CGI (smaller executable).
*/
#ifdef notdef
#define EXECUTE_CGI
#endif

#ifdef EXECUTE_CGI

/* CONFIGURE: CGI, define this if you want to compile CGI-CLI
** (Command Language Interpreter) support (EXECUTE_CGI must be defined);
** CGI-CLI support enables loading associations (from external file)
** between file patterns and executable interpreters (file name to interpret
** is passed to interpreter as first argument).
** This allows to not write interpreter path name in the first line
** of every command file, i.e.: # /usr/local/bin/perl
** To prevent possible security holes, interpreted files should be set with
** executable bits (chmod +x) anyway, in order to prevent unwanted file reads
** by web clients.
*/
#define EXECUTE_CGICLI
#ifdef notdef
#endif

/* CONFIGURE: CGI, define this if you want that CGI-CLI pages
** have executable bit in order to be interpreted.
** This can save some CPU time when also serving static pages
** (CGICLI pattern matching is done only if requested page is executable).
*/
#define CGICLI_WANTS_EXEC_BIT
#ifdef notdef
#endif

/* CONFIGURE: CGI, how many CGI-CLI associations are allowed.
** This is used only if EXECUTE_CGICLI is defined.
** HINT: for performance reasons, keep this number low (must be >= 1).
*/
#define MAX_CGICLI_ENTRIES	8

#endif /* EXECUTE_CGI */

/* CONFIGURE: CGI programs must match this pattern to get executed.  It's
** a simple shell-style wildcard pattern, with * meaning any string not
** containing a slash, ** meaning any string at all, and ? meaning any
** single character; or multiple such patterns separated by |.  The
** patterns get checked against the filename part of the incoming URL.
**
** Restricting CGI programs to a single directory lets the site administrator
** review them for security holes, and is strongly recommended.  If there
** are individual users that you trust, you can enable their directories too.
**
** You can also specify a CGI pattern on the command line, with the -c flag.
** Such a pattern overrides this compiled-in default.
**
** If no CGI pattern is specified, neither here nor on the command line,
** then CGI programs cannot be run at all.  If you want to disable CGI
** as a security measure that's how you do it, just don't define any
** pattern here and don't run with the -c flag.
*/
#ifdef notdef
/* Some sample patterns.  Allow programs only in one central directory: */
#define CGI_PATTERN "/cgi-bin/*"
/* Allow programs in a central directory, or anywhere in a trusted
** user's tree: */
#define CGI_PATTERN "/cgi-bin/*|/jef/**"
/* Allow any program ending with a .cgi: */
#define CGI_PATTERN "**.cgi"
/* When virtual hosting, enable the central directory on every host: */
#define CGI_PATTERN "/*/cgi-bin/*"
#endif

/* CONFIGURE: How much data to allow when parsing CGI HTTP headers
** ( done when CGI name doesn't start with these 4 characters: nph- ).
** HTTP headers longer than this limit will trigger an error response.
** A value of 0 removes check of headers length
** (in this case they are limited only by available memory).
** Range  values: 0, 1024 - 131072
** Default value: 4096
*/
#define CGI_MAX_HEADERS_LENGTH 4096

/* CONFIGURE: How many seconds to allow CGI programs to run before killing
** them.  This is in case someone writes a CGI program that goes into an
** infinite loop, or does a massive database lookup that would take hours,
** or whatever.  If you don't want any limit, comment this out, but that's
** probably a really bad idea.
** A short timelimit implies that your CGIs don't output much more data
** than what can fit into socket send buffer size ( usually 16 KB - 64 KB ).
** Range  values: 10 - 3600
** Default value: 30
*/
#define CGI_TIMELIMIT 30
#ifdef notdef
#endif

/* CONFIGURE: If you define this then thttpd will disallow
** query string and/or path info in URLs
** which resolve to regular static files
** (i.e. not including directory listings, CGI, etc.);
** NOTE: this is usually desired because it is good for
** security and robustness reasons (defining DISALLOW_*),
** unluckily sometimes a short query string is used for small images
** in order to reload them at every page load
** (i.e. useful to implement trivial counters by
**  counting the number of times a certain image
**  has been logged into request log file,
**  of course, in this case, you should not use / set MAX_AGE=nseconds).
**
** Default: defined
*/
#ifdef notdef
#define DISALLOW_QRYSTR_IN_STFILES
#endif

/* CONFIGURE: Define this if you want to change the default size of
** receive socket buffer(s);  the idea is that receive buffer size
** can ben much smaller than send buffer size (only when not using CGI)
** and that, usually, default value is not optimal
** in order to not waste memory.
** NOTE: you may prefer to set this value in configuration file (-C option).
** HINT: set it to a low value (4 - 8 KB)
**       if thttpd has to serve only static contents
**       for thousands of connections in order to not waste
**       too much memory space;  HTTP requests are small,
**       usually around 0.5 - 0.8 KB each,
**       thus 4 KB should allow a sufficient number (5-6)
**       of pipelined requests (your mileage may vary).
** NOTE: if ==> IPV6 <== is enabled and / or jumbo packets (4-8 KB)
**       are used then set it over 8-16 KB.
** NOTE: the real memory space used by OS may be much higher
**       than this value (i.e. twice on Linux, etc.) because
**       of needed control structures, protocol header buffers, etc.;
** NOTE: some OSs (i.e. Linux, etc.) report the total memory space
**       used by all this stuff (data buffer + control structures, etc.)
**       instead of the size of the data buffer.
** NOTE: many OSs can automatically reduce the buffer sizes
**       under memory pressure
**       (i.e. low available memory + thousands of connections +
**        lots of memory space used by high priority processes, etc.),
**       anyway it is better to avoid such a "scenario".
** NOTE: default value is changed only if this value is >= 4096.
** Range  values: 0, 4096 - 1048576 bytes
** Default value: 0
*/
#ifdef notdef
#define CONN_SO_RCVBUF		8192
#endif

/* CONFIGURE: Define this if you want to set the size of
** send socket buffer(s).
** NOTE: you may prefer to set this value in configuration file (-C option).
** HINT: set it to a relatively low value (8 - 16 KB) if thttpd has to serve
**       mainly small files or if thttpd serves thousands of relatively slow
**       connections (< 640 Kbit/sec.) and / or you want to throttle bandwidth
**       when RTT goes over (200 - 300 mlsec).
** HINT: set it to a high value (64 - 128 KB) if thttpd has to serve many
**       big files ( >= 1 - 100 MB ) for hundreds or thousands of
**       FAST connections ( >= 2-4 Mbit/sec. each) and
**       your new super fast computer has enough available RAM and
**       you want to minimize disk seeks.
**       As usual you mileage may vary.
** INFO: many recent TCP/IP stacks are able to dynamically set
**       size of socket buffers, thus sometime it is more effective
**       to let TCP/IP stack to choose optimal size by not setting
**       a static value for send buffer.
** NOTE: default value is changed only if this value is >= 4096.
** NOTE: of course OS can lower the upper limit.
**
** See Also: MAX_SENDFILE_BLK_SIZE
**
** Range  values: 0, 4096 - 4194304 bytes	( <= MAX_SENDFILE_BLK_SIZE)
** Default value: 0
*/
#ifdef notdef
#define CONN_SO_SNDBUF		16384
#endif

/* CONFIGURE: Define this if you want to use an accept filter (data ready)
** for incoming HTTP connections;  this filter can reduce server load
** for idle connections in read state.
** Accept filter should be available in FreeBSD 4.x and Linux 2.4
** and following versions.
** NOTE: FreeBSD, there should be no strange problem defining this.
** NOTE: Linux be sure to use a properly patched or a recent kernel
**       (i.e. at least Linux 2.4.22) before defining this.
*/
#ifdef notdef
#define USE_ACCEPT_FILTER
#endif

/* CONFIGURE: Define this if your OS let new accepted connections
** to inherit non blocking mode from listening socket.
** Defining this constant allows thttpd to spare a few cycles of CPU time
** for each new connection.
** HINT: if you are not sure about what this means,
**       leave it undefined.
*/
#ifdef notdef
#define INHERIT_FD_NONBLOCK_AA
#endif

/* CONFIGURE: Define this if you want to force a fdwatch synchronization
** just before every close(fd).
** Synchronization is meaningful only for:
**      - "kqueue"    (*BSD);
**      - "/dev/poll" (SunOS / Solaris).
** If you have enabled keep-alive and thttpd runs on Sun OS,
** you may want to define this in order to not generate spurious events
** (with only a small speed penalty).
*/
#ifdef notdef
#define SYNC_FD_ON_CLOSE
#endif

/* CONFIGURE: How many seconds to allow for reading the initial request
** on a new connection.
** Range  values: 4 - 90
** Default value: 50
*/
#define IDLE_READ_TIMELIMIT 50

/* CONFIGURE: How many seconds to allow for reading the subsequent requests
** on a keep-alive connection.  This value depends also on bandwidth
** saturation, RTT (Round Time Trip) of TCP/IP packets, etc.;  the values
** listed below are for 2-4 persistent connections HTTP/1.1 per client;
** if clients have low bandwidth (< 256 Kbit./sec) and
** they use more than 4 persistent connections and do pipelining,
** then those values should be highered (+2-4 seconds or more) otherwise
** connections will be closed too often (which is not too bad in order
** to teach people to not deploy too much download accelerators).
** NOTE: under certain conditions (i.e. keep alive with pipelining, etc.),
**       thttpd will AUTOMATICALLY USE a slightly HIGHER VALUE (+2-6 sec.).
** NOTE: connections are kept open only if their count is below
**       high water mark 2 (80% of max. allowed).
** NOTE: closing connections after a few requests or after a big request
**       is not too bad (unless client is pipelining lots of requests).
** HINT: keep it higher than LINGER_TIME * 2.
** HINT: if you want to serve HUGE numbers of Internet connections,
**       don't set OS default write socket buffer size too high (nor too low)
**       and don't set keep alive too high (over 14-16 seconds)
**       unless the majority of your clients use really slow modem connections
**       or your network has very high latencies
**       (RTT > 2000 - 3000 milliseconds).
** The following values are estimated considering mean bandwidth
** available between client and server in two typical scenarios
** (LAN and Internet) with lots of clients:
**       values for a fast LAN (1000 - 100 Mbit/sec.): 1-2
**       values for a slow LAN         (10 Mbit/sec.): 2-3
**       values for Internet high   bandwidth (4000 - 640 KBit/sec.):  3-8
**       values for Internet medium bandwidth (640  - 128 Kbit/sec.):  8-14
**       values for Internet low    bandwidth ( 56  -  28 Kbit/sec.): 16-28
** Range  values: 2 - 64
** Default value: 12
*/
#define IDLE_KEEPALIVE_TIMELIMIT 12

/* CONFIGURE: How many keep alive requests per connection to allow
** when there are few connections ( < high water mark 1, 60% ).
** Name: Low Water Mark Keep Alive Requests Limit.
** Range  values: 0 - 32000.
** Default value: 400
*/
#define LOWM_KEEPALIVE_RQSLIMIT 4000

/* CONFIGURE: How many keep alive requests per connection to allow
** when there are many connections ( >= high water mark 1, 60% ).
** Name: High Water Mark Keep Alive Requests Limit.
** Range  values: 0 - 1000.
** Default value: 40
*/
#define HIWM_KEEPALIVE_RQSLIMIT 40

/* CONFIGURE: How many CR or LF extra characters to allow between
** two keep-alive requests. These extra CRLFs are forbidden by
** HTTP/1.1 specifications and are generated only by BUGGY HTTP clients
** (unfortunately some of them are rather popular, i.e. MSIE 4.x - 6).
** NOTE: Mozilla 1.x and later, Netscape 7.x and later and usually
**       many other open source browsers are fully standard compliant.
** HINT: set value to 0 or undefine it if you don't want thttpd to be tolerant.
** Range  values: 0 - 32
** Default value: 16
*/
#define MAX_KEEPALIVE_EXTRA_CRLFs 16
#ifdef notdef
#endif

/* CONFIGURE: Set max. file size to keep connection alive;
** connection is closed if file being sent has a size greater
** than MAX_KEEPALIVE_FILE_SIZE.
** A value of 0 means no limit on file size.
** Range  values: 0 - 1073741824 (2 ^ 30)
** Default value: 64 KB
*/
#ifdef notdef
#define MAX_KEEPALIVE_FILE_SIZE  (1024 * 64)
#endif

/* CONFIGURE: How many seconds before an idle connection
** in "send file contents" state, gets closed.
** Range  values: 10 - 300
** Default value: 300
*/
#define IDLE_SEND_TIMELIMIT 300

/* CONFIGURE: How many seconds before an idle connection,
** in "send response" state, gets closed.
** You may want to increase this value up to 60, 120 or 180 seconds
** to be reasonably sure that error responses are sent entirely
** through very slow links (much less than 1 KB/sec.) or decrease it
** if your traffic is local and bandwidth is high enough (10 - 1000 Mbit/sec.).
** Range  values: 10 - 120
** Default value: 60
*/
#define IDLE_SEND_RESP_TIMELIMIT 60

/* CONFIGURE: The syslog facility to use.  Using this you can set up your
** syslog.conf so that all thttpd messages go into a separate file.  Note
** that even if you use the -l command line flag to send logging to a
** file, errors still get sent via syslog.
*/
#define LOG_FACILITY LOG_DAEMON

/* CONFIGURE: Tilde mapping.  Many URLs use ~username to indicate a
** user's home directory.  thttpd provides two options for mapping
** this construct to an actual filename.
**
** 1) Map ~username to <prefix>/username.  This is the recommended choice.
** Each user gets a subdirectory in the main chrootable web tree, and
** the tilde construct points there.  The prefix could be something
** like "users", or it could be empty.  See also the makeweb program
** for letting users create their own web subdirectories.
**
** 2) Map ~username to <user's homedir>/<postfix>.  The postfix would be
** the name of a subdirectory off of the user's actual home dir, something
** like "public_html".  This is what Apache and other servers do.  The problem
** is, you can't do this and chroot() at the same time, so it's inherently
** a security hole.  This is strongly dis-recommended, but it's here because
** some people really want it.  Use at your own risk.
**
** You can also leave both options undefined, and thttpd will not do
** anything special about tildes (saving a bit of CPU time).
** Enabling both options is an error.
*/
#ifdef notdef
#define TILDE_MAP_1 "users"
#define TILDE_MAP_2 "public_html"
#endif

/* CONFIGURE: The file to use for authentication.  If this is defined then
** thttpd checks for this file in the local directory before every fetch.
** If the file exists then authentication is done, otherwise the fetch
** proceeds as usual.
**
** If you undefine this then thttpd will not implement authentication
** at all and will not check for auth files, which saves a bit of CPU time
** and disk reads.
*/
#ifdef notdef
#define AUTH_FILE ".htpasswd"
#endif

/* CONFIGURE: If you define this then thttpd will allow access to
** files which have "group" instead of "other" (public) rights.
*/
#ifdef notdef
#define ALLOW_ACCESS_GRP	1
#endif

/* CONFIGURE: The default character set name to use with text MIME types.
** This gets substituted into the MIME types where they have a "%s".
**
** You can override this in the config file with the "charset" setting,
** or on the command like with the -T flag.
*/
#define DEFAULT_CHARSET "iso-8859-1"

/* CONFIGURE: The default mime type used when the file has no or unknown
** extension;
** if you define this then thttpd sends this mime type whenever
** it does not find or recognize a file extension.
** If you undefine this then no default mime type is sent to client
** for files without or with unknown extension
** (i.e. README, ChangeLog, Secret.xzy, etc.).
**
** RFC 2616 (7.2.1) states that if mime type is unknown (for a given file)
** then server may omit "Content-Type" header in order to allow client
** (i.e. browser, etc.) to guess its type;  this would seem to be
** the right thing to do because if the client does not recognize
** mime type by file extension or by examining first n bytes of it
** then client should handle that unknown content as "application/octet-stream".
**
** NOTE: unfortunately most browsers are too dumb to handle properly
**       commonly known contents such as C source files, etc.
**       because they are easily screwed by HTML entities
**       (i.e.: <, >, etc. found in #include <stdio.h>, etc.).
**
** INFO: in theory it should be safe to leave it undefined,
**       in practice it is not because most browsers
**       are not smart enough (i.e. are not standard compliant)
**       to handle a missing mime type.
**
*/
#define DEFAULT_MIME_TYPE	"text/plain; charset=%s"
#ifdef notdef
#endif

/* CONFIGURE: The default mime type used when the file has too many
** multiple encodings (more than MAX_FILE_MIME_ENCODINGS) or
** (maybe in next future) when it looks like file content is binary.
*/
#define DEFAULT_MIME_TYPE_BIN	"application/octet-stream"
#ifdef notdef
#endif

/* CONFIGURE: The max. number of encodings for each file name (i.e. *.gz.uu).
** thttpd gives up over this limit because, in this case,
** it is clear that the file name has been hacked by a malicious user.
** Range values:  2 - 16
** Default value: 8
*/
#define MAX_MIME_ENCODINGS_LIMIT	8

/*
** Most people won't want to change anything below here.
**
** NOTE: ... instead, web administrators, geeks, etc.
** usually want to check / tweak the following values
** (specially those regarding the file CACHE).
*/

/* CONFIGURE: This controls the SERVER_NAME environment variable that gets
** passed to CGI programs.  By default thttpd does a gethostname(), which
** gives the host's canonical name.  If you want to always use some other name
** you can define it here.
**
** Alternately, if you want to run the same thttpd binary on multiple
** machines, and want to build in alternate names for some or all of
** them, you can define a list of canonical name to altername name
** mappings.  thttpd seatches the list and when it finds a match on
** the canonical name, that alternate name gets used.  If no match
** is found, the canonical name gets used.
**
** If both SERVER_NAME and SERVER_NAME_LIST are defined here, thttpd searches
** the list as above, and if no match is found then SERVER_NAME gets used.
**
** In any case, if thttpd is started with the -h flag, that name always
** gets used.
*/
#ifdef notdef
#define SERVER_NAME "your.hostname.here"
#define SERVER_NAME_LIST \
    "canonical.name.here/alternate.name.here", \
    "canonical.name.two/alternate.name.two"
#endif

/* CONFIGURE: Undefine this if you want thttpd to hide its specific version
** when returning into to browsers.  Instead it'll just say "thttpd" with
** no version.
** See Also: ERR_HREF_SERVER_ADDRESS to make it hyperlinked.
*/
#define SHOW_SERVER_VERSION
#ifdef notdef
#endif

/* CONFIGURE: Define this if you want to always chroot(), without having
** to give the -r command line flag.  Some people like this as a security
** measure, to prevent inadvertant exposure by accidentally running without -r.
** You can still disable it at runtime with the -nor flag.
** NOTE: enabling chroot and / or disabling symlink checking
**       with the -nos flag, allows thttpd to spare some CPU time
**       when serving static contents.
** HINT: turn chroot on or nosymlink for best performances.
*/
#ifdef notdef
#define ALWAYS_CHROOT
#endif

/* CONFIGURE: Define this if you want to always do virtual hosting, without
** having to give the -v command line flag.  You can still disable it at
** runtime with the -nov flag.
*/
#ifdef notdef
#define ALWAYS_VHOST
#endif

/* CONFIGURE: If you're using the vhost feature and you have a LOT of
** virtual hostnames (like, hundreds or thousands), you will want to
** enable this feature.  It avoids a problem with most Unix filesystems,
** where if there are a whole lot of items in a directory then name lookup
** becomes very slow.  This feature makes thttpd use subdirectories
** based on the first characters of each hostname.  You can set it to use
** from one to three characters.  If the hostname starts with "www.", that
** part is skipped over.  Dots are also skipped over, and if the name isn't
** long enough then "_"s are used.  Here are some examples of how hostnames
** would get turned into directory paths, for each different setting:
** 1: www.acme.com ->    a/www.acme.com
** 1: foobar.acme.com -> f/foobar.acme.com
** 2: www.acme.com ->    a/c/www.acme.com
** 2: foobar.acme.com -> f/o/foobar.acme.com
** 3: www.acme.com ->    a/c/m/www.acme.com
** 3: foobar.acme.com -> f/o/o/foobar.acme.com
** 3: m.tv ->            m/t/v/m.tv
** 4: m.tv ->            m/t/v/_/m.tv
** Note that if you compile this setting in but then forget to set up
** the corresponding subdirectories, the only error indication you'll
** get is a "404 Not Found" when you try to visit a site.  So be careful.
*/
#ifdef notdef
#define VHOST_DIRLEVELS 1
#define VHOST_DIRLEVELS 2
#define VHOST_DIRLEVELS 3
#endif

/* CONFIGURE: Define this if you want to always use a global passwd file,
** without having to give the -P command line flag.  You can still disable
** it at runtime with the -noP flag.
**
** NOTE: in order to work, AUTH_FILE must be defined (see above).
*/
#ifdef notdef
#define ALWAYS_GLOBAL_PASSWD
#endif

/* CONFIGURE: When started as root, the default username to switch to after
** initializing.  If this user (or the one specified by the -u flag) does
** not exist, the program will refuse to run.
*/
#define DEFAULT_USER "nobody"

/* CONFIGURE: When started as root, the program can automatically chdir()
** to the home directory of the user specified by -u or DEFAULT_USER.
** An explicit -d still overrides this.
*/
#ifdef notdef
#define USE_USER_DIR
#endif

/* CONFIGURE: If this is defined, some of the built-in error pages will
** have more explicit information about exactly what the problem is.
** Some sysadmins don't like this, for security reasons.
*/
#define EXPLICIT_ERROR_PAGES
#ifdef notdef
#endif

/* CONFIGURE: Subdirectory for custom vhost error pages.
** The error filenames are $WEBDIR/hostname/$ERR_VHOST_DIR/err%d.html,
** they are searched only if virtual hosting is enabled.  This allows
** different custom error pages for each virtual hosting web server.
** If ERR_VHOST_DIR is not defined or no custom page for a given error
** can be found, then error handling defaults first to ERR_DIR (if defined)
** and then to built-in errors.
** HINT: undefine this for best performances.
*/
#ifdef notdef
#define ERR_VHOST_DIR "errors"
#endif

/* CONFIGURE: Subdirectory for custom global error pages.
** The error filenames are $WEBDIR/$ERR_DIR/err%d.html,
** they are searched after ERR_VHOST_DIR;  if ERR_DIR is not defined
** or no custom page for a given error can be found, the built-in error page
** is generated.
** HINT: undefine this for best performances.
*/
#ifdef notdef
#define ERR_DIR "errors"
#endif

/* CONFIGURE: Define this if you want a standard HTML tail containing
** $SERVER_SOFTWARE and $SERVER_ADDRESS to be appended to the custom error
** pages.  (It is always appended to the built-in error pages.)
*/
#define ERR_APPEND_SERVER_INFO
#ifdef notdef
#endif

/* CONFIGURE: Define this if you want to add an hyperlink
** on $SERVER_SOFTWARE to $SERVER_ADDRESS
** in custom or in built-in error pages.
** Some sys-admins, for security / paranoid reasons,
** don't like hyperlinks to server software
** (so they undefine this).
*/
#ifdef notdef
#define ERR_HREF_SERVER_ADDRESS
#endif

/* CONFIGURE: Define this if you want to force MSIE-[56]
** client browsers to always show server errors.
** This is accomplished by padding error messages
** in order to make them bigger than 512 bytes.
** If you don't define this, MSIE browsers will usually
** show their canned (but localized) HTTP error messages.
** NOTE:  disabling padding is not too bad,
**        after all MSIE users can always switch to other browsers or
**        turn off the "canned HTTP messages" feature.
** HINT: undefine this for best performances
**       if USE_LAYOUT is enabled and
**          header + footer layout files are bigger than 250-300 bytes
**       or
**       if HTTP errors (i.e. 404 Not Found, etc.)
**          are very very frequent.
*/
#ifdef notdef
#define ERR_PAD_MSIE
#endif

/* CONFIGURE: nice(2) value to use for CGI programs.  If this is undefined,
** CGI programs run at normal priority.
** Range  values: 0 - 20
** Default value: 10
*/
#define CGI_NICE 10

/* CONFIGURE: $PATH to use for CGI programs.
*/
#define CGI_PATH "/usr/local/bin:/usr/ucb:/bin:/usr/bin"

/* CONFIGURE: If defined, $LD_LIBRARY_PATH to use for CGI programs.
*/
#ifdef notdef
#define CGI_LD_LIBRARY_PATH "/usr/local/lib:/usr/lib"
#endif

/* CONFIGURE: The default max-age value used for Cache-Control HTTP/1.1 header.
**
** NOTE: Cache-Control HTTP header is sent only if max_age is >= 0,
**       in this case clients won't request the same file
**       till max_age seconds elapses.
**
** HINT: setting max_age to a positive value between 60 and 86400 seconds
**       (or even more), can be useful for servers serving ONLY static content
**       that never or rarely changes (i.e. images, style sheets, etc.)
**       after creation.
**
** You can override this in the config file with the "max_age" setting,
** or on the command like with the -M flag.
**
** Range  values: -1, 0 - 30123456      (at most 1 year)
** Default value: -1
*/
#define DEFAULT_MAX_AGE		-1

/* CONFIGURE: Define this if you want to send also HTTP/1.0 Expires: header
** when MAX_AGE value is set (i.e. >= 0).
**
** NOTE: define this only if you set MAX_AGE value and
**       you have lots of HTTP/1.0 requests.
*/
#define USE_EXPIRES
#ifdef notdef
#endif

/* CONFIGURE: How long a mapped file (L3 size) should stay in cache.
** NOTE: cache levels / zones have these expire ages:
**       L0     DEFAULT_EXPIRE_AGE * 120
**       L1     DEFAULT_EXPIRE_AGE *  10
**       L2     DEFAULT_EXPIRE_AGE *   4
**       L3     DEFAULT_EXPIRE_AGE *   1
**       L4     DEFAULT_EXPIRE_AGE /  32
**       L5     DEFAULT_EXPIRE_AGE /  64
**       See also: DEF_MUL_EXPIRE_AGE_L0-L5 in mmc.c.
** Range  values: 32 - 3600
** Default value: 150
*/
#define DEFAULT_EXPIRE_AGE 150

/* CONFIGURE: How often to run the occasional cleanup job
** for mmc file cache.
** HINT: try to lower it if and only if there are lots of requests per second
**       (over 300-400) for unique / new / BIG FILES and
**       thttpd sometimes runs out of memory (malloc or mmap);
**       you can look for this by searching for: ENOMEM in syslog messages;
**       see also: USE_SENDFILE.
** HINT: keep it between 8 and 32 seconds.
** Range  values: 2 - 200
** Default value: 12
*/
#define OCCASIONAL_MMC_TIME 12

/* CONFIGURE: How often to run the occasional cleanup job
** for allocated timers.
** HINT: keep it between 100 and 1000 seconds.
** Range  values: 10 - 1000
** Default value: 300
*/
#define OCCASIONAL_TMR_TIME 300

/* CONFIGURE: How often to run the occasional cleanup job
** for timed out connections.
** HINT: keep it between 2 and 5 seconds.
** Range  values: 1 - 8
** Default value: 2
*/
#define OCCASIONAL_IDLE_TIME 2

/* CONFIGURE: Seconds between stats syslogs.  If this is undefined then
** no stats are accumulated and no stats syslogs are done.
** Range  values: 1 - 86400
** Default value: 3600
*/
#define STATS_TIME 3600
#ifdef notdef
#endif

/* CONFIGURE: Define this if you want to syslog each
** "too many connections" error message.
** Undefine this if you want to spare some CPU time and syslog space
** by "syslogging" only once or at most twice for each overflow condition.
** HINT: leave it undefined.
*/
#ifdef notdef
#define SYSLOG_EACH_TOOMCONNS
#endif

/* CONFIGURE: Define this if you want to syslog the begin and
** the end of "too many connections" error message when
** SYSLOG_EACH_TOOMCONNS is NOT defined.
** This define is useful to measure the delay between stopping
** accepting new connections and restarting accepting them.
** Undefine this if you want to spare some CPU time and syslog space
** by "syslogging" only once: when reaching upper limit (maxconnects).
** HINT: define it only for debugging purposes.
*/
#ifdef notdef
#define SYSLOG_BEGEND_TOOMCONNS
#endif

/* CONFIGURE: Define this if you want to syslog each
** "timed out connection" error message.
** Undefine this if you want to spare lots of CPU time and syslog space.
*/
#ifdef notdef
#define SYSLOG_EACH_CONNTMO
#endif

/* CONFIGURE: Define this if you want to syslog the total number of
** "timed out connection" after each periodic connection expiring cycle.
** Undefine this if you see lots of connection timeouts and
** you want to spare a few syslog space.
** HINT: initially you may want to leave it defined for a while
**       in order to gather useful statistics.
*/
#define SYSLOG_TOTCNT_CONNTMO
#ifdef notdef
#endif

/* CONFIGURE: Define this if you want to syslog messages
** reporting that there is no index and "directory indexing is disabled".
** HINT: initially you may want to leave it defined for a while
**       in order to gather useful statistics.
*/
#define SYSLOG_INDEXING_DISABLED
#ifdef notdef
#endif

/* CONFIGURE: Seconds between two log file flushes.  If this is undefined then
** log file is flushed only when it is closed. If this is defined then
** there are two cases:
**    value = 0, log file is flushed after every make_log_entry call.
**    value > 0, log file is flushed periodically every value seconds.
** NOTE: this define is effective only if an external log file
**       is used (options -l or logfile=xxx) instead of default syslog().
** HINT: undefine it to get best performances.
** Range  values: 0 - 3600
** Default value: 5
*/
#define LOG_FLUSH_TIME 5
#ifdef notdef
#endif

/* CONFIGURE: Define this if you want vhostname to be prepended to
** all other log fields;  this is useful if hosting virtual hosts
** in order to facilitate log file analysis.
** Leave it undefined if you want to keep it as first part of encoded url.
** Default: undefined
*/
#ifdef notdef
#define LOG_PREPEND_VHOSTNAME
#endif

/* CONFIGURE: The file CACHE L0 tries to keep the total number of allocated
** file contents (size <= MAX_FILE_SIZE_L0) below this number.
** This limit is useful to keep in cache a reasonable number (not too high)
** of files when their size is near to 0.
** It's not advisable to set it over 300000 - 400000.
** HINT: keep it in sync with DESIRED_MAX_MALLOC_BYTES.
** HINT: keep it in sync with DESIRED_MAX_MAPPED_FILES.
** Typical value for a big/busy server: 50000
** Range  values: 10 - 500000
** Default value: 5000
*/
#define DESIRED_MAX_MALLOC_FILES        5000

/* CONFIGURE: The file CACHE L0 tries to keep the total malloc(ated) bytes
** below this number, so that you don't run out of memory space (no swap).
** This is not a hard limit, thttpd will go slightly over it if you really
** are accessing lots of small files in a few seconds.
** HINT: keep it in sync with DESIRED_MAX_MALLOC_FILES.
** Typical value for a big/busy server: (1024 * 1024 * 20)
** Range  values: (1024 * 1) - (1024 * 1024 * 256)
** Default value: (1024 * 1024 * 2)
*/
#define DESIRED_MAX_MALLOC_BYTES        (1024 * 1024 * 2)

/* CONFIGURE: The mmap CACHE L1-L4 tries to keep the total number of mapped
** files below this number, so you don't run out of kernel file descriptors.
** If you have reconfigured your kernel to have more descriptors, you can
** raise this and thttpd will keep more maps cached.  However it's not
** a hard limit, thttpd will go over it if you really are accessing
** a whole lot of files.
** HINT: if you want to reduce disk I/O and your system has enough RAM
**       and it has a max mappable space large enough (at least 1 - 2 GB)
**       and thttpd has to serve mainly small and medium sized files
**       (much smaller than 128 KB)
**       then try to increase it (up to 30000 - 40000).
** HINT for Linux users: check value of /proc/sys/fs/file-max
** because it limits max. mappable files (see also: virtual file system)
** HINT: keep it in sync with DESIRED_MAX_MALLOC_FILES.
** Typical value for a big/busy server: 20000
** Range  values: 2 - 100000
** Default value: 2000
*/
#define DESIRED_MAX_MAPPED_FILES        2000

/* CONFIGURE: The mmap CACHE L1-L4 also tries to keep the total mapped bytes
** below this number, so you don't run out of address space.  Again
** it's not a hard limit, thttpd will go over it if you really are
** accessing a bunch of large files (in this case you may want
** to enable sendfile and to lower DEFAULT_EXPIRE_AGE).
** MANDATORY: it must be much less than 2 GB (1600 MB at most).
** Typical value for a big/busy server: (1024 * 1024 * 1200)
** Range  values: 1024 - 1024 * 1024 * 1500
** Default value: 1024 * 1024 * 800
*/
#define DESIRED_MAX_MAPPED_BYTES        (1024 * 1024 * 800)

/* CONFIGURE: The fdmap CACHE L5 tries to keep the total number of opened
** and unused files below this number, so you don't run out of
** file descriptors between two cache cleanups (OCCASIONAL_MMC_TIME).
** HINT: you can keep it between 1/10 and 1/30 of max. files
**       (see also: ulimit -n).
** MANDATORY: keep it much lower than max files (ulimit -n).
** Range  values: 2 - 5000
** Default value: 100
*/
#define DESIRED_MAX_OPENED_FILES        100

/* CONFIGURE: files, whose size is less than or equal to this limit (bytes),
** are cached by malloc() instead of by mmap();
** they have an expire age 100 times higher than default value.
** MANDATORY: keep it less than 4096 bytes.
** NOTE: setting it to 0 disables cache L0.
** Typical value for an almost slow server: 1024
** Typical value for a  big / busy  server: 2048
** Typical value for a huge / busy  server: 2880
** HINT: try to keep the number as a multiple of 64.
** Range  values: 0 - 4096
** Default value: 2048
*/
#define	MAX_FILE_SIZE_L0	(2048)

/* CONFIGURE: files, whose size is less than or equal to this limit (bytes),
** have an expire age 10 times higher than default value.
** MANDATORY: MAX_FILE_SIZE_L1 > MAX_FILE_SIZE_L0
** HINT: try to keep the number as a multiple of 4096.
*/
#define	MAX_FILE_SIZE_L1	(1024 * 16)

/* CONFIGURE: files, whose size is less than or equal to this limit (bytes),
** have an expire age 4 times higher than default value.
** Choose a value accordingly to available RAM,
** mean file size to be served and network traffic.
** MANDATORY: MAX_FILE_SIZE_L2 > MAX_FILE_SIZE_L1
** HINT: try to keep the number as a multiple of 4096.
*/
#define	MAX_FILE_SIZE_L2	(1024 * 96)

/* CONFIGURE: files, whose size is less than or equal to this limit (bytes),
** have an expire age equal to default value.
** Choose a value accordingly to: available RAM,
** mean file size to be served and network traffic.
** MANDATORY: MAX_FILE_SIZE_L3 > MAX_FILE_SIZE_L2
** HINT: try to keep the number as a multiple of 4096.
*/
#define	MAX_FILE_SIZE_L3	(1024 * 256)

/* CONFIGURE: files, whose size is less than or equal to this limit (bytes),
** along with all bigger files (when use sendfile is disabled),
** have an expire age 32 times lower than default value.
** If MAX_FILE_SIZE_L4 <= MAX_FILE_SIZE_L3 then MAX_FILE_SIZE_L4 is ignored
** and only MAX_FILE_SIZE_L3 limit is used for big files.
** HINT: try to keep the number as a multiple of 4096.
*/
#define	MAX_FILE_SIZE_L4	(1024 * 512)

/* CONFIGURE: this define applies to native sendfile() only.
** In many OS it is useful to limit the block size
** for sendfile calls, specially if network link is faster
** than disk speed or if there can be many parallel downloads
** of different BIG FILES (>= 10 MB - 100 MB) whose total size
** greately exceeds RAM size (I/O disk bound).
** The most efficient size of this block depends on:
** OS, disk and network speed, disk seek time, number of parallel downloads
** to serve, speed of client downloads, send socket size, etc.
**
** BLK. size
**      ----
**         4 KB  Pico  / embedded systems,   DMA disabled  <    1 MB/sec.
**         8 KB  Micro / embedded systems,   DMA disabled  <    2 MB/sec.
**        16 KB  Micro / embedded systems,   DMA disabled  <  2-3 MB/sec.
**        32 KB  Small / old OS, slow disks, DMA disabled  <  3-4 MB/sec.
**        64 KB  Linux 2.2.x, BSD 3.x, 4.x, disks with DMA >=  10 MB/sec.
**       128 KB  Linux 2.4.x, fast network and fast disks  >=  20 MB/sec.
**       256 KB  Linux 2.6.x, etc. with      fast disks    >=  40 MB/sec.
**       512 KB  High end systems with very  fast disks    >=  80 MB/sec.
**      1024 KB  Idem, net.  1 GBit, L2 4 MB, SATA disks   >= 100 MB/sec.
**      2048 KB  Idem, net.  1 GBit, L2 8 MB, SATA disks   >= 200 MB/sec.
**      4096 KB  Idem, net. 10 Gbit, 64 bit OS, SCSI disks >= 500 MB/sec.
**
** NOTE: disk speed is intended as that showed by hdparm(8) (Linux),
**       hdparm -t diskDeviceName.
**
** NOTE: set the value to a power of two, or at least to a multiple
**       of a RAM page (4096 / 16384 bytes);
**       65536 should be right for 80% of Internet thttpd servers;
**       for best performances the value should be from 1 to 4 times
**       greater than current socket send buffer size.
**
** See Also: CONN_SO_SNDBUF (in -C configfile too).
**
** HINT: at run-time you can set this value by uncommenting
**       the same name (MAX_SENDFILE_BLK_SIZE) in -C configfile.
**
** Suggested       * 1    * 2    * 4     * 8     * 16    * 32     * 64
**        values: 16384, 32768, 65536, 131072, 262144, 524288, 1048576.
** Range  values: 4096 - 4194304	( >= CONN_SO_SNDBUF )
** Default value: 65536 (16384 * 4)
*/
#define	MAX_SENDFILE_BLK_SIZE	(16384 * 4)

/* CONFIGURE: Define this to enable, by default, sendfile()
** (instead of mmap()) for files bigger then
** MAX_FILE_SIZE_L3 or MAX_FILE_SIZE_L4
** (if MAX_FILE_SIZE_L4 > MAX_FILE_SIZE_L3).
**
** This is really useful if thttpd has to serve:
**    - single files whose size is over 100 - 200 MB or
**      whose size is over available RAM - 25%
**      (i.e. 100 MB if you have 128 MB RAM);
**        or
**    - many (more than 10 - 20) big files, each bigger than 50 MB - 100 MB;
**        or
**    - lots of medium sized (0.5 - 50 MB) files, whose total size
**      is near or over OS max mmap limit ( usually 1 - 2 GB ),
**      which are likely to be downloaded through many parallel connections.
**
** NOTE: Linux 2.2, sendfile() works well even if it is not as efficient
**       as in Linux 2.4 and later.
**
** NOTE: Linux >= 2.4: if you enable sendfile() and
**       your Gigabit Ethernet card is ZERO_COPY capable
**       (of course all Gigabit cards should be ZERO_COPY ready) and
**       you have a Gigabit network, then you may want to keep
**       above cache limits (only MAX_FILE_SIZE_L2, L3, L4)
**       between 32768 and 131072 bytes (with L4 <= L3)
**       in order to boost performances (your mileage may vary).
**
** NOTE: by default sendfile() is emulated by read()+write();
**       to enable native sendfile()
**       (if your OS has it for the filesystem(s) you are using),
**       simply re-run ./configure and verify that
**       one of these defines are assigned to the variable DEFS
**       inside generated Makefile (if it is not, then added it),
**       i.e. DEFS = -DHAVE_PROGNAME=1 ... -DHAVE_LINUX_SENDFILE=1:
**
**           -DHAVE_BSD_SENDFILE
**               or
**           -DHAVE_LINUX_SENDFILE
**               or
**           -DHAVE_SOLARIS_SENDFILE
**               or
**           -DHAVE_SOLARIS_SENDFILEV
**
**       then, of course, recompile thttpd (this has to be re-done
**       after every re-run of ./configure script).
**
** WARNING: many native / old sendfile() implementations are broken
**          when used for files lying on RAM disks, TmpFS, NFS file systems
**          or FAT / NTFS partitions.
**
** HINT: at run-time you can enable or disable sendfile anyway
**       by adding:
**    USE_SENDFILE
**        or
**    NO_SENDFILE
** to configuration file ( -C command line option ).
*/
#ifdef notdef
#define USE_SENDFILE
#endif

/* CONFIGURE: Define this to enable, by default, O_NOATIME
** in open() files (flag available since Linux 2.6.8).
** This flag is useful to not update access time of served files.
** NOTE: this should spare some pico CPU time; well, setting noatime
**       option in /etc/fstab is certainly more efficient because
**       all kind of files (including directories) are read
**       without updating access time.
** HINT: at run-time you can enable or disable O_NOATIME anyway
**       by adding:
**    USE_O_NOATIME
**        or
**    NO_O_NOATIME
** to configuration file ( -C command line option ).
*/
#ifdef notdef
#define USE_O_NOATIME
#endif

/* CONFIGURE: Minimum and maximum intervals between child-process reaping,
** in seconds (used only if EXECUTE_CGI is defined).
** MANDATORY: MAX_REAP_TIME >= MIN_REAP_TIME * 3
*/
#define MIN_REAP_TIME 3
#define MAX_REAP_TIME 12

/* CONFIGURE: Maximum number of calls to fork() before child-process reaping;
** this is useful if lots (hundreds) of CGIs or directory listings
** are launched in a few seconds.
** HINT: keep it between 1 and 50.
*/
#define MAX_REAP_COUNT 5

/* You almost certainly don't want to change anything below here. */

/* CONFIGURE: When throttling CGI programs, we don't know how many bytes
** they send back to the client because it would be inefficient to
** interpose a counter.  CGI programs are much more expensive than
** regular files to serve, so we set an arbitrary and high byte count
** that gets applied to all CGI programs for throttling purposes.
*/
#define CGI_BYTECOUNT 50000

/* CONFIGURE: The default port to listen on.  80 is the standard HTTP port.
*/
#define DEFAULT_PORT 80

/* CONFIGURE: A list of index filenames to check.  The files are searched
** for in this order.  These must be simple file names.  They cannot
** contain wildcard characters.
** NOTE:  index.cgi is always retrieved if it is not executable
**        otherwise it is executed only if EXECUTE_CGI is defined and
**        there is a CGI pattern.
** HINT:  if you use only GET method,
**        you may want to use nph-index.cgi instead of index.cgi.
*/
#define INDEX_STATIC_NAMES "index.html", "index.htm", "index.xhtml", "index.xht", "Default.htm"
#ifdef EXECUTE_CGI
#define INDEX_NAMES	INDEX_STATIC_NAMES, "index.cgi"
#else
#define INDEX_NAMES	INDEX_STATIC_NAMES
#endif

/* CONFIGURE: If this is defined then thttpd will automatically generate
** index pages for directories that don't have an explicit index file.
** If you want to disable this behavior site-wide, perhaps for security
** reasons, just undefine this.  Note that you can disable indexing of
** individual directories by merely doing a "chmod 711" on them - the
** standard Unix file permission to allow file access but disable "ls".
*/
#ifdef notdef
#define GENERATE_INDEXES
#endif

/* CONFIGURE: If this is defined then thttpd will skip file names
** starting with a dot (excepted for "." and ".."), when generating
** directory listings.
*/
#ifdef notdef
#define INDEXES_SKIP_DOTFILES
#endif

/* CONFIGURE: If this is defined then thttpd will skip current dot
** directory name ("."), when generating directory listings.
*/
#define INDEXES_SKIP_DOTCURDIR
#ifdef notdef
#endif

/* CONFIGURE: If this is defined then thttpd will add a remark/comment
** to "." and "..", in order to clarify what they represent
** (useful to non geeks), when generating directory listings.
*/
#define INDEXES_REMARK_DOTDIRS
#ifdef notdef
#endif

/* CONFIGURE: If this is defined then thttpd tries to remove trailing
** slashes from the end of "regular file names" (not CGIs and not directories)
** and then will redirect the request to force client using new URL.
** If this is not defined then such file names (ie. /pub/readme.txt//)
** lead to "error 404 not found".
** HINT: leave it undefined to force Apache behaviour and stop bad URLs
**       from being used.
*/
#ifdef notdef
#define FNREG_FIX_TRAILING_SLASHES
#endif

/* CONFIGURE: Whether to log unknown request headers.  Most sites will not
** want to log them, which will save them a bit of CPU time.
*/
#ifdef notdef
#define LOG_UNKNOWN_HEADERS
#endif

/* CONFIGURE: names of browsers / user agents that don't properly
** support keep-alive even if they claim to.
** NOTE: only HTTP/1.1 connections are kept alive by thttpd,
**       thus all old Mozilla / Netscape browsers up to 4.x
**       are not needed in this list (because they use HTTP/1.0 + keep-alive).
** NOTE: list taken from Apache 1.3.19.
** HINT: for best performance, keep the list short or undefine it at all;
**       well, indeed, if a "luser" enables HTTP/1.1 and keep alive in these
**       browsers, then he/she should be punished by hanging HTTP connections.
*/
#ifdef notdef
#define BAD_KEEPALIVE_UA_LIST	\
/*	"Mozilla/2",   */	\
	"MSIE 4.0b2;"
#endif

/* CONFIGURE: Time between updates of the throttle table's rolling averages.
** If you network is relatively slow, then don't set it too low
** (i.e. less than 3-4 sec.) because, in this case,
** mean traffic cannot be correctly computed).
** In any case don't set it too high (let's say over 60-70 seconds)
** because responsiveness to traffic peaks becomes poor and because,
** at Gigabit speed, tables may overflow.
** HINT: optimal values for high speed networks (LANs) are:
**       2 - 4   1000 Mbit/sec. (1 Gbit/sec.)
**       2 - 8    100 Mbit/sec.
**       4 - 12    10 Mbit/sec.
**       4 - 12     1 Mbit/sec.
**       optimal values for slow Internet connections are:
**       4 -  8  1000 Mbit/sec. total bandwidth.
**       4 - 12   100 Mbit/sec. total bandwidth.
** HINT: if possible use a power of two (2, 4, 8).
*/
#define THROTTLE_TIME 4

/* CONFIGURE: Define this if you want to enable IPv4 throttles
** (IPv6 and other address types are happily ignored).
** This feature (contributed by Emmanuel Hocdet) let thttpd
** to throttle clients by their IP address, thus allowing different
** throttling policies based on network interfaces (i.e. lan1, lan2, etc.).
** NOTE: this feature works along default URI throttling.
** HINT: if you enable this feature and you also want to deploy
**       normal URI throttling, you may also want to increase
**       default MAXTHROTTLENUMS.
*/
#ifdef notdef
#define USE_IPTHROTTLE
#endif

/* CONFIGURE: Maximum number of throttle patterns that any single URL can
** be included in.  This has nothing to do with the number of throttle
** patterns that you can define, which is unlimited.
** HINT: use 2, 10 or 18 to align connecttab elements
**       to 64, 96 or 128 bytes boundaries.
*/
#define MAXTHROTTLENUMS 2

/* CONFIGURE: Maximum bandwidth (bytes/sec.) you allow for any throttle pattern.
** Max. limits loaded from throttle files are trimmed down to this limit.
** HINT: keep it much lower than (1024 / THROTTLE_TIME) * 1048576L.
*/
#define MAX_THROTTLE_LIMIT	( 64 * 1048576L )

/* CONFIGURE: Minimum bandwidth (bytes/sec.) you allow for any throttle pattern.
** If computed value (throttle limit / number of files being downloaded)
** is less than this limit then connection is refused in order
** to grant the minimum bandwidth in byte/sec.
** HINT: keep it higher than 100 bytes/sec. (possibly > 1000 bytes/sec.).
*/
#define MIN_THROTTLE_LIMIT	256

/* CONFIGURE: Maximum bandwidth (bytes/sec.) per connection;
** if this is defined then thttpd will limit the number
** of bytes per second sent through every connection.
** It is useful if you want to limit bandwidth for every connection
** independently from global throttle limits, number of active connections
** or bandwidth saturation.
** HINT: keep it a power of two: 2048, 4096, 8192, 16384, 32768, etc.
*/
#ifdef notdef
#define MAX_CONN_BYTES_LIMIT	16384
#endif

/* CONFIGURE: The listen() backlog queue length.  The 1024 doesn't actually
** get used, the kernel uses its maximum allowed value.  This is a config
** parameter only in case there's some OS where asking for too high a queue
** length causes an error.  Note that on many systems the maximum length is
** way too small - see http://www.acme.com/software/thttpd/notes.html
*/
#define LISTEN_BACKLOG 1024

/* CONFIGURE: Number of file descriptors to reserve for uses other than
** connections.  Currently this is 10, representing one for the listen fd,
** one for dup()ing at connection startup time, one for reading the file,
** one for syslog, and possibly one for the regular log file, which is
** five, plus a factor of two for who knows what.
*/
#define SPARE_FDS 10

/* CONFIGURE: How many seconds to leave a connection open while doing a
** lingering close.  The higher is RTT (Round Time Trip) of TCP/IP packets
** (see: ping(8), traceroute(8)), the higher this value should be set
** (i.e. max. RTT rounded up + 1 sec.).
** NOTE: under certain conditions (i.e. keep alive, pipelining, etc.),
**       if DYNAMIC_LINGER_TIME is defined, thttpd will AUTOMATICALLY USE
**       a slightly HIGHER VALUE (+1 sec.) or LOWER value (1/2).
** MANDATORY: keep it between 1 and 3 seconds.
** See also: IDLE_KEEPALIVE_TIMELIMIT.
** Typical value for a fast LAN (1000 - 100 Mbit/sec.): 1
** Typical value for a slow LAN         (10 Mbit/sec.): 1
** Typical value for Internet high   bandwidth (4000 - 640 KBit/sec.):  1
** Typical value for Internet medium bandwidth (640  - 128 Kbit/sec.):  1
** Typical value for Internet low    bandwidth ( 56  -  28 Kbit/sec.):  1-2
*/
#define LINGER_TIME 1

/* CONFIGURE: Define this to enable automatic adjustment of LINGER_TIME
** value under certain conditions (client is pipelining, etc.).
** HINT: leave it defined.
*/
#define DYNAMIC_LINGER_TIME
#ifdef notdef
#endif

/* CONFIGURE: Maximum number of symbolic links to follow before
** assuming there's a loop.
** Range  values: 1 - 30
** Default value: 10
*/
#define MAX_LINKS 10

/* CONFIGURE: You don't even want to know.
*/
#define MIN_WOULDBLOCK_DELAY 100L

/* CONFIGURE: Define this if you want to log string alloc() statistics;
** they are not useful unless you are debugging the code.
*/
#ifdef notdef
#define DO_ALLOC_STATS
#endif

/* CONFIGURE: Define this if you want to use my old syslog(3)
** functions in syslog.c (this file has been removed since thttpd-2.23).
** Nowadays most OS have reliable syslog(3) functions thus it is safe
** to leave this undefined.
*/
#ifdef notdef
#define USE_MY_OLD_SYSLOG
#endif

/* CONFIGURE: Define this if you want to use layout handling
** in order to be able to send a static header and/or footer
** with every html file served.
** You also need to add:
**     layout_header=filename
** and/or
**     layout_footer=filename
** to configuration file (-C option) to effectively enable it.
*/
#ifdef notdef
#define USE_LAYOUT
#endif

/* CONFIGURE: This define is automatically enabled when needed;
** if you want to disable child execution, undefine both above
** EXECUTE_CGI and GENERATE_INDEXES.
*/
#ifndef EXECUTE_CHILD
#if	defined(EXECUTE_CGI) || defined(GENERATE_INDEXES)
#define EXECUTE_CHILD
#endif
#endif

#endif /* _CONFIG_H_ */
