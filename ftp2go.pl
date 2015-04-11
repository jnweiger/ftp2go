#! /usr/bin/perl -w
#
# $Id: ftp2go.pl,v 1.1 2006/10/05 21:50:41 jw Exp jw $
# ftp2go.pl -- ein minimaler FTP-Server
#
# 17.6.2001, jw, V0.1 
# Initial framework. Can talk ftp protocol basics. 
# All commands are dummies. LIST returns a constant string.
#
# 18.6.2001, jw. V0.2 RETR working. Even on Win32.
# 19.6.2001, jw. V0.3 STOR, REST working.
# 19.6.2001, jw. V0.4 NLST, DELE working.
# 19.6.2001, jw. V0.5 RNFR RNTO MKD RMD working. Voyager Client compatibe.
# 31.7.2001, jw, V0.6 Three ways to lookup our hostname
#
# Ich habe doch eine Verbindung. Der socket zeigt bei 
# einer multihomed maschine bereits in die richtige Richtung.
# Die hostname Versuche laufen alle Gefahr sich an einem defekten DNS zu verklemmen.
# 27.11.2001, jw, V0.7 Also schnappen wir uns die richtige lokale ip per sockname().
# 27.11.2001, jw, V0.8 Mit -x aufgerufen gibts ein execute feature. Stefan mag das gar nicht.
#
# $Log: ftp2go.pl,v $
# Revision 1.1  2006/10/05 21:50:41  jw
# Initial revision
#
# Revision 1.6  2002/09/25 13:06:56  jweigert
# ftp2go.pl v0.8d
# tftp idea documented, but not yet implemented
#
# Revision 1.5  2002/09/25 12:52:41  jweigert
# ftp2go.pl 0.8c kommt beim NLIST (ls vom DOS ftp-client) jetzt ohne Parameter aus.
#
# Revision 1.4  2002/09/24 08:46:25  jweigert
# ftp2go.pl fuer ein altes 5.004_02 tauglich gemacht
#
# Revision 1.3  2001/11/27 21:37:53  jweigert
# V0.8a: Voller windows support mit stderr redirect zum client.
# V0.8b: Muss was für das schlechte Gewissen tun.
# 	Netzmasken eingeführt. -x geht nur, wenn man mit -m eine oder mehrere Netzmasken angibt.
#
# Revision 1.2  2001/11/27 20:26:34  jweigert
# autoexec feature eingebaut. Stefan mag das gar nicht.
# Aber es muss sein :->>
#
# Das feature ist nur dann freigeschaltet, wenn man ftp2go.pl -x aufruft.
# -x wie execute. NICHT BENUTZEN, denn Effekte wie folgt:
#
# 1.  Die Begruessung enthaelt den text "Trojan FTP Server" anstelle von "FTP Server".
# 2.  Das Verzeichnis /autoexec.bat/ wird nicht mehr im listing angezeigt.
# 3.  Alles was in das Verzeichnis /autoexec.bat/ geladen wird, wird
#     Direkt nach dem Hochladen ausgefuehrt.
#     STDOUT und STDERR zeigen gemeinsam richtung ftp-client, STDIN ist auf /dev/null.
#     Das Arbeitsverzeichnis ist die FTP-Root.
# 4.  Sicherheitstechnisch ist der Effekt vergleichbar mit einem login ohne Passwort.
#     Es kann beliebiger Code hereingeladen und ausgefuehrt werden. Eine Beschränkung
#     auf die FTP-Root gibt es nicht. Daher wird auch gar nicht erst der Versuch unternommen
#     den Pfadnamen vor ; ^ \ $ " ' Sonderzeichen zu schützen.
#
# Das ganze funktioniert unter Windows genauso wie unter Unix.
# Ich sag das mal so allgemein.  Getestet unter NT4.0 und Suse7.2
# Schönheitsfehler bei Windows: Debug-Output auf STDERR wird nach dem ersten
# ausgeführten Kommando nie wieder ausgegeben.  Irgendwas verreckt mir da im open3() call.
#
# Revision 1.1  2001/11/27 10:52:23  jweigert
# Ein minimalistischer FTP-Server, der sowohl auf Windows als auch auf UNIX laeuft.
#
# Keine Passwortabfrage, keine Sicherheit. Wer das Teil startet, muss es beobachten und
# auch wieder stoppen.
# Das Verzeichnis in dem er gestartet wird schreib und lesbar per FTP angeboten.
# Kann passive und active mode down und upload.
#
# Dieser hier benutzt (ausser Standard Modulen wie IO::Socket) keine weiteren Module.
# Insbesondere *nicht* das monströse FTP::Server Modul.
#
#
# 8.12.2001, jw, V0.8c
# Perl_5.004_04 auf Solaris 413_U1 braucht zwei Patches:
# syswrite() bitte mit 3 Parametern und recv() liefert '', wenn o.k.
# And don't blame ftp2go.pl if files get ruined during upload from a
# solaris-client. The client must see a 'bi' command or it won't work.
#
# 24.2.2002, jw. Feature Idea:
# Neue Optionen "-t 69", "-T 69".
# Startet einen tftp-server auf udp port 69 und leert die server_ports liste.
# Wer tftp und ftp gelichzeitig bekommen will, muss dann "-t 69 -p 21" schreiben.
# Fuer -t sollte zuerst ein chdir /tftpboot gemacht werden. Das soll aber der
# Aufrufer vorher machen. Wir pruefen pwd, wenn der auf "/tftpboot" endet, sind wir zufrieden und
# setzen $tftp_prefix auf "./". Andernfalls setzen wir $tftp_prefix auf "./tftpboot/" und testen,
# ob dieses Unterverzeichnis existiert. Wenn ja sind wir zufrienden, wenn nein geben wir eine
# Warnung aus. In jedem Fall startet der tftp-server aber unter Angabe des verwendeten
# tftp-Arbeitsverzeichnisses.
# Der Sun tftpd macht folgende Restriktionen: Nur Dateien mit world-read koennen per tftp geholt
# werden, nur existierende Dateien mit world-write koennen per tftp ueberschrieben werden.
#
# diese Restriktionen gelten, fall '-t 69' angegeben wurde auch. Falls '-T 69' angegeben wurde,
# gelten nur die ueblichen Zugriffsrechte des ftp2go.pl selbst.
# Protokoll a la RFC 783.

#
# 0.8f, 20.09.2004, jw -- ABOR debugging added against 
#			  Use of uninitialized value in delete at fp2go.pl line 910.
# 2006-08-03, V0.8g, jw -- resolved my $a = foo if bar; to avoid perl madness.
#
# 2011-12-06, V0.8h, jw -- chmod support added, needed by ruby/1.8/net/ftp.rb



use strict;
use IO::Socket;
use IO::File;
use Net::hostent;	# gethost
#use Data::Dumper;	# only for debugging

BEGIN
{
  eval 'use Net::Domain;';	# only way to get a fqdn
  eval 'use POSIX;';		# use (POSIX::uname)[1]       if Sys::Hostname unavail.
  eval 'use Sys::Hostname;';	# use Sys::Hostname::hostname if Net::Domain unavail.
}

use Cwd ();
use Config;

umask 000;

my $version		= '0.8h';
my $progname		= 'Ftp-2-Go';
my $author_email	= 'jw@suse.de';
my $verbose		= 1;
my $delay		= 0;			# sleep seconds before each select
my @server_ports	= (21, 2121);
my @server_ports_t	= ();			# per default, we are no tftp server.
my $with_stdin		= ! -d 'C:\\';		# Win32 select explodes with STDIN
my $max_timeout		= 10.0;			# Seconds waiting for select
my $max_write_size	= 100*1024;			# Bytes per TCP packet sent.
my $no_hostlookup	= 1;			# Unseren eigenen Namen brauchen eh wir nur für die Startmeldung.
my $allow_autoexec	= 0;			# Be a Trojan-FTP-Server? Are you sure?
my $autoexec_dir	= '/autoexec.bat';	# inside our ftp root, of course...
my $autoexec_out	= "$autoexec_dir/autoexec.out";
my $tftp_path_prefix	= '';			# what we try first.
my $tftp_path_match	= '/tftpboot';		# what our pwd must suffix match
my $tftp_pseudo_secure	= 0;			# serve only world-read/write files.

########################## end of user config #################################

$| = 1;

my @netmask;
my $hostname = '<undef>';
my $ip_addr_a = '0.0.0.0';
my $win32 = -d 'C:\\';
# $win32 = 1 if "$Config{archname}:$Config{osname}" =~ m{win32}i;

unless ($no_hostlookup)
  {
    $hostname = eval 'Net::Domain::hostfqdn' ||
			  eval '(POSIX::uname)[1]' ||
			  eval 'Sys::Hostname::hostname';

    $ip_addr_a = inet_ntoa(@{gethost($hostname)->addr_list}[0]);
  }

while (defined(my $arg = shift))
  {
    $allow_autoexec	= 1	if $arg eq '-x';	
    push @server_ports, shift	if $arg eq '-p';
    @server_ports = ()	 	if $arg =~ m{-t}i;
    push @server_ports_t, shift	if $arg =~ m{-t}i;
    $tftp_pseudo_secure++	if $arg eq '-t';
    push @netmask, shift	if $arg eq '-m';
    unless ($arg =~ m{^-[tTxpm]})
      {
        print STDERR qq{
-$progname $version. 
A simple non-authenticating standalone FTP-Server.

$0 [-x] [-t|T 69] [-p port] [-m net/mask]

-p	Specify additional ftp port numbers.
-x	Trojan-FTP-server. Do not do, unless you know why.
-m	Restrict access via netmask. Highly recommended.
};

#-t 	Become a TFTP server on the given port. 
#	FTP service is disabled unless -p specified.
#-T	As -t, but world-read/write files are not enforced.
#
#};
	exit 0;
      }
  }


if ($allow_autoexec and scalar(@netmask)< 1)
  {
    print STDERR qq{
Security alert: Must specify a netmask when running with -x!
Example:
$0 -x -m 127.0.0.1 -m 10/8
};
    exit 0;
  }

if (scalar @server_ports_t)
  {
    print STDERR qq{
TFTP-service not implemented. Sorry.
Please study RFC 783 and submit a patch.
};
    exit 0;
  }


my %server;


for my $port (@server_ports)
  {
    my $fd = IO::Socket::INET->new(
	LocalPort	=> $port,
	LocalAddr	=> 'localhost',
	Multihomed	=> 1,
	Proto		=> 'tcp',
	ReuseAddr	=> 1,
	Reuse_Port	=> 1,
	Listen		=> SOMAXCONN) or
      print STDERR "cannot set up server port $port: $!";
    $server{listen}{$port}{fd} = $fd if $fd;
  }

print STDERR qq{
$progname V$version:
listening on };
print STDERR "$hostname, " unless $no_hostlookup;
print STDERR "$ip_addr_a:" . join(',', keys %{$server{listen}});
print STDERR " with autoexec in $autoexec_dir" if $allow_autoexec;
print STDERR "\n";
print STDERR "for " . join(' or ', @netmask) . "\n" if scalar @netmask > 0;

@netmask = parse_netmask(@netmask);

$server{clients}{STDIN}{fd} = \*STDIN if $with_stdin;

for (;;)
  {
    my ($rin, $rout) = mkfdset(\%server);
    
    my $timeout = $max_timeout;
    sleep($delay) if $delay;
    my ($nfound, $timeleft) = select($rin, $rout, undef, $timeout);
    my $buffer;

    print "\tAccept connections\n" if $verbose > 1;
    ################################################
    ### Accept connections
    ################################################
    for my $port (keys %{$server{listen}})
      {
	print "accept?" .  vec($rin, $server{listen}{$port}{fd}->fileno, 1) . "\n" if $verbose > 1;
	next unless vec($rin, $server{listen}{$port}{fd}->fileno, 1);
	my ($fd, $paddr) = $server{listen}{$port}{fd}->accept();
	my ($peer_port, $peer_iaddr) = sockaddr_in($paddr);
	my ($sock_port, $sock_iaddr) = sockaddr_in($fd->sockname());

        unless (grant_access($peer_iaddr))
	  {
	    print STDERR "grant_access failed for " . inet_ntoa($peer_iaddr) . "\n";
            send($fd, "530 go away\r\n", 0);
	    close $fd;
	    next;
	  }

	my $peer = inet_ntoa($peer_iaddr) . ":$peer_port";
	$server{clients}{$peer}{fd} 		=  $fd;
	$server{clients}{$peer}{sockaddr_a}	= inet_ntoa($sock_iaddr);	# my own ip-addr

	print STDERR "my ip is $server{clients}{$peer}{sockaddr_a}\n" if $verbose > 0;

	if (defined(my $ctrl = $server{listen}{$port}{ctrl_peer}))
	  {
	    ### data connection in passive mode
	    if (defined(my $data = $server{clients}{$ctrl}{data_peer}))
	      {
		print STDERR "zapping old data connection ($data)\n";
		delete $server{clients}{$data};
	      }
	    $server{clients}{$peer}{ctrl_peer}	= $ctrl;
	    $server{clients}{$peer}{waiting_for_command} = 1;
	    $server{clients}{$ctrl}{data_peer}	= $peer;
	    print STDERR "pasv data connection to $peer open\n";
	    delete $server{listen}{$port};	# wanted exactly this conn
	  }
	else
	  {
	    ### new client control connection
	    $server{clients}{$peer}{serverport} = $port;
	    do_init($server{clients}{$peer}, $peer);
	  }
      }

    print "\tWrite obufs\n" if $verbose > 1;
    ################################################
    ### Write obuf
    ################################################
    for my $peer (keys %{$server{clients}})
      {
	drained_obuf($peer) unless obuf_size_client($peer);
	next unless my $len = obuf_size_client($peer);

        my $p = $server{clients}{$peer};

	## Special hack for Voyager FTP:
	## If data transfer ends before '150 Opening' was sent, 
	## the client locks up. Thus we hold back data
	## while ctrl obuf is unflushed.
	##
	next if $p->{ctrl_peer} and obuf_size_client($p->{ctrl_peer});
	next unless vec($rout, fileno($p->{fd}), 1);

	shovel_obuf($peer, $len);
	drained_obuf($peer) unless obuf_size_client($peer);
      }

    print "\tRead ibufs\n" if $verbose > 1;
    ################################################
    ### Read ibuf
    ################################################
    for my $peer (keys %{$server{clients}})
      {
        print "\t\tchecking $peer for input\n" if $verbose > 1;
        my $p = $server{clients}{$peer};
	print join(',', keys %$p) . "\n" if $verbose > 1;
	next unless vec($rin, fileno($p->{fd}), 1);
	if ($peer =~ m{:})
	  {
	    # INET
	    my $r = $p->{fd}->recv($buffer, 1024, 0);
	    if (!defined($r) || !length($buffer))
	      {
	        warn "recv $peer: $!" unless defined $r;

		### take our data peer with us, if we are ctrl and have one
		if (defined(my $data_peer = $server{clients}{$peer}{data_peer}))
		  {
		    delete $server{clients}{$data_peer};
		  }

		### notify our ctrl peer, if we are data and have one
		if (defined(my $ctrl_peer = $server{clients}{$peer}{ctrl_peer}))
		  {
		    delete $server{clients}{$ctrl_peer}{data_peer};
		    data_close_hook($p, '226 Transfer complete.');
		  }
		delete $server{clients}{$peer};
	        print STDERR "closed $peer\n";
	      }
	    else
	      {
	      	# fixme: if $r or not $r, what makes the difference here?
	        $p->{ibuf} .= $buffer;	# if $r;
	      }
	  }
	else
	  {
	    # Something like STDIN
	    $p->{ibuf} .= $buffer if sysread($p->{fd}, $buffer, 1024) > 0;
	  }
      }

    ################################################
    ### Process Buffers
    ################################################
    for my $peer (keys %{$server{clients}})
      {
        my $p = $server{clients}{$peer};
	my $r; $r = do_process($p, $peer) if $p->{ibuf} and length $p->{ibuf};
	if ($r)
	  {
	    delete $server{clients}{$peer}; 
	    print STDERR "done $peer\n";
	  }
      }
  }

exit 0;
#########################################################

sub mkfdset
{
  my ($s) = @_;
  my $rin = '';
  my $rout = '';

  for my $peer (keys %{$s->{clients}})
    {
      my $p = $s->{clients}{$peer};
      next unless defined $p->{fd};

      if ($p->{obuf} and length $p->{obuf})
        {
	  print "\tmkfdset setting vec, rout, $peer\n" if $verbose > 1;
          vec($rout, fileno($p->{fd}), 1) = 1;
	}
      else
        {
	  print "\tmkfdset setting vec, rin, $peer\n" if $verbose > 1;
          vec($rin, fileno($p->{fd}), 1) = 1;
	}
    }

  for my $port (keys %{$s->{listen}})
    {
      print "\tmkfdset setting vec, rin, listen $port\n" if $verbose > 1;
      vec($rin, $s->{listen}{$port}{fd}->fileno, 1) = 1;
    }

  return ($rin, $rout);
}


#
# shovel_obuf returns what send() returns.
#
sub shovel_obuf
{
  my ($name, $len) = @_;

  my $p = $server{clients}{$name};

  if ($name =~ m{:})
    {
      # INET
      my $str = substr($p->{obuf}, 0, $max_write_size);
      my $r = send($p->{fd}, $str, 0);
      unless (defined($r))
	{
	  warn "cannot send to $name: $!";
	  delete $server{clients}{$name};
	  print STDERR "disconnect $name\n";
	}
      else
	{
	  if ($r < $len)
	    {
	      print STDERR "$r bytes of $len written.\n" if $verbose > 1;
	      $p->{obuf} = substr($p->{obuf}, $r);
	    }
	  else
	    {
	      print STDERR "$r bytes written.\n" if $verbose > 1;
	      $p->{obuf} = '';
	    }
	}
      return $r;
    }

  # Something like STDIN
  syswrite $p->{fd}, $p->{obuf}, length $p->{obuf};
  $p->{obuf} = '';
  return $len;
}

sub do_process
{
  my ($p, $name) = @_;

  return do_process_ftp_data(@_) if defined $p->{ctrl_peer};
  return do_process_ftp_ctrl(@_);
}

sub do_process_ftp_data
{
  my ($p, $name) = @_;
  my $c = $server{clients}{$p->{ctrl_peer}};
  if (defined(my $fd = $p->{stor_fd}))
    {
      my $len = length $p->{ibuf};
      my $r = syswrite($fd, $p->{ibuf}, $len);
      print STDERR "$r bytes stored.\n" if $verbose > 1;
      if ($r < $len)
        {
	  my $msg = "$name: short write on STOR: $!\n";
          $c->{obuf} .= fmt_text("500 $msg");
	  warn $msg;
	  delete $server{clients}{$name};
	  delete $c->{data_peer};
	}
      $p->{ibuf} = '';
      return 0;
    }
  $c->{obuf} .= fmt_text("500 '$name' Reading data without STOR");
  return 1;
}

sub do_process_ftp_ctrl
{
  my ($p, $name) = @_;

  my $buf = $p->{ibuf};
  print STDERR "seen " . length($p->{ibuf}) . " bytes from $name\n" if $verbose;
  return 0 unless $buf =~ m{[\r\n]$};

  $buf =~ s{[\r\n]+$}{};	# chomp entfernt crlf nur halb.

  print STDERR qq{$buf\n} if $verbose;

  my $o = '500';
  if    ($buf =~ m{^QUIT\b}i) { return 1; }
  elsif ($buf =~ m{^USER\b}i) { $o = '331 Guest login, type no password'; }
  elsif ($buf =~ m{^PASS\b}i) { $o = '230 Guest login o.k.'; }
  elsif ($buf =~ m{^SYST\b}i) { $o = '215 UNIX Type: L8'; }
  elsif ($buf =~ m{^TYPE\b}i) { $o = '200 Type set to I (constant parameter)'; }
  elsif ($buf =~ m{^LIST\b}i) { $o = cmd_list($name, $buf); }
  elsif ($buf =~ m{^NLST\b}i) { $o = cmd_nlst($name, $buf); }
  elsif ($buf =~ m{^CWD\b}i)  { $o = cmd_cwd ($name, $buf); }
  elsif ($buf =~ m{^CDUP\b}i) { $o = cmd_cwd ($name, "CD .."); }
  elsif ($buf =~ m{^PORT\b}i) { $o = cmd_port($name, $buf); }
  elsif ($buf =~ m{^PASV\b}i) { $o = cmd_pasv($name, $buf); }
  elsif ($buf =~ m{^SIZE\b}i) { $o = cmd_size($name, $buf); }
  elsif ($buf =~ m{^MDTM\b}i) { $o = cmd_mdtm($name, $buf); }
  elsif ($buf =~ m{^RETR\b}i) { $o = cmd_retr($name, $buf); }
  elsif ($buf =~ m{^STOR\b}i) { $o = cmd_stor($name, $buf); }
  elsif ($buf =~ m{^REST\b}i) { $o = cmd_rest($name, $buf); }
  elsif ($buf =~ m{^DELE\b}i) { $o = cmd_dele($name, $buf); }
  elsif ($buf =~ m{^ABOR\b}i) { $o = cmd_abor($name, $buf); }
  elsif ($buf =~ m{^RNTO\b}i) { $o = cmd_rnto($name, $buf); }
  elsif ($buf =~ m{^RNFR\b}i) { $o = cmd_rnfr($name, $buf); }
  elsif ($buf =~ m{^MKD\b}i)  { $o = cmd_mkd ($name, $buf); }
  elsif ($buf =~ m{^RMD\b}i)  { $o = cmd_rmd ($name, $buf); }
  elsif ($buf =~ m{^NOOP\b}i) { $o = '200 NOOP command successful.'; }
  elsif ($buf =~ m{^PWD\b}i)  { $o = "257 \"$p->{cwd}\" is current directory. ($p->{root}$p->{cwd})"; }
  elsif ($buf =~ m{^SITE IDLE\b}i)  { $o = '200 Maximum IDLE time unlimited'; }
  elsif ($buf =~ m{^SITE CHMOD\b}i) { $o = cmd_chmod($name, $buf); }

  elsif ($buf =~ m{^HELP\b}i) 
    { 
      $o = qq{214- The following commands are recognized by $progname V$version:
  USER PASS PWD  PORT LIST TYPE CWD  CDUP RETR STOR MKD  RMD
  RNFR RNTO NOOP SYST SIZE MDTM PASV ABOR REST HELP QUIT 
  SITE_IDLE SITE_CHMOD
214 Direct comments to $author_email.\n};  
    }

  else                        
    {
      $o = "500 '$buf': command not understood"; 
    }

  $p->{ibuf} = '';

  $p->{obuf} .= fmt_text($o);
  return 0;
}

sub do_init
{
  my ($p, $name) = @_;

  $p->{obuf}	= "220 ";
  $p->{obuf}	.= "$hostname " unless $no_hostlookup;
  $p->{obuf}	.= "Trojan " if $allow_autoexec;
  $p->{obuf}	.= "FTP Server (ftp2go.pl V$version) ready.\r\n";
  $p->{root}	= Cwd::cwd;	# uses forward slashes even under Win32
  $p->{cwd}	= '/';
  print "accept from $name\n";
}

sub obuf_size_client
{
  my ($name) = @_;
  return 0 unless defined $server{clients}{$name};
  return 0 unless defined $server{clients}{$name}{obuf};
  return length $server{clients}{$name}{obuf};
}

sub fmt_text
{
  my ($txt, $lineprefix) = @_;

  $txt .= "\n" unless $txt =~ m{\n$}s;
  $txt =~ s{([^\r])\n}{$1\r\n}gs;
  $txt =~ s{^}{$lineprefix}gm if defined $lineprefix;
  return $txt;
}

sub drained_obuf
{
  my ($name) = @_;
  my $r = 1;		# will die per default

  # assert that we are a data connection depending on a ctrl_peer
  return 0 unless defined(my $ctrl = $server{clients}{$name}{ctrl_peer});
  my $p = $server{clients}{$name};

  # Do we have more data to send?
  if (defined(my $fd = $p->{retr_fd}))
    {
      for my $i (1..20)
        {
	  my $buf = '';
	  my $rr;
	  if ($rr = $fd->sysread($buf, $max_write_size))
	    {
	      $p->{obuf} .= $buf;
	    }
	  else
	    {
	      delete $p->{retr_fd};
	    }
	  last if $rr < $max_write_size;
	}
      $r = 0 if length $p->{obuf};
    }

  if (defined($p->{stor_fd}))
    {
      print STDERR "STOR from data connection $name\n" if $verbose > 1;
      $r = 0;
    }
  
  if (defined($p->{waiting_for_command}))
    {
      print STDERR "data connection $name waiting for command\n" if $verbose > 1;
      $r = 0;
    }
  
  # All data shuffled. Die and tell our ctrl about that.
  if ($r)
    {
      delete $server{clients}{$name};	
      delete $server{clients}{$ctrl}{data_peer};
      print STDERR "done $name (data)\n" if $verbose;
      data_close_hook($p, '226 Transfer complete.');
    }
  return $r;
}

###
### abs_path is responsible for not returning anything that
### contains enough .. to point upwards beyond /.
### Actually, it shall resolve all .. path components.
###
sub abs_path
{
  my ($dir, $file) = @_;

  $file     =~ s{\\}{/};		# we are talking forward slashes here

  $dir      .= '/'        unless $dir   =~ m{/$};	# append a slash here
  $file     .= '/'        unless $file  =~ m{/$};	# append a slash there
  $file     = "$dir$file" unless $file  =~ m{^/};	# relative path

  $file     =~ s{[^/]+/\.\./}{}g;	# snap away .. things with parent.
  $file     =~ s{/\.\.?/}{/}g;		# snap away .. things without parent.
  $file     =~ s{/+}{/}g;		# snap away multi slashes
  $file     =~ s{([^/])/$}{$1}g;	# snap away the trailing slash

  return $file;
}


sub cmd_size
{
  my ($ctrl, $cmd) = @_;
  my $c            = $server{clients}{$ctrl};

  $cmd             =~ s{^\w+\s+}{};		# skip the command word
  $cmd             = abs_path($c->{cwd}, $cmd);
  return "550 $c->{root}$cmd: no such file." unless -f "$c->{root}$cmd";
  return "213 " . -s "$c->{root}$cmd";
}

sub cmd_mdtm
{
  my ($ctrl, $cmd) = @_;
  my $c            = $server{clients}{$ctrl};

  $cmd             =~ s{^\w+\s+}{};		# skip the command word
  $cmd             = abs_path($c->{cwd}, $cmd);
  return "550 $c->{root}$cmd: no such file." unless -f "$c->{root}$cmd";
  my @t = localtime((stat("$c->{root}$cmd"))[9]);
  return sprintf "213 %04d%02d%02d%02d%02d%02d", 
  	$t[5] + 1900, $t[4] + 1, $t[3], $t[2], $t[1], $t[0];
}


sub cmd_nlst
{
  my ($ctrl, $cmd) = @_;

  my $data_peer = $server{clients}{$ctrl}{data_peer};
  return "500 No data connection." unless defined $data_peer;

  my $c =         $server{clients}{$ctrl};
  my $p =         $server{clients}{$data_peer};
  my $d =         "$c->{root}$c->{cwd}";
  return "500 Bad data peer???" unless defined $p;
  delete $p->{waiting_for_command};

  opendir DIR, "$d" or return "500 opendir $d failed: $!";
  my @files = sort grep { -f "$d/$_" } readdir DIR;
  closedir DIR;
  print STDERR "cmd_nlst: '$cmd'\n" if $verbose > 1;

  $cmd   =~ s{^\w+\s*}{};		# skip the command word, even if nothing follows
  $cmd   = '*' unless $cmd;		# empty string means all
  $cmd   = "\Q$cmd\E";			# quote to make it regexp save
  print STDERR "cmd_nlst: glob pattern translated to RE '$cmd'\n" if $verbose > 1;
  $cmd   =~ s{\\\?}{\.}g;		# glob ? allowed.
  print STDERR "cmd_nlst: glob pattern translated to RE '$cmd'\n" if $verbose > 1;
  $cmd   =~ s{\\\*}{\.\*}g;		# glob * allowed.

  print STDERR "cmd_nlst: glob translated to /^$cmd/\n" if $verbose;
  @files = grep { /^$cmd$/ } @files;

  $p->{obuf} .= fmt_text(join("\n", @files));

  return "150 Opening ASCII conn for NLIST.";
}

sub cmd_list
{
  my ($ctrl, $cmd) = @_;

  my $data_peer = $server{clients}{$ctrl}{data_peer};
  return "500 No data connection." unless defined $data_peer;

  my $c 	= $server{clients}{$ctrl};
  my $p 	= $server{clients}{$data_peer};
  my $d 	= "$c->{root}$c->{cwd}";
  my $hide	= "$c->{root}$autoexec_dir";
  $hide =~ s{/+}{/}g;

  return "500 Bad data peer???" unless defined $p;
  delete $p->{waiting_for_command};

  opendir DIR, "$d" or return "500 opendir $d failed: $!";
  my @files = sort readdir DIR;
  closedir DIR;

  @files = grep { !/^\./ } @files unless $cmd =~ m{\s-\w*a\b};

  $p->{obuf} .= fmt_text(qq{total } . scalar @files);
  for my $f (@files)
    {
      my $path = "$d/$f";
      $path =~ s{/+}{/}g;
      next if $allow_autoexec and $path =~ m{^$hide};
      my @st = stat("$path");
      next if $#st < 9;		# stat failed.

      my $tstamp = scalar localtime($st[9]);
      $tstamp =~ s{^\w\w\w\s}{};	# Wochentag weg.
      $tstamp =~ s{\s\d\d\d\d$}{};	# Jahreszahl weg, sonst verschluckt sich der wsftp!

      my $r = (-r _) ? 'r' : '-';
      my $w = (-w _) ? 'w' : '-';
      my $x = (-x _) ? 'x' : '-';
      my $d = (-d _) ? 'd' : '-';
      my $line = sprintf "$d$r$w$x------ 1  ftp  ftp %8d $tstamp $f", -s _;

      $p->{obuf} .= fmt_text($line);
    }

  return "150 Opening ASCII conn for ls.";
}


sub cmd_dele
{
  my ($ctrl, $cmd) = @_;
  my $c            = $server{clients}{$ctrl};
  $cmd             =~ s{^\w+\s+}{};		# skip the command word
  $cmd             = $c->{root} . abs_path($c->{cwd}, $cmd);

  return "550 $cmd: no such file." unless -f $cmd;

  unlink $cmd;
  return "550 $cmd: DELE failed: $!" if -f $cmd;

  return "250 DELE Command successful.";
}


sub cmd_retr
{
  my ($ctrl, $cmd) = @_;

  my $data_peer    = $server{clients}{$ctrl}{data_peer};
  return "500 No data connection." unless defined $data_peer;

  my $c            = $server{clients}{$ctrl};
  my $p            = $server{clients}{$data_peer};
  return "500 Bad data peer???" unless defined $p;

  $cmd             =~ s{^\w+\s+}{};		# skip the command word
  $cmd             = $c->{root} . abs_path($c->{cwd}, $cmd);
  unless (-f $cmd)
    {
      delete $server{clients}{$data_peer};
      delete $c->{data_peer};
      return "550 $cmd: no such file.";
    }

  my $s = -s $cmd;
  my $fd = new IO::File $cmd, "r";
  unless ($fd)
    {
      delete $server{clients}{$data_peer};
      delete $c->{data_peer};
      return "550 $cmd: open failed: $!";
    }
  binmode $fd;

  sysseek($fd, $c->{rest_offset}, 0) if $c->{rest_offset};
  delete $c->{rest_offset};
  delete $p->{waiting_for_command};
  $p->{retr_fd} = $fd;

  return "150 Opening BINARY data conn for '$cmd' ($s bytes).";
}

sub cmd_stor
{
  my ($ctrl, $cmd) = @_;

  my $data_peer    	= $server{clients}{$ctrl}{data_peer};
  return "500 No data connection." unless defined $data_peer;

  my $c            	= $server{clients}{$ctrl};
  my $p            	= $server{clients}{$data_peer};
  return "500 Bad data peer???" unless defined $p;

  $cmd             	=~ s{^\w+\s+}{};		# skip the command word
  $cmd             	= abs_path($c->{cwd}, $cmd);
  $p->{exec_on_close}	= $cmd if $allow_autoexec and $cmd =~ m{^$autoexec_dir/};
  $cmd             	= $c->{root} . $cmd;

  my $fd 		= new IO::File $cmd, "w";
  unless ($fd)
    {
      delete $server{clients}{$data_peer};
      delete $c->{data_peer};
      return "550 $cmd: open failed: $!";
    }
  binmode $fd;

  sysseek($fd, $c->{rest_offset}, 0) if $c->{rest_offset};
  delete $c->{rest_offset};
  delete $p->{waiting_for_command};
  $p->{stor_fd} = $fd;

  return "150 Opening BINARY data conn for '$cmd'.";
}


sub cmd_pasv
{
  my ($ctrl, $cmd) = @_;
  my $fd = IO::Socket::INET->new(
	LocalAddr	=> '0.0.0.0',
	Proto		=> 'tcp',
	Reuse		=> 1,
	Listen		=> SOMAXCONN);
  return "550 cannot set up passive listener: $!" unless $fd;
  my $port = $fd->sockport;
  my $host = $server{clients}{$ctrl}{sockaddr_a};	# this is the correct IP, in case I am multihomed.

  $server{listen}{$port}{fd} = $fd;
  $server{listen}{$port}{ctrl_peer} = $ctrl;
  print STDERR "cmd_pasv: data listener on $host:$port\n" if $verbose;
  $host =~ s{\.}{,}g;
  return sprintf "227 Entering Passive Mode ($host,%d,%d)", 
  	$port >> 8, $port & 255;
}


sub cmd_port
{
  my ($ctrl, $cmd) = @_;

  if ($cmd =~ m{(\d+),(\d+),(\d+),(\d+),(\d+),(\d+)} )
    {
      my ($ip1,$ip2,$ip3,$ip4,$port_hi,$port) = ($1,$2,$3,$4,$5,$6);
      $port += 256 * $port_hi;
      my $peer = "$ip1.$ip2.$ip3.$ip4:$port";
      if (defined(my $fd = IO::Socket::INET->new($peer)))
	{
	  if (defined(my $data = $server{clients}{$ctrl}{data_peer}))
	    {
	      print STDERR "zapping old data connection ($data)\n" if $verbose > 1;
	      delete $server{clients}{$data};
	    }
	  $server{clients}{$peer}{fd} = $fd;
	  $server{clients}{$peer}{ctrl_peer} = $ctrl;
	  $server{clients}{$peer}{waiting_for_command} = 1;
	  $server{clients}{$ctrl}{data_peer} = $peer;
	  print STDERR "data connection to $peer open\n" if $verbose;
	  return '200 PORT command successful.';
	}
      return "500 PORT command failed: Cannot connect to $peer: $!";
    }
 return "500 '$cmd' command garbled";
}

sub cmd_cwd	# change working directory
{
  my ($ctrl, $cmd) = @_;
  my $c            = $server{clients}{$ctrl};

  $cmd             =~ s{^\w+\s+}{};
  $cmd             = abs_path($c->{cwd}, $cmd);
  return "550 $c->{root}$cmd: no such directory." unless -d "$c->{root}$cmd";
  $c->{cwd}        = $cmd;
  return "250 CWD Command successful. ($c->{root}$c->{cwd})";
}

sub cmd_abor
{
  my ($ctrl, $cmd) = @_;
  my $c            = $server{clients}{$ctrl};
  my $data_peer    = $c->{data_peer};

  print STDERR "cmd_abor: c->{data_peer} is undef??\n" unless defined $data_peer;
  delete $server{clients}{$data_peer};
  delete $c->{data_peer};
  return "225 ABOR Command successful.";
}

sub cmd_rest
{
  my ($ctrl, $cmd) = @_;
  my $c            = $server{clients}{$ctrl};
  my $data_peer    = $c->{data_peer};

  if ($cmd =~ m{(\d+)})
    {
#      $server{clients}{$data_peer}{rest_offset} = $1;
      $c->{rest_offset} = $1;
      return "350 Restarting at $1. Send STOR or RETR.";
    }
  return "550 REST numeric param missing.";
}

sub cmd_rnto
{
  my ($ctrl, $cmd) = @_;
  my $c            = $server{clients}{$ctrl};
  $cmd             =~ s{^\w+\s+}{};
  $cmd             = abs_path($c->{cwd}, $cmd);

  return "550 no RNFR name given." unless $c->{rnfr};
  rename "$c->{root}$c->{rnfr}", "$c->{root}$cmd";
  return "550 Rename failed: $!" if -f "$c->{root}$c->{rnfr}";

  delete $c->{rnfr};
  return "250 RNTO Command successful.";
}

sub cmd_rnfr
{
  my ($ctrl, $cmd) = @_;
  my $c            = $server{clients}{$ctrl};
  $cmd             =~ s{^\w+\s+}{};
  $cmd             = abs_path($c->{cwd}, $cmd);

  return "550 $c->{root}$cmd: no such file." unless -e "$c->{root}$cmd";
  $c->{rnfr}       = $cmd;

  return "350 File exists, ready for rename.";
}

sub cmd_chmod
{
  my ($ctrl, $cmd) = @_;
  my $c            = $server{clients}{$ctrl};
  $cmd             =~ s{^SITE\s+}{};
  $cmd             =~ s{^\w+\s+}{};
  my $mode = $1 if $cmd =~ s{^(0\d+)\s+}{};
  return "550 chmod bad mode: $cmd" unless defined $mode;
  $cmd             = abs_path($c->{cwd}, $cmd);
  chmod $mode, $cmd;
  return "258 chmod done.";
}

sub cmd_mkd
{
  my ($ctrl, $cmd) = @_;
  my $c            = $server{clients}{$ctrl};
  $cmd             =~ s{^\w+\s+}{};
  $cmd             = abs_path($c->{cwd}, $cmd);
  mkdir "$c->{root}$cmd", 0777;
  return "550 $cmd: MKD failed: $!" unless -d "$c->{root}$cmd";

  return "257 \"$c->{root}$cmd\" directory created.";
}

sub cmd_rmd
{
  my ($ctrl, $cmd) = @_;
  my $c            = $server{clients}{$ctrl};
  $cmd             =~ s{^\w+\s+}{};
  $cmd             = abs_path($c->{cwd}, $cmd);
  rmdir "$c->{root}$cmd";
  return "550 $c->{root}$cmd: RMD failed: $!" if -e "$c->{root}$cmd";

  return "250 RMD Command successful.";
}

##############################################################################

sub data_close_hook
{
  my ($data_peer, $msg) = @_;
  my $ctrl = $data_peer->{ctrl_peer};
  my $c = $server{clients}{$ctrl};

  $data_peer->{stor_fd}->close() if defined $data_peer->{stor_fd};

  if (my $cmd = $data_peer->{exec_on_close})
    {
      use IPC::Open3;	# you can rewwrite to use a normal open($systemcmd|"), 
		        # but then Win32 cannot give you your STDERR

      my $seconds = time;
      my $stdoutcount = 0;
      my $minuts = 0;
      my $systemcmd;

      if ($win32)
        {
	  # flip them darn slashes if not at start of word, there they could be switches.

	  $cmd = "./$cmd";
	  $cmd =~ s{([^\s])/+}{$1\\}g;
	  my $edir = $c->{root};
	  $edir =~ s{([^\s])/+}{$1\\}g;
	  $systemcmd = qq{cmd.exe /c "chdir $edir && $cmd"};
	  open NULLFD, "< nul:";
#  	  open SAVEDERR, ">&STDERR";
	}
      else
        {
          chmod 0700, "$c->{root}/$cmd";
          $systemcmd = "sh -c 'cd $c->{root} && ./$cmd'";
	  open NULLFD, "</dev/null";
	}

      $c->{obuf} = fmt_text($msg . " Running '$cmd'.");
      $c->{obuf} =~ s{(\d+)(\s)}{$1-$2};	# a continuation message starts here

      print STDERR "`$systemcmd`\n";
#      unless (open CMD, "$systemcmd |")

      unless (open3("<&NULLFD", \*CMD, \*CMD, $systemcmd))
	{
	  $c->{obuf} .= fmt_text("cannot fork $systemcmd\nError $! ($@)", '  ');
	}
      else
	{
	  while (defined(my $line = <CMD>))
	    {
	      $stdoutcount += length $line;
	      $c->{obuf} .= fmt_text($line, '  ');
	      shovel_obuf($ctrl, obuf_size_client($ctrl));
	    }
	  close CMD or $c->{obuf} .= fmt_text("cannot close pipe: $! $@", '  ');
	}
      
      if ($win32)
        {
	  # poor little dos box is confused by the FD juggling above.
	  # I've lost my stderr here
	  # none of these helps:
          # 	open(STDERR, ">&SAVEDERR");
	  #	open(STDERR, "> con:");
	}

      # NULLFD is already closed.

      $seconds = time - $seconds;
      $c->{obuf} .= fmt_text('-' x 75, '  ');
      $c->{obuf} .= fmt_text("$cmd done in $seconds seconds, $stdoutcount bytes output", '  ');
      print STDERR           "$cmd done in $seconds seconds, $stdoutcount bytes output\n";

      # in case of unflushed error handling...
      while (my $len = obuf_size_client($ctrl))
        {
	  shovel_obuf($ctrl, $len);
	}
      
    }

  # in any case, we return with a single line message in the buffer.
  $c->{obuf} = fmt_text($msg); 
}

sub grant_access
{
  my ($peer) = @_;
  return 1 if scalar @netmask < 1;
  return 0 unless inet_ntoa($peer) =~ m{^(\d+)\.(\d+)\.(\d+)\.(\d+)$};
  $peer = ($1 << 24) | ($2 << 16) | ($3 << 8) | $4;

  for my $n (@netmask)
    {
      print STDERR "peer=$peer addr=$n->{addr}, mask=$n->{mask}\n" if $verbose > 1;
      my $s = 32 - $n->{mask};

      return 1 if ($peer >> $s) == ($n->{addr} >> $s);
    }
  return 0;
}

sub parse_netmask
{
  my @r;

  for my $n (@_)
    {
      my ($m, $d1, $d2, $d3, $d4) = (32, 0, 0, 0, 0);

      ($n,$m) = ($1,$2) if $n =~ m{^([\d\.]+)/(\d+)$};
      $d1 = $1 if $n =~ s{^(\d+)\.?}{};
      $d2 = $1 if $n =~ s{^(\d+)\.?}{};
      $d3 = $1 if $n =~ s{^(\d+)\.?}{};
      $d4 = $1 if $n =~ s{^(\d+)\.?}{};

      push @r, { addr => ($d1 << 24) | ($d2 << 16) | ($d3 << 8) | $d4, mask => $m };
    }

  return @r;
}
