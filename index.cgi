#!/usr/bin/perl

# The Loveline Companion Forum
# Copyright (C) MMIII Silent Virgin Software
# Intent to Open Source code: 
# http://www.dolland.net/loveline/forum/people/silentvirgin/messages/185219.html

use CGI::Carp qw(fatalsToBrowser);
use CGI;
use DBI;
use HTML::Template;
use POSIX qw(strftime);
use Time::Local;

#----------------------------------------------------------------------
# Config

my $dbName = 'drospri_tlcforum';
my $dbUser = 'drospri_sv';
my $dbPassword = '';

my $docRoot = '/home/drospri/public_html'; #$ENV{DOCUMENT_ROOT};

my $forumDocRoot = "$docRoot/loveline/forum";
my $httpHost = 'www.dolland.net'; # 'cpanel2.amihost.com';
my $uriRoot = '/loveline/forum'; # '/~drospri/loveline/forum';
my $uriStrip = '/~drospri';
my $urlRoot = "http://$httpHost$uriRoot";
#my $peopleDocRoot = "$docRoot/loveline/people";
#my $peopleUriRoot = '/loveline/people';
my $peopleDocRoot = "$forumDocRoot/people";
my $peopleUriRoot = "$uriRoot/people";
my $peopleUrlRoot = "http://$httpHost$peopleUriRoot";

#----------------------------------------------------------------------
# Constants

# Change this to expire all cookies.
use constant cookieVersion => 20050222;

# flags -- privilege
use constant flagSuperUser      => 0x00000001;
use constant flagModerator      => 0x00000002;
use constant flagVip            => 0x00000004;
# flags -- status
use constant flagBanned         => 0x00000008;
use constant flagUnconfirmed    => 0x00000010;
# flags -- info
use constant flagDeleted        => 0x00000020;
use constant flagLocked         => 0x00000040; # on Machine, logout
use constant flagSticky         => 0x00000080; # on Machine, remember
# flags -- misc.
use constant flagDst            => 0x00000100; # daylight savings
use constant flagDebug          => 0x00000200;
use constant flagImported       => 0x00000400;
use constant flagTard           => 0x00000800;
use constant contagiousFlags    => 0x0000080f;
my $flagInvisible = flagBanned | flagDeleted;

# prefs
# 98 7654 3210
# ee rrrr cccc
# prefs -- email
use constant prefEmailAccessMask    => 0x00000300;
use constant prefEmailPrivate       => 0x00000000;
use constant prefEmailProtected     => 0x00000100;
use constant prefEmailPublic        => 0x00000200;

#----------------------------------------------------------------------

my $uri = (split /\?/, $ENV{REQUEST_URI})[0]; # /.

my $cgi = new CGI();

my $remoteAddr = ipStrToInt($ENV{REMOTE_ADDR});
if (0 && $ENV{REMOTE_ADDR} =~ /66\.215\.4\.21/) {
    # me
    dieWithText("forum down -- database error");
}
if (0 && $ENV{REMOTE_ADDR} =~ /67\.126\.229\.[0-9]+/) {
    # Krista 67.126.229.227
    dieWithText("forum down -- database error");
}

# Connect to the database.
my $dbh = DBI->connect("DBI:mysql:$dbName:localhost", $dbUser, $dbPassword)
    or dieWithText('Cannot connect: ' . $DBI::errstr);
my $sth = undef;

# Let's check the time real fast.  It's 11:48 and ten seconds.  That's
# eleven minutes and fifty seconds away from the top of the hour.
my $now = time();
my $dateTime = timeToStr($now);

my $login;
my $machine;
my $cookie;
my $readLastCookie;

# Perform cookie maintenance.
cookieMonster();

# Evil banning logic.
my $loginSuperUser = $login && ($login->{flags} & flagSuperUser);
my $loginModerator = $login && ($login->{flags} & flagModerator);
my $isVis;
if ($loginModerator) {
    $isVis = '1';
} else {
    $isVis =
        '(!(Message.flags & ' . flagDeleted . ') && '
        . '(!(Message.flags & ' . flagBanned . ') || '
        . 'Message.machine = ' . ($machine ? $machine->{id} : 0) . '))';
}

my $tmpl;
my $error;

# Use the URI to select the sub-application.
if ($uri eq "$uriRoot/") {
    $uri = "$uriRoot/index.html";
} elsif ($uri eq "$uriRoot/archive/") {
    $uri = "$uriRoot/archive/index.html";
} elsif ($uri eq "$peopleUriRoot/") {
    $uri = "$peopleUriRoot/index.html";
} elsif ($uri eq "$uriRoot/settings/") {
    $uri = "$uriRoot/settings/index.html";
}
my $tmplPathname = uriToFs($uri);
if (-f $tmplPathname) {
    $tmpl = new HTML::Template(filename => "$tmplPathname",
                               die_on_bad_params => 0,
                               loop_context_vars => 1,
                               global_vars => 1);
}
if ($uri eq "$uriRoot/index.html") {
    getIndex();
} elsif ($uri eq "$uriRoot/login.html") {
    login();
} elsif ($uri eq "$uriRoot/logout.html") {
    logout();
} elsif ($uri eq "$uriRoot/post.html") {
    post();
} elsif ($uri eq "$uriRoot/edit.html") {
    editMessage(0);
} elsif ($uri eq "$uriRoot/delete.html") {
    editMessage(1);
} elsif ($uri eq "$uriRoot/register.html") {
    register();
} elsif ($uri eq "$uriRoot/confirm.html") {
    confirm();
} elsif ($uri eq "$uriRoot/unconfirmed.html") {
    unconfirmed();
} elsif ($uri eq "$uriRoot/archive/index.html") {
    archiveIndex();
} elsif ($uri eq "$uriRoot/settings/computer.html") {
    settingsComputer();
} elsif ($uri eq "$uriRoot/settings/email.html") {
    settingsEmail();
} elsif ($uri eq "$uriRoot/settings/password.html") {
    settingsPassword();
} elsif ($uri eq "$uriRoot/settings/profile.html") {
    settingsProfile();
} elsif ($uri eq "$uriRoot/settings/index.html") {
    settingsIndex();
} elsif ($uri eq "$uriRoot/backup.html") {
    backup(1);
} elsif ($uri eq "$uriRoot/restore.html") {
    backup(0);
} elsif ($uri eq "$uriRoot/machines.html") {
    getMachines();
} elsif ($uri eq "$uriRoot/betatesters.html") {
    getBetaTesters();
} elsif ($uri eq "$uriRoot/env.html") {
    my @env;
    foreach (sort keys %ENV) {
        push @env, { var_name => $_, var_value => $ENV{$_} };
    }
    $tmpl->param(env => \@env);
} elsif ($uri =~ /^$uriRoot\/threads\/(\d+)\.html$/) {
    getThread($1);
} elsif ($uri =~ /^$uriRoot\/messages\/(\d+)\.html$/) {
    getMessage($1);
} elsif ($uri =~ /^$uriRoot\/archive\/(\d+)\/(\d+)\/threads\/(\d+)\.html$/) {
    getThread($3, $1, $2);
} elsif ($uri =~ /^$uriRoot\/archive\/(\d+)\/(\d+)\/messages\/(\d+)\.html$/) {
    getMessage($3, $1, $2);
} elsif ($uri =~ /^$uriRoot\/archive\/(\d+)\/(\d+)\/index.html$/) {
    archiveMonth($1, $2);
} elsif ($uri =~ /^$peopleUriRoot\/([\w\-]*)\.html$/) {
    getPeopleIndex($1);
} elsif ($uri =~ /^$peopleUriRoot\/(\w+)(\/)?$/) {
    personProfile($1, $2);
} elsif ($uri =~ /^$peopleUriRoot\/(\w+)\/admin.html$/) {
    personAdmin($1);
} elsif ($uri =~ /^$peopleUriRoot\/(\w+)\/contact.html$/) {
    personContact($1);
} elsif ($uri =~ /^$peopleUriRoot\/(\w+)\/info.html$/) {
    personInfo($1);
} elsif ($uri =~ /^$peopleUriRoot\/(\w+)\/messages(\/)?$/) {
    personMessages($1, $2 ? 0 : -1);
} elsif ($uri =~ /^$peopleUriRoot\/(\w+)\/messages\/(\d+)\.html$/) {
    personMessages($1, $2);
} elsif ($uri eq $ENV{SCRIPT_NAME}) {
    # User hit "Refresh" on a POST reply.
    redirect("$urlRoot/index.html");
}

unless ($tmpl) {
    if (0) {
        $tmpl = new HTML::Template(filename => "$forumDocRoot/env.html",
                                   die_on_bad_params => 0);
        my @env;
        foreach (sort keys %ENV) {
            push @env, { var_name => $_, var_value => $ENV{$_} };
        }
        $tmpl->param(env => \@env);
    } else {
        notFound(__LINE__, $uri);
    }
}

# Disconnect from the database.
$dbh->disconnect();

# Fill out common template params.
$tmpl->param(uri => $uri,
             uriRoot => $uriRoot,
             peopleUriRoot => $peopleUriRoot,
             httpHost => $httpHost,
             );
if ($login) {
    $tmpl->param(login => $login->{name},
                 loginSuperUser => $loginSuperUser,
                 loginModerator => $loginModerator,
                 loginVip => ($login->{flags} & flagVip),
                 );
}
if ($machine && ($machine->{flags} & flagDebug)) {
    $tmpl->param(debug => 1, machine => machineStr());
}
if ($error) {
    $tmpl->param(error => 1, $error => 1);
}

my @cookies;
if (defined $cookie) {
    push @cookies, $cgi->cookie( -name    => 'machine',
                                 -value   => $cookie,
                                 -expires => '+10y',
                                 -path    => '/' );
}
if (defined $readLastCookie) {
    push @cookies, $readLastCookie;
}

# Print the output.
print $cgi->header(-type => "text/html", -cookies => \@cookies);
$tmpl->output(print_to => *STDOUT);

#----------------------------------------------------------------------
# Cookies

sub cookieMonster {
    # Ensure cookie consistency by always using the full domain name.
    # (There is a way to do this in .htaccess, but I can't get it to
    # work.)
    if ($ENV{HTTP_HOST} ne $httpHost) {
        redirect("http://$httpHost$ENV{REQUEST_URI}");
    }
    
    my $testCookie = '0';
    # 'C' is for cookie.  It's good enough for me.  Hey!
    my $c = $cgi->cookie('machine');
    unless (defined $c) {
        # There's no cookies in my box.  Send out a test cookie.
        $cookie = $testCookie;
        return;
    }
    if ($c eq '0') {
        # Client accepts cookies; record the new machine.
        newMachine();
        makeCookie();
    } else {
        my @cookiePieces = split /:/, $c; # /.
        # 0  1   2   3   4  5  6  7
        # v  id  usr flg tz ct lu cs
        if (int(@cookiePieces) != 8) {
            # Bogus cookie; send out a test cookie.
            $cookie = $testCookie;
            return;
        }
    # Check cookie version, importing legacy cookies.
        if ($cookiePieces[0] != cookieVersion &&
        $cookiePieces[0] != 20040131) {
            # Bogus cookie; send out a test cookie.
            $cookie = $testCookie;
            return;
        }
        my $lastUsed = int($cookiePieces[6]);
        $machine = {
            id => hex($cookiePieces[1]),
            user => hex($cookiePieces[2]),
            flags => hex($cookiePieces[3]),
            timeZone => int($cookiePieces[4]),
            createTime => int($cookiePieces[5]),
            lastUsed => $lastUsed,
            warm => isWarm($lastUsed),
        };
        my $crumbs = $cookiePieces[7];
        if ($cookiePieces[0] != cookieVersion ||
            crypt(passnumber(), $crumbs) ne $crumbs) {
            # Bogus/obsolete/stolen cookie; zap login.
            $machine->{user} = 0;
            makeCookie();
            return;
        }
        # Is a user logged in?
        if ($machine->{user} != 0 && !($machine->{flags} & flagLocked) &&
            (($machine->{flags} & flagSticky) || $machine->{warm})) {
            # Yes, get login info.
            setLogin($machine->{user}, $machine->{warm});
            # Touch the machine's last used time.
            $machine->{lastUsed} = $now;
            makeCookie();
        }
    }
}

sub machineStr {
    return sprintf '%lx:%lx:%lx:%d:%d:%d',
        $machine->{id}, $machine->{user}, $machine->{flags},
        $machine->{timeZone}, $machine->{createTime}, $machine->{lastUsed};
}

sub makeCookie {
    #                  v  id  usr flg tz ct lu cs
    $cookie = sprintf '%u:%lx:%lx:%lx:%d:%d:%d:%s', # 8 pieces
        cookieVersion,
        $machine->{id}, $machine->{user}, $machine->{flags},
        $machine->{timeZone}, $machine->{createTime}, $machine->{lastUsed},
        encrypt(passnumber());
}

sub newMachine {
    $sth = $dbh->prepare('UPDATE MachineCounter SET id=LAST_INSERT_ID(id+1)')
        or dieWithText('Cannot prepare: ' . $dbh->errstr());
    $sth->execute()
        or dieWithText('Cannot execute: ' . $sth->errstr());
    $sth->finish();
    $machine = {
        id => selectLastInsertId(),
        user => 0,
        flags => flagDst,
        timeZone => -8, # Loveline time
        createTime => $now,
        lastUsed => $now,
        warm => 1,
    };
}

sub passnumber {
    # This function is used to protect sensitive cookie values.
    # Since a one-way encryption algorithm is applied in
    # makeCookie(), the "passnumber" returned by this function is
    # used to validate the cookie values, which are also stored as
    # plaintext on the user's machine.
    
    # This enables the 'Machine' table to be implemented in a
    # distributed fashion, while still providing a modicum of
    # data integrity and security.
    
    # The 'flags' and 'lastUsed' are included in the checksum to
    # prevent a logged-out cookie from being used to activate a
    # bogus session.  (Including 'lastUsed' forces us to change
    # the 'passnumber' on every HTTP request!)
    
    my $checksum =
        (($machine->{user} << 16) |
         ($machine->{id} ^ $machine->{flags})) ^
        $machine->{lastUsed};
    
    # This formula acts as a password.  In order to create a bogus
    # cookie, Hack must become... a rapist.  In order for a mason
    # jar hacker to create a bogus cookie, he would have to guess
    # this formula -- in addition to figuring out that crypt(3) is
    # being used.  Warning: this formula is a skeleton key for
    # every user account!
    my $passnumber = (($checksum + 9540) ^ 0x4C656966)
    ^ $remoteAddr; # 2005-02-22
    
    # For crypt(3), only the first eight characters are significant
    # (not coincidentally, this is also the Unix password limit).
    # This is just enough characters for a 32-bit hex number.
    $passnumber = sprintf '%lx', $passnumber;
    
    return $passnumber;
}

#----------------------------------------------------------------------
# Index

sub getIndex {
    # Query for threads.
    my $newLast = 0;
    my $newPrev = 0;
    my $setNewPrev;
    my $newPrevPrev;
    my $debug = $cgi->param('debug');
    if ($machine && defined $debug) {
        if ($debug) {
            $machine->{flags} |= flagDebug;
        } else {
            $machine->{flags} &= ~flagDebug;
        }
        makeCookie();
    }
    if ($login) {
        my $old = $cgi->param('old');
        if ($old) {
            $login->{newPrev} = $old;
            $setNewPrev = ", newPrev = $old";
            $newPrevPrev = $cgi->param('undo');
        }
        $newPrev = $login->{newPrev};
    }
    $sth = $dbh->prepare("
        SELECT
            Message.id,         #0
            Message.thread,     #1
            Message.author,     #2
            Message.machine,    #3
            Message.flags,      #4
            Message.createTime, #5
            Message.subject,    #6
            Person.name,        #7
            Person.flags        #8
        FROM Message, Person
        WHERE Message.author = Person.id
            AND (Message.createTime > DATE_SUB(NOW(),INTERVAL 7 DAY))
            AND $isVis
        ORDER BY Message.id")
        or dieWithText('Cannot prepare: ' . $dbh->errstr());
    $sth->execute()
        or dieWithText('Cannot execute: ' . $sth->errstr());
    
    # Fetch thread results.
    my @threads;
    my %threadIndex;
    my @row;
    while (@row = $sth->fetchrow_array()) {
        my $id = $row[0];
        my $thread = $row[1];
        my $flags = $row[4];
        next unless $thread; # race during post
        unless (defined $threadIndex[$thread]) {
            # Enter a new row.
            $threadIndex[$thread] = int(@threads);
            push @threads, {
                # the main columns
                author => undef,
                subject => undef, thread => $thread, url => undef,
                date => undef,
                # tallies
                count => 0,
                countVip => 0,
                newCount => 0,
                newCountVip => 0,
                # flags
                authorVip => 0,
                authorBanned => 0,
                deleted => 0,
                locked => 0,
                visible => 1,
                # new/old bar
                firstOld => 0,
                # sort
                lastPost => 0,
            };
        }
        my $r = $threads[$threadIndex[$thread]];
        if ($id == $thread) {
            $r->{author} = truncAuthor($row[7]);
            $r->{subject} = truncSubject($row[6]);
            if ($flags & flagVip) {
                $r->{authorVip} = 1;
            }
            if ($flags & flagLocked) {
                $r->{locked} = 1;
            }
            if ($loginModerator) {
                if ($flags & flagBanned) {
                    $r->{authorBanned} = 1;
                }
                if ($flags & $flagInvisible) {
                    $r->{deleted} = 1;
                }
            }
        }
        $r->{date} = dateTimeDisplay(strToTime($row[5]), 1),
        ++$r->{count};
        $r->{lastPost} = $id;
        if ($row[4] & flagVip) {
            ++$r->{countVip};
        }
        if ($login) {
            if ($id > $newPrev) {
                ++$r->{newCount};
                if ($flags & flagVip) {
                    ++$r->{newCountVip};
                }
            }
            if ($id > $newLast) {
                $newLast = $id;
            }
        } else {
            $r->{newCount} = '-';
        }
    }
    $sth->finish();
    for (my $i = 0; $i < int(@threads); ++$i) {
        my $r = $threads[$i];
        my $thread = $r->{thread};
        unless ($r->{subject}) {
            # This happens when there are new posts in an old thread --
            # if the original post is over one month old, it will be
            # missing from the query results.
            @row = selectOne(
                "SELECT
                    Message.flags,
                    Message.subject,
                    Person.name
                 FROM Message, Person
                 WHERE Message.author = Person.id
                    AND Message.id = $thread"
                );
            $r->{author} = truncAuthor($row[2]);
            $r->{subject} = truncSubject($row[1]);
            my $flags = $row[0];
            if ($flags & flagVip) {
                $r->{authorVip} = 1;
            }
            if ($flags & flagLocked) {
                $r->{locked} = 1;
            }
            if ($loginModerator) {
                if ($flags & flagBanned) {
                    $r->{authorBanned} = 1;
                }
                if ($flags & $flagInvisible) {
                    $r->{deleted} = 1;
                }
            } else {
                # This is reached if there are replies to
                # a banned thread.
                if ($flags & $flagInvisible) {
                    $r->{visible} = 0;
                }
            }
            # Revise the message tallies for this thread.
            @row = selectOne(
                "SELECT COUNT(id), BIT_OR(flags)
                 FROM Message
                 WHERE thread = $thread
                 GROUP BY thread"
                );
            $r->{count} = $row[0];
            if ($row[1] & flagVip) {
                ++$r->{countVip};
            }
        }
        my $count = $r->{count};
        my $anchor = ($login && $r->{newCount}) ? '#unread' : '';
        $r->{url} = "threads/$thread.html?n=$count$anchor";
    }
    @threads = grep { $_->{visible} } @threads;
    @threads = sort { $b->{lastPost} <=> $a->{lastPost} } @threads;
    if ($login) {
        for (my $i = 0; $i < int(@threads); ++$i) {
            my $r = $threads[$i];
            unless ($r->{newCount}) {
                $r->{firstOld} = 1;
                last;
            }
        }
    }
    if ($login) {
        # Update the user's read stats.
        $sth = $dbh->prepare("
            UPDATE Person
            SET newLast = $newLast$setNewPrev
            WHERE id = " . $login->{id})
            or dieWithText('Cannot prepare: ' . $dbh->errstr());
        $sth->execute()
            or dieWithText('Cannot execute: ' . $sth->errstr());
        $sth->finish();
    }
    
    # Fill-in the template.
    unless ($tmpl) {
dieWithText("No template!\n$docRoot$uri\n");
}
    $tmpl->param(threads => \@threads);
    if ($login) {
        $tmpl->param(
            newLast => (($newLast > $newPrev) ? $newLast : undef),
            newPrev => $newPrev,
            newPrevPrev => $newPrevPrev,
            );
    }
}

#----------------------------------------------------------------------
# Thread

sub getThread {
    my $thread = shift;
    my $year = shift;
    my $month = shift;
    $tmpl = new HTML::Template(filename => "$forumDocRoot/threads/thread.html",
                               die_on_bad_params => 0,
                               loop_context_vars => 1,
                               global_vars => 1);
    
    # If this page was reached via a stale link on the index page,
    # limit the number of messages returned so that the "visited"
    # state of the link reflects the number of messages the user
    # has read.  Ideally, we would redirect to an updated link.  A
    # redirect works in Navigator 4, but not IE 5, which drops the
    # "#unread". IE picks up the whole link only after hitting "Back"
    # and then "Forward" again (WTF?!@#$%*).  Tried encoding '#'
    # as "&#35;" -- no difference.  Tried JavaScript "onload", but
    # this leaves an entry for the original link in the history
    # list -- i.e., it works just as if one had used
    # HTTP-EQUIV="refresh", but without the annoying pause (now
    # there's a trick to remember for the future).
    my $n = $cgi->param('n');
    
    # Keep track of read messages using the virtual field
    # Person.readLast, actually a cookie on the client machine.
    my $cookieName;
    my %cookieHash = ();
    my $readLast;
    if ($n && $login) {
        $cookieName = sprintf 'person_%d_readLast', $login->{id};
        my $c = $cgi->cookie($cookieName);
        if (defined $c) {
            %cookieHash = split /-/, $c; #/
            $readLast = $cookieHash{$thread};
            unless (defined $readLast) {
                $readLast = 0;
            }
        } else {
            $readLast = 0;
        }
    }
    
    $readLast = getThreadMessages($thread, $year, $month, $n, $readLast);
    
    if ($n && $login) {
        $cookieHash{$thread} = $readLast;
        my $c = '';
        while (my ($key, $value) = each %cookieHash) {
            $c .= "$key-$value-";
        }
        $readLastCookie = $cgi->cookie( -name    => $cookieName,
                                        -value   => $c,
                                        -expires => '+1d',
                                        -path    => '/' );;
    }
}

sub getThreadMessages {
    my ($thread, $year, $month, $n, $readLast) = @_;
    my $archive = ($year && $month);
    my $relativeUriRoot = ($archive
                           ? "$uriRoot/archive/$year/$month"
                           : $uriRoot);
    
    my $newPrev = 0;
    if ($login) {
        $newPrev = $login->{newPrev};
    }
    
    # Query for messages.
    $sth = $dbh->prepare("
        SELECT
            Message.id, #0
            Person.idStr, #1
            Person.name, #2
            Person.flags, #3
            Message.createTime, #4
            Message.modTime, #5
            Message.flags, #6
            Message.subject, #7
            Message.body, #8
            Person.id #9
        FROM Message, Person
        WHERE Message.thread = $thread
            AND Person.id = Message.author
            AND $isVis
        ORDER BY Message.id")
        or dieWithText('Cannot prepare: ' . $dbh->errstr());
    $sth->execute()
        or dieWithText('Cannot execute: ' . $sth->errstr());
    
    # Fetch message results.
    my $subject;
    my $threadFlags;
    my $firstNew;
    my @row;
    my @messages;
    while ((@row = $sth->fetchrow_array()) && (!$n || int(@messages) < $n)) {
        unless ($subject) {
            $subject = $row[7];
            $threadFlags = $row[6];
        }
        my $isNew = ($login && $row[0] > $newPrev);
        my $isUnread; my $firstUnread;
        if ($isNew) {
            if (!$firstNew) {
                $firstNew = int(@messages);
            }
            if (defined $readLast) {
                if ($readLast == 0) {
                    # This is the user's first visit to this thread
                    # during this login session.  The first unread
                    # message is the first new one.
                    $readLast = int(@messages);
                }
                $isUnread = (int(@messages) >= $readLast);
                $firstUnread = (int(@messages) == $readLast);
            }
        }
        my $createTime = strToTime($row[4]);
        my $header;
        my $body = $row[8];
        my $signature = $row[2];
        if ($row[6] & flagImported) {
            ($header, $body, $signature) = stripHeader($body);
        }
        push @messages, {
            id => $row[0],
            author => $row[2],
            authorUrl => $peopleUriRoot . '/' . $row[1] . '/',
            # Note the slight inconsisitency here: VIP is from
            # Message.flags, but 'banned' is from author flags.
            authorVip => ($row[6] & flagVip),
            authorBanned => $loginModerator && ($row[3] & flagBanned),
            createTime => dateTimeDisplay($createTime, 0),
            modTime => dateTimeDisplay(strToTime($row[5]), 0),
            messageSubject => $row[7],
            header => $header,
            body => htmlify($body),
            signature => $signature,
            isNew => $isNew,
            firstNew => (int(@messages) == $firstNew),
            isUnread => $isUnread,
            firstUnread => $firstUnread,
            deleted => $loginModerator && ($row[6] & $flagInvisible),
            editable => $loginModerator ||
                        ($login && $login->{id} == $row[9] &&
                         isWarm($createTime) &&
                         !($threadFlags & flagLocked)),
        };
    }
    $sth->finish();
    if (not $subject) {
        notFound(__LINE__);
    }
    # If there are no unread messages, "#unread" defaults to "#new".
    if (int(@messages) <= $readLast) {
        $messages[$firstNew]->{firstUnread} = 1;
    }
    
    $tmpl->param(thread => $thread,
                 subject => $subject,
                 truncSubject => truncSubject($subject),
                 messages => \@messages,
                 
                 archive => $archive,
                 year => $year,
                 monthName => monthName($month),
                 threadLocked => ($threadFlags & flagLocked),
                 relativeUriRoot => $relativeUriRoot,
                 );
    return int(@messages);
}

#----------------------------------------------------------------------
# Message

sub getMessage {
    my $message = shift;
    my $year = shift;
    my $month = shift;
    my $archive = ($year && $month);
    $tmpl = new HTML::Template(filename => "$forumDocRoot/messages/message.html",
                               die_on_bad_params => 0);
    my $newPrev = 0;
    if ($login) {
        $newPrev = $login->{newPrev};
    }
    
    # Query for the message.
    $sth = $dbh->prepare("
        SELECT
            Message.id, #0
            Message.thread, #1
            Message.createTime, #2
            Message.modTime, #3
            Message.body, #4
            Person.id, #5
            Person.idStr, #6
            Person.name, #7
            Message.flags, #8 Person.flags?
            Message.subject #9
        FROM Message, Person
        WHERE Message.id = $message AND
            Person.id = Message.author")
        or dieWithText('Cannot prepare: ' . $dbh->errstr());
    $sth->execute()
        or dieWithText('Cannot execute: ' . $sth->errstr());
    my @row = $sth->fetchrow_array();
    $sth->finish();
    if (not @row) {
        notFound(__LINE__);
    }
    my $createTime = strToTime($row[2]);
    my ($threadFlags, $subject) = selectThread($row[1]);
    my $header;
    my $body = $row[4];
    my $signature = $row[7];
    if ($row[8] & flagImported) {
        ($header, $body, $signature) = stripHeader($body);
    }
    $tmpl->param(id => $row[0],
                 thread => $row[1],
                 subject => $subject,
                 truncSubject => truncSubject($subject),
                 author => $row[7],
                 authorUrl => $peopleUriRoot . '/' . $row[6] . '/',
                 authorVip => ($row[8] & flagVip),
                 createTime => dateTimeDisplay($createTime, 0),
                 modTime => dateTimeDisplay(strToTime($row[3]), 0),
                 messageSubject => $row[9],
                 header => $header,
                 body => htmlify($body),
                 signature => $signature,
                 isFollowUp => ($row[0] != $row[1]),
                 isNew => ($login && $row[0] > $newPrev),
                 editable => $loginModerator ||
                             ($login && $login->{id} == $row[5] &&
                              isWarm($createTime) &&
                              !($threadFlags & flagLocked)),
                 archive => $archive,
                 year => $year,
                 monthName => monthName($month),
                 relativeUriRoot => (
                    $archive
                    ? "$uriRoot/archive/$year/$month"
                    : $uriRoot
                    ),
                 );
}

#----------------------------------------------------------------------
# Login/Logout

sub getLoginParams {
    my $rememberLogin = shift;
    my $rememberedLogin = shift;
    unless ($rememberedLogin) {
        if ($machine->{flags} & flagSticky && $machine->{user}) {
            $rememberedLogin = selectOne('
                SELECT name
                FROM Person
                WHERE ' . $machine->{user} . ' = id');
        }
    }
    # Initially, 'destination' comes from the query string.
    $tmpl->param(rememberedLogin => $rememberedLogin);
    $tmpl->param(rememberLogin => $rememberLogin);
    $tmpl->param(destination => $cgi->param('destination'));
}

sub login {
    unless (defined $machine) {
        redirect("$urlRoot/nocookie.html");
    }
    if ($login) {
        # Nothing to do here.
        welcomeBack();
        return;
    }
    unless ($ENV{REQUEST_METHOD} eq 'POST' && $cgi->param('submit')) {
        getLoginParams($machine->{flags} & flagSticky);
        return;
    }
    
    my $loginId;
    my $loginName = $cgi->param('login');
    my $password = $cgi->param('password');
    my $idStr = smush($loginName);
    
    $sth = $dbh->prepare('
        SELECT id, password, flags
        FROM Person
        WHERE Person.idStr = ' . $dbh->quote($idStr));
    $sth->execute()
        or dieWithText('Cannot execute: ' . $sth->errstr());
    my @row = $sth->fetchrow_array();
    $sth->finish();
    if (not @row) {
        $error = 'errorBadLogin';
    } elsif (crypt($password, $row[1]) ne $row[1]) {
        if ($row[2] & flagImported) {
            $error = 'errorImported';
        } else {
            $error = 'errorBadPassword';
        }
    } else {
        $loginId = $row[0];
    }
    
    if ($error) {
        getLoginParams($cgi->param('rememberLogin') ? 1 : 0, $loginName);
        return;
    }
    
    # Success.
    if ($cgi->param('rememberLogin')) {
        $machine->{flags} |= flagSticky;
    } else {
        $machine->{flags} &= ~flagSticky;
    }
    setLogin($loginId, 0);
    setUserId();
    welcomeBack();
}

sub loginCheck {
    # If the user is not logged-in, lead them through the login
    # page first.
    unless ($login) {
        my $destination = shift;
        my $args = shift;
        if ($destination) {
            redirect("$urlRoot/login.html?destination=$destination$args");
        }
        redirect("$urlRoot/login.html");
    }
}

sub logout {
    unless (defined $login && defined $machine) {
        # Nothing to do here.
        redirect("$urlRoot/index.html");
    }
    $machine->{flags} |= flagLocked;
    makeCookie();
    return;
}

sub setLogin {
    my $id = shift;
    my $warm = shift;
    
    $sth = $dbh->prepare('
        SELECT name, email, flags, prefs, random, newLast, newPrev
        FROM Person
        WHERE id = ' . $id)
        or dieWithText('Cannot prepare: ' . $dbh->errstr());
    $sth->execute()
        or dieWithText('Cannot execute: ' . $sth->errstr());
    @row = $sth->fetchrow_array();
    $sth->finish();
    
    $login = {
        id => $id,
        name => $row[0],
        email => $row[1],
        flags => $row[2],
        prefs => $row[3],
        random => $row[4],
        newLast => $row[5],
        newPrev => $row[6]
    };
    
    unless ($warm) {
        # Update the user's stats.
        $login->{newPrev} = $login->{newLast};
        $sth = $dbh->prepare("
            UPDATE Person
            SET
                lastLogin = $dateTime,
                machine = " . $machine->{id} . ",
                newPrev = " . $login->{newPrev} . "
            WHERE id = " . $login->{id})
            or dieWithText('Cannot prepare: ' . $dbh->errstr());
        $sth->execute()
            or dieWithText('Cannot execute: ' . $sth->errstr());
        $sth->finish();
        $readLastCookie = $cgi->cookie(
            -name    => (sprintf 'person_%d_readLast', $login->{id}),
            -value   => '',
            -expires => '-1d', # delete it
            -path    => '/'
            );
    }
}

sub setUserId {
    $machine->{user} = $login->{id};
    $machine->{flags} &= ~flagLocked;
    $machine->{lastUsed} = $now;
    makeCookie();
    # Update the machine record, if any.
    $sth = $dbh->prepare("
        UPDATE Machine
        SET
            user = " . $machine->{user} . ",
            timeZone = " . $machine->{timeZone} . ",
            createTime = " . timeToStr($machine->{createTime}) . ",
            lastUsed = $dateTime,
            ip = " . $remoteAddr . "
        WHERE id = " . $machine->{id})
        or dieWithText('Cannot prepare: ' . $dbh->errstr());
    $sth->execute()
        or dieWithText('Cannot execute: ' . $sth->errstr());
    $sth->finish();
}

sub welcomeBack {
    my $destination = $cgi->param('destination');
    my $params = '';
    if ($destination) {
        my @list = split /[-]/, $destination;
        my $n = scalar(@list);
        if ($n >= 3 && $n % 2 == 1) {
            $destination = $list[0];
            $params = "?$list[1]=$list[2]";
            for (my $i = 3; $i < $n; $i += 2) {
                $params .= ";$list[$i]=$list[$i+1]";
            }
        }
    } else {
        $destination = 'index.html';
    }
    redirect("$urlRoot/$destination$params");
    # I'm paranoid that not all browsers will set cookies on a
    # redirect...
    #$tmpl->param(destination => "$urlRoot/$destination$params");
}

#----------------------------------------------------------------------
# Post

sub getPostParams {
    my $thread = $cgi->param('thread');
    my $body = stripCarriageReturns($cgi->param('body'));
    my $advancedOptions = $cgi->param('advancedOptions');
    my $preview = $cgi->param('preview');
    if ($cgi->param('submitToggleAdvancedOptions.x')) {
        $advancedOptions = $advancedOptions ? 0 : 1;
    } elsif ($cgi->param('submitPreviewMessage.x')) {
        $preview = 1;
    }
    my $previewBody;
    if ($preview) {
        $previewBody = htmlify(makeBody($body));
    }
    $tmpl->param(body => $body,
                 url => $cgi->param('url'),
                 urlTitle => $cgi->param('urlTitle'),
                 imageUrl => $cgi->param('imageUrl'),
                 advancedOptions => $advancedOptions,
                 preview => $preview,
                 previewBody => $previewBody,
                 );
    if ($thread) {
        getThreadMessages($thread);
    } else {
        my $subject = $cgi->param('subject');
        $tmpl->param(subject => $subject);
    }
}

sub post {
    my $thread = $cgi->param('thread');
    my $subject;
    my $body;
    loginCheck('post.html', $thread ? "-thread-$thread" : "");
    if ($login->{flags} & flagUnconfirmed) {
        redirect("$urlRoot/unconfirmed.html");
    }
    if ($thread) {
        my $threadFlags = selectOne(
            "SELECT flags FROM Message WHERE id = $thread"
            );
        if ($threadFlags & flagLocked) {
            $error = 'errorLocked';
            return;
        }
    }
    if ($ENV{REQUEST_METHOD} eq 'GET') {
        $tmpl->param(advancedOptions => 0);
        if ($thread) {
            getThreadMessages($thread);
        }
        return;
    } elsif ($cgi->param('submit')) {
        $subject = $cgi->param('subject');
        $body = $cgi->param('body');
    } else {
        getPostParams();
        return;
    }
    
    $body = makeBody($body);
    unless ($thread || $subject) {
        $error = 'errorNoSubject';
        getPostParams();
        return;
    }
    unless ($body) {
        $error =  'errorNoBody';
        getPostParams();
        return;
    }
    
    # Create the new message.
    unless ($thread) { $thread = 0; }
    my $flags = $login->{flags} & contagiousFlags;
    $sth = $dbh->prepare("
        INSERT INTO Message (thread, author, machine, flags, createTime,
            subject, body)
        VALUES ($thread, "
            . $login->{id} . ", " . $machine->{id}
            . ", $flags, $dateTime, " .
            ($thread == 0 ? $dbh->quote($subject) : 'NULL') . ', '
            . $dbh->quote($body) . ')')
        or dieWithText('Cannot prepare: ' . $dbh->errstr());
    $sth->execute()
        or dieWithText('Cannot execute: ' . $sth->errstr());
    $sth->finish();
    my $n = 1;
    my $message = selectLastInsertId();
    if ($thread) {
        $n = selectOne(
            "SELECT COUNT(id) FROM Message WHERE thread = $thread"
            );
    } else {
        # Set the thread id.  Note that the message will be skipped
        # by getThreadIndex() during the instant it has a thread ID
        # of zero.  There is probably an atomic way to do this in
        # MySQL...
        $thread = $message;
        $sth = $dbh->prepare("
            UPDATE Message
            SET thread = $thread
            WHERE id = $thread")
            or dieWithText('Cannot prepare: ' . $dbh->errstr());
        $sth->execute()
            or dieWithText('Cannot execute: ' . $sth->errstr());
        $sth->finish();
    }
    
    # That damn IE bug again.  See the comment in getThread().
    if (0) { redirect("$urlRoot/threads/$thread.html?n=$n#unread"); }
    $tmpl->param(thread => $thread, newPostNumber => $n);
}

sub makeBody {
    my $body = shift;
    my $url = $cgi->param('url');
    my $urlTitle = $cgi->param('urlTitle');
    unless ($urlTitle) {
        $urlTitle = $url;
    }
    my $imageUrl = $cgi->param('imageUrl');
    $body = stripCarriageReturns($body);
    if ($url || $imageUrl) {
        unless ($body =~ /^.+\n$/) {
            $body .= "\n";
        }
        if ($url) {
            $body .= "\n<ul><li><a href=\"$url\">$urlTitle</a></ul>\n";
        }
        if ($imageUrl) {
            $body .= "\n<img src=\"$imageUrl\">\n";
        }
    }
    return $body;
}

#----------------------------------------------------------------------
# Edit/Delete Message

sub editMessage {
    my $isDelete = shift;
    my $message = $cgi->param('message');
    if (not $message) {
        redirect("$urlRoot/post.html");
    }
    loginCheck('edit.html', "-message-$message");
    $sth = $dbh->prepare("
        SELECT
            Message.thread, #0
            Message.author, #1
            Message.machine, #2
            Message.flags, #3
            Message.createTime, #4
            Message.body, #5
            Person.name #6
        FROM Message, Person
        WHERE Message.id = $message AND
            Person.id = Message.author")
        or dieWithText('Cannot prepare: ' . $dbh->errstr());
    $sth->execute()
        or dieWithText('Cannot execute: ' . $sth->errstr());
    my @row = $sth->fetchrow_array();
    $sth->finish();
    if (not @row) {
        $tmpl->param(errorNoEdit => 1);
        $error = 'errorMessageNotFound';
        return;
    }
    unless ($loginModerator) {
        if ($row[1] != $login->{id}) {
            $tmpl->param(errorNoEdit => 1);
            $error = 'errorNotAuthor';
            return;
        }
        if (!isWarm(strToTime($row[4]))) {
            $tmpl->param(errorNoEdit => 1);
            $error = 'errorTooOld';
            return;
        }
        my $threadFlags = selectOne(
            "SELECT flags FROM Message WHERE id = " . $row[0]);
        if ($threadFlags & flagLocked) {
            $tmpl->param(errorNoEdit => 1);
            $error = 'errorLocked';
            return;
        }
    }
    
    unless ($ENV{REQUEST_METHOD} eq 'POST') {
        getEditMessageParams(@row);
        return;
    }
    
    my $isFollowUp = ($message != $row[0]);
    my $flags = $row[3];
    
    my $setSubject;
    my $setThread;
    my $setFlags;
    my $setModTime;
    my $setBody;
    
    if ($isDelete) {
        if ($cgi->param('submitUndo')) {
            $flags &= ~flagDeleted;
        } else {
            $flags |= flagDeleted;
        }
        $setFlags = "flags = $flags";
    } else {
        my $body = $cgi->param('body');
        unless ($body) {
            $error = 'errorNoBody';
            getEditMessageParams(@row);
            return;
        }
        $body = stripCarriageReturns($body);
        unless ($isFollowUp) {
            my $subject = $cgi->param('subject');
            unless ($subject) {
                $error = 'errorNoSubject';
                getEditMessageParams(@row);
                return;
            }
            $setSubject = "subject = " . $dbh->quote($subject) . ",";
        }
        if ($loginSuperUser) {
            my $author = $dbh->quote(smush($cgi->param('author')));
            $author = selectOne("SELECT id FROM Person WHERE idStr = $author");
            unless ($author) {
                $error = 'errorPersonNotFound';
                getEditMessageParams(@row);
                return;
            }
            $setAuthor = "author = $author,";
        }
        if ($loginModerator) {
            my $thread = $cgi->param('thread');
            $setThread = "thread = $thread,";
            $flags = tweakFlags($flags,
                                (flagVip | flagBanned | flagDeleted | flagLocked));
            $setFlags = "flags = $flags,";
            my $willBeFollowUp = ($thread != $message);
            if ($isFollowUp != $willBeFollowUp) {
                if ($willBeFollowUp) {
                    $setSubject = "subject = NULL,";
                } else {
                    $setSubject = "subject = 'untitled',";
                }
            }
        }
        $setBody = "body = " . $dbh->quote($body);
    }
    # Giving moderators stealth here is only really important for the
    # 'banned' flag.
    unless ($isDelete || $loginModerator) {
        $setModTime = "modTime = $dateTime,";
    }
    $sth = $dbh->prepare("
        UPDATE Message
        SET
            $setThread
            $setAuthor
            $setFlags
            $setSubject
            $setModTime
            $setBody
        WHERE id = $message")
        or dieWithText('Cannot prepare: ' . $dbh->errstr());
    $sth->execute()
        or dieWithText('Cannot execute: ' . $sth->errstr());
    $sth->finish();
    if ($isDelete && ($flags & flagDeleted)) {
        $tmpl->param(message => $message,
                     subject => getSubject($row[0], $isFollowUp),
                     flagDeleted => 1,
                     );
        return;
    }
    redirect("$urlRoot/messages/$message.html");
}

sub getEditMessageParams {
    my @row = @_;
    my $message = $cgi->param('message');
    my $flags = $row[3];
    my $isFollowUp = ($message != $row[0]);
    $tmpl->param(message => $message,
                 subject => getSubject($row[0], $isFollowUp),
                 author => $row[6],
                 body => $row[5],
                 isFollowUp => $isFollowUp,
                 );
    if ($loginModerator) {
        $tmpl->param(thread => $row[0],
                     machine => $row[2],
                     flagVip => checked($flags & flagVip),
                     flagBanned => checked($flags & flagBanned),
                     flagDeleted => checked($flags & flagDeleted),
                     flagLocked => checked($flags & flagLocked),
                     ),
    }
}

#----------------------------------------------------------------------
# Register

sub confirm {
    my $key = $cgi->param('key');
    unless ($key) { $key = 0; }
    loginCheck('confirm.html', "-key-$key");
    if ($key != $login->{random}) {
        redirect("$urlRoot/unconfirmed.html");
    }
    $login->{flags} &= ~flagUnconfirmed;
    updateLoginFlags();
}

sub getRegisterParams {
    my $rememberedLogin = $cgi->param('login');
    my $newPassword = $cgi->param('newPassword');
    my $verifyPassword = $cgi->param('verifyPassword');
    my $email = $cgi->param('email');
    my $emailAccess = $cgi->param('emailAccess');
    my $ea = emailAccess($emailAccess);
    $tmpl->param(
        rememberedLogin => $rememberedLogin,
        newPassword => $newPassword,
        verifyPassword => $verifyPassword,
        email => $email,
        emailAccess => $emailAccess,
        prefEmailPrivate => checked($ea == prefEmailPrivate),
        prefEmailProtected => checked($ea == prefEmailProtected),
        prefEmailPublic => checked($ea == prefEmailPublic),
        );
}

sub register {
    unless (defined $machine) {
        redirect("$urlRoot/nocookie.html");
    }
    unless ($ENV{REQUEST_METHOD} eq 'POST') {
        $tmpl->param(prefEmailPrivate => checked(1));
        return;
    }
    
    my $name = $cgi->param('login');
    unless ($name) {
        $error = 'errorNoLogin';
        getRegisterParams();
        return;
    }
    # Smush the name to create the person ID string.
    my $idStr = smush($name);
    if ($idStr eq '') {
        $error = 'errorBadLogin';
        getRegisterParams();
        return;
    }
    my $newPassword = $cgi->param('newPassword');
    unless ($newPassword) {
        $error = 'errorNoPassword';
        getRegisterParams();
        return;
    }
    my $verifyPassword = $cgi->param('verifyPassword');
    unless ($verifyPassword) {
        $error = 'errorNoVerifyPassword';
        getRegisterParams();
        return;
    }
    if ($newPassword ne $verifyPassword) {
        $error = 'errorPasswordMismatch';
        getRegisterParams();
        return;
    }
    my $email = $cgi->param('email');
    unless ($email) {
        $error = 'errorNoEmail';
        getRegisterParams();
        return;
    }
    
    my $random = int(rand 10000);
    $newPassword = $dbh->quote(encrypt($newPassword));
    $idStr = $dbh->quote($idStr);
    
    # Here, we only care about the machine flags in the database --
    # not the flags in the machine cookie.  A moderator can cause
    # all users who register from a particular machine to be
    # automatically banned by setting that machine's banned bit.
    my $machineFlags = selectOne(
        'SELECT flags FROM Machine WHERE id = ' . $machine->{id}
        );
    # 8/18/04 Added 'flagBanned' because of Pan Pan and vengeful attackers.
    # 2/25/08 Removed 'flagBanned' because I don't have time for this.
    my $flags = flagUnconfirmed | flagTard | ($machineFlags & contagiousFlags);
    my $prefs = emailAccess($cgi->param('emailAccess'));
    
    my $newPrev = 0;
    
    # Create the new person.
    my $id;
CREATE:
    $sth = $dbh->prepare("
        INSERT INTO Person (idStr, name, password, email, flags, prefs, random,
                            since, lastLogin, machine)
        VALUES ($idStr, " . $dbh->quote($name) . ", $newPassword, "
                . $dbh->quote($email) . ", $flags, $prefs, $random,
                $dateTime, $dateTime, " . $machine->{id} . ")")
        or dieWithText('Cannot prepare: ' . $dbh->errstr());
    if ($sth->execute()) {
        $sth->finish();
        $id = selectLastInsertId();
    } else {
        my $errstr = $sth->errstr();
        $sth->finish();
        if ($errstr =~ /Duplicate entry .* key (\d+)/) {
            my $expr;
            if ($1 == 2) {
                $error = 'errorDuplicateLogin';
                $expr = "idStr = $idStr";
            } elsif ($1 == 3) {
                $error = 'errorDuplicateEmail';
                $expr = "email = " . $dbh->quote($email);
            }
            my @importedPerson = selectOne(
                "SELECT id, idStr, name, flags, newPrev FROM Person WHERE $expr"
                );
            unless ($importedPerson[3] & flagImported) {
                getRegisterParams();
                return;
            }
            if ($cgi->param('submit')) {
                $error =~ s/Duplicate/Imported/;
                getRegisterParams();
                my $messageCount = selectOne("
                    SELECT COUNT(id) FROM Message
                    WHERE author = " . $importedPerson[0]);
                $tmpl->param(errorImported => 1,
                             idStr => $importedPerson[1],
                             messageCount => $messageCount);
                return;
            }
            if ($cgi->param('submitImport')) {
                # Update the imported person with the new registration
                # values.  Note that this clears the import flag.
                $id = $importedPerson[0];
                $flags = $importedPerson[3];
                $flags &= ~flagImported;
                $sth = $dbh->prepare("
                    UPDATE Person
                    SET idStr = $idStr,
                        name = " . $dbh->quote($name) . ",
                        password = $newPassword,
                        email = " . $dbh->quote($email) . ",
                        flags = $flags,
                        prefs = $prefs,
                        random = $random,
                        lastLogin = $dateTime,
                        machine = " . $machine->{id} . "
                    WHERE id = $id")
                    or dieWithText('Cannot prepare: ' . $dbh->errstr());
                $sth->execute()
                    or dieWithText('Cannot execute: ' . $sth->errstr());
                $sth->finish();
                $newPrev = $importedPerson[4]; # last imported message
                # Fall through and proceed with regsitration.
            } else {
                # Rename the imported person.
                my $newIdStr = $importedPerson[1] . 'thefirst';
                my $newName = $dbh->quote($importedPerson[2] . ' the First');
                $sth = $dbh->prepare("
                    UPDATE Person
                    SET idStr = '$newIdStr', name = $newName,
                        email = '$newIdStr@dolland.net'
                    WHERE id = " . $importedPerson[0])
                    or dieWithText('Cannot prepare: ' . $dbh->errstr());
                $sth->execute()
                    or dieWithText('Cannot execute: ' . $sth->errstr());
                $sth->finish();
                # Try again.
                goto CREATE;
            }
        } else {
            dieWithText('Cannot execute: ' . $errstr);
        }
    }
    
    # Login.
    $login = {
        id => $id,
        name => $name,
        email => $email,
        flags => $flags,
        prefs => $prefs,
        random => $random,
        newLast => $newPrev,
        newPrev => $newPrev,
    };
    setUserId();
    if ($login->{id} == 1) {
        # Give the first user super powers.
        $login->{flags} |= flagSuperUser | flagModerator;
        updateLoginFlags();
    }
    
    sendConfirmationEmail();
    
    $tmpl->param(email => $login->{email});
}

sub sendConfirmationEmail {
    # Send a confirmation e-mail.
    my $email = $login->{email};
    my $random = $login->{random};
    open MAIL, "| /usr/sbin/sendmail -t -i"
        or dieWithText("Could not open sendmail: $!");
    print MAIL <<END_OF_MESSAGE;
To: $email
Subject: Welcome!


Welcome to The Loveline Companion Forum!

Please visit the following web page to confirm your e-mail address:

    $urlRoot/confirm.html?key=$random

END_OF_MESSAGE
    close MAIL or dieWithText("Error closing sendmail: $!");
}

sub unconfirmed {
    unless ($ENV{REQUEST_METHOD} eq 'POST' && $cgi->param('submit')) {
        return;
    }
    sendConfirmationEmail();
    $tmpl->param(email => $login->{email});
}

#----------------------------------------------------------------------
# Archive

sub archiveEpoch {
    my $oldest = selectOne('SELECT MIN(createTime) from Message');
    return $oldest ? strToTime($oldest) : $now;
}

sub archiveIndex {
    my $tzAdjust = timeZoneAdjust();
    my (undef,undef,undef,undef,$epochMonth,$epochYear,undef,undef,undef)
        = gmtime(archiveEpoch() + $tzAdjust);
    my (undef,undef,undef,undef,$nowMonth,$nowYear,undef,undef,undef)
        = gmtime($now + $tzAdjust);
    $epochYear += 1900;
    $nowYear += 1900;
    ++$epochMonth;
    ++$nowMonth;
    my @years;
    for (my $year = $nowYear; $year >= $epochYear; --$year) {
        my @months;
        for (my $month = 1; $month <= 12; ++$month) {
            my $disabled = 0;
            if ($year == $nowYear) {
                $disabled = ($nowMonth < $month);
            }
            if ($year == $epochYear) {
                $disabled = $disabled || ($month < $epochMonth);
            }
            push @months, {
                year => $year,
                month => sprintf('%02d', $month),
                monthName => monthName($month),
                disabled => $disabled,
            };
        }
        push @years, {
            year => $year,
            months => \@months,
        };
    }
    $tmpl->param(years => \@years);
}

sub archiveMonth {
    my $year = int(shift);
    my $month = int(shift);
    $tmpl = new HTML::Template(filename => "$forumDocRoot/archive/month.html",
                               die_on_bad_params => 0);
    
    my $prevMonth = $month - 1;
    my $prevYear = $year;
    my $nextMonth = $month + 1;
    my $nextYear = $year;
    if ($prevMonth == 0) {
        --$prevYear;
        $prevMonth = 12;
    } elsif ($nextMonth == 13) {
        ++$nextYear;
        $nextMonth = 1;
    }
    my $tzAdjust = timeZoneAdjust();
    my $beginTime = timegm(0,0,0,1,$month-1,$year) - $tzAdjust;
    my $endTime = timegm(0,0,0,1,$nextMonth-1,$nextYear) - $tzAdjust;
    my $prevUrl;
    my $nextUrl;
    if (archiveEpoch() < $beginTime) {
        $prevUrl = sprintf('../../%d/%02d/index.html', $prevYear, $prevMonth);
    }
    if ($endTime < $now) {
        $nextUrl = sprintf('../../%d/%02d/index.html', $nextYear, $nextMonth);
    }
    $beginTime = timeToStr($beginTime);
    $endTime = timeToStr($endTime);
    
    $sth = $dbh->prepare("
        SELECT
            Person.name,              #0 Author
            Person.flags,             #1 (Author flags)
            Message.thread,           #2 ID (URL)
            Message.subject,          #3 Subject
            Message.createTime,       #4 Created
            Message.flags             #5
        FROM Message, Person
        WHERE Person.id = Message.author
            AND (Message.id = Message.thread)
            AND ($beginTime <= Message.createTime)
            AND (Message.createTime < $endTime)
            AND $isVis")
        or dieWithText('Cannot prepare: ' . $dbh->errstr());
    $sth->execute()
        or dieWithText('Cannot execute: ' . $sth->errstr());
    
    my @threads;
    my @row;
    while (@row = $sth->fetchrow_array()) {
        my $id = $row[2];
        my ($count, $threadMessageFlags) = selectThreadMessages($id);
        push @threads, {
            url => "threads/$id.html",
            subject => truncSubject($row[3]),
            author => truncAuthor($row[0]),
            authorVip => ($row[1] & flagVip),
            authorBanned => $loginModerator && ($row[1] & flagBanned),
            date => dateTimeDisplay(strToTime($row[4]), 1),
            count => $count,
            countVip => ($threadMessageFlags & flagVip),
            deleted => $loginModerator && ($row[5] & $flagInvisible),
            locked => ($row[5] & flagLocked),
        };
    }
    $sth->finish();
    
    $tmpl->param(
        year => $year,
        monthName => monthName($month),
        threads => \@threads,
        prevUrl => $prevUrl,
        nextUrl => $nextUrl,
        );
}

#----------------------------------------------------------------------
# Settings

sub checkedEA {
    my $access = shift;
    return checked(($login->{prefs} & prefEmailAccessMask) == $access);
}

sub getSettingsEmailParams {
    $tmpl->param(
        email => $login->{email},
        prefEmailPrivate => checkedEA(prefEmailPrivate),
        prefEmailProtected => checkedEA(prefEmailProtected),
        prefEmailPublic => checkedEA(prefEmailPublic)
        );
}

sub selectedTZ {
    my $timeZone = shift;
    return selected($machine->{timeZone} == $timeZone);
}

sub settingsComputer {
    loginCheck('settings', '');
    unless ($ENV{REQUEST_METHOD} eq 'POST' && $cgi->param('submit')) {
        $tmpl->param(
            rememberLogin => checked($machine->{flags} & flagSticky),
            tzHawaii => selectedTZ(-10),
            tzAlaska => selectedTZ(-9),
            tzPacific => selectedTZ(-8),
            tzMountain => selectedTZ(-7),
            tzCentral => selectedTZ(-6),
            tzEastern => selectedTZ(-5),
            daylightSavingTime => checked($machine->{flags} & flagDst)
            );
        return;
    }
    if ($cgi->param('rememberLogin')) {
        $machine->{flags} |= flagSticky;
    } else {
        $machine->{flags} &= ~flagSticky;
    }
    my $timeZone = $cgi->param('timeZone');
    if ($timeZone eq 'Hawaii/Aleutian') {
        $machine->{timeZone} = -10;
    } elsif ($timeZone eq 'Alaska') {
        $machine->{timeZone} = -9;
    } elsif ($timeZone eq 'Pacific') {
        $machine->{timeZone} = -8;
    } elsif ($timeZone eq 'Mountain') {
        $machine->{timeZone} = -7;
    } elsif ($timeZone eq 'Central') {
        $machine->{timeZone} = -6;
    } elsif ($timeZone eq 'Eastern') {
        $machine->{timeZone} = -5;
    }
    if ($cgi->param('daylightSavingTime')) {
        $machine->{flags} |= flagDst;
    } else {
        $machine->{flags} &= ~flagDst;
    }
    makeCookie();
    $tmpl->param(saved => 1);
}

sub settingsEmail {
    loginCheck('settings', '');
    unless ($ENV{REQUEST_METHOD} eq 'POST' && $cgi->param('submit')) {
        getSettingsEmailParams();
        return;
    }
    $login->{prefs} = ($login->{prefs} & ~prefEmailAccessMask) |
                      emailAccess($cgi->param('emailAccess'));
    if ($cgi->param('email') eq $login->{email}) {
        $sth = $dbh->prepare('
            UPDATE Person
            SET prefs = ' . $login->{prefs} . '
            WHERE id = ' . $login->{id})
            or dieWithText('Cannot prepare: ' . $dbh->errstr());
        $sth->execute()
            or dieWithText('Cannot execute: ' . $sth->errstr());
        $sth->finish();
        $tmpl->param(saved => 1);
        return;
    }
    $login->{email} = $cgi->param('email');
    $login->{flags} |= flagUnconfirmed;
    $login->{random} = int(rand 10000);
    $sth = $dbh->prepare('
        UPDATE Person
        SET email = ' . $dbh->quote($login->{email})
        . ', flags = ' . $login->{flags}
        . ', prefs = ' . $login->{prefs}
        . ', random = ' . $login->{random} . '
        WHERE id = ' . $login->{id})
        or dieWithText('Cannot prepare: ' . $dbh->errstr());
    unless ($sth->execute()) {
        if ($sth->errstr() =~ /Duplicate entry/) {
            $error = 'errorDuplicateEmail';
            getSettingsEmailParams();
            return;
        }
        dieWithText('Cannot execute: ' . $sth->errstr());
    }
    $sth->finish();
    sendConfirmationEmail();
    $tmpl->param(saved => 1,
                 email => $login->{email});
}

sub settingsPassword {
    loginCheck('settings', '');
    unless ($ENV{REQUEST_METHOD} eq 'POST' && $cgi->param('submit')) {
        return;
    }
    my $password = $cgi->param('password');
    my $pw = selectOne('SELECT password FROM Person WHERE id = ' .
                       $login->{id});
    if (crypt($password, $pw) ne $pw) {
        $error = 'errorBadPassword';
        return;
    }
    my $newPassword = $cgi->param('newPassword');
    unless ($newPassword) {
        $error = 'errorNoPassword';
        return;
    }
    my $verifyPassword = $cgi->param('verifyPassword');
    unless ($verifyPassword) {
        $error = 'errorNoVerifyPassword';
        return;
    }
    if ($newPassword ne $verifyPassword) {
        $error = 'errorPasswordMismatch';
        return;
    }
    $newPassword = $dbh->quote(encrypt($newPassword));
    $sth = $dbh->prepare("
        UPDATE Person
        SET password = $newPassword
        WHERE id = " . $login->{id})
        or dieWithText('Cannot prepare: ' . $dbh->errstr());
    $sth->execute()
        or dieWithText('Cannot execute: ' . $sth->errstr());
    $sth->finish();
    $tmpl->param(saved => 1);
}

sub settingsProfile {
    loginCheck('settings', '');
    unless ($ENV{REQUEST_METHOD} eq 'POST' && $cgi->param('submit')) {
        my $profile = selectOne(
            'SELECT profile FROM Person WHERE id = ' . $login->{id});
        $tmpl->param(profile => $profile);
        return;
    }
    my $profile = $cgi->param('profile');
    if (defined $profile) {
        $profile = $dbh->quote(stripCarriageReturns($profile));
    } else {
        $profile = 'NULL';
    }
    $sth = $dbh->prepare("
        UPDATE Person
        SET profile = $profile
        WHERE id = " . $login->{id})
        or dieWithText('Cannot prepare: ' . $dbh->errstr());
    $sth->execute()
        or dieWithText('Cannot execute: ' . $sth->errstr());
    $sth->finish();
    $tmpl->param(saved => 1);
}

sub settingsIndex {
    loginCheck('settings', '');
}

#----------------------------------------------------------------------
# People

sub getPeopleIndex {
    # Peoples is peoples.
    my $i = shift;
    $tmpl = new HTML::Template(filename => "$peopleDocRoot/index.html",
                               die_on_bad_params => 0);
    
    my $registeredCounter = selectOne('SELECT COUNT(id) FROM Person');
    my $machineCounter = selectOne('SELECT id FROM MachineCounter');
    my $visitorCounter = 0;
    if ($machineCounter > $registeredCounter) {
        $visitorCounter = $machineCounter - $registeredCounter;
    }
    
    # Create the thumb index.
    my @thumbIndex;
    push @thumbIndex, {
        url => '0-9.html',
        title => '0-9',
        selected => ($i eq '0-9'),
    };
    # She has a 'little girl' voice; let's gamble on her past.
    for (my $letter = 0; $letter < 26; ++$letter) {
        my $j = chr(ord('a') + $letter);
        push @thumbIndex, {
            url => ($j . '.html'),
            title => chr(ord('A') + $letter),
            selected => ($i eq $j),
        };
    }
    
    # Query for people.
    my $like = ($i eq '0-9') ? "RLIKE '^[0-9].*'" : "LIKE '$i%'";
    my $filter;
    if (1 || $loginModerator) {
        $filter = '';
    } else {
        $filter = "AND (!(flags & $flagInvisible) || "
            . 'machine = ' . ($machine ? $machine->{id} : 0) . ')';
    }
    $sth = $dbh->prepare("
        SELECT idStr, name, flags
        FROM Person
        WHERE idStr $like $filter
        ORDER BY idStr")
        or dieWithText('Cannot prepare: ' . $dbh->errstr());
    $sth->execute()
        or dieWithText('Cannot execute: ' . $sth->errstr());
    
    # Fetch people results.
    my @people;
    my @row;
    while (@row = $sth->fetchrow_array()) {
        push @people, {
            url => $row[0] . '/',
            name => $row[1],
            vip => ($row[2] & flagVip),
            deleted => $loginModerator && ($row[2] & $flagInvisible),
        };
    }
    $sth->finish();
    
    # Fill-in the template.
    $tmpl->param(registeredCounter => $registeredCounter,
                 visitorCounter => $visitorCounter,
                 thumbIndex => \@thumbIndex,
                 people => \@people,
                 );
}

#----------------------------------------------------------------------
# Person

sub getContact {
    my $prefs = shift;
    my $emailAccess = ($prefs & prefEmailAccessMask);
    if ($emailAccess == prefEmailPublic) {
        return 1;
    } elsif ($emailAccess == prefEmailProtected && $login) {
        return 1;
    }
    return 0;
}

sub personAdmin {
    my $idStr = shift;
    moderatorCheck();
    $tmpl = new HTML::Template(filename => "$peopleDocRoot/admin.html",
                               die_on_bad_params => 0);
    $sth = $dbh->prepare("
        SELECT
            id, name, email, flags, since, lastLogin, prefs, !ISNULL(profile),
            machine
        FROM Person
        WHERE idStr = " . $dbh->quote($idStr))
        or dieWithText('Cannot prepare: ' . $dbh->errstr());
    $sth->execute()
        or dieWithText('Cannot execute: ' . $sth->errstr());
    my @row = $sth->fetchrow_array();
    $sth->finish();
    if (not @row) {
        notFound(__LINE__);
    }
    my $id = $row[0];
    my $name = $row[1];
    my $messageCount = selectOne("
        SELECT COUNT(id) FROM Message
        WHERE author = $id");
    unless ($ENV{REQUEST_METHOD} eq 'POST') {
        $tmpl->param(id => $id,
                     idStr => $idStr,
                     name => $name,
                     newPassword => randomPassword(),
                     email => $row[2],
                     vip => $row[3] & flagVip,
                     since => dateTimeDisplay(strToTime($row[4]), 0),
                     lastLogin => dateTimeDisplay(strToTime($row[5]), 0),
                     flagModerator => checked($row[3] & flagModerator),
                     flagVip => checked($row[3] & flagVip),
                     flagBanned => checked($row[3] & flagBanned),
                     flagUnconfirmed => checked($row[3] & flagUnconfirmed),
                     flagImported => checked($row[3] & flagImported),
                     flagTard => checked($row[3] & flagTard),
                     machine => $row[8],
                     
                     contact => getContact($row[6]),
                     profile => $row[7],
                     messageCount => $messageCount,
                     );
        return;
    }
    if ($cgi->param('submit')) {
        $name = $cgi->param('name');
        $idStr = smush($name);
        die unless $idStr;
        my $email = $dbh->quote($cgi->param('email'));
        my $flags = $row[3];
        $flags = tweakFlags($flags,
                            (flagModerator | flagVip |
                             flagBanned | flagUnconfirmed |
                             flagImported | flagTard));
        $sth = $dbh->prepare("
            UPDATE Person
            SET
                idStr = " . $dbh->quote($idStr) . ",
                name = " . $dbh->quote($name) . ",
                email = $email, flags = $flags
            WHERE id = $id")
            or dieWithText('Cannot prepare: ' . $dbh->errstr());
        $sth->execute()
            or dieWithText('Cannot execute: ' . $sth->errstr());
        $sth->finish();
    } elsif ($cgi->param('submitNewPassword')) {
        my $newPassword = $cgi->param('newPassword');
        $newPassword = $dbh->quote(encrypt($newPassword));
        $sth = $dbh->prepare("
            UPDATE Person
            SET password = $newPassword
            WHERE id = $id")
            or dieWithText('Cannot prepare: ' . $dbh->errstr());
        $sth->execute()
            or dieWithText('Cannot execute: ' . $sth->errstr());
        $sth->finish();
    }
    $tmpl->param(
        saved => 1,
        idStr => $idStr,
        name => $name,
        contact => getContact($row[6]),
        profile => $row[7],
        messageCount => $messageCount,
        );
}

sub personContact {
    my $idStr = shift;
    $tmpl = new HTML::Template(filename => "$peopleDocRoot/contact.html",
                               die_on_bad_params => 0);
    $sth = $dbh->prepare("
        SELECT id, name, email, flags, prefs, !ISNULL(profile)
        FROM Person
        WHERE idStr = " . $dbh->quote($idStr))
        or dieWithText('Cannot prepare: ' . $dbh->errstr());
    $sth->execute()
        or dieWithText('Cannot execute: ' . $sth->errstr());
    my @row = $sth->fetchrow_array();
    $sth->finish();
    if (not @row) {
        notFound(__LINE__);
    }
    my $email;
    my $emailAccess = ($row[4] & prefEmailAccessMask);
    if ($emailAccess == prefEmailPrivate) {
        notFound(__LINE__);
    } elsif ($emailAccess == prefEmailPublic) {
        $email = $row[2];
    } else {
        loginCheck();
    }
    my $messageCount = selectOne("
        SELECT COUNT(id) FROM Message
        WHERE author = " . $row[0]);
    $tmpl->param(idStr => $idStr,
                 name => $row[1],
                 vip => ($row[3] & flagVip),
                 email => $email,
                 profile => $row[5],
                 messageCount => $messageCount,
                 );
    unless ($ENV{REQUEST_METHOD} eq 'POST' && $cgi->param('submit')) {
        return;
    }
    loginCheck();
    my $subject = $cgi->param('subject');
    my $body = $cgi->param('body');
    unless ($body) {
        $error = 'errorNoBody';
    }
    $body = stripCarriageReturns($body);
    unless ($subject) {
        $error = 'errorNoSubject';
    }
    if ($error) {
        $tmpl->param(subject => $subject,
                     body => $body,
                     );
        return;
    }
    my $fromName = $login->{name};
    my $fromEmail = $login->{email};
    my $toName = $row[1];
    my $toEmail = $row[2];
    open MAIL, "| /usr/sbin/sendmail -t -i"
        or dieWithText("Could not open sendmail: $!");
    print MAIL <<END_OF_HEADER;
From: $fromName <$fromEmail>
To: $toName <$toEmail>
Subject: $subject


END_OF_HEADER
    unless ($emailAccess == prefEmailPublic) {
        print MAIL <<END_OF_BANNER;
***************************************************************
* The Loveline Companion delivered this message without       *
* sharing your e-mail address with the sender.  If you choose *
* to reply to this message directly, your e-mail address will *
* be included in your response.                               *
***************************************************************

END_OF_BANNER
    }
    print MAIL <<END_OF_MESSAGE;
$body
END_OF_MESSAGE
    close MAIL or dieWithText("Error closing sendmail: $!");
    $tmpl->param(sent => 1);
}

sub personInfo {
    my $idStr = shift;
    $tmpl = new HTML::Template(filename => "$peopleDocRoot/info.html",
                               die_on_bad_params => 0);
    # Query for the person.
    $sth = $dbh->prepare("
        SELECT
            id, name, flags, prefs, since, lastLogin, !ISNULL(profile)
        FROM Person
        WHERE idStr = " . $dbh->quote($idStr))
        or dieWithText('Cannot prepare: ' . $dbh->errstr());
    $sth->execute()
        or dieWithText('Cannot execute: ' . $sth->errstr());
    my @row = $sth->fetchrow_array();
    $sth->finish();
    if (not @row) {
        notFound(__LINE__);
    }
    my $lastLogin;
    unless ($row[2] & flagVip) {
        $lastLogin = dateTimeDisplay(strToTime($row[5]), 0);
    }
    my $messageCount = selectOne("
        SELECT COUNT(id) FROM Message
        WHERE author = " . $row[0]);
    $tmpl->param(idStr => $idStr,
                 name => $row[1],
                 vip => $row[2] & flagVip,
                 since => dateTimeDisplay(strToTime($row[4]), 0),
                 lastLogin => $lastLogin,
                 contact => getContact($row[3]),
                 profile => $row[6],
                 messageCount => $messageCount,
                 );
}

sub personProfile {
    my $idStr = shift;
    my $slash = shift;
    $tmpl = new HTML::Template(filename => "$peopleDocRoot/profile.html",
                               die_on_bad_params => 0);
    # Query for the person.
    $sth = $dbh->prepare("
        SELECT
            id, name, flags, prefs, profile
        FROM Person
        WHERE idStr = " . $dbh->quote($idStr))
        or dieWithText('Cannot prepare: ' . $dbh->errstr());
    $sth->execute()
        or dieWithText('Cannot execute: ' . $sth->errstr());
    my @row = $sth->fetchrow_array();
    $sth->finish();
    unless (@row) {
        notFound(__LINE__);
    }
    unless ($slash) {
        redirect("$peopleUrlRoot/$idStr/");
    }
    my $messageCount = selectOne("
        SELECT COUNT(id) FROM Message
        WHERE author = " . $row[0]);
    $tmpl->param(idStr => $idStr,
                 name => $row[1],
                 vip => $row[2] & flagVip,
                 contact => getContact($row[3]),
                 profile => $row[4] ? htmlify($row[4]) : undef,
                 messageCount => $messageCount,
                 );
}

#----------------------------------------------------------------------
# Person/Messages

sub personMessages {
    my $idStr = shift;
    my $message = shift;
    $tmpl = new HTML::Template(filename => "$peopleDocRoot/messages.html",
                               die_on_bad_params => 0,
                               global_vars => 1);
    
    # Get author info.
    $sth = $dbh->prepare("
        SELECT id, name, flags, prefs, !ISNULL(profile)
        FROM Person
        WHERE idStr = " . $dbh->quote($idStr))
        or dieWithText('Cannot prepare: ' . $dbh->errstr());
    $sth->execute()
        or dieWithText('Cannot execute: ' . $sth->errstr());
    my @row = $sth->fetchrow_array();
    $sth->finish();
    if (not @row) {
        notFound(__LINE__);
    }
    if ($message == -1) {
        redirect("$peopleUrlRoot/$idStr/messages/");
    }
    my $message = int($message);
    my $authorId = $row[0];
    my $author = $row[1];
    my $authorFlags = $row[2];
    my $contact = getContact($row[3]);
    my $profile = $row[4];
    
    # Get the message IDs, the message count, and the index
    # of the current message in the list of all messages.
    $sth = $dbh->prepare("
        SELECT id FROM Message
        WHERE author = $authorId AND $isVis
        ORDER BY id
        ")
        or dieWithText('Cannot prepare: ' . $dbh->errstr());
    $sth->execute()
        or dieWithText('Cannot execute: ' . $sth->errstr());
    my @messageIds;
    my $messageIndex = -1;
    my @row;
    while (@row = $sth->fetchrow_array()) {
        if ($row[0] == $message) {
            $messageIndex = int(@messageIds);
        }
        push @messageIds, $row[0];
    }
    $sth->finish();
    my $messageCount = int(@messageIds);
    if ($messageIndex < 0) {
        $messageIndex = $messageCount - 1;
    }
    
    my $start = int($messageIndex / 10) * 10;
    my $thumbStart = int($messageIndex / 100) * 100;
    my $thumbFinish = $thumbStart + 100;
    my $thumbPrev;
    my $thumbNext;
    if ($messageCount < $thumbFinish) {
        $thumbFinish = $messageCount;
    } elsif ($thumbFinish < $messageCount) {
        $thumbNext = $thumbFinish + 9;
        if ($messageCount <= $thumbNext) {
            $thumbNext = $messageCount - 1;
        }
        $thumbNext = $messageIds[$thumbNext] . '.html';
    }
    if ($thumbStart) {
        $thumbPrev = $messageIds[$thumbStart - 1] . '.html';
    }
    
    # Create the thumb index.
    my @thumbIndex;
    for (my $s = $thumbStart; $s < $thumbFinish; $s += 10) {
        my $first = $s + 1;
        my $last = $s + 10;
        if ($messageCount < $last) {
            $last = $messageCount;
        }
        unshift @thumbIndex, {
            url => $messageIds[$last - 1] . '.html',
            title => (($first == $last) ? $first : "$last-$first"),
            selected => ($s == $start),
        };
    }
    
    # Query for messages.
    $sth = $dbh->prepare("
        SELECT id, thread, createTime, body, flags, subject
        FROM Message
        WHERE author = $authorId AND $isVis
        ORDER BY id
        LIMIT $start,10
        ")
        or dieWithText('Cannot prepare: ' . $dbh->errstr());
    $sth->execute()
        or dieWithText('Cannot execute: ' . $sth->errstr());
    
    # Fetch message results.
    my @messages;
    my @row;
    while (@row = $sth->fetchrow_array()) {
        my $selected = ($message && $start + int(@messages) == $messageIndex);
        my $isFollowUp = ($row[0] != $row[1]);
        my $subject = selectThread($row[1]);
        unshift @messages, {
            url => $row[0] . '.html',
            subject => truncSubject(tweakSubject($subject, $isFollowUp)),
            selected => $selected,
            deleted => $loginModerator && ($row[4] & $flagInvisible),
        };
        if ($selected) {
            my $header;
            my $body = $row[3];
            my $signature = $author;
            if ($row[4] & flagImported) {
                ($header, $body, $signature) = stripHeader($body);
            }
            $tmpl->param(
                createTime => dateTimeDisplay(strToTime($row[2]), 0),
                isFollowUp => $isFollowUp,
                subject => $subject, thread => $row[1],
                messageSubject => $row[5],
                header => $header,
                body => htmlify($body),
                signature => $signature,
                );
        }
    }
    $sth->finish();
    
    # Fill-in the template.
    $tmpl->param(
        thumbIndex => \@thumbIndex,
        thumbPrev => $thumbPrev,
        thumbNext => $thumbNext,
        messages => \@messages,
        
        idStr => $idStr,
        name => $author,
        vip => ($authorFlags & flagVip),
        contact => $contact,
        profile => $profile,
        messageCount => $messageCount,
        );
}

#----------------------------------------------------------------------
# Machines

sub getMachines {
    moderatorCheck();
    
    my $id = $cgi->param('id');
    my $start = $cgi->param('start');
    
    # Query for machines.
    unless ($start) { $start = 0; }
    my $filter = '';
    if ($cgi->param('user')) {
        $filter = 'WHERE Machine.user = ' . $cgi->param('user');
    } elsif ($id) {
        $filter = 'WHERE Machine.id = ' . $id;
        if ($ENV{REQUEST_METHOD} eq 'POST') {
            setMachineFlags($id);
            return;
        }
    }
    $sth = $dbh->prepare("
        SELECT
            Machine.id, #0
            Machine.ip, #1
            Person.name, #2
            Machine.flags, #3
            Machine.createTime, #4
            Machine.lastUsed #5
        FROM Machine
        LEFT JOIN Person ON (Machine.user = Person.id)
            $filter
        ORDER BY Machine.id
        LIMIT $start,10")
        or dieWithText('Cannot prepare: ' . $dbh->errstr());
    $sth->execute()
        or dieWithText('Cannot execute: ' . $sth->errstr());
    
    # Fetch machine results.
    my @row;
    if ($id) {
        @row = $sth->fetchrow_array();
        $sth->finish();
        if (@row) {
            $tmpl->param(id => $row[0],
                         ip => intToIpStr($row[1]),
                         user => $row[2],
                         flagVip => checked($row[3] & flagVip),
                         flagBanned => checked($row[3] & flagBanned),
                         createTime => dateTimeDisplay(strToTime($row[4]), 0),
                         lastUsed => dateTimeDisplay(strToTime($row[5]), 0),
                         );
        } else {
            $tmpl->param(id => $id, errorNotFound => 1);
        }
    } else {
        my @machines;
        while (@row = $sth->fetchrow_array()) {
            push @machines, {
                id => $row[0],
                ip => intToIpStr($row[1]),
                user => $row[2],
                flags => flagsStr($row[3]),
                createTime => dateTimeDisplay(strToTime($row[4]), 0),
                lastUsed => dateTimeDisplay(strToTime($row[5]), 0),
            };
        }
        $sth->finish();
        $tmpl->param(machines => \@machines);
    }
}

sub setMachineFlags {
    my $id = shift;
    if ($cgi->param('submitInsert')) {
        my $flags = tweakFlags(0, (flagVip | flagBanned));
        $sth = $dbh->prepare("
            INSERT INTO Machine
            VALUES ($id, 0, $flags, 0, NULL, NULL, 0)
            ")
            or dieWithText('Cannot prepare: ' . $dbh->errstr());
    } else {
        my $flags = selectOne(
            "SELECT flags FROM Machine WHERE id = $id"
            );
        $flags = tweakFlags($flags, (flagVip | flagBanned));
        $sth = $dbh->prepare("
            UPDATE Machine
            SET flags = $flags
            WHERE id = $id")
            or dieWithText('Cannot prepare: ' . $dbh->errstr());
    }
    $sth->execute()
        or dieWithText('Cannot execute: ' . $sth->errstr());
    $sth->finish();
    $tmpl->param(saved => 1);
}

#----------------------------------------------------------------------
# Beta Testers

sub getBetaTesters {
    moderatorCheck();
    
    # Query for beta testers (non-imported people). (Orig).
    $sth = $dbh->prepare("
        SELECT id, idStr, name, password, email, lastLogin, !ISNULL(profile)
        FROM Person
        WHERE !(flags & " . flagImported . ")
        ORDER BY idStr")
        or dieWithText('Cannot prepare: ' . $dbh->errstr());
    # Query for beta testers (non-imported people).
    $sth = $dbh->prepare("
         SELECT id, idStr, name, password, email, lastLogin, random
         FROM Person
         WHERE !(flags & " . flagImported . ")
             AND (flags & " . flagUnconfirmed . ")
         ORDER BY idStr")
         or dieWithText('Cannot prepare: ' . $dbh->errstr());
    # Query for moderators.
    $sth = $dbh->prepare("
        SELECT id, idStr, name, password, email, lastLogin, random
        FROM Person
        WHERE (flags & " . flagModerator . ")
        ORDER BY idStr")
        or dieWithText('Cannot prepare: ' . $dbh->errstr());
    $sth->execute()
        or dieWithText('Cannot execute: ' . $sth->errstr());
    
    # Fetch results.
    my @row;
    my @betaTesters;
    while (@row = $sth->fetchrow_array()) {
        my $messageCount = selectOne("
            SELECT COUNT(id) FROM Message
            WHERE author = " . $row[0] . "
                AND id > 10673");
        push @betaTesters, {
            id => $row[0],
            idStr => $row[1],
            name => $row[2],
            password => $row[3],
            email => $row[4],
            lastLogin => dateTimeDisplay(strToTime($row[5]), 0),
            profile => $row[6],
            posts => $messageCount,
        };
    }
    $sth->finish();
    $tmpl->param(betaTesters => \@betaTesters);
}

#----------------------------------------------------------------------
# Backup

sub backup {
    unless ($loginSuperUser) {
        notFound(__LINE__);
    }
    unless ($ENV{REQUEST_METHOD} eq 'POST' && $cgi->param('submit')) {
        return;
    }
    my $isBackup = shift;
    my $archive = 'loveline/output/backup.sql.gz';
    my $sqlgz = "$docRoot/$archive";
    my $errortxt = "$docRoot/loveline/output/error.txt";
    if ($isBackup) {
        if (system "/usr/local/bin/mysqldump --opt --user=$dbUser --password=$dbPassword $dbName | /usr/bin/gzip - > $sqlgz 2>$errortxt") {
            $error = 'errorSpawn';
            $tmpl->param(errorOs => $!);
            return;
        }
        $tmpl->param(archive => "http://$httpHost/$archive");
    } else {
        if (system "/usr/bin/gzip -d -c $sqlgz | /usr/local/bin/mysql --user=$dbUser --password=$dbPassword $dbName 2>$errortxt") {
            $error = 'errorSpawn';
            $tmpl->param(errorOs => $!);
            return;
        }
        $tmpl->param(restored => 1);
    }
}

#----------------------------------------------------------------------
# SQL utility routines

sub selectLastInsertId {
    return selectOne('SELECT LAST_INSERT_ID()');
}

sub selectOne {
    my $sql = shift;
    my $sth = $dbh->prepare($sql)
        or dieWithText('Cannot prepare: ' . $dbh->errstr());
    $sth->execute()
        or dieWithText('Cannot execute: ' . $sth->errstr());
    my @row = $sth->fetchrow_array();
    $sth->finish();
    return undef unless @row;
    return wantarray ? @row : $row[0];
}

sub selectThread {
    my $thread = shift;
    my @row = selectOne(
        "SELECT flags, subject FROM Message WHERE id = $thread"
        );
    return wantarray ? @row : $row[1];
}

sub selectThreadMessages {
    my $thread = shift;
    return selectOne(
        "SELECT COUNT(id), BIT_OR(flags)
         FROM Message
         WHERE thread = $thread AND $isVis"
        );
}

sub updateLoginFlags {
    $sth = $dbh->prepare('
        UPDATE Person
        SET flags = ' . $login->{flags}. '
        WHERE id = ' . $login->{id})
        or dieWithText('Cannot prepare: ' . $dbh->errstr());
    $sth->execute()
        or dieWithText('Cannot execute: ' . $sth->errstr());
    $sth->finish();
}

#----------------------------------------------------------------------
# misc. utility routines

sub checked {
    return (shift) ? 'CHECKED' : '';
}

sub dateTimeDisplay {
    my $time = shift;
    my $short = shift;
    
    return undef unless defined $time;
    
    my $tzAdjust = timeZoneAdjust();
    
    my (undef,undef,undef,undef,undef,$tyear,undef,$tyday,undef)
        = gmtime($now + $tzAdjust);
    my ($sec,$min,$hour,$mday,$month,$year,$wday,$yday,undef)
        = gmtime($time + $tzAdjust);
    
    my $ampm = 'AM';
    if ($hour > 12) {
       $hour = $hour - 12;
       $ampm = 'PM';
    } elsif ($hour == 12) {
       $ampm = 'PM';
    } elsif ($hour == 0) {
       $hour = 12;
    }
    if ($tyear == $year) {
        if ($tyday == $yday) {
            return sprintf("Today at %d:%02d %s",$hour,$min,$ampm);
        } elsif ($tyday == $yday + 1) {
            return sprintf("Yesterday at %d:%02d %s",$hour,$min,$ampm);
        }
    } elsif ($tyear == $year + 1 && $tyday == 0 && $yday == 364) {
        # Happy New Year!
        return sprintf("Yesterday at %d:%02d %s",$hour,$min,$ampm);
    }
    
    $year += 1900;
    ++$month;
    my @days = ("Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday");
    my $date = sprintf("%s, %s %d",$days[$wday],monthName($month),$mday);
    if ($short) {
        return $date;
    }
    return sprintf("%s, %d at %d:%02d %s",$date,$year,$hour,$min,$ampm);
}

sub dieWithText {
    my $text = shift;
    print $cgi->header( -type => 'text/plain' ),
          $text;
    exit;
}

sub emailAccess {
    my $ea = shift;
    if ($ea eq 'private') {
        return prefEmailPrivate;
    } elsif ($ea eq 'protected') {
        return prefEmailProtected;
    } elsif ($ea eq 'public') {
        return prefEmailPublic;
    }
    return prefEmailPrivate;
}

sub encrypt {
    my $arg = shift;
    my $salt = '';
    for ( my $i=0 ; $i < 8 ; ++$i ) {
        $salt .= (0..9, 'A'..'Z', 'a'..'z', '.', '/')[rand(64)];
    }
    return crypt($arg, $salt);
}

sub flagsStr {
    my $flags = shift;
    my $ret = '';
    if ($flags & flagVip) {
        $ret .= 'v';
    }
    if ($flags & flagBanned) {
        $ret .= 'b';
    }
    return $ret;
}

sub getSubject {
    my $thread = shift;
    my $followUp = shift;
    return tweakSubject(scalar(selectThread($thread)), $followUp);
}

sub htmlify {
    my $body = shift;
    $body =~ s/\n\n/<p>/g;
    $body =~ s/\n/<br>/g;
    return $body;
}

sub ipStrToInt {
    my $ipStr = shift;
    my $ip = 0;
    if ($ipStr =~ /(\d+)\.(\d+)\.(\d+)\.(\d+)/) {
        $ip = (int($1) << 24) |
              (int($2) << 16) |
              (int($3) << 8) |
              (int($4));
    }
    return $ip;
}

sub intToIpStr {
    my $ip = shift;
    my $a = ($ip & 0xff000000) >> 24;
    my $b = ($ip & 0x00ff0000) >> 16;
    my $c = ($ip & 0x0000ff00) >> 8;
    my $d = ($ip & 0x000000ff);
    return "$a.$b.$c.$d";
}

sub isWarm {
    my $time = shift;
    return ($now - $time < 3600);
}

sub moderatorCheck {
    unless ($loginModerator) {
        notFound(__LINE__);
    }
}

sub monthName {
    my $month = shift;
    my @months = ("", "January","February","March","April","May","June",
               "July","August","September","October","November","December");
    return $months[$month];
}

sub notFound {
    # '404 Not Found'
    # NYI: Is there a way to go through .htaccess somehow?
    $line = shift;
    $file = __FILE__;
    dieWithText("notFound at line $line\n$docRoot\n$file\n\n");
    redirect("http://$httpHost/loveline/errors/404.html");
}

sub randomPassword {
    my @words = ('adam', 'drew', 'love', 'line', 'call', 'mason', 'jar');
    my $word = $words[rand(int(@words))];
    my $number = int(rand 100);
    return "$word$number";
}

sub redirect {
    my $url = shift;
    $dbh->disconnect();
    my @cookies;
    if (defined $cookie) {
        push @cookies, $cgi->cookie( -name    => 'machine',
                                     -value   => $cookie,
                                     -expires => '+10y',
                                     -path    => '/' );
    }
    if (defined $readLastCookie) {
        push @cookies, $readLastCookie;
    }
    print $cgi->redirect(-location=> $url, -cookies => \@cookies);
    exit;
}

sub selected {
    return (shift) ? 'SELECTED' : '';
}

sub smush {
    my $arg = shift;
    for ($arg) {
        # Trim whitespace.
        s/^\s+//;
        s/\s+$//;
        s/\s+/ /g;
        # Push to lowercase.
        tr/A-Z/a-z/;
        # Discard non-alphanumeric chars.
        s/[^a-z0-9]+//g;
    }
    return $arg;
}

sub stripCarriageReturns {
    my $text = shift;
    $text =~ s/\cM//g;
    return $text;
}

sub stripHeader {
    my $body = shift;
    my $header; my $signature;
    if ($body =~ /^<!--\n(.*)\n-->\n(.*)$/s) {
        $header = $1;
        $body = $2;
        # _Programming Perl_, Chapter 29, "split" (p. 796)
        my %header = ('FRONTSTUFF', split /^(\S*?):\s*/m, $header); # /
        $signature = $header{Name};
        chomp $signature;
        $header =~ s/\n/ /g;
    }
    return ($header, $body, $signature);
}

sub strToTime {
    my $str = shift;
    # '%Y-%m-%d %H:%M:%S'
    #  $1 $2 $3 $4 $5 $6
    if ($str =~ /(\d+)-(\d+)-(\d+) (\d+):(\d+):(\d+)/) {
        return timegm($6,$5,$4,int($3)?$3:1,int($2)?$2-1:0,$1);
    }
    return undef;
}

sub timeToStr {
    my $t = shift;
    $t = strftime('%Y-%m-%d %H:%M:%S', gmtime($t));
    return $dbh->quote($t);
}

sub timeZoneAdjust {
    my $isdst = (localtime)[8];
    my $tzAdjust = -8;
    if ($machine) {
        $tzAdjust = $machine->{timeZone};
        $isdst = $isdst && ($machine->{flags} & flagDst);
    }
    if ($isdst) {
        $tzAdjust += 1;
    }
    $tzAdjust *= 3600;
    return $tzAdjust;
}

sub truncAuthor {
    return truncString(shift, 30);
}

sub truncString {
    my $s = shift;
    my $l = shift;
    if (length $s > $l) {
        return substr($s, 0, $l) . '...';
    }
    return $s;
}

sub truncSubject {
    return truncString((shift), 60);
}

sub tweakFlags {
    my $flags = shift;
    my $mask = shift;
    if ($loginSuperUser && ($mask & flagModerator)) {
        if ($cgi->param('flagModerator')) {
            $flags |= flagModerator;
        } else {
            $flags &= ~flagModerator;
        }
    }
    if ($mask & flagVip) {
        if ($cgi->param('flagVip')) {
            $flags |= flagVip;
        } else {
            $flags &= ~flagVip;
        }
    }
    if ($mask & flagBanned) {
        if ($cgi->param('flagBanned')) {
            $flags |= flagBanned;
        } else {
            $flags &= ~flagBanned;
        }
    }
    if ($mask & flagUnconfirmed) {
        if ($cgi->param('flagUnconfirmed')) {
            $flags |= flagUnconfirmed;
        } else {
            $flags &= ~flagUnconfirmed;
        }
    }
    if ($mask & flagDeleted) {
        if ($cgi->param('flagDeleted')) {
            $flags |= flagDeleted;
        } else {
            $flags &= ~flagDeleted;
        }
    }
    if ($mask & flagLocked) {
        if ($cgi->param('flagLocked')) {
            $flags |= flagLocked;
        } else {
            $flags &= ~flagLocked;
        }
    }
    if ($mask & flagImported) {
        if ($cgi->param('flagImported')) {
            $flags |= flagImported;
        } else {
            $flags &= ~flagImported;
        }
    }
    if ($mask & flagTard) {
        if ($cgi->param('flagTard')) {
            $flags |= flagTard;
        } else {
            $flags &= ~flagTard;
        }
    }
    return $flags;
}

sub tweakSubject {
    my $subject = shift;
    my $followUp = shift;
    return undef unless $subject;
    if ($followUp) {
        $subject = 'Re: ' . $subject;
    }
    return $subject;
}

sub uriToFs {
    my $uri = shift;
    #$uri =~ s/$uriStrip//g;
    return "$docRoot$uri";
}

# end of file

