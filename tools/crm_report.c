/*
 * Copyright 2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

/*
 * Main
 */

int
main(int argc, char **argv)
{
    crm_log_cli_init("crm_report");
    return CRM_EX_UNIMPLEMENT_FEATURE;
}

/*
## report.common.in

host=`uname -n`
shorthost=`echo $host | sed s:\\\\..*::`
if [ -z $verbose ]; then
    verbose=0
fi

# Target Files
EVENTS_F=events.txt
ANALYSIS_F=analysis.txt
HALOG_F=cluster-log.txt
BT_F=backtraces.txt
SYSINFO_F=sysinfo.txt
SYSSTATS_F=sysstats.txt
DLM_DUMP_F=dlm_dump.txt
CRM_MON_F=crm_mon.txt
MEMBERSHIP_F=members.txt
CRM_VERIFY_F=crm_verify.txt
PERMISSIONS_F=permissions.txt
CIB_F=cib.xml
CIB_TXT_F=cib.txt
DRBD_INFO_F=drbd_info.txt

EVENT_PATTERNS="
state		do_state_transition
membership	pcmk_peer_update.*(lost|memb):
quorum		(crmd|pacemaker-controld).*crm_update_quorum
pause		Process.pause.detected
resources	(lrmd|pacemaker-execd).*rsc:(start|stop)
stonith		te_fence_node|fenced.*(requests|(Succeeded|Failed).to.|result=)
start_stop	shutdown.decision|Corosync.Cluster.Engine|corosync.*Initializing.transport|Executive.Service.RELEASE|crm_shutdown:.Requesting.shutdown|pcmk_shutdown:.Shutdown.complete
"

# superset of all packages of interest on all distros
# (the package manager will be used to validate the installation
# of any of these packages that are installed)
PACKAGES="pacemaker pacemaker-libs pacemaker-cluster-libs libpacemaker3
pacemaker-remote pacemaker-pygui pacemaker-pymgmt pymgmt-client
corosync corosynclib libcorosync4
resource-agents cluster-glue-libs cluster-glue libglue2 ldirectord
ocfs2-tools ocfs2-tools-o2cb ocfs2console
ocfs2-kmp-default ocfs2-kmp-pae ocfs2-kmp-xen ocfs2-kmp-debug ocfs2-kmp-trace
drbd drbd-kmp-xen drbd-kmp-pae drbd-kmp-default drbd-kmp-debug drbd-kmp-trace
drbd-pacemaker drbd-utils drbd-bash-completion drbd-xen
lvm2 lvm2-clvm cmirrord
libdlm libdlm2 libdlm3
hawk ruby lighttpd
kernel-default kernel-pae kernel-xen
glibc
"

# Potential locations of system log files
SYSLOGS="
    /var/log/ *
    /var/logs/ *
    /var/syslog/ *
    /var/adm/ *
    /var/log/ha/ *
    /var/log/cluster/ *
"

# Whether pacemaker-remoted was found (0 = yes, 1 = no, -1 = haven't looked yet)
REMOTED_STATUS=-1

#
# keep the user posted
#
record() {
    if [ x != x"$REPORT_HOME" -a -d "${REPORT_HOME}/$shorthost" ]; then
        rec="${REPORT_HOME}/$shorthost/report.out"

    elif [ x != x"${l_base}" -a -d "${l_base}" ]; then
        rec="${l_base}/report.summary"

    else
        rec="/dev/null"
    fi
    printf "%-10s  $*\n" "$shorthost:" 2>&1 >> "${rec}"
}

log() {
    printf "%-10s  $*\n" "$shorthost:" 1>&2
    record "$*"
}

debug() {
    if [ $verbose -gt 0 ]; then
	log "Debug: $*"
    else
        record "Debug: $*"
    fi
}

info() {
    log "$*"
}

warning() {
    log "WARN: $*"
}

fatal() {
    log "ERROR: $*"
    exit 1
}

require_tar() {
    which tar >/dev/null 2>&1
    if [ $? -ne 0 ]; then
        fatal "Required program 'tar' not found, please install and re-run"
    fi
}

# check if process of given substring in its name does exist;
# only look for processes originated by user 0 (by UID), "@CRM_DAEMON_USER@"
# or effective user running this script, and/or group 0 (by GID),
# "@CRM_DAEMON_GROUP@" or one of the groups the effective user belongs to
# (there's no business in probing any other processes)
is_running() {
    ps -G "0 $(getent group '@CRM_DAEMON_GROUP@' 2>/dev/null | cut -d: -f3) $(id -G)" \
       -u "0 @CRM_DAEMON_USER@ $(id -u)" -f \
      | grep -Eqs  $(echo "$1" | sed -e 's/^\(.\)/[\1]/')
}

has_remoted() {
    if [ $REMOTED_STATUS -eq -1 ]; then
        REMOTED_STATUS=1
        if which pacemaker-remoted >/dev/null 2>&1; then
            REMOTED_STATUS=0
        # Check for pre-2.0.0 daemon name in case we have mixed-version cluster
        elif which pacemaker_remoted >/dev/null 2>&1; then
            REMOTED_STATUS=0
        elif [ -x "@sbindir@/pacemaker-remoted" ]; then
            REMOTED_STATUS=0
        elif [ -x "@sbindir@/pacemaker_remoted" ]; then
            REMOTED_STATUS=0
        else
            # @TODO: the binary might be elsewhere,
            # but a global search is too expensive
            for d in /{usr,opt}/{local/,}{s,}bin; do
                if [ -x "${d}/pacemaker-remoted" ]; then
                    REMOTED_STATUS=0
                elif [ -x "${d}/pacemaker_remoted" ]; then
                    REMOTED_STATUS=0
                fi
            done
        fi
    fi
    return $REMOTED_STATUS
}

# found_dir <description> <dirname>
found_dir() {
    echo "$2"
    info "Pacemaker $1 found in: $2"
}

detect_daemon_dir() {
    info "Searching for where Pacemaker daemons live... this may take a while"

    for d in \
        {/usr,/usr/local,/opt/local,@exec_prefix@}/{libexec,lib64,lib}/pacemaker
    do
        # pacemaker and pacemaker-cts packages can install to daemon directory,
        # so check for a file from each
        if [ -e $d/pacemaker-schedulerd ] || [ -e $d/cts-exec-helper ]; then
            found_dir "daemons" "$d"
            return
        fi
    done

    # Pacemaker Remote nodes don't need to install daemons
    if has_remoted; then
        info "Pacemaker daemons not found (this appears to be a Pacemaker Remote node)"
        return
    fi

    for f in $(find / -maxdepth $maxdepth -type f -name pacemaker-schedulerd -o -name cts-exec-helper); do
        d=$(dirname "$f")
        found_dir "daemons" "$d"
        return
    done

    fatal "Pacemaker daemons not found (nonstandard installation?)"
}

detect_cib_dir() {
    d="${local_state_dir}/lib/pacemaker/cib" 
    if [ -f "$d/cib.xml" ]; then
        found_dir "config files" "$d"
        return
    fi

    # Pacemaker Remote nodes don't need a CIB
    if has_remoted; then
        info "Pacemaker config not found (this appears to be a Pacemaker Remote node)"
        return
    fi

    info "Searching for where Pacemaker keeps config information... this may take a while"
    # TODO: What about false positives where someone copied the CIB?
    for f in $(find / -maxdepth $maxdepth -type f -name cib.xml); do
        d=$(dirname $f)
        found_dir "config files" "$d"
        return
    done

    warning "Pacemaker config not found (nonstandard installation?)"
}

detect_state_dir() {
    if [ -n "$CRM_CONFIG_DIR" ]; then
        # Assume new layout
        # $local_state_dir/lib/pacemaker/(cib,pengine,blackbox,cores)
        dirname "$CRM_CONFIG_DIR"

    # Pacemaker Remote nodes might not have a CRM_CONFIG_DIR
    elif [ -d "$local_state_dir/lib/pacemaker" ]; then
        echo $local_state_dir/lib/pacemaker
    fi
}

detect_pe_dir() {
    config_root="$1"

    d="$config_root/pengine"
    if [ -d "$d" ]; then
        found_dir "scheduler inputs" "$d"
        return
    fi

    if has_remoted; then
        info "Pacemaker scheduler inputs not found (this appears to be a Pacemaker Remote node)"
        return
    fi

    info "Searching for where Pacemaker keeps scheduler inputs... this may take a while"
    for d in $(find / -maxdepth $maxdepth -type d -name pengine); do
        found_dir "scheduler inputs" "$d"
        return
    done

    fatal "Pacemaker scheduler inputs not found (nonstandard installation?)"
}

detect_host() {
    local_state_dir=@localstatedir@

    if [ -d $local_state_dir/run ]; then
	CRM_STATE_DIR=$local_state_dir/run/crm
    else
        info "Searching for where Pacemaker keeps runtime data... this may take a while"
	for d in `find / -maxdepth $maxdepth -type d -name run`; do
	    local_state_dir=`dirname $d`
	    CRM_STATE_DIR=$d/crm
	    break
	done
	info "Found: $CRM_STATE_DIR"
    fi
    debug "Machine runtime directory: $local_state_dir"
    debug "Pacemaker runtime data located in: $CRM_STATE_DIR"

    CRM_DAEMON_DIR=$(detect_daemon_dir)
    CRM_CONFIG_DIR=$(detect_cib_dir)
    config_root=$(detect_state_dir)

    # Older versions had none
    BLACKBOX_DIR=$config_root/blackbox
    debug "Pacemaker blackboxes (if any) located in: $BLACKBOX_DIR"

    PCMK_SCHEDULER_INPUT_DIR=$(detect_pe_dir "$config_root")

    CRM_CORE_DIRS=""
    for d in $config_root/cores $local_state_dir/lib/corosync; do
	if [ -d $d ]; then
	    CRM_CORE_DIRS="$CRM_CORE_DIRS $d"
	fi
    done
    debug "Core files located under: $CRM_CORE_DIRS"
}

time2str() {
	perl -e "use POSIX; print strftime('%x %X',localtime($1));"
}

get_time() {
	perl -e "\$time=\"$*\";" -e '
	$unix_tm = 0;
	eval "use Date::Parse";
	if (index($time, ":") < 0) {
	} elsif (!$@) {
		$unix_tm = str2time($time);
	} else {
		eval "use Date::Manip";
		if (!$@) {
			$unix_tm = UnixDate(ParseDateString($time), "%s");
		}
	}
	if ($unix_tm != "") {
		print int($unix_tm);
	} else {
		print "";
	}
	'
}

get_time_syslog() {
    awk '{print $1,$2,$3}'
}

get_time_legacy() {
    awk '{print $2}' | sed 's/_/ /'
}

get_time_iso8601() {
    awk '{print $1}'
}

get_time_format_for_string() {
    l="$*"
    t=$(get_time `echo $l | get_time_syslog`)
    if [ "x$t" != x ]; then
	echo syslog
	return
    fi

    t=$(get_time `echo $l | get_time_iso8601`)
    if [ "x$t" != x ]; then
	echo iso8601
	return
    fi

    t=$(get_time `echo $l | get_time_legacy`)
    if [ "x$t" != x ]; then
	echo legacy
	return
    fi
}

get_time_format() {
    t=0 l="" func=""
    trycnt=10
    while [ $trycnt -gt 0 ] && read l; do
	func=$(get_time_format_for_string $l)
	if [ "x$func" != x ]; then
	    break
	fi
	trycnt=$(($trycnt-1))
    done
    #debug "Logfile uses the $func time format"
    echo $func
}

get_time_from_line() {
    GTFL_FORMAT="$1"
    shift
    if [ "$GTFL_FORMAT" = "" ]; then
        GTFL_FORMAT=$(get_time_format_for_string "$@")
    fi
    case $GTFL_FORMAT in
        syslog|legacy|iso8601)
            get_time $(echo "$@" | get_time_${GTFL_FORMAT})
            ;;
        *)
            warning "Unknown time format in: $@"
            ;;
    esac
}

get_first_time() {
    l=""
    format=$1
    while read l; do
        ts=$(get_time_from_line "$format" "$l")
	if [ "x$ts" != x ]; then
	    echo "$ts"
	    return
	fi
    done
}

get_last_time() {
    l=""
    best=`date +%s` # Now
    format=$1
    while read l; do
        ts=$(get_time_from_line "$format" "$l")
	if [ "x$ts" != x ]; then
	    best=$ts
	fi
    done
    echo $best
}

linetime() {
    get_time_from_line "" $(tail -n +$2 $1 | grep -a ":[0-5][0-9]:" | head -n 1)
}

#
# findmsg <max> <pattern>
#
# Print the names of up to <max> system logs that contain <pattern>,
# ordered by most recently modified.
#
findmsg() {
    max=$1
    pattern="$2"
    found=0

    # List all potential system logs ordered by most recently modified.
    candidates=$(ls -1td $SYSLOGS 2>/dev/null)
    if [ -z "$candidates" ]; then
        debug "No system logs found to search for pattern \'$pattern\'"
        return
    fi

    # Portable way to handle files with spaces in their names.
    SAVE_IFS=$IFS
    IFS="
"

    # Check each log file for matches.
    logfiles=""
    for f in $candidates; do
        local cat=""

        # We only care about readable files with something in them.
        if [ ! -f "$f" ] || [ ! -r "$f" ] || [ ! -s "$f" ] ; then
            continue
        fi

        cat=$(find_decompressor "$f")

        # We want to avoid grepping through potentially huge binary logs such
        # as lastlog. However, control characters sometimes find their way into
        # text logs, so we use a heuristic of more than 256 nonprintable
        # characters in the file's first kilobyte.
        if [ $($cat "$f" 2>/dev/null | head -c 1024 | tr -d '[:print:][:space:]' | wc -c) -gt 256 ]
        then
            continue
        fi

        # Our patterns are ASCII, so we can use LC_ALL="C" to speed up grep
        $cat "$f" 2>/dev/null | LC_ALL="C" grep -q -e "$pattern"
        if [ $? -eq 0 ]; then

            # Add this file to the list of hits
            # (using newline as separator to handle spaces in names).
            if [ -z "$logfiles" ]; then
                logfiles="$f"
            else
                logfiles="$logfiles
$f"
            fi

            # If we have enough hits, print them and return.
            found=$(($found+1))
            if [ $found -ge $max ]; then
                break
            fi
        fi
    done 2>/dev/null
    IFS=$SAVE_IFS
    if [ -z "$logfiles" ]; then
        debug "Pattern \'$pattern\' not found in any system logs"
    else
        debug "Pattern \'$pattern\' found in: [ $logfiles ]"
        echo "$logfiles"
    fi
}

node_events() {
  if [ -e $1 ]; then
    Epatt=`echo "$EVENT_PATTERNS" |
      while read title p; do [ -n "$p" ] && echo -n "|$p"; done |
      sed 's/.//'
      `
    grep -E "$Epatt" $1
  fi
}

pickfirst() {
    for x; do
	which $x >/dev/null 2>&1 && {
	    echo $x
	    return 0
	}
    done
    return 1
}

shrink() {
    olddir=$PWD
    dir=`dirname $1`
    base=`basename $1`

    target=$1.tar
    tar_options="cf"

    variant=`pickfirst bzip2 gzip xz false`
    case $variant in
	bz*)
	    tar_options="jcf"
	    target="$target.bz2"
	    ;;
	gz*)
	    tar_options="zcf"
	    target="$target.gz"
	    ;;
	xz*)
	    tar_options="Jcf"
	    target="$target.xz"
	    ;;
	*)
	    warning "Could not find a compression program, the resulting tarball may be huge"
	    ;;
    esac

    if [ -e $target ]; then
	fatal "Destination $target already exists, specify an alternate name with --dest"
    fi

    cd $dir  >/dev/null 2>&1
    tar $tar_options $target $base >/dev/null 2>&1
    if [ $? -ne 0 ]; then
        fatal "Could not archive $base, please investigate and collect manually"
    fi
    cd $olddir  >/dev/null 2>&1

    echo $target
}

findln_by_time() {
    local logf=$1
    local tm=$2
    local first=1

    # Some logs can be massive (over 1,500,000,000 lines have been seen in the wild) 
    # Even just 'wc -l' on these files can take 10+ minutes 

    local fileSize=`ls -lh "$logf" | awk '{ print $5 }' | grep -ie G`
    if [ x$fileSize != x ]; then
        warning "$logf is ${fileSize} in size and could take many hours to process. Skipping."
        return
    fi

    local last=`wc -l < $logf`
    while [ $first -le $last ]; do
	mid=$((($last+$first)/2))
	trycnt=10
	while [ $trycnt -gt 0 ]; do
	    tmid=`linetime $logf $mid`
	    [ "$tmid" ] && break
	    warning "cannot extract time: $logf:$mid; will try the next one"
	    trycnt=$(($trycnt-1))
			# shift the whole first-last segment
	    first=$(($first-1))
	    last=$(($last-1))
	    mid=$((($last+$first)/2))
	done
	if [ -z "$tmid" ]; then
	    warning "giving up on log..."
	    return
	fi
	if [ $tmid -gt $tm ]; then
	    last=$(($mid-1))
	elif [ $tmid -lt $tm ]; then
	    first=$(($mid+1))
	else
	    break
	fi
    done
    echo $mid
}

dumplog() {
    local logf=$1
    local from_line=$2
    local to_line=$3
    [ "$from_line" ] ||
    return
    tail -n +$from_line $logf |
    if [ "$to_line" ]; then
	head -$(($to_line-$from_line+1))
    else
	cat
    fi
}

#
# find log/set of logs which are interesting for us
#
#
# find log slices
#

find_decompressor() {
    case $1 in
        *bz2) echo "bzip2 -dc" ;;
        *gz)  echo "gzip -dc" ;;
        *xz)  echo "xz -dc" ;;
        *)    echo "cat" ;;
    esac
}

#
# check if the log contains a piece of our segment
#
is_our_log() {
	local logf=$1
	local from_time=$2
	local to_time=$3

	local cat=`find_decompressor $logf`
	local format=`$cat $logf | get_time_format`
	local first_time=`$cat $logf | head -10 | get_first_time $format`
	local last_time=`$cat $logf | tail -10 | get_last_time $format`

	if [ x = "x$first_time" -o x = "x$last_time" ]; then
	    warning "Skipping bad logfile '$1': Could not determine log dates"
	    return 0 # skip (empty log?)
	fi
	if [ $from_time -gt $last_time ]; then
		# we shouldn't get here anyway if the logs are in order
		return 2 # we're past good logs; exit
	fi
	if [ $from_time -ge $first_time ]; then
		return 3 # this is the last good log
	fi
	# have to go further back
	if [ x = "x$to_time" -o $to_time -ge $first_time ]; then
		return 1 # include this log
	else
		return 0 # don't include this log
	fi
}
#
# go through archived logs (timewise backwards) and see if there
# are lines belonging to us
# (we rely on untouched log files, i.e. that modify time
# hasn't been changed)
#
arch_logs() {
	local logf=$1
	local from_time=$2
	local to_time=$3

	# look for files such as: ha-log-20090308 or
	# ha-log-20090308.gz (.bz2) or ha-log.0, etc
	ls -t $logf $logf*[0-9z] 2>/dev/null |
	while read next_log; do
		is_our_log $next_log $from_time $to_time
		case $? in
		0) ;;  # noop, continue
		1) echo $next_log  # include log and continue
			debug "Found log $next_log"
			;;
		2) break;; # don't go through older logs!
		3) echo $next_log  # include log and continue
			debug "Found log $next_log"
			break
			;; # don't go through older logs!
		esac
	done
}

#
# print part of the log
#
drop_tmp_file() {
	[ -z "$tmp" ] || rm -f "$tmp"
}

print_logseg() {
	local logf=$1
	local from_time=$2
	local to_time=$3

	# uncompress to a temp file (if necessary)
	local cat=`find_decompressor $logf`
	if [ "$cat" != "cat" ]; then
		tmp=`mktemp`
		$cat $logf > $tmp
		trap drop_tmp_file 0
		sourcef=$tmp
	else
		sourcef=$logf
		tmp=""
	fi

	if [ "$from_time" = 0 ]; then
		FROM_LINE=1
	else
		FROM_LINE=`findln_by_time $sourcef $from_time`
	fi
	if [ -z "$FROM_LINE" ]; then
		warning "couldn't find line for time $from_time; corrupt log file?"
		return
	fi

	TO_LINE=""
	if [ "$to_time" != 0 ]; then
		TO_LINE=`findln_by_time $sourcef $to_time`
		if [ -z "$TO_LINE" ]; then
			warning "couldn't find line for time $to_time; corrupt log file?"
			return
		fi
		if [ $FROM_LINE -lt $TO_LINE ]; then
		    dumplog $sourcef $FROM_LINE $TO_LINE
		    log "Including segment [$FROM_LINE-$TO_LINE] from $logf"
		else
		    debug "Empty segment [$FROM_LINE-$TO_LINE] from $logf"
		fi
	else
	    dumplog $sourcef $FROM_LINE $TO_LINE
	    log "Including all logs after line $FROM_LINE from $logf"
	fi
	drop_tmp_file
	trap "" 0
}

#
# find log/set of logs which are interesting for us
#
dumplogset() {
	local logf=$1
	local from_time=$2
	local to_time=$3

	local logf_set=`arch_logs $logf $from_time $to_time`
	if [ x = "x$logf_set" ]; then
		return
	fi

	local num_logs=`echo "$logf_set" | wc -l`
	local oldest=`echo $logf_set | awk '{print $NF}'`
	local newest=`echo $logf_set | awk '{print $1}'`
	local mid_logfiles=`echo $logf_set | awk '{for(i=NF-1; i>1; i--) print $i}'`

	# the first logfile: from $from_time to $to_time (or end)
	# logfiles in the middle: all
	# the last logfile: from beginning to $to_time (or end)
	case $num_logs in
	1) print_logseg $newest $from_time $to_time;;
	*)
		print_logseg $oldest $from_time 0
		for f in $mid_logfiles; do
		    `find_decompressor $f` $f
		    debug "including complete $f logfile"
		done
		print_logseg $newest 0 $to_time
	;;
	esac
}

# cut out a stanza
getstanza() {
	awk -v name="$1" '
	!in_stanza && NF==2 && /^[a-z][a-z]*[[:space:]]*{/ { # stanza start
		if ($1 == name)
			in_stanza = 1
	}
	in_stanza { print }
	in_stanza && NF==1 && $1 == "}" { exit }
	'
}
# supply stanza in $1 and variable name in $2
# (stanza is optional)
getcfvar() {
    cf_type=$1; shift;
    cf_var=$1; shift;
    cf_file=$*

    [ -f "$cf_file" ] || return
    case $cf_type in
	corosync)
	    sed 's@#.*@@' < $cf_file |
	        if [ $# -eq 2 ]; then
			getstanza "$cf_var"
			shift 1
		else
			cat
		fi |
		awk -v varname="$cf_var" '
		NF==2 && match($1,varname":$")==1 { print $2; exit; }
		'
	;;
    esac
}

pickfirst() {
    for x; do
	which $x >/dev/null 2>&1 && {
	    echo $x
	    return 0
	}
    done
    return 1
}

#
# figure out the cluster type, depending on the process list
# and existence of configuration files
#
get_cluster_type() {
    if is_running corosync; then
	tool=`pickfirst corosync-objctl corosync-cmapctl`
	case $tool in
	    *objctl) quorum=`$tool -a | grep quorum.provider | sed 's@.*=\s*@@'`;;
	    *cmapctl) quorum=`$tool | grep quorum.provider | sed 's@.*=\s*@@'`;;
	esac
        stack="corosync"

    # Now we're guessing...

    # TODO: Technically these could be anywhere :-/
    elif [ -f "@PCMK__COROSYNC_CONF@" ]; then
	stack="corosync"

    else
        # We still don't know. This might be a Pacemaker Remote node,
        # or the configuration might be in a nonstandard location.
        stack="any"
    fi

    debug "Detected the '$stack' cluster stack"
    echo $stack
}

find_cluster_cf() {
    case $1 in
	corosync)
	    best_size=0
	    best_file=""

	    # TODO: Technically these could be anywhere :-/
	    for cf in "@PCMK__COROSYNC_CONF@"; do
		if [ -f $cf ]; then
		    size=`wc -l $cf | awk '{print $1}'`
		    if [ $size -gt $best_size ]; then
			best_size=$size
			best_file=$cf
		    fi
		fi
	    done
	    if [ -z "$best_file" ]; then
		debug "Looking for corosync configuration file. This may take a while..."
		for f in `find / -maxdepth $maxdepth -type f -name corosync.conf`; do
		    best_file=$f
		    break
		done
	    fi
	    debug "Located corosync config file: $best_file"
	    echo "$best_file"
	    ;;
	any)
	    # Cluster type is undetermined. Don't complain, because this
	    # might be a Pacemaker Remote node.
	    ;;
	*)
	    warning "Unknown cluster type: $1"
	    ;;
    esac
}

#
# check for the major prereq for a) parameter parsing and b)
# parsing logs
#
t=`get_time "12:00"`
if [ "$t" = "" ]; then
	fatal "please install the perl Date::Parse module (perl-DateTime-Format-DateParse on Fedora/Red Hat)"
fi

# Override any locale settings so collected output is in a common language
LC_ALL="C"
export LC_ALL


## report.collector.in

if
    echo $REPORT_HOME | grep -qs '^/'
then
    debug "Using full path to working directory: $REPORT_HOME"
else
    REPORT_HOME="$HOME/$REPORT_HOME"
    debug "Canonicalizing working directory path: $REPORT_HOME"
fi

detect_host

#
# find files newer than a and older than b
#
isnumber() {
    echo "$*" | grep -qs '^[0-9][0-9]*$'
}

touchfile() {
    t=`mktemp` &&
        perl -e "\$file=\"$t\"; \$tm=$1;" -e 'utime $tm, $tm, $file;' &&
        echo $t
}

find_files_clean() {
    [ -z "$from_stamp" ] || rm -f "$from_stamp"
    [ -z "$to_stamp" ] || rm -f "$to_stamp"
    from_stamp=""
    to_stamp=""
}

find_files() {
    dirs=
    from_time=$2
    to_time=$3
    for d in $1; do
        if [ -d $d ]; then
	   dirs="$dirs $d"
	fi
    done

    if [ x"$dirs" = x ]; then
	return
    fi

    isnumber "$from_time" && [ "$from_time" -gt 0 ] || {
	warning "sorry, can't find files in [ $1 ] based on time if you don't supply time"
	return
    }
    trap find_files_clean 0
    if ! from_stamp=`touchfile $from_time`; then
	warning "sorry, can't create temporary file for find_files"
	return
    fi
    findexp="-newer $from_stamp"
    if isnumber "$to_time" && [ "$to_time" -gt 0 ]; then
	if ! to_stamp=`touchfile $to_time`; then
	    warning "sorry, can't create temporary file for find_files"
	    find_files_clean
	    return
	fi
	findexp="$findexp ! -newer $to_stamp"
    fi
    find $dirs -type f $findexp
    find_files_clean
    trap "" 0
}

#
# check permissions of files/dirs
#
pl_checkperms() {
    perl -e '
	# check permissions and ownership
	# uid and gid are numeric
	# everything must match exactly
	# no error checking! (file should exist, etc)
	($filename, $perms, $in_uid, $in_gid) = @ARGV;
	($mode,$uid,$gid) = (stat($filename))[2,4,5];
	$p=sprintf("%04o", $mode & 07777);
	$p ne $perms and exit(1);
	$uid ne $in_uid and exit(1);
	$gid ne $in_gid and exit(1);
    ' $*
}

num_id() {
    getent $1 $2 | awk -F: '{print $3}'
}

chk_id() {
    [ "$2" ] && return 0
    echo "$1: id not found"
    return 1
}

check_perms() {
    while read type f p uid gid; do
        if [ ! -e "$f" ]; then
            echo "$f doesn't exist"
            continue
        elif [ ! -$type "$f" ]; then
            echo "$f has wrong type"
            continue
        fi
	n_uid=`num_id passwd $uid`
	chk_id "$uid" "$n_uid" || continue
	n_gid=`num_id group $gid`
	chk_id "$gid" "$n_gid" || continue
	pl_checkperms $f $p $n_uid $n_gid || {
	    echo "wrong permissions or ownership for $f:"
	    ls -ld $f
	}
    done
}

#
# coredumps
#
findbinary() {
    random_binary=`which cat 2>/dev/null` # suppose we are lucky
    binary=`gdb $random_binary $1 < /dev/null 2>/dev/null |
	grep 'Core was generated' | awk '{print $5}' |
	sed "s/^.//;s/[.':]*$//"`
    if [ x = x"$binary" ]; then
	debug "Could not detect the program name for core $1 from the gdb output; will try with file(1)"
	binary=$(file $1 | awk '/from/{
			for( i=1; i<=NF; i++ )
				if( $i == "from" ) {
					print $(i+1)
					break
				}
			}')
	binary=`echo $binary | tr -d "'"`
	binary=$(echo $binary | tr -d '`')
	if [ "$binary" ]; then
	    binary=`which $binary 2>/dev/null`
	fi
    fi
    if [ x = x"$binary" ]; then
	warning "Could not find the program path for core $1"
	return
    fi
    fullpath=`which $binary 2>/dev/null`
    if [ x = x"$fullpath" ]; then
	if [ -x $CRM_DAEMON_DIR/$binary ]; then
	    echo $CRM_DAEMON_DIR/$binary
	    debug "Found the program at $CRM_DAEMON_DIR/$binary for core $1"
	else
	    warning "Could not find the program path for core $1"
	fi
    else
	echo $fullpath
	debug "Found the program at $fullpath for core $1"
    fi
}

getbt() {
    which gdb > /dev/null 2>&1 || {
	warning "Please install gdb to get backtraces"
	return
    }
    for corefile; do
	absbinpath=`findbinary $corefile`
	[ x = x"$absbinpath" ] && continue
	echo "====================== start backtrace ======================"
	ls -l $corefile
	# Summary first...
	gdb -batch -n -quiet -ex ${BT_OPTS:-"thread apply all bt"} -ex quit \
	    $absbinpath $corefile 2>/dev/null
	echo "====================== start detail ======================"
	# Now the unreadable details...
	gdb -batch -n -quiet -ex ${BT_OPTS:-"thread apply all bt full"} -ex quit \
	    $absbinpath $corefile 2>/dev/null
	echo "======================= end backtrace ======================="
    done
}

dump_status_and_config() {
    crm_mon -1 2>&1 | grep -v '^Last upd' > $target/$CRM_MON_F
    cibadmin -Ql 2>/dev/null > $target/${CIB_F}.live
}

getconfig() {
    cluster=$1; shift;
    target=$1; shift;

    for cf in $*; do
	if [ -e "$cf" ]; then
	    cp -a "$cf" $target/
	fi
    done

    if is_running pacemaker-controld; then
        dump_status_and_config
        crm_node -p > "$target/$MEMBERSHIP_F" 2>&1
	echo "$host" > $target/RUNNING

    elif is_running pacemaker-remoted; then
        dump_status_and_config
        echo "$host" > $target/RUNNING

    # Pre-2.0.0 daemon name in case we're collecting on a mixed-version cluster
    elif is_running pacemaker_remoted; then
        dump_status_and_config
        echo "$host" > $target/RUNNING

    else
	echo "$host" > $target/STOPPED
    fi
}

get_readable_cib() {
    target="$1"; shift;

    if [ -f "$target/$CIB_F" ]; then
        crm_verify -V -x "$target/$CIB_F" >"$target/$CRM_VERIFY_F" 2>&1
        if which crm >/dev/null 2>&1 ; then
            CIB_file="$target/$CIB_F" crm configure show >"$target/$CIB_TXT_F" 2>&1
        elif which pcs >/dev/null 2>&1 ; then
            pcs config -f "$target/$CIB_F" >"$target/$CIB_TXT_F" 2>&1
        fi
    fi
}

#
# remove values of sensitive attributes
#
# this is not proper xml parsing, but it will work under the
# circumstances
sanitize_xml_attrs() {
    sed $(
	for patt in $SANITIZE; do
	    echo "-e /name=\"$patt\"/s/value=\"[^\"]*\"/value=\"****\"/"
	done
    )
}

sanitize_hacf() {
    awk '
	$1=="stonith_host"{ for( i=5; i<=NF; i++ ) $i="****"; }
	{print}
	'
}

sanitize_one_clean() {
    [ -z "$tmp" ] || rm -f "$tmp"
    tmp=""
    [ -z "$ref" ] || rm -f "$ref"
    ref=""
}

sanitize() {
    file=$1
    compress=""
    if [ -z "$SANITIZE" ]; then
	return
    fi
    echo $file | grep -qs 'gz$' && compress=gzip
    echo $file | grep -qs 'bz2$' && compress=bzip2
    if [ "$compress" ]; then
	decompress="$compress -dc"
    else
	compress=cat
	decompress=cat
    fi
    trap sanitize_one_clean 0
    tmp=`mktemp`
    ref=`mktemp`
    if [ -z "$tmp" -o -z "$ref" ]; then
	sanitize_one_clean
	fatal "cannot create temporary files"
    fi
    touch -r $file $ref  # save the mtime
    if [ "`basename $file`" = ha.cf ]; then
	sanitize_hacf
    else
	$decompress | sanitize_xml_attrs | $compress
    fi < $file > $tmp
    mv $tmp $file
	# note: cleaning $tmp up is still needed even after it's renamed
	# because its temp directory is still there.

	touch -r $ref $file
	sanitize_one_clean
	trap "" 0
}

#
# get some system info
#
distro() {
    if
	which lsb_release >/dev/null 2>&1
    then
	lsb_release -d | sed -e 's@^Description:\s*@@'
	debug "Using lsb_release for distribution info"
	return
    fi

    relf=`ls /etc/debian_version 2>/dev/null` ||
    relf=`ls /etc/slackware-version 2>/dev/null` ||
    relf=`ls -d /etc/ *-release 2>/dev/null` && {
	for f in $relf; do
	    test -f $f && {
		echo "`ls $f` `cat $f`"
		debug "Found `echo $relf | tr '\n' ' '` distribution release file(s)"
		return
	    }
	done
    }
    warning "No lsb_release, no /etc/ *-release, no /etc/debian_version: no distro information"
}

pkg_ver() {
    if which dpkg >/dev/null 2>&1 ; then
	pkg_mgr="deb"
    elif which rpm >/dev/null 2>&1 ; then
	pkg_mgr="rpm"
    elif which pkg_info >/dev/null 2>&1 ; then
	pkg_mgr="pkg_info"
    elif which pkginfo >/dev/null 2>&1 ; then
	pkg_mgr="pkginfo"
    else
	warning "Unknown package manager"
	return
    fi
    debug "The package manager is: $pkg_mgr"
    echo "The package manager is: $pkg_mgr"

    echo "Installed packages:"
    case $pkg_mgr in
	deb)
	    dpkg-query -f '${Package} ${Version} ${Architecture}\n' -W | sort
            echo
	    for pkg in $*; do
		if dpkg-query -W $pkg 2>/dev/null ; then
		    debug "Verifying installation of: $pkg"
		    echo "Verifying installation of: $pkg"
		    debsums -s $pkg 2>/dev/null
		fi
	    done
	    ;;
	rpm)
	    rpm -qa --qf '%{name} %{version}-%{release} - %{distribution} %{arch}\n' | sort
            echo
	    for pkg in $*; do
		if rpm -q $pkg >/dev/null 2>&1 ; then
		    debug "Verifying installation of: $pkg"
		    echo "Verifying installation of: $pkg"
		    rpm --verify $pkg 2>&1
		fi
	    done
	    ;;
	pkg_info)
	    pkg_info
	    ;;
	pkginfo)
	    pkginfo | awk '{print $3}'  # format?
	    ;;
    esac
}

getbacktraces() {
    debug "Looking for backtraces: $*"
    flist=$(
	for f in `find_files "$CRM_CORE_DIRS" $1 $2`; do
	    bf=`basename $f`
	    test `expr match $bf core` -gt 0 &&
	    echo $f
	done)
    if [ "$flist" ]; then
	for core in $flist; do
	    log "Found core file: `ls -al $core`"
	done

	# Make a copy of them in case we need more data later
	# Luckily they compress well
	mkdir cores >/dev/null 2>&1
	cp -a $flist cores/
	shrink cores
	rm -rf cores

	# Now get as much as we can from them automagically
	for f in $flist; do
	    getbt $f
        done
    fi
}

getpeinputs() {
    if [ -n "$PCMK_SCHEDULER_INPUT_DIR" ]; then
        flist=$(
            find_files "$PCMK_SCHEDULER_INPUT_DIR" "$1" "$2" | sed "s,`dirname $PCMK_SCHEDULER_INPUT_DIR`/,,g"
        )
        if [ "$flist" ]; then
            (cd $(dirname "$PCMK_SCHEDULER_INPUT_DIR") && tar cf - $flist) | (cd "$3" && tar xf -)
            debug "found `echo $flist | wc -w` scheduler input files in $PCMK_SCHEDULER_INPUT_DIR"
        fi
    fi
}

getblackboxes() {
    flist=$(
	find_files $BLACKBOX_DIR $1 $2
    )

    for bb in $flist; do
        bb_short=`basename $bb`
	qb-blackbox $bb > $3/${bb_short}.blackbox 2>&1
	info "Extracting contents of blackbox: $bb_short"
    done
}

#
# some basic system info and stats
#
sys_info() {
    cluster=$1; shift
    echo "Platform: `uname`"
    echo "Kernel release: `uname -r`"
    echo "Architecture: `uname -m`"
    if [ `uname` = Linux ]; then
	echo "Distribution: `distro`"
    fi

    echo
    cibadmin --version 2>&1 | head -1
    cibadmin -! 2>&1
    case $cluster in
	corosync)
	    /usr/sbin/corosync -v 2>&1 | head -1
	    ;;
    esac

    # Cluster glue version hash (if available)
    stonith -V 2>/dev/null

    # Resource agents version hash
    echo "resource-agents: `grep 'Build version:' /usr/lib/ocf/resource.d/heartbeat/.ocf-shellfuncs`"

    echo
    pkg_ver $*
}

sys_stats() {
    set -x
    uname -n
    uptime
    ps axf
    ps auxw
    top -b -n 1
    ifconfig -a
    ip addr list
    netstat -i
    arp -an
    test -d /proc && {
	cat /proc/cpuinfo
    }
    lsscsi
    lspci
    lsblk
    mount
    df
    set +x
}

dlm_dump() {
    if which dlm_tool >/dev/null 2>&1 ; then
      if is_running dlm_controld; then
	echo "--- Lockspace overview:"
	dlm_tool ls -n

	echo "---Lockspace history:"
	dlm_tool dump

	echo "---Lockspace status:"
	dlm_tool status
	dlm_tool status -v

	echo "---Lockspace config:"
	dlm_tool dump_config

	dlm_tool log_plock

	dlm_tool ls | grep name |
	while read X N ; do
	    echo "--- Lockspace $N:"
	    dlm_tool lockdump "$N"
	    dlm_tool lockdebug -svw "$N"
	done
      fi
    fi
}

drbd_info() {
    test -f /proc/drbd && {
        echo "--- /proc/drbd:"
        cat /proc/drbd 2>&1
        echo
    }

    if which drbdadm >/dev/null 2>&1; then
        echo "--- drbdadm dump:"
        if [ -z "$SANITIZE"]; then
            drbdadm dump 2>&1
        else
            drbdadm dump 2>&1 | sed "s/\(shared-secret[ 	]*\"\)[^\"]*\";/\1****\";/"
        fi
        echo

        echo "--- drbdadm status:"
        drbdadm status 2>&1
        echo

        echo "--- drbdadm show-gi:"
        for res in $(drbdsetup status | grep -e ^\\S | awk '{ print $1 }'); do
            echo "$res:"
            drbdadm show-gi $res 2>&1
            echo
        done
    fi

    if which drbd-overview >/dev/null 2>&1; then
        echo "--- drbd-overview:"
        drbd-overview 2>&1
        echo
    fi

    if which drbdsetup >/dev/null 2>&1; then
        echo "--- drbdsetup status:"
        drbdsetup status --verbose --statistics 2>&1
        echo

        echo "--- drbdsetup events2:"
        drbdsetup events2 --timestamps --statistics --now 2>&1
        echo
    fi
}

iscfvarset() {
    test "`getcfvar $1 $2`"
}

iscfvartrue() {
    getcfvar $1 $2 $3 | grep -E -qsi "^(true|y|yes|on|1)"
}

iscfvarfalse() {
    getcfvar $1 $2 $3 | grep -E -qsi "^(false|n|no|off|0)"
}

find_syslog() {
    priority="$1"

    # Always include system logs (if we can find them)
    msg="Mark:pcmk:`perl -e 'print time()'`"
    logger -p "$priority" "$msg" >/dev/null 2>&1

    # Force buffer flush
    killall -HUP rsyslogd >/dev/null 2>&1

    sleep 2 # Give syslog time to catch up in case it's busy
    findmsg 1 "$msg"
}

get_logfiles_cs() {
    if [ ! -f "$cf_file" ]; then
        return
    fi

    debug "Reading $cf_type log settings from $cf_file"

    # The default value of to_syslog is yes.
    if ! iscfvarfalse $cf_type to_syslog "$cf_file"; then
        facility_cs=$(getcfvar $cf_type syslog_facility "$cf_file")
        if [ -z "$facility_cs" ]; then
            facility_cs="daemon"
        fi

        find_syslog "$facility_cs.info"
    fi
    if [ "$SOS_MODE" = "1" ]; then
        return
    fi

    if iscfvartrue $cf_type to_logfile "$cf_file"; then
        logfile=$(getcfvar $cf_type logfile "$cf_file")
        if [ -f "$logfile" ]; then
            debug "Log settings found for cluster type $cf_type: $logfile"
            echo "$logfile"
        fi
    fi
}

get_logfiles() {
    cf_type=$1
    cf_file="$2"

    case $cf_type in
        corosync) get_logfiles_cs;;
    esac

    . @CONFIGDIR@/pacemaker

    facility="$PCMK_logfacility"
    if [ -z "$facility" ]; then
        facility="daemon"
    fi
    if [ "$facility" != "$facility_cs" ]&&[ "$facility" != none ]; then
        find_syslog "$facility.notice"
    fi
    if [ "$SOS_MODE" = "1" ]; then
        return
    fi

    logfile="$PCMK_logfile"
    if [ "$logfile" != none ]; then
        if [ -z "$logfile" ]; then
            for logfile in "@CRM_LOG_DIR@/pacemaker.log" "/var/log/pacemaker.log"; do
                if [ -f "$logfile" ]; then
                    debug "Log settings not found for Pacemaker, assuming $logfile"
                    echo "$logfile"
                    break
                fi
            done

        elif [ -f "$logfile" ]; then
            debug "Log settings found for Pacemaker: $logfile"
            echo "$logfile"
        fi
    fi

    # Look for detail logs:

    # - initial pacemakerd logs and tracing might go to a different file
    pattern="Starting Pacemaker"

    # - make sure we get something from the scheduler
    pattern="$pattern\\|Calculated transition"

    # - cib and pacemaker-execd updates
    # (helpful on non-DC nodes and when cluster has been up for a long time)
    pattern="$pattern\\|cib_perform_op\\|process_lrm_event"

    # - pacemaker_remote might use a different file
    pattern="$pattern\\|pacemaker[-_]remoted:"

    findmsg 3 "$pattern"
}

essential_files() {
	cat<<EOF
d $PCMK_SCHEDULER_INPUT_DIR 0750 hacluster haclient
d $CRM_CONFIG_DIR 0750 hacluster haclient
d $CRM_STATE_DIR 0750 hacluster haclient
EOF
}

# Trim leading and ending whitespace (using only POSIX expressions)
trim() {
    TRIM_S="$1"

    TRIM_S="${TRIM_S#"${TRIM_S%%[![:space:]]*}"}"
    TRIM_S="${TRIM_S%"${TRIM_S##*[![:space:]]}"}"
    echo -n "$TRIM_S"
}

collect_logs() {
    CL_START="$1"
    shift
    CL_END="$1"
    shift
    CL_LOGFILES="$@"

    which journalctl > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        cl_have_journald=1
    else
        cl_have_journald=0
    fi

    cl_lognames="$CL_LOGFILES"
    if [ $cl_have_journald -eq 1 ]; then
        cl_lognames="$cl_lognames journalctl"
    fi
    cl_lognames=$(trim "$cl_lognames")
    if [ -z "$cl_lognames" ]; then
        return
    fi

    # YYYY-MM-DD HH:MM:SS
    cl_start_ymd=$(date -d @${CL_START} +"%F %T")
    cl_end_ymd=$(date -d @${CL_END} +"%F %T")

    debug "Gathering logs from $cl_start_ymd to $cl_end_ymd:"
    debug "   $cl_lognames"

    # Remove our temporary file if we get interrupted here
    trap '[ -z "$cl_pattfile" ] || rm -f "$cl_pattfile"' 0

    # Create a temporary file with patterns to grep for
    cl_pattfile=$(mktemp) || fatal "cannot create temporary files"
    for cl_pattern in $LOG_PATTERNS; do
        echo "$cl_pattern"
    done > $cl_pattfile

    echo "Log pattern matches from $REPORT_TARGET:" > $ANALYSIS_F
    if [ -n "$CL_LOGFILES" ]; then
        for cl_logfile in $CL_LOGFILES; do
            cl_extract="$(basename $cl_logfile).extract.txt"

            if [ ! -f "$cl_logfile" ]; then
                # Not a file
                continue

            elif [ -f "$cl_extract" ]; then
                # We already have it
                continue
            fi

            dumplogset "$cl_logfile" $LOG_START $LOG_END > "$cl_extract"
            sanitize "$cl_extract"

            grep -f "$cl_pattfile" "$cl_extract" >> $ANALYSIS_F
        done
    fi

    # Collect systemd logs if present
    if [ $cl_have_journald -eq 1 ]; then
        journalctl --since "$cl_start_ymd" --until "$cl_end_ymd" > journal.log
        grep -f "$cl_pattfile" journal.log >> $ANALYSIS_F
    fi

    rm -f $cl_pattfile
    trap "" 0
}

require_tar

debug "Initializing $REPORT_TARGET subdir"
if [ "$REPORT_MASTER" != "$REPORT_TARGET" ]; then
  if [ -e $REPORT_HOME/$REPORT_TARGET ]; then
    warning "Directory $REPORT_HOME/$REPORT_TARGET already exists, using /tmp/$$/$REPORT_TARGET instead"
    REPORT_HOME=/tmp/$$
  fi
fi

mkdir -p $REPORT_HOME/$REPORT_TARGET
cd $REPORT_HOME/$REPORT_TARGET

case $CLUSTER in
    any) cluster=`get_cluster_type`;;
    *) cluster=$CLUSTER;;
esac

cluster_cf=`find_cluster_cf $cluster`

# If cluster stack is still "any", this might be a Pacemaker Remote node,
# so don't complain in that case.
if [ -z "$cluster_cf" ] && [ $cluster != "any" ]; then
   warning "Could not determine the location of your cluster configuration"
fi

if [ "$SEARCH_LOGS" = "1" ]; then
    logfiles=$(get_logfiles "$cluster" "$cluster_cf" | sort -u)
fi
logfiles="$(trim "$logfiles $EXTRA_LOGS")"

if [ -z "$logfiles" ]; then
    which journalctl > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        info "Systemd journal will be only log collected"
    else
        info "No logs will be collected"
    fi
    info "No log files found or specified with --logfile /some/path"
fi

debug "Config: $cluster ($cluster_cf) $logfiles"

sys_info $cluster $PACKAGES > $SYSINFO_F
essential_files $cluster | check_perms  > $PERMISSIONS_F 2>&1
getconfig $cluster "$REPORT_HOME/$REPORT_TARGET" "$cluster_cf" "$CRM_CONFIG_DIR/$CIB_F" "/etc/drbd.conf" "/etc/drbd.d" "/etc/booth"

getpeinputs    $LOG_START $LOG_END $REPORT_HOME/$REPORT_TARGET
getbacktraces  $LOG_START $LOG_END > $REPORT_HOME/$REPORT_TARGET/$BT_F
getblackboxes  $LOG_START $LOG_END $REPORT_HOME/$REPORT_TARGET

case $cluster in
    corosync)
	if is_running corosync; then
            corosync-blackbox >corosync-blackbox-live.txt 2>&1
#           corosync-fplay > corosync-blackbox.txt
            tool=`pickfirst corosync-objctl corosync-cmapctl`
            case $tool in
                *objctl)  $tool -a > corosync.dump  2>/dev/null;;
                *cmapctl) $tool    > corosync.dump  2>/dev/null;;
            esac
            corosync-quorumtool -s -i > corosync.quorum 2>&1
	fi
	;;
esac

dc=`crm_mon -1 2>/dev/null | awk '/Current DC/ {print $3}'`
if [ "$REPORT_TARGET" = "$dc" ]; then
    echo "$REPORT_TARGET" > DC
fi

dlm_dump  > $DLM_DUMP_F 2>&1
sys_stats > $SYSSTATS_F 2>&1
drbd_info > $DRBD_INFO_F 2>&1

debug "Sanitizing files: $SANITIZE"
#
# replace sensitive info with '****'
#
cf=""
if [ ! -z "$cluster_cf" ]; then
   cf=`basename $cluster_cf`
fi
for f in "$cf" "$CIB_F" "$CIB_F.live" pengine/ *; do
    if [ -f "$f" ]; then
	sanitize "$f"
    fi
done

# For convenience, generate human-readable version of CIB and any XML errors
# in it (AFTER sanitizing, so we don't need to sanitize this output).
# sosreport does this itself, so we do not need to when run by sosreport.
if [ "$SOS_MODE" != "1" ]; then
    get_readable_cib "$REPORT_HOME/$REPORT_TARGET"
fi

collect_logs "$LOG_START" "$LOG_END" $logfiles

# Purge files containing no information
for f in `ls -1`; do
    if [ -d "$f" ]; then
	continue
    elif [ ! -s "$f" ]; then
        case $f in
	    *core*) log "Detected empty core file: $f";;
	    *)	    debug "Removing empty file: `ls -al $f`"
		    rm -f $f
		    ;;
	esac
    fi
done

# Parse for events
for l in $logfiles; do
    b="$(basename $l).extract.txt"
    node_events "$b" > $EVENTS_F

    # Link the first logfile to a standard name if it doesn't yet exist
    if [ -e "$b" -a ! -e "$HALOG_F" ]; then
	ln -s "$b" "$HALOG_F"
    fi
done

if [ -e $REPORT_HOME/.env ]; then
    debug "Localhost: $REPORT_MASTER $REPORT_TARGET"

elif [ "$REPORT_MASTER" != "$REPORT_TARGET" ]; then
    debug "Streaming report back to $REPORT_MASTER"
    (cd $REPORT_HOME && tar cf - $REPORT_TARGET)
    if [ "$REMOVE" = "1" ]; then
	cd
	rm -rf $REPORT_HOME
    fi
fi

## crm_report.in

TEMP=`@GETOPT_PATH@			\
    -o hv?xl:f:t:n:T:L:p:c:dSCu:D:MVse:	\
    --long help,corosync,cts:,cts-log:,dest:,node:,nodes:,from:,to:,sos-mode,logfile:,as-directory,single-node,cluster:,user:,max-depth:,version,features,rsh:	\
    -n 'crm_report' -- "$@"`
# The quotes around $TEMP are essential
eval set -- "$TEMP"

progname=$(basename "$0")
rsh="ssh -T"
tests=""
nodes=""
compress=1
cluster="any"
ssh_user="root"
search_logs=1
sos_mode=0
report_data=`dirname $0`
maxdepth=5

extra_logs=""
sanitize_patterns="passw.*"
log_patterns="CRIT: ERROR:"

usage() {
cat<<EOF
$progname - Create archive of everything needed when reporting cluster problems


Usage: $progname [options] [DEST]

Required option:
  -f, --from TIME       time prior to problems beginning
                        (as "YYYY-M-D H:M:S" including the quotes)

Options:
  -V                    increase verbosity (may be specified multiple times)
  -h, --help            display this message
  -v, --version         display software version
  --features            display software features
  -t, --to TIME         time at which all problems were resolved
                        (as "YYYY-M-D H:M:S" including the quotes; default "now")
  -T, --cts TEST        CTS test or set of tests to extract
  --cts-log             CTS master logfile
  -n, --nodes NODES     node names for this cluster (only needed if cluster is
                        not active on this host; accepts -n "a b" or -n a -n b)
  -M                    do not search for cluster logs
  -l, --logfile FILE    log file to collect (in addition to detected logs if -M
                        is not specified; may be specified multiple times)
  -p PATT               additional regular expression to match variables to be
                        masked in output (default: "passw.*")
  -L PATT               additional regular expression to match in log files for
                        analysis (default: $log_patterns)
  -S, --single-node     don't attempt to collect data from other nodes
  -c, --cluster TYPE    force the cluster type instead of detecting
                        (currently only corosync is supported)
  -C, --corosync        force the cluster type to be corosync
  -u, --user USER       username to use when collecting data from other nodes
                        (default root)
  -D, --max-depth       search depth to use when attempting to locate files
  -e, --rsh             command to use to run commands on other nodes
                        (default ssh -T)
  -d, --as-directory    leave result as a directory tree instead of archiving
  --sos-mode            use defaults suitable for being called by sosreport tool
                        (behavior subject to change and not useful to end users)
  DEST, --dest DEST     custom destination directory or file name

$progname works best when run from a cluster node on a running cluster,
but can be run from a stopped cluster node or a Pacemaker Remote node.

If neither --nodes nor --single-node is given, $progname will guess the
node list, but may have trouble detecting Pacemaker Remote nodes.
Unless --single-node is given, the node names (whether specified by --nodes
or detected automatically) must be resolvable and reachable via the command
specified by -e/--rsh using the user specified by -u/--user.

Examples:
   $progname -f "2011-12-14 13:05:00" unexplained-apache-failure
   $progname -f 2011-12-14 -t 2011-12-15 something-that-took-multiple-days
   $progname -f 13:05:00   -t 13:12:00   brief-outage
EOF
}

case "$1" in
    -v|--version)   echo "$progname @VERSION@-@BUILD_VERSION@"; exit 0;;
    --features)     echo "@VERSION@-@BUILD_VERSION@: @PCMK_FEATURES@"; exit 0;;
    --|-h|--help) usage; exit 0;;
esac

# Prefer helpers in the same directory if they exist, to simplify development
if [ ! -f $report_data/report.common ]; then
    report_data=@datadir@/@PACKAGE@
else
    echo "Using local helpers"
fi

. $report_data/report.common

while true; do
    case "$1" in
	-x) set -x; shift;;
	-V) verbose=`expr $verbose + 1`; shift;;
	-T|--cts) tests="$tests $2"; shift; shift;;
	   --cts-log) ctslog="$2"; shift; shift;;
	-f|--from) start_time=`get_time "$2"`; shift; shift;;
	-t|--to) end_time=`get_time "$2"`; shift; shift;;
	-n|--node|--nodes) nodes="$nodes $2"; shift; shift;;
	-S|--single-node) nodes="$host"; shift;;
	-l|--logfile) extra_logs="$extra_logs $2"; shift; shift;;
	-p) sanitize_patterns="$sanitize_patterns $2"; shift; shift;;
	-L) log_patterns="$log_patterns `echo $2 | sed 's/ /\\\W/g'`"; shift; shift;;
	-d|--as-directory) compress=0; shift;;
	-C|--corosync)  cluster="corosync";  shift;;
	-c|--cluster)   cluster="$2"; shift; shift;;
	-e|--rsh)       rsh="$2";     shift; shift;;
	-u|--user)      ssh_user="$2"; shift; shift;;
        -D|--max-depth)     maxdepth="$2"; shift; shift;;
	-M) search_logs=0; shift;;
        --sos-mode) sos_mode=1; nodes="$host"; shift;;
	--dest) DESTDIR=$2; shift; shift;;
	--) if [ ! -z $2 ]; then DESTDIR=$2; fi; break;;
	-h|--help) usage; exit 0;;
	# Options for compatibility with hb_report
	-s) shift;;

	*) echo "Unknown argument: $1"; usage; exit 1;;
    esac
done


collect_data() {
    label="$1"
    start=`expr $2 - 10`
    end=`expr $3 + 10`
    masterlog=$4

    if [ "x$DESTDIR" != x ]; then
	echo $DESTDIR | grep -e "^/" -qs
	if [ $? = 0 ]; then
	    l_base=$DESTDIR
	else
	    l_base="`pwd`/$DESTDIR"
	fi
	debug "Using custom scratch dir: $l_base"
	r_base=`basename $l_base`
    else
	l_base=$HOME/$label
	r_base=$label
    fi

    if [ -e $l_base ]; then
	fatal "Output directory $l_base already exists, specify an alternate name with --dest"
    fi
    mkdir -p $l_base

    if [ "x$masterlog" != "x" ]; then
	dumplogset "$masterlog" $start $end > "$l_base/$HALOG_F"
    fi

    for node in $nodes; do
	cat <<EOF >$l_base/.env
LABEL="$label"
REPORT_HOME="$r_base"
REPORT_MASTER="$host"
REPORT_TARGET="$node"
LOG_START=$start
LOG_END=$end
REMOVE=1
SANITIZE="$sanitize_patterns"
CLUSTER=$cluster
LOG_PATTERNS="$log_patterns"
EXTRA_LOGS="$extra_logs"
SEARCH_LOGS=$search_logs
SOS_MODE=$sos_mode
verbose=$verbose
maxdepth=$maxdepth
EOF

	if [ $host = $node ]; then
	    cat <<EOF >>$l_base/.env
REPORT_HOME="$l_base"
EOF
	    cat $l_base/.env $report_data/report.common $report_data/report.collector > $l_base/collector
	    bash $l_base/collector
	else
	    cat $l_base/.env $report_data/report.common $report_data/report.collector \
		| $rsh -l $ssh_user $node -- "mkdir -p $r_base; cat > $r_base/collector; bash $r_base/collector" | (cd $l_base && tar mxf -)
	fi
    done

    analyze $l_base > $l_base/$ANALYSIS_F
    if [ -f $l_base/$HALOG_F ]; then
	node_events $l_base/$HALOG_F > $l_base/$EVENTS_F
    fi

    for node in $nodes; do
	cat $l_base/$node/$ANALYSIS_F >> $l_base/$ANALYSIS_F
	if [ -s $l_base/$node/$EVENTS_F ]; then
	    cat $l_base/$node/$EVENTS_F >> $l_base/$EVENTS_F
	elif [ -s $l_base/$HALOG_F ]; then
	    awk "\$4==\"$nodes\"" $l_base/$EVENTS_F >> $l_base/$n/$EVENTS_F
	fi
    done

    log " "
    if [ $compress = 1 ]; then
	fname=`shrink $l_base`
	rm -rf $l_base
	log "Collected results are available in $fname"
	log " "
	log "Please create a bug entry at"
	log "    @BUG_URL@"
	log "Include a description of your problem and attach this tarball"
	log " "
	log "Thank you for taking time to create this report."
    else
	log "Collected results are available in $l_base"
    fi
    log " "
}

#
# check if files have same content in the cluster
#
cibdiff() {
    d1=$(dirname $1)
    d2=$(dirname $2)

    if [ -f "$d1/RUNNING" ] && [ ! -f "$d2/RUNNING" ]; then
        DIFF_OK=0
    elif [ -f "$d1/STOPPED" ] && [ ! -f "$d2/STOPPED" ]; then
        DIFF_OK=0
    else
        DIFF_OK=1
    fi

    if [ $DIFF_OK -eq 1 ]; then
	if which crm_diff > /dev/null 2>&1; then
	    crm_diff -c -n $1 -o $2
	else
	    info "crm_diff(8) not found, cannot diff CIBs"
	fi
    else
	echo "can't compare cibs from running and stopped systems"
    fi
}

diffcheck() {
    [ -f "$1" ] || {
	echo "$1 does not exist"
	return 1
    }
    [ -f "$2" ] || {
	echo "$2 does not exist"
	return 1
    }
    case $(basename "$1") in
        $CIB_F)  cibdiff $1 $2 ;;
        *)       diff -u $1 $2 ;;
    esac
}

#
# remove duplicates if files are same, make links instead
#
consolidate() {
    for n in $nodes; do
	if [ -f $1/$2 ]; then
	    rm $1/$n/$2
	else
	    mv $1/$n/$2 $1
	fi
	ln -s ../$2 $1/$n
    done
}

analyze_one() {
    rc=0
    node0=""
    for n in $nodes; do
	if [ "$node0" ]; then
	    diffcheck $1/$node0/$2 $1/$n/$2
	    rc=$(($rc+$?))
	else
	    node0=$n
	fi
    done
    return $rc
}

analyze() {
    flist="$MEMBERSHIP_F $CIB_F $CRM_MON_F $SYSINFO_F"
    for f in $flist; do
	printf "Diff $f... "
	ls $1/ * /$f >/dev/null 2>&1 || {
	    echo "no $1/ * /$f :/"
	    continue
	}
	if analyze_one $1 $f; then
	    echo "OK"
	    [ "$f" != $CIB_F ] && consolidate $1 $f
	else
	    echo ""
	fi
    done
}

do_cts() {
    test_sets=`echo $tests | tr ',' ' '`
    for test_set in $test_sets; do

	start_time=0
	start_test=`echo $test_set | tr '-' ' ' | awk '{print $1}'`

	end_time=0
	end_test=`echo $test_set | tr '-' ' ' | awk '{print $2}'`

	if [ x$end_test = x ]; then
	    msg="Extracting test $start_test"
	    label="CTS-$start_test-`date +"%b-%d-%Y"`"
	    end_test=`expr $start_test + 1`
	else
	    msg="Extracting tests $start_test to $end_test"
	    label="CTS-$start_test-$end_test-`date +"%b-%d-%Y"`"
	    end_test=`expr $end_test + 1`
	fi

	if [ $start_test = 0 ]; then
	    start_pat="BEGINNING [0-9].* TESTS"
	else
	    start_pat="Running test.*\[ *$start_test\]"
	fi

	if [ x$ctslog = x ]; then
	    ctslog=`findmsg 1 "$start_pat"`

	    if [ x$ctslog = x ]; then
		fatal "No CTS control file detected"
	    else
		log "Using CTS control file: $ctslog"
	    fi
	fi

	line=`grep -n "$start_pat" $ctslog | tail -1 | sed 's@:.*@@'`
	if [ ! -z "$line" ]; then
	    start_time=`linetime $ctslog $line`
	fi

	line=`grep -n "Running test.*\[ *$end_test\]" $ctslog | tail -1 | sed 's@:.*@@'`
	if [ ! -z "$line" ]; then
	    end_time=`linetime $ctslog $line`
	fi

	if [ -z "$nodes" ]; then
	    nodes=`grep CTS: $ctslog | grep -v debug: | grep " \* " | sed s:.*\\\*::g | sort -u  | tr '\\n' ' '`
	    log "Calculated node list: $nodes"
	fi

	if [ $end_time -lt $start_time ]; then
	    debug "Test didn't complete, grabbing everything up to now"
	    end_time=`date +%s`
	fi

	if [ $start_time != 0 ];then
	    log "$msg (`time2str $start_time` to `time2str $end_time`)"
	    collect_data $label $start_time $end_time $ctslog
	else
	    fatal "$msg failed: not found"
	fi
    done
}

node_names_from_xml() {
    awk '
      /uname/ {
            for( i=1; i<=NF; i++ )
                    if( $i~/^uname=/ ) {
                            sub("uname=.","",$i);
                            sub("\".*","",$i);
                            print $i;
                            next;
                    }
      }
    ' | tr '\n' ' '
}

getnodes() {
    cluster="$1"

    # 1. Live (cluster nodes or Pacemaker Remote nodes)
    # TODO: This will not detect Pacemaker Remote nodes unless they
    # have ever had a permanent node attribute set, because it only
    # searches the nodes section. It should also search the config
    # for resources that create Pacemaker Remote nodes.
    cib_nodes=$(cibadmin -Ql -o nodes 2>/dev/null)
    if [ $? -eq 0 ]; then
	debug "Querying CIB for nodes"
        echo "$cib_nodes" | node_names_from_xml
        return
    fi

    # 2. Saved
    if [ -f "@CRM_CONFIG_DIR@/cib.xml" ]; then
	debug "Querying on-disk CIB for nodes"
        grep "node " "@CRM_CONFIG_DIR@/cib.xml" | node_names_from_xml
        return
    fi

    # 3. logs
    # TODO: Look for something like crm_update_peer
}

if [ $compress -eq 1 ]; then
    require_tar
fi

if [ "x$tests" != "x" ]; then
    do_cts

elif [ "x$start_time" != "x" ]; then
    masterlog=""

    if [ -z "$sanitize_patterns" ]; then
	log "WARNING: The tarball produced by this program may contain"
	log "         sensitive information such as passwords."
	log ""
	log "We will attempt to remove such information if you use the"
	log "-p option. For example: -p \"pass.*\" -p \"user.*\""
	log ""
	log "However, doing this may reduce the ability for the recipients"
	log "to diagnose issues and generally provide assistance."
	log ""
	log "IT IS YOUR RESPONSIBILITY TO PROTECT SENSITIVE DATA FROM EXPOSURE"
	log ""
    fi

    # If user didn't specify a cluster stack, make a best guess if possible.
    if [ -z "$cluster" ] || [ "$cluster" = "any" ]; then
        cluster=$(get_cluster_type)
    fi

    # If user didn't specify node(s), make a best guess if possible.
    if [ -z "$nodes" ]; then
	nodes=`getnodes $cluster`
        if [ -n "$nodes" ]; then
            log "Calculated node list: $nodes"
        else
            fatal "Cannot determine nodes; specify --nodes or --single-node"
        fi
    fi

    if
	echo $nodes | grep -qs $host
    then
	debug "We are a cluster node"
    else
	debug "We are a log master"
	masterlog=`findmsg 1 "pacemaker-controld\\|CTS"`
    fi


    if [ -z $end_time ]; then
	end_time=`perl -e 'print time()'`
    fi
    label="pcmk-`date +"%a-%d-%b-%Y"`"
    log "Collecting data from $nodes (`time2str $start_time` to `time2str $end_time`)"
    collect_data $label $start_time $end_time $masterlog
else
    fatal "Not sure what to do, no tests or time ranges to extract"
fi
*/
