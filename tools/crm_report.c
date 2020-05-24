/*
 * Copyright 2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <glib.h>
#include <sys/stat.h>

#include <crm/crm.h>
#include <crm/common/cmdline_internal.h>
#include <crm/common/output.h>
#include <crm/common/iso8601.h>

static char *host = NULL;
static char *shorthost = NULL;
static char *report_home = NULL;
static FILE *report_file = NULL;

static crm_exit_t finish(crm_exit_t exit_code);
static void time2str(char *s, size_t n, const char *fmt, time_t t);

/*
 * Command-line option parsing
 */

#define SUMMARY "crm_report - Collect an archive of information needed to report cluster problems"

#define HELP_FOOTER \
    "crm_report works best when run from a cluster node on a running cluster,\n"    \
    "but can be run from a stopped cluster node or a Pacemaker Remote node.\n\n"    \
    "If neither --nodes nor --single-node is given, crm_report will guess the\n"    \
    "node list, but may have trouble detecting Pacemaker Remote nodes.\n"           \
    "Unless --single-node is given, the node names (whether specified by --nodes\n" \
    "or detected automatically) must be resolvable and reachable via the command\n" \
    "specified by -e/--rsh using the user specified by -u/--user.\n\n"              \
    "Examples:\n"                                                                   \
    "   crm_report -f \"2011-12-14 13:05:00\"    unexplained-apache-failure\n"      \
    "   crm_report -f 2011-12-14 -t 2011-12-15 something-that-took-multiple-days\n" \
    "   crm_report -f 13:05:00   -t 13:12:00   brief-outage"

#define DEFAULT_SANITIZE_PATTERNS   "passw.*"
#define DEFAULT_LOG_PATTERNS        "CRIT: ERROR:"
#define DEFAULT_REMOTE_USER         "root"
#define DEFAULT_REMOTE_SHELL        "ssh -T"
#define DEFAULT_MAX_DEPTH           5
#define DEFAULT_MAX_DEPTH_S         "5"

// for multiple lines of help text
#define HNL "\n                             "

/* This is comparable to libcrmcluster's cluster_type_e, but we don't want to
 * link crm_report against libcrmcluster, and the library's not a good fit for
 * what we need anyway.
 */
enum cluster_e {
    cluster_any = 0,
    cluster_corosync,
};

static const char *cluster2str(enum cluster_e cluster_type);

static struct {
    pcmk__common_args_t *args;
    GOptionContext *context;
    gchar **processed_args;
    pcmk__output_t *out;

    gboolean show_help;
    gboolean show_features;
    gboolean no_search;
    gboolean single_node;
    gboolean as_dir;
    gboolean sos;
    gboolean deprecated;
    gint depth;
    time_t from_time;
    time_t to_time;
    gchar *dest;
    gchar *user;
    gchar *shell;
    gchar *cts_log;
    gchar **logfile;
    gchar **analysis;
    gchar **sanitize;
    GList *nodes;
    GList *cts;
    enum cluster_e cluster_type;
} options = { NULL, };

// true if str is in strings
static bool
str_in(const char *str, const char *strings[])
{
    if (str != NULL) {
        for (int i = 0; strings[i] != NULL; ++i) {
            if (!strcmp(str, strings[i])) {
                return true;
            }
        }
    }
    return false;
}

#define NODE_OPTIONS    (const char *[]) { "--node", "--nodes", "-n", NULL }
#define CTS_OPTIONS     (const char *[]) { "--cts", "-T", NULL }

// Add optarg to list, with whitespace splitting into individual items
static gboolean
string_list_split_cb(const gchar *option_name, const gchar *optarg,
                     gpointer data, GError **error)
{
    GList **list = NULL;

    if (str_in(option_name, NODE_OPTIONS)) {
        list = &(options.nodes);
    } else if (str_in(option_name, CTS_OPTIONS)) {
        list = &(options.cts);
    }

    if (list == NULL) {
        return FALSE;
    }

    while (*optarg) {
        size_t n = strcspn(optarg, " \t");

        *list = g_list_prepend(*list, strndup(optarg, n));
        optarg += n;
        n = strspn(optarg, " \t");
        optarg += n;
    }
    return TRUE;
}

static gboolean
cluster_type_cb(const gchar *option_name, const gchar *optarg,
                gpointer data, GError **error)
{
    const gchar *name = option_name;

    // Get just the option name (without - or --)
    while (name && (*name == '-')) {
        ++name;
    }

    // If -c/--cluster, type is the option argument
    if (!strcmp(name, "c") || !strcmp(name, "cluster")) {
        name = optarg;
    }

    if (!strcmp(name, "C") || !strcmp(name, "corosync")) {
        options.cluster_type = cluster_corosync;
    } else {
        options.cluster_type = cluster_any;
    }
    return (options.cluster_type != cluster_any);
}

// Store user-supplied ISO 8601 date/time argument as time_t
static gboolean
datetime_cb(const gchar *option_name, const gchar *optarg, gpointer data,
            GError **error)
{
    time_t *result;
    crm_time_t *t;

    if (!strcmp(option_name, "-f") || !strcmp(option_name, "--from")) {
        result = &(options.from_time);
    } else if (!strcmp(option_name, "-t") || !strcmp(option_name, "--to")) {
        result = &(options.to_time);
    } else {
        return FALSE;
    }

    t = crm_time_new(optarg);
    if (t == NULL) {
        return FALSE;
    }

    *result = (time_t) crm_time_get_seconds_since_epoch(t);
    return TRUE;
}

static GOptionContext *
build_arg_context(pcmk__common_args_t *args, GOptionGroup **group)
{
    GOptionContext *context = NULL;
    GOptionEntry main_args[] = {
        {
            "features", 0, 0, G_OPTION_ARG_NONE, &(options.show_features),
            "Show software features and exit",
            NULL
        },

        /* For backward compatibility with the original shell script version of
         * crm_report, accept -v as an alias for --version and -h for --help.
         */
        {
            "version", 'v', G_OPTION_FLAG_HIDDEN, G_OPTION_ARG_NONE, &(args->version),
            NULL, NULL
        },
        {
            "help", 'h', G_OPTION_FLAG_HIDDEN, G_OPTION_ARG_NONE, &(options.show_help),
            NULL, NULL
        },
        { NULL }
    };
    GOptionEntry reporting_args[] = {
        {
            "from", 'f', 0, G_OPTION_ARG_CALLBACK, datetime_cb,
            "Extract logs starting at this time" HNL
                "(as \"YYYY-M-D H:M:S\" including the quotes) (required)",
            "TIME"
        },
        {
            "to", 't', 0, G_OPTION_ARG_CALLBACK, datetime_cb,
            "Extract logs until this time" HNL
                "(as \"YYYY-M-D H:M:S\" including the quotes; default now)",
            "TIME"
        },
        {
            "nodes", 'n',  0, G_OPTION_ARG_CALLBACK, string_list_split_cb,
            "Names of nodes to collect from (default is to" HNL
                "detect all nodes, if cluster is active locally;" HNL
                "accepts -n \"a b\" or -n a -n b)",
            "NODES"
        },
        {
            // --node is accepted as an alias for --nodes
            "node", 0, G_OPTION_FLAG_HIDDEN, G_OPTION_ARG_CALLBACK,
            string_list_split_cb, NULL, NULL
        },
        {
            "single-node", 'S', 0, G_OPTION_ARG_NONE, &(options.single_node),
            "Collect data from local node only (this option should be used "
                "on a cluster node, not a central log host, and should not "
                "be used with --nodes)",
            NULL,
        },
        {
            "no-search", 'M', 0, G_OPTION_ARG_NONE, &(options.no_search),
            "Do not search for cluster logs",
            NULL,
        },
        {
            "logfile", 'l', 0, G_OPTION_ARG_FILENAME_ARRAY, &(options.logfile),
            "Log file to collect (in addition to any logs found by" HNL
                "searching; may be specified multiple times)",
            "FILE"
        },
        {
            "sanitize", 'p', 0, G_OPTION_ARG_STRING_ARRAY, &(options.sanitize),
            "Regular expression to match variables to be masked in" HNL
                "output (in addition to \"" DEFAULT_SANITIZE_PATTERNS "\";" HNL
                "may be specified multiple times)",
            "PATTERN"
        },
        {
            "analysis", 'L', 0, G_OPTION_ARG_STRING_ARRAY, &(options.analysis),
            "Regular expression to match in log files for analysis" HNL
                "(in addition to \"" DEFAULT_LOG_PATTERNS "\"; may be specified" HNL
                "multiple times)",
            "PATTERN"
        },
        {
            "as-directory", 'd', 0, G_OPTION_ARG_NONE, &(options.as_dir),
            "Leave collected information as un-archived directory",
            NULL,
        },
        {
            "dest", 0, 0, G_OPTION_ARG_FILENAME, &(options.dest),
            "Destination directory or file name" HNL
                "(default \"pcmk-<DATE>\")",
            "NAME"
        },
        {
            "user", 'u', 0, G_OPTION_ARG_STRING, &(options.user),
            "User account to use to collect data from other nodes" HNL
                "(default \"" DEFAULT_REMOTE_USER "\")",
            "USER"
        },
        {
            "max-depth", 'D', 0, G_OPTION_ARG_INT, &(options.depth),
            "Search depth to use when attempting to locate files" HNL
                "(default " DEFAULT_MAX_DEPTH_S ")",
            "USER"
        },
        {
            "rsh", 'e', 0, G_OPTION_ARG_STRING, &(options.shell),
            "Command to use to run commands on other nodes" HNL
                "(default \"" DEFAULT_REMOTE_SHELL "\")",
            "COMMAND"
        },
        {
            "cluster", 'c', 0, G_OPTION_ARG_CALLBACK, cluster_type_cb,
            "Force the cluster type instead of detecting" HNL
                "(currently only \"corosync\" is supported)",
            "TYPE"
        },
        {
            "corosync", 'C', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK,
            cluster_type_cb,
            "Force the cluster type to be corosync",
            "TYPE"
        },
        {
            "sos-mode", 0, 0, G_OPTION_ARG_NONE, &(options.sos),
            "Use defaults suitable for being called by sosreport tool" HNL
                "(behavior subject to change and not useful to end users)",
            NULL,
        },
        { NULL }
    };
    GOptionEntry cts_args[] = {
        {
            "cts", 'T', 0, G_OPTION_ARG_CALLBACK, string_list_split_cb,
            "CTS test or tests to extract" HNL
                "(may be specified multiple times)",
            "TEST"
        },
        {
            "cts-log", 0, 0, G_OPTION_ARG_FILENAME, &(options.cts_log),
            "CTS master logfile",
            "FILE"
        },
        { NULL }
    };
    GOptionEntry deprecated_args[] = {
        {
            "deprecated-s", 's', 0, G_OPTION_ARG_NONE, &(options.deprecated),
            "Ignored (accepted for backward compatibility)",
            NULL,
        },
        {
            "deprecated-x", 'x', 0, G_OPTION_ARG_NONE, &(options.deprecated),
            "Ignored (accepted for backward compatibility)",
            NULL,
        },
        { NULL }
    };

    context = pcmk__build_arg_context(args, "text (default), xml",  group, NULL);
    pcmk__add_main_args(context, main_args);
    pcmk__add_arg_group(context, "reporting", "Reporting options:",
                        "Show reporting help", reporting_args);
    pcmk__add_arg_group(context, "cts",
                        "CTS options (rarely useful to end users):",
                        "Show CTS help", cts_args);
    pcmk__add_arg_group(context, "deprecated",
                        "Deprecated options (to be removed in future release):",
                        "Show deprecated option help", deprecated_args);
    g_option_context_set_description(context, HELP_FOOTER);
    return context;
}

// Return the number of strings in a glib string vector
static size_t
strvlen(gchar **strv)
{
    int len = 0;

    if (strv == NULL) {
        return 0;
    }
    while (strv[len++] != NULL);
    return len - 1;
}

// Return string vector of strv1 + strv2 (which will be freed)
static gchar **
merge_strv(gchar **strv1, gchar **strv2)
{
    int strv1_len = strvlen(strv1);
    int strv2_len = strvlen(strv2);
    int combined_len = strv1_len + strv2_len + 1; // + 1 for NULL entry
    int i = 0;
    gchar **strv_new = NULL;

    if (combined_len == 1) {
        return NULL;
    }
    strv_new = g_malloc0_n(combined_len, sizeof(gchar*));

    for (i = 0; i < strv1_len; ++i) {
        strv_new[i] = strv1[i];
    }
    for (; i < (combined_len - 1); ++i) {
        strv_new[i] = strv2[i - strv1_len];
    }
    strv_new[i] = NULL;
    g_free(strv1);
    g_free(strv2);
    return strv_new;
}

static void
parse_args(int argc, char **argv)
{
    GError *error = NULL;
    GOptionGroup *output_group = NULL;

    pcmk__supported_format_t formats[] = {
        PCMK__SUPPORTED_FORMAT_TEXT,
        PCMK__SUPPORTED_FORMAT_XML,
        { NULL, NULL, NULL }
    };

    options.depth = DEFAULT_MAX_DEPTH;

    options.args = pcmk__new_common_args(SUMMARY);
    options.context = build_arg_context(options.args, &output_group);
    pcmk__register_formats(output_group, formats);
    options.processed_args = pcmk__cmdline_preproc(argv, "ceflnptuDLT");
    if (!g_option_context_parse_strv(options.context,
                                     &(options.processed_args), &error)) {
        fprintf(stderr, "%s: %s\n\n", g_get_prgname(), error->message);
        fprintf(stderr, "%s",
                g_option_context_get_help(options.context, TRUE, NULL));
        crm_exit(CRM_EX_USAGE);
    }

    if (options.processed_args[1] != NULL) { // [0] is command name
        if (options.dest != NULL) {
            g_free(options.dest);
        }
        options.dest = g_strdup(options.processed_args[1]);
        // @TODO warn if additional arguments specified?
    }

    if (options.user == NULL) {
        options.user = g_strdup(DEFAULT_REMOTE_USER);
    }
    if (options.shell == NULL) {
        options.shell = g_strdup(DEFAULT_REMOTE_SHELL);
    }
    options.sanitize = merge_strv(g_strsplit(DEFAULT_SANITIZE_PATTERNS, " ", -1),
                                  options.sanitize);
    options.analysis = merge_strv(g_strsplit(DEFAULT_LOG_PATTERNS, " ", -1),
                                  options.analysis);

    // Sanity check
    if ((options.to_time != 0) && (options.to_time < options.from_time)) {
        fprintf(stderr,
                "Usage error: 'to' time cannot be earlier than 'from' time\n");
        crm_exit(CRM_EX_USAGE);
    }
}

static void
handle_common_args(int argc, char **argv)
{
    int rc = pcmk_rc_ok;

    if (options.show_help) {
        printf("%s", g_option_context_get_help(options.context, TRUE, NULL));
    }

    for (int i = 0; i < options.args->verbosity; ++i) {
        crm_bump_log_level(argc, argv);
    }

    rc = pcmk__output_new(&(options.out), options.args->output_ty,
                          options.args->output_dest, argv);
    if (rc != pcmk_rc_ok) {
        fprintf(stderr, "Error creating output format %s: %s\n",
                options.args->output_ty, pcmk_rc_str(rc));
        crm_exit(pcmk_rc2exitc(rc));
    }

    if (options.args->version) {
        options.out->version(options.out, false);
        crm_exit(CRM_EX_OK);
    }

    if (options.show_features) {
        options.out->version(options.out, true);
        crm_exit(CRM_EX_OK);
    }
}


/*
 * User messaging
 *
 * crm_report handles user output differently than other Pacemaker command-line
 * tools; messages are both displayed to the user and written to a report file.
 */

static void
set_report(bool summary)
{
    char *report_name = NULL;

    /* The report initiator keeps a main report summary directly under the
     * report home, and collection reports for each host (including the
     * initiator itself, if it is a node) in subdirectories by hostname.
     */
    if (summary) {
        report_name = crm_strdup_printf("%s/report.summary", report_home);
    } else {
        report_name = crm_strdup_printf("%s/%s/report.out", report_home, host);
    }

    if (report_file != NULL) {
        fclose(report_file);
    }
    report_file = fopen(report_name, "w");
    free(report_name);
}

/*!
 * \internal
 * \brief Log a message to the report summary and/or the user
 *
 * If the report summary has been opened, the given message will always be
 * logged there. If requested, and the output object has been opened, the
 * message will also be shown to the user, as error output if log_level is
 * LOG_ERR, or as normal output otherwise.
 *
 * \param[in] log_level  Severity of message
 * \param[in] file_only  If true, do not show message to user
 * \param[in] format     printf(3)-style format
 * \param[in] ...        format arguments
 */
static void
record_message(int log_level, bool file_only, const char *format, ...)
{
    va_list ap;
    int len = 0;
    char *str = NULL;
    char *message = NULL;
    const char *prefix = NULL;
    bool as_err = false;
    static char *tag = NULL;

    if ((options.out == NULL) && (report_file == NULL)) {
        return;
    }

    switch (log_level) {
        case LOG_DEBUG:
            prefix = "Debug: ";
            break;
        case LOG_WARNING:
            prefix = "WARN: ";
            break;
        case LOG_ERR:
            prefix = "ERROR: ";
            as_err = true;
            break;
        default:
            prefix = "";
            break;
    }

    // Get the desired message as a string
    va_start(ap, format);
    len = vasprintf(&str, format, ap);
    if (len <= 0) {
        va_end(ap);
        return;
    }

    // Tag the message with host name and prefix
    if ((tag == NULL) && (shorthost != NULL)) {
        tag = crm_strdup_printf("%s:", shorthost);
    }
    message = crm_strdup_printf("%-10s  %s%s",
                                (tag? tag : "localhost:"), prefix, str);
    free(str);

    // If desired, show message to user
    if (!file_only && options.out) {
        if (as_err) {
            options.out->err(options.out, "%s", message);
        } else {
            options.out->info(options.out, "%s", message);
        }
    }

    // If we have an open report, write message to it
    if (report_file != NULL) {
        fprintf(report_file, "%s\n", message);
    }
    free(message);
    va_end(ap);
}

#define info(fmt, fmtargs...) record_message(LOG_INFO, false, fmt, ##fmtargs)

#define debug(fmt, fmtargs...) record_message(LOG_DEBUG,                        \
                                              (options.args->verbosity == 0),   \
                                              fmt, ##fmtargs)

#define warning(fmt, fmtargs...) record_message(LOG_WARNING, false, fmt, ##fmtargs)

#define fatal(fmt, args...) do {                        \
        record_message(LOG_ERR, false, fmt, ##args);    \
        exit(finish(CRM_EX_ERROR));                     \
    } while (0)

static void
log_options(void)
{
    int i;
    char from_str[1024] = { '\0', };
    char to_str[1024] = { '\0', };

    record_message(LOG_INFO, true, "Options in effect:");
    record_message(LOG_INFO, true, "* %s for cluster logs",
                   (options.no_search? "Do not search" : "Search"));

    time2str(from_str, sizeof(from_str), "%x %X", options.from_time);
    time2str(to_str, sizeof(to_str), "%x %X", options.to_time);
    record_message(LOG_INFO, true, "* Times: @%lld (%s) to @%lld (%s)",
                   (long long) options.from_time, from_str,
                   (long long) options.to_time, to_str);

    record_message(LOG_INFO, true, "* Remote execution: %s -u %s",
                   options.shell, options.user);
    record_message(LOG_INFO, true, "* Cluster type: %s",
                   cluster2str(options.cluster_type));
    record_message(LOG_INFO, true, "* Max. search depth: %d", options.depth);
    for (i = 0; options.logfile && options.logfile[i]; ++i) {
        record_message(LOG_INFO, true, "* Additional log: %s",
                       options.logfile[i]);
    }
    for (i = 0; options.sanitize && options.sanitize[i]; ++i) {
        record_message(LOG_INFO, true, "* Sanitize pattern: %s",
                       options.sanitize[i]);
    }
    for (i = 0; options.analysis && options.analysis[i]; ++i) {
        record_message(LOG_INFO, true, "* Log pattern: %s", options.analysis[i]);
    }
    for (GList *nodei = options.nodes; nodei != NULL; nodei = nodei->next) {
        record_message(LOG_INFO, true, "* Node: %s", (const char *) nodei->data);
    }
}


/*
 * Basic utility functions
 */

static const char *
cluster2str(enum cluster_e cluster_type)
{
    switch (cluster_type) {
        case cluster_corosync:
            return "corosync";
        default:
            return "any";
    }
}

// \return Standard Pacemaker return code
static int
detect_hostname(void)
{
    char *dot = NULL;

    host = pcmk_hostname();
    if ((host == NULL) || (*host == '.')) {
        return ENXIO;
    }

    dot = strchr(host, '.');
    if (dot == NULL) {
        shorthost = strdup(host);
    } else {
        shorthost = strndup(host, (dot - host));
    }
    if (shorthost == NULL) {
        return ENXIO;
    }

    // @TODO If the cluster is live, also get host's node name in cluster

    return pcmk_rc_ok;
}

static bool
file_exists(const char *filename)
{
    struct stat fileinfo;

    return (filename != NULL) && (stat(filename, &fileinfo) == 0);
}

static char *
absolute_path(const char *filename)
{
    char *path = NULL;

    if (filename[0] == '/') {
        // filename is already absolute
        path = strdup(filename);
        CRM_ASSERT(path != NULL);

    } else {
        // filename is relative (to current directory)
        char cwd[PATH_MAX] = { '\0', };

        if (getcwd(cwd, sizeof(cwd)) == NULL) {
            fatal("Couldn't get current directory: %s", strerror(errno));
        }
        path = crm_strdup_printf("%s/%s", cwd, filename);
    }
    return path;
}

static void
create_report_home(const char *default_base_name)
{
    int rc = pcmk_rc_ok;

    if (report_home != NULL) {
        return;
    }
    if (options.dest != NULL) {
        // User specified a destination directory
        report_home = absolute_path(options.dest);
        debug("Using custom scratch dir: %s", report_home);

    } else {
        // User didn't specify a directory, use default (in home directory)
        char *home = getenv("HOME");

        report_home = crm_strdup_printf("%s/%s", (home? home : "/tmp"),
                                        default_base_name);
    }

    if (file_exists(report_home)) {
        fatal("Output directory %s already exists, "
              "specify an alternate name with --dest", report_home);
    }

    rc = pcmk__build_path(report_home, 0700);
    if (rc != pcmk_rc_ok) {
        fatal("Couldn't create destination directory '%s': %s",
              report_home, pcmk_rc_str(rc));
    }
}

/*!
 * \internal
 * \brief Find the first command in a list that is on the path
 *
 * \param[in] cmd  A command to search for
 * \param[in] ...  If previous attempt failed, another command to search for
 *
 * \return The first of the arguments found on the path
 */
static const char *
first_command(const char *cmd, ...)
{
    va_list ap;

    va_start(ap, cmd);
    for (; cmd != NULL; cmd = va_arg(ap, const char *)) {
        char *call;
        int rc;

        call = crm_strdup_printf("which %s >/dev/null 2>/dev/null", cmd);
        rc = system(call);
        free(call);

        if ((rc >= 0) && WIFEXITED(rc) && (WEXITSTATUS(rc) == 0)) {
            return cmd;
        }
    }
    va_end(ap);
    return NULL;
}

static void
time2str(char *s, size_t n, const char *fmt, time_t t)
{
#ifdef GCC_FORMAT_NONLITERAL_CHECKING_ENABLED
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
#endif
    if (!strftime(s, n, fmt, localtime(&t))) {
        // Should never happen, but have a fallback just in case
        snprintf(s, n, "time-%lld", (long long) t);
    }
#ifdef GCC_FORMAT_NONLITERAL_CHECKING_ENABLED
#pragma GCC diagnostic pop
#endif
}


/*
 * Cluster utility functions (needed by both CTS and cluster reports)
 */

/* Check whether a process with given substring in its name is running as
 * uid 0 or the cluster daemon user. (This assumes all cluster daemon names fit
 * within the "ps -o comm" truncation, which is 15 characters on Linux.)
 */
static bool
cluster_daemon_running(const char *command)
{
    FILE *pipe = NULL;
    bool running = false;
    char *call = NULL;
    char line[LINE_MAX];
    static uid_t cl_uid = 0;

    if ((cl_uid == 0) && (crm_user_lookup(CRM_DAEMON_USER, &cl_uid, 0) < 0)) {
        debug("Couldn't find user id of %s", CRM_DAEMON_USER);
    }

    call = crm_strdup_printf("ps -u \"0 %d\" -e -o comm", cl_uid);
    pipe = popen(call, "r");
    if (pipe == NULL) {
        debug("Couldn't run ps to check for %s: %s",
              command, strerror(errno));
        goto done;
    }

    while (!feof(pipe)) {
        if (fgets(line, LINE_MAX, pipe) == NULL) {
            break;
        }
        if (!strncmp(line, command, strlen(command))) {
            running = true;
            break;
        }
    }

    if (pclose(pipe) < 0) {
        debug("Couldn't close ps pipe for %s: %s",
              command, strerror(errno));
    }

done:
    free(call);
    return running;
}

/* Detect the cluster type, depending on the process list and existence of
 * configuration files. This is comparable to libcrmcluster's
 * get_cluster_type(), but works even if the cluster is not running, and doesn't
 * require linking against the corosync libraries.
 */
static enum cluster_e
detect_cluster_type(void)
{
    enum cluster_e detected = cluster_any;

    // First, check whether known cluster daemons are running
    if (cluster_daemon_running("corosync")) {
        detected = cluster_corosync;

    // If not, check for common configuration file locations
    } else if (file_exists(PCMK__COROSYNC_CONF)) {
        detected = cluster_corosync;

    } else {
        /* We still don't know. This might be a Pacemaker Remote node, or the
         * configuration might be in a nonstandard location.
         */
    }
    debug("Detected cluster type %s", cluster2str(detected));
    return detected;
}


/*
 * Cluster report
 */

static crm_exit_t
cluster_report(void)
{
    /*
    # If user didn't specify node(s), make a best guess if possible.
    if [ -z "$options.nodes" ]; then
	options.nodes=`getnodes $options.cluster_type`
        if [ -n "$options.nodes" ]; then
            info "Calculated node list: $options.nodes"
        else
            fatal "Cannot determine nodes; specify --nodes or --single-node"
        fi
    fi

    master_log=
    if
	echo $options.nodes | grep -qs $host
    then
	debug "We are a cluster node"
    else
	debug "We are a log master"
	master_log=`findmsg 1 "pacemaker-controld\\|CTS"`
    fi


    label="pcmk-`date +"%a-%d-%b-%Y"`"
    info "Collecting data from $options.nodes (`time2str $options.from_time` to `time2str $options.to_time`)"
    collect_data $label $options.from_time $options.to_time $master_log
    */
    options.out->err(options.out, "Cluster report not implemented yet"); // @WIP
    return CRM_EX_UNIMPLEMENT_FEATURE;
}


/*
 * CTS report
 */

static crm_exit_t
cts_report(void)
{
    /*
    test_sets=`echo $options.cts | tr ',' ' '`
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

	if [ x$options.cts_log = x ]; then
	    options.cts_log=`findmsg 1 "$start_pat"`

	    if [ x$options.cts_log = x ]; then
		fatal "No CTS control file detected"
	    else
		info "Using CTS control file: $options.cts_log"
	    fi
	fi

	line=`grep -n "$start_pat" $options.cts_log | tail -1 | sed 's@:.*@@'`
	if [ ! -z "$line" ]; then
	    start_time=`linetime $options.cts_log $line`
	fi

	line=`grep -n "Running test.*\[ *$end_test\]" $options.cts_log | tail -1 | sed 's@:.*@@'`
	if [ ! -z "$line" ]; then
	    end_time=`linetime $options.cts_log $line`
	fi

	if [ -z "$options.nodes" ]; then
	    options.nodes=`grep CTS: $options.cts_log | grep -v debug: | grep " \* " | sed s:.*\\\*::g | sort -u  | tr '\\n' ' '`
	    info "Calculated node list: $options.nodes"
	fi

	if [ $end_time -lt $start_time ]; then
	    debug "Test didn't complete, grabbing everything up to now"
	    end_time=`date +%s`
	fi

	if [ $start_time != 0 ];then
	    info "$msg (`time2str $start_time` to `time2str $end_time`)"
	    collect_data $label $start_time $end_time $options.cts_log
	else
	    fatal "$msg failed: not found"
	fi
    done
    */
    options.out->err(options.out, "CTS report not implemented yet"); // @WIP
    return CRM_EX_UNIMPLEMENT_FEATURE;
}


/*
 * Main
 */

static crm_exit_t
finish(crm_exit_t exit_code)
{
    if (report_file != NULL) {
        fclose(report_file);
    }

    g_strfreev(options.processed_args);
    g_option_context_free(options.context);
    if (options.out != NULL) {
        options.out->finish(options.out, exit_code, true, NULL);
        pcmk__output_free(options.out);
    }

    g_free(options.dest);
    g_free(options.user);
    g_free(options.shell);
    g_free(options.cts_log);
    g_strfreev(options.logfile);
    g_strfreev(options.analysis);
    g_strfreev(options.sanitize);
    g_list_free_full(options.nodes, free);
    g_list_free_full(options.cts, free);

    free(host);
    free(shorthost);
    free(report_home);

    return exit_code;
}

int
main(int argc, char **argv)
{
    crm_exit_t exit_code = CRM_EX_OK;

    crm_log_cli_init("crm_report");
    parse_args(argc, argv);
    handle_common_args(argc, argv);

    if (detect_hostname() != pcmk_rc_ok) {
        options.out->err(options.out, "Unable to get local hostname");
        return finish(CRM_EX_OSERR);
    }

    if (options.to_time == 0) {
        options.to_time = time(NULL);
    }

    if (options.single_node || options.sos) {
        if (options.nodes != NULL) {
            // @TODO error and exit CRM_EX_USAGE (at a new series release)
            warning("--nodes is ignored with %s",
                    (options.single_node? "--single-node" : "--sos-mode"));
            g_list_free_full(options.nodes, free);
        }
        options.nodes = g_list_prepend(NULL, strdup(host));
    }

    // @WIP For now, define a log file for testing
    create_report_home("report-test");
    set_report(true);
    log_options();

    // Check early if tar is unavailable so we don't waste effort
    if (!options.as_dir
        && (first_command("tar", NULL) == NULL)) {
        fatal("Required program 'tar' not found, please install and re-run");
    }

    // If user didn't specify a cluster type, make a best guess
    if (options.cluster_type == cluster_any) {
        options.cluster_type = detect_cluster_type();
    }

    if (options.cts != NULL) {
        exit_code = cts_report();

    } else if (options.from_time > 0) {
        exit_code = cluster_report();

    } else {
        fatal("Not sure what to do, no tests or time ranges to extract");
    }
    return finish(exit_code);
}

/*
## report.common.in

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

    for f in $(find / -maxdepth $options.depth -type f -name pacemaker-schedulerd -o -name cts-exec-helper); do
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
    for f in $(find / -maxdepth $options.depth -type f -name cib.xml); do
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
    for d in $(find / -maxdepth $options.depth -type d -name pengine); do
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
	for d in `find / -maxdepth $options.depth -type d -name run`; do
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

shrink() {
    olddir=$PWD
    dir=`dirname $1`
    base=`basename $1`

    target=$1.tar
    tar_options="cf"

    variant=`first_command bzip2 gzip xz false NULL`
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
		    info "Including segment [$FROM_LINE-$TO_LINE] from $logf"
		else
		    debug "Empty segment [$FROM_LINE-$TO_LINE] from $logf"
		fi
	else
	    dumplog $sourcef $FROM_LINE $TO_LINE
	    info "Including all logs after line $FROM_LINE from $logf"
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
		for f in `find / -maxdepth $options.depth -type f -name corosync.conf`; do
		    best_file=$f
		    break
		done
	    fi
	    debug "Located corosync config file: $best_file"
	    echo "$best_file"
	    ;;
	cluster_any)
	    # Cluster type is undetermined. Don't complain, because this
	    # might be a Pacemaker Remote node.
	    ;;
	*)
	    warning "Unknown cluster type: $1"
	    ;;
    esac
}

# Override any locale settings so collected output is in a common language
LC_ALL="C"
export LC_ALL


## report.collector.in

if
    echo $report_home | grep -qs '^/'
then
    debug "Using full path to working directory: $report_home"
else
    report_home="$HOME/$report_home"
    debug "Canonicalizing working directory path: $report_home"
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

    if cluster_daemon_running pacemaker-controld; then
        dump_status_and_config
        crm_node -p > "$target/$MEMBERSHIP_F" 2>&1
	echo "$host" > $target/RUNNING

    elif cluster_daemon_running pacemaker-remoted; then
        dump_status_and_config
        echo "$host" > $target/RUNNING

    # Pre-2.0.0 daemon name in case we're collecting on a mixed-version cluster
    elif cluster_daemon_running pacemaker_remoted; then
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
	    info "Found core file: `ls -al $core`"
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
      if cluster_daemon_running dlm_controld; then
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

debug "Initializing $REPORT_TARGET subdir"
if [ "$REPORT_MASTER" != "$REPORT_TARGET" ]; then
  if [ -e $report_home/$REPORT_TARGET ]; then
    warning "Directory $report_home/$REPORT_TARGET already exists, using /tmp/$$/$REPORT_TARGET instead"
    report_home=/tmp/$$
  fi
fi

mkdir -p $report_home/$REPORT_TARGET
cd $report_home/$REPORT_TARGET

case $CLUSTER in
    cluster_any) options.cluster_type=`detect_cluster_type`;;
    *) options.cluster_type=$CLUSTER;;
esac

cluster_cf=`find_cluster_cf $options.cluster_type`

# If cluster stack is still "any", this might be a Pacemaker Remote node,
# so don't complain in that case.
if [ -z "$cluster_cf" ] && [ $options.cluster_type != "cluster_any" ]; then
   warning "Could not determine the location of your cluster configuration"
fi

if [ "$SEARCH_LOGS" = "1" ]; then
    logfiles=$(get_logfiles "$options.cluster_type" "$cluster_cf" | sort -u)
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

debug "Config: $options.cluster_type ($cluster_cf) $logfiles"

sys_info $options.cluster_type $PACKAGES > $SYSINFO_F
essential_files $options.cluster_type | check_perms  > $PERMISSIONS_F 2>&1
getconfig $options.cluster_type "$report_home/$REPORT_TARGET" "$cluster_cf" "$CRM_CONFIG_DIR/$CIB_F" "/etc/drbd.conf" "/etc/drbd.d" "/etc/booth"

getpeinputs    $LOG_START $LOG_END $report_home/$REPORT_TARGET
getbacktraces  $LOG_START $LOG_END > $report_home/$REPORT_TARGET/$BT_F
getblackboxes  $LOG_START $LOG_END $report_home/$REPORT_TARGET

case $options.cluster_type in
    corosync)
	if cluster_daemon_running corosync; then
            corosync-blackbox >corosync-blackbox-live.txt 2>&1
#           corosync-fplay > corosync-blackbox.txt
            tool=`first_command corosync-objctl corosync-cmapctl NULL`
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
    get_readable_cib "$report_home/$REPORT_TARGET"
fi

collect_logs "$LOG_START" "$LOG_END" $logfiles

# Purge files containing no information
for f in `ls -1`; do
    if [ -d "$f" ]; then
	continue
    elif [ ! -s "$f" ]; then
        case $f in
	    *core*) info "Detected empty core file: $f";;
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

if [ -e $report_home/.env ]; then
    debug "Localhost: $REPORT_MASTER $REPORT_TARGET"

elif [ "$REPORT_MASTER" != "$REPORT_TARGET" ]; then
    debug "Streaming report back to $REPORT_MASTER"
    (cd $report_home && tar cf - $REPORT_TARGET)
    if [ "$REMOVE" = "1" ]; then
	cd
	rm -rf $report_home
    fi
fi

## crm_report.in

collect_data() {
    label="$1"
    start=`expr $2 - 10`
    end=`expr $3 + 10`
    masterlog=$4

    create_report_home($label)
    if [ "x$masterlog" != "x" ]; then
	dumplogset "$masterlog" $start $end > "$report_home/$HALOG_F"
    fi

    for node in $options.nodes; do
	cat <<EOF >$report_home/.env
LABEL="$label"
report_home="$r_base"
REPORT_MASTER="$host"
REPORT_TARGET="$node"
LOG_START=$start
LOG_END=$end
REMOVE=1
SANITIZE="$options.sanitize"
CLUSTER=$options.cluster_type
LOG_PATTERNS="$options.analysis"
EXTRA_LOGS="$options.logfile"
SEARCH_LOGS=($options.no_search? 0 : 1)
SOS_MODE=$options.sos
verbose=$options.args->verbosity
maxdepth=$options.depth
EOF

	if [ $host = $node ]; then
	    cat <<EOF >>$report_home/.env
report_home="$report_home"
EOF
	    cat $report_home/.env $report_data/report.common $report_data/report.collector > $report_home/collector
	    bash $report_home/collector
	else
	    cat $report_home/.env $report_data/report.common $report_data/report.collector \
		| $options.shell -l $options.user $node -- "mkdir -p $r_base; cat > $r_base/collector; bash $r_base/collector" | (cd $report_home && tar mxf -)
	fi
    done

    analyze $report_home > $report_home/$ANALYSIS_F
    if [ -f $report_home/$HALOG_F ]; then
	node_events $report_home/$HALOG_F > $report_home/$EVENTS_F
    fi

    for node in $options.nodes; do
	cat $report_home/$node/$ANALYSIS_F >> $report_home/$ANALYSIS_F
	if [ -s $report_home/$node/$EVENTS_F ]; then
	    cat $report_home/$node/$EVENTS_F >> $report_home/$EVENTS_F
	elif [ -s $report_home/$HALOG_F ]; then
	    awk "\$4==\"$options.nodes\"" $report_home/$EVENTS_F >> $report_home/$n/$EVENTS_F
	fi
    done

    info " "
    if [ $options.as_dir -ne 1 ]; then
	fname=`shrink $report_home`
	rm -rf $report_home
	info "Collected results are available in $fname"
	info " "
	info "Please create a bug entry at"
	info "    @BUG_URL@"
	info "Include a description of your problem and attach this tarball"
	info " "
	info "Thank you for taking time to create this report."
    else
	info "Collected results are available in $report_home"
    fi
    info " "
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
    for n in $options.nodes; do
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
    for n in $options.nodes; do
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
*/
