/*
 * Copyright 2017-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <crm/crm.h>
#include "pacemaker-execd.h"

static pid_t main_pid = 0;

static void
sigdone(void)
{
    crm_exit(CRM_EX_OK);
}

static void
sigreap(void)
{
    pid_t pid = 0;
    int status;

    do {
        /*
         * Opinions seem to differ as to what to put here:
         *  -1, any child process
         *  0,  any child process whose process group ID is equal to that of the calling process
         */
        pid = waitpid(-1, &status, WNOHANG);
        if (pid == main_pid) {
            /* Exit when pacemaker-remote exits and use the same return code */
            if (WIFEXITED(status)) {
                crm_exit(WEXITSTATUS(status));
            }
            crm_exit(CRM_EX_ERROR);
        }
    } while (pid > 0);
}

static struct {
    int sig;
    void (*handler)(void);
} sigmap[] = {
    { SIGCHLD, sigreap },
    { SIGINT,  sigdone },
};

void
remoted_spawn_pidone(int argc, char **argv, char **envp)
{
    sigset_t set;

    /* This environment variable exists for two purposes:
     * - For testing, setting it to "full" enables full PID 1 behavior even
     *   when PID is not 1
     * - Setting to "vars" enables just the loading of environment variables
     *   from /etc/pacemaker/pcmk-init.env, which could be useful for testing or
     *   containers with a custom PID 1 script that launches the remote
     *   executor.
     */
    const char *pid1 = PCMK_VALUE_DEFAULT;

    if (getpid() != 1) {
        pid1 = pcmk__env_option(PCMK__ENV_REMOTE_PID1);
        if (!pcmk__str_any_of(pid1, "full", "vars", NULL)) {
            // Default, unset, or invalid
            return;
        }
    }

    /* When a container is launched, it may be given specific environment
     * variables, which for Pacemaker bundles are given in the bundle
     * configuration. However, that does not allow for host-specific values.
     * To allow for that, look for a special file containing a shell-like syntax
     * of name/value pairs, and export those into the environment.
     */
    pcmk__load_env_options("/etc/pacemaker/pcmk-init.env", NULL);

    if (strcmp(pid1, "vars") == 0) {
        return;
    }

    /* Containers can be expected to have /var/log, but they may not have
     * /var/log/pacemaker, so use a different default if no value has been
     * explicitly configured in the container's environment.
     */
    if (pcmk__env_option(PCMK__ENV_LOGFILE) == NULL) {
        pcmk__set_env_option(PCMK__ENV_LOGFILE, "/var/log/pcmk-init.log", true);
    }

    sigfillset(&set);
    sigprocmask(SIG_BLOCK, &set, 0);

    main_pid = fork();
    switch (main_pid) {
        case 0:
            sigprocmask(SIG_UNBLOCK, &set, NULL);
            setsid();
            setpgid(0, 0);

            // Child remains as pacemaker-remoted
            return;
        case -1:
            crm_err("fork failed: %s", pcmk_rc_str(errno));
    }

    /* Parent becomes the reaper of zombie processes */
    /* Safe to initialize logging now if needed */

#  ifdef HAVE_PROGNAME
    /* Differentiate ourselves in the 'ps' output */
    {
        char *p;
        int i, maxlen;
        char *LastArgv = NULL;
        const char *name = "pcmk-init";

        for (i = 0; i < argc; i++) {
            if (!i || (LastArgv + 1 == argv[i]))
                LastArgv = argv[i] + strlen(argv[i]);
        }

        for (i = 0; envp[i] != NULL; i++) {
            if ((LastArgv + 1) == envp[i]) {
                LastArgv = envp[i] + strlen(envp[i]);
            }
        }

        maxlen = (LastArgv - argv[0]) - 2;

        i = strlen(name);

        /* We can overwrite individual argv[] arguments */
        snprintf(argv[0], maxlen, "%s", name);

        /* Now zero out everything else */
        p = &argv[0][i];
        while (p < LastArgv) {
            *p++ = '\0';
        }
        argv[1] = NULL;
    }
#  endif // HAVE_PROGNAME

    while (1) {
        int sig;
        size_t i;

        sigwait(&set, &sig);
        for (i = 0; i < PCMK__NELEM(sigmap); i++) {
            if (sigmap[i].sig == sig) {
                sigmap[i].handler();
                break;
            }
        }
    }
}
