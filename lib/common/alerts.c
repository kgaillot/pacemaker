/*
 * Copyright 2015-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>
#include <crm/crm.h>
#include <crm/lrmd.h>
#include <crm/common/xml.h>
#include <crm/common/alerts_internal.h>
#include <crm/common/cib_internal.h>
#include <crm/common/xml_internal.h>

/*
 * to allow script compatibility we can have more than one
 * set of environment variables
 */
const char *pcmk__alert_keys[PCMK__ALERT_INTERNAL_KEY_MAX][3] =
{
    [PCMK__alert_key_recipient] = {
        "CRM_notify_recipient",         "CRM_alert_recipient",          NULL
    },
    [PCMK__alert_key_node] = {
        "CRM_notify_node",              "CRM_alert_node",               NULL
    },
    [PCMK__alert_key_nodeid] = {
        "CRM_notify_nodeid",            "CRM_alert_nodeid",             NULL
    },
    [PCMK__alert_key_rsc] = {
        "CRM_notify_rsc",               "CRM_alert_rsc",                NULL
    },
    [PCMK__alert_key_task] = {
        "CRM_notify_task",              "CRM_alert_task",               NULL
    },
    [PCMK__alert_key_interval] = {
        "CRM_notify_interval",          "CRM_alert_interval",           NULL
    },
    [PCMK__alert_key_desc] = {
        "CRM_notify_desc",              "CRM_alert_desc",               NULL
    },
    [PCMK__alert_key_status] = {
        "CRM_notify_status",            "CRM_alert_status",             NULL
    },
    [PCMK__alert_key_target_rc] = {
        "CRM_notify_target_rc",         "CRM_alert_target_rc",          NULL
    },
    [PCMK__alert_key_rc] = {
        "CRM_notify_rc",                "CRM_alert_rc",                 NULL
    },
    [PCMK__alert_key_kind] = {
        "CRM_notify_kind",              "CRM_alert_kind",               NULL
    },
    [PCMK__alert_key_version] = {
        "CRM_notify_version",           "CRM_alert_version",            NULL
    },
    [PCMK__alert_key_node_sequence] = {
        "CRM_notify_node_sequence",     PCMK__ALERT_NODE_SEQUENCE,      NULL
    },
    [PCMK__alert_key_timestamp] = {
        "CRM_notify_timestamp",         "CRM_alert_timestamp",          NULL
    },
    [PCMK__alert_key_attribute_name] = {
        "CRM_notify_attribute_name",    "CRM_alert_attribute_name",     NULL
    },
    [PCMK__alert_key_attribute_value] = {
        "CRM_notify_attribute_value",   "CRM_alert_attribute_value",    NULL
    },
    [PCMK__alert_key_timestamp_epoch] = {
        "CRM_notify_timestamp_epoch",   "CRM_alert_timestamp_epoch",    NULL
    },
    [PCMK__alert_key_timestamp_usec] = {
        "CRM_notify_timestamp_usec",    "CRM_alert_timestamp_usec",     NULL
    },
    [PCMK__alert_key_exec_time] = {
        "CRM_notify_exec_time",         "CRM_alert_exec_time",          NULL
    }
};

/*!
 * \brief Create a new alert entry structure
 *
 * \param[in] id  ID to use
 * \param[in] path  Path to alert agent executable
 *
 * \return Pointer to newly allocated alert entry
 * \note Non-string fields will be filled in with defaults.
 *       It is the caller's responsibility to free the result,
 *       using pcmk__free_alert().
 */
pcmk__alert_t *
pcmk__alert_new(const char *id, const char *path)
{
    pcmk__alert_t *entry = pcmk__assert_alloc(1, sizeof(pcmk__alert_t));

    pcmk__assert((id != NULL) && (path != NULL));
    entry->id = pcmk__str_copy(id);
    entry->path = pcmk__str_copy(path);
    entry->timeout = PCMK__ALERT_DEFAULT_TIMEOUT_MS;
    entry->flags = pcmk__alert_default;
    return entry;
}

void
pcmk__free_alert(pcmk__alert_t *entry)
{
    if (entry) {
        free(entry->id);
        free(entry->path);
        free(entry->tstamp_format);
        free(entry->recipient);

        g_strfreev(entry->select_attribute_name);
        if (entry->envvars) {
            g_hash_table_destroy(entry->envvars);
        }
        free(entry);
    }
}

/*!
 * \internal
 * \brief Duplicate an alert entry
 *
 * \param[in] entry  Alert entry to duplicate
 *
 * \return Duplicate of alert entry
 */
pcmk__alert_t *
pcmk__dup_alert(const pcmk__alert_t *entry)
{
    pcmk__alert_t *new_entry = pcmk__alert_new(entry->id, entry->path);

    new_entry->timeout = entry->timeout;
    new_entry->flags = entry->flags;
    new_entry->envvars = pcmk__str_table_dup(entry->envvars);
    new_entry->tstamp_format = pcmk__str_copy(entry->tstamp_format);
    new_entry->recipient = pcmk__str_copy(entry->recipient);
    if (entry->select_attribute_name) {
        new_entry->select_attribute_name = g_strdupv(entry->select_attribute_name);
    }
    return new_entry;
}

void
pcmk__add_alert_key(GHashTable *table, enum pcmk__alert_keys_e name,
                    const char *value)
{
    for (const char **key = pcmk__alert_keys[name]; *key; key++) {
        if (value) {
            crm_trace("Inserting alert key %s = '%s'", *key, value);
            pcmk__insert_dup(table, *key, value);
        } else {
            crm_trace("Removing alert key %s (no value given)", *key);
            g_hash_table_remove(table, *key);
        }
    }
}

void
pcmk__add_alert_key_int(GHashTable *table, enum pcmk__alert_keys_e name,
                        int value)
{
    for (const char **key = pcmk__alert_keys[name]; *key; key++) {
        crm_trace("Inserting alert key %s = %d", *key, value);
        g_hash_table_insert(table, pcmk__str_copy(*key), pcmk__itoa(value));
    }
}
