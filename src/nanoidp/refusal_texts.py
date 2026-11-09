"""What every surface says, in words, for a configuration or a runtime store
that cannot be used right now (#477).

Fixed texts: the exceptions behind them name the configuration directory,
the file that does not load, the parser's or the lock's own words, which
are for the log (the surfaces write it), not for an answer. The HTTP app
and the MCP server read them from here, so a condition reads the same on
both. No Flask here: the MCP server does not import it.
"""

CONFIGURATION_UNAVAILABLE_TEXT = (
    "The configuration files could not be read or loaded right now; the configuration "
    "loaded before stays in force. Try again."
)
CONFIGURATION_UNLOADABLE_TEXT = (
    "The configuration files changed and do not load; the configuration loaded before stays "
    "in force until they are fixed."
)
# A first load that failed: there is no configuration before it to stay in
# force. Said for a failure that coming back may resolve too; whether it may
# is the answer's `retryable`, not these words.
NO_CONFIGURATION_TEXT = "No configuration could be loaded."
# A lock the configuration needs, not had: the configuration directory's,
# when the files are looked at before a call, or the keys directory's, which
# a load takes. Whether coming back helps is the answer's `retryable`.
CONFIGURATION_LOCK_UNAVAILABLE_TEXT = "A lock the configuration needs could not be taken."
# save_config wrote nothing, because of a file already on disk or of the
# directory's lock (MCP).
SAVE_FILES_UNLOADABLE_TEXT = f"{CONFIGURATION_UNLOADABLE_TEXT} Nothing was written."
SAVE_FILES_UNAVAILABLE_TEXT = (
    "The configuration files could not be read right now; the configuration loaded before "
    "stays in force. Nothing was written; try again."
)
SAVE_FILES_NOT_EDITABLE_TEXT = (
    "The configuration cannot be edited because it contains duplicate keys. Nothing was written."
)
SAVE_LOCK_UNAVAILABLE_TEXT = "The lock of the configuration files could not be taken; nothing was written."
# "Another writer": SQLite reports contention between processes and between
# this process's own connections the same way.
RUNTIME_STORE_UNAVAILABLE_TEXT = "The runtime store is held by another writer; try again."
