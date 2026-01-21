#!/bin/bash
case $COMMIT_ACTION in
    DELETE)
    systemctl stop ssh --no-block 2>/dev/null || true
    ;;
    *)
    vyatta-update-ssh.pl > /etc/ssh/sshd_config
    # Use --no-block to avoid deadlock during Vyatta commit
    # SSH depends on nss-user-lookup.target which may wait for system-configure
    systemctl restart ssh --no-block 2>/dev/null || true
    ;;
esac
