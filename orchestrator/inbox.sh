#!/bin/bash

echo "=============================="
echo " WAIO INBOX"
echo "=============================="
echo "jobs/"
echo "logs/"
echo "orchestrator/"
echo "results/"
echo "workers/"
echo ""

while true; do
    read -p "WAIO> " REQUEST

    if [ "$REQUEST" = "exit" ]; then
        echo "WAIO exit"
        break
    fi

    if [ -z "$REQUEST" ]; then
        continue
    fi

    echo "[RECEIVED] $REQUEST"
    echo "[STATUS] MVP inbox is alive"
    echo ""
done
