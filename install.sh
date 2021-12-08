#!/usr/bin/env bash

# Change directory to the current script directory
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd $DIR

SCRIPT="$0"
DISSECTOR="medius_wireshark_dissector.lua"

if [ "$1" = "-u" ] || [ "$1" = "--uninstall" ]; then
	rm -rf ~/.local/lib/wireshark/plugins/medius-wireshark >/dev/null 2>&1
	echo -e "> Successfully uninstalled medius-wireshark plugin"
	exit 0
fi


mkdir -p ~/.local/lib/wireshark/plugins/medius-wireshark >/dev/null 2>&1
rm ~/.local/lib/wireshark/plugins/medius-wireshark/${DISSECTOR} >/dev/null 2>&1
cp ${DISSECTOR} ~/.local/lib/wireshark/plugins/medius-wireshark >/dev/null 2>&1

echo -e "> Successfully installed medius-wireshark plugin"

