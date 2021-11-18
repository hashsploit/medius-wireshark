#!/usr/bin/env bash

# Change directory to the current script directory
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd $DIR

SCRIPT="$0"
DISSECTOR="medius_wireshark_dissector.lua"

mkdir -p ~/.local/lib/wireshark/plugins  >/dev/null 2>&1
rm ~/.local/lib/wireshark/plugins/${DISSECTOR} >/dev/null 2>&1
cp ${DISSECTOR} ~/.local/lib/wireshark/plugins >/dev/null 2>&1

echo -e "> Installed ${DISSECTOR}"

