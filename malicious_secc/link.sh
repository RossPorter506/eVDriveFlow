#!/bin/bash

# Change working directory to script location
cd "$(dirname "$0")"

# Delete all symlinks in current folder (and subfolder)
find . -maxdepth 2 -type l -delete

# For each file in ../secc create a symlink in ./
for filepath in ../secc/* ; do
    if [[ $filepath == *"__pycache__"* || -d $filepath ]]; then
        continue
    else
        ln -s $filepath ${filepath:8}
    fi
done

# Same for subfolder (need to prefix link with ../ though)
for filepath in ../secc/states/* ; do
    if [[ $filepath == *"__pycache__"* || -d $filepath ]]; then
        continue
    else
        ln -s ../$filepath ${filepath:8}
    fi
done
