#!/bin/bash

ls $2|while read A ; do find $1 -type f -name "*.yar" -exec yara {} $2/$A \; 2>&1|grep -iv 'error\|warning' ;done
