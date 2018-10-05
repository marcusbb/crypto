#!/bin/bash
set -e
set -x

VERSION=$1

mvn versions:set -DnewVersion=$VERSION -DgenerateBackupPoms=false -N