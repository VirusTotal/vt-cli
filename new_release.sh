#!/bin/bash

mkdir dist
zip -j dist/MacOSX.zip build/darwin/amd64/vt
zip -j dist/Linux32.zip build/linux/386/vt
zip -j dist/Linux64.zip build/linux/amd64/vt
zip -j dist/Windows32.zip build/windows/386/vt.exe
zip -j dist/Windows64.zip build/windows/amd64/vt.exe
zip -j dist/FreeBSD32.zip build/freebsd/386/vt
zip -j dist/FreeBSD64.zip build/freebsd/amd64/vt
ghr -t $GITHUB_TOKEN -u VirusTotal -replace $VERSION dist/
