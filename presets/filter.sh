#!/usr/bin/env bash

for file in {/Applications/*.app,/Applications/*/*.app} ; do
  # echo $file
  bundle=$(defaults read "$file/Contents/Info" CFBundleIdentifier);
  # echo $bundle
  if [[ $bundle =~ ^com\.apple\. ]]
  then
    codesign "-R=anchor apple" -v $f 2>/dev/null && echo $file;
  fi
done > app.txt