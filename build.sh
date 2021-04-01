#!/bin/bash

rm Payload.ipa
xcodebuild build CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO -sdk iphoneos
mkdir Payload
mv build/Release-iphoneos/ap0110.app Payload/
zip -r Payload.ipa Payload
rm -rf Payload
rm -rf build
xcodebuild clean
