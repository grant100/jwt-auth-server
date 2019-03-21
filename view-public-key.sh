#!/bin/bash
keystore=$1
keytool -list -rfc -keystore "src/main/resources/$keystore.jks" -alias $keystore -storepass changeit
