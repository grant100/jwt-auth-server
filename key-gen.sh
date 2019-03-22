#!/bin/bash
name=$1
keytool -genkey -alias $name -keyalg RSA -keypass changeit -storepass changeit -keystore temp.jks
