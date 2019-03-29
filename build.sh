#!/bin/bash
./gradlew clean
./gradlew build
reset
docker build --tag=auth-server .
docker tag auth-server gsowards/auth-server:latest
docker push gsowards/auth-server:latest
#docker run -p 443:8080 gsowards/auth-server:latest
