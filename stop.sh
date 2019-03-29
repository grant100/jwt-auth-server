#!/bin/bash
docker stack ps masters
docker stack rm masters
docker swarm leave --force
docker stack ps masters