#!/bin/bash

IMAGES=("python:latest" "python:3.13" "sagemath/sagemath:latest" "ubuntu:latest")

for img in "${IMAGES[@]}"
do
    docker pull $img
done

