FROM alpine:latest

# Install required packages
RUN apk add --update alpine-sdk linux-headers
RUN apk add cmake gdb python3 python3-dev py3-pip

COPY . /workspaces/Debugger

WORKDIR /workspaces/Debugger