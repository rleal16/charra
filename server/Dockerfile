
#FROM --platform=linux/arm64/v8 ubuntu
#FROM ubuntu
FROM golang:1.18-buster
WORKDIR /home
COPY hardened_encryption/ .
COPY server.py ahe-demo/client
COPY he_placeholder.py ahe-demo/client
RUN apt update -y
RUN apt upgrade -y
RUN apt install -y build-essential zlib1g-dev libncurses5-dev libgdbm-dev libnss3-dev libssl-dev libreadline-dev libffi-dev libsqlite3-dev wget libbz2-dev
RUN apt -y install python3
RUN apt -y install python3-venv
RUN apt -y install python3-pip
RUN apt-get install -y python3-sphinx
RUN pip3 install pynacl
WORKDIR /home/ahe-bindings/cgo
RUN ["/bin/bash", "-c","make x86_64"]
WORKDIR /
WORKDIR /home/ahe-bindings/Python
RUN make
WORKDIR /home/ahe-bindings/Python/dist
RUN python3 -m pip install ahe_bindings-0.0.1-py3-none-any.whl
WORKDIR /home/ahe-demo/client/libs/linux-x86-64
RUN ["/bin/bash", "-c","cp ../../../../ahe-bindings/build/libahe.so ."]
WORKDIR /home/ahe-demo/client
#CMD  "python3 client.py" 