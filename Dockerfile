from debian

add . /tmp/ike/

workdir /tmp/ike/

run apt update && apt install -y cmake build-essential libreadline-dev \
    openssl libssl-dev libevent-dev libncurses-dev zlib1g-dev && \
    ./configure && make && make install

cmd vpnserver start

