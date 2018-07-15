SHELL:=/bin/bash
VPN_SRC_DIR=$(pwd)

build-deb:
	sudo vpnserver stop
	sudo pkill -f vpnserver
	sudo rm /etc/debug.txt
	sudo apt remove -y softether-vpncmd softether-vpnserver
	pushd ${VPN_SRC_DIR} && dpkg-buildpackage -us -uc -b && cmake . && popd
	dpkg -i softether-vpncmd_* softether-vpnserver_*
	vpnserver start

build:
	pushd ${VPN_SRC_DIR} && ./configure && make clean && dpkg-buildpackage -us -uc -b && popd

rebuild:
	pushd ${VPN_SRC_DIR} && rm -rf tmp/objs/Cedar/IPsec_IKEv2.o tmp/objs/Cedar/IPsec_Ikev2Packet.o && \
		./configure && sudo make && cmake . && popd

ssbuild:
	pushd ./strongswan-5.6.2 && ./configure --prefix=/usr --sysconfdir=/etc --enable-eap-mschapv2 --enable-kernel-libipsec --enable-swanctl \
	 	--enable-unity --enable-unbound --enable-vici --enable-xauth-eap --enable-xauth-noauth --enable-charon-cmd \
		--enable-eap-identity --enable-md4 --enable-pem --enable-openssl --enable-pubkey --enable-farp\n && make && sudo make install && popd

clean:
	sudo pkill -f vpnserver
	sudo apt remove -y softether-vpncmd softether-vpnserver
	sudo rm /etc/debug.txt softether-vpn*
