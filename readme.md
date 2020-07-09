How to build SoftEther VPN for UNIX
===================================

And this command for Debian/Ubuntu:

How to build and install on Debian-like systems
------------
```
$ apt-get install -y dpkg debhelper dh-exec gcc libncurses5-dev libreadline-dev libssl-dev make libz-dev 
```

Make sure you have cloned repo into `ike` directory or change `ike` as you want,
but not forget to update VPN_SRC_DIR variable in makefile.
To build the programs from the source code, run the following commands:

```
$ ./configure
$ make build
$ dpkg -i softether_vpncmd_* softether_vpnserver_*
$ vpnserver start
```

Don't forget to configure hub, user and do `IPsecEnable` to enable ike1/2 and specify
PSK in vpncmd tool.
