# IKEv2 Implementation for SoftEther

We in [NovaVPN](https://novavpn.com) attempted to implement support the IKEv2 protocol for the SoftEtherVPN. The work was not finished, despite this we want to share the results with the community.

### What was done
* Fully implemented support of IKEv2 protocol (Key exchange, create session and tunnel)
* Removed Windows support (sorry guys)
* Removed IPv6 support for simplicity

### What does not work
* **Traffic is not routed to the Internet for IKEv2 clients**. Probably its easy to fix issue.

##How to build and install on Debian-like systems
```
$ apt-get install -y dpkg debhelper dh-exec gcc libncurses5-dev libreadline-dev libssl-dev make libz-dev
```

Make sure you have cloned repo into `ike` directory or chnge `ike` as you want,
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
~a