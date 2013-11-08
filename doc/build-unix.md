Copyright (c) 2009-2013 Bitcoin Developers

Distributed under the MIT/X11 software license, see the accompanying
file COPYING or http://www.opensource.org/licenses/mit-license.php.
This product includes software developed by the OpenSSL Project for
use in the [OpenSSL Toolkit](http://www.openssl.org/). This product
includes cryptographic software written by Eric Young
([eay@cryptsoft.com](mailto:eay@cryptsoft.com)), and UPnP software
written by Thomas Bernard.


UNIX BUILD NOTES
====================

To Build
---------------------

  cd src/
  make -f makefile.unix   # Headless ptsminer

Dependencies
---------------------

Required:
 - libssl (SSL Support)
 - libdb4.8 (Berkeley DB)
 - libboost (Boost C++ Library)
 - libgmp (GNU Multiprecision)

Optional:
 - miniupnpc (UPnP Support)

Versions used in this release:
 - GCC           4.3.3
 - OpenSSL       1.0.1c
 - Berkeley DB   4.8.30.NC (not 5.x!)
 - Boost         1.48
 - GMP           5.0.2
 - miniupnpc     1.6

Licenses of statically linked libraries:
 - Berkeley DB: New BSD license with additional requirement that linked software must be free open source
 - Boost: MIT-like license
 - miniupnpc: New (3-clause) BSD license


Dependency Build Instructions: Ubuntu & Debian
----------------------------------------------
Build requirements:

  sudo apt-get install build-essential libssl-dev libboost-all-dev libgmp-dev

Berkeley db4.8 packages are available [here](https://launchpad.net/~bitcoin/+archive/bitcoin):

  sudo add-apt-repository ppa:bitcoin/bitcoin
  sudo apt-get update
  sudo apt-get install libdb4.8-dev libdb4.8++-dev

Ubuntu precise has packages for libdb5.1-dev and libdb5.1++-dev,
but using these will break binary wallet compatibility, and is not recommended.

If you have trouble with libboost dependencies, make sure these are installed:

  sudo apt-get install libboost-chrono1.48-dev libboost-filesystem1.48-dev libboost-system1.48-dev libboost-program-options1.48-dev libboost-thread1.48-dev

(If using Boost 1.37, append -mt to the boost libraries in the makefile,
use `apt-cache search libboost` to find out which version is available for your system.)

Optional:

  sudo apt-get install libminiupnpc-dev

[miniupnpc](http://miniupnp.free.fr/) may be used for UPnP port mapping.
It can be downloaded from [here](http://miniupnp.tuxfamily.org/files/).
UPnP support is compiled in and turned off by default.
Set USE_UPNP to a different value to control this:

  USE_UPNP=    No UPnP support miniupnp not required
  USE_UPNP=0    (the default) UPnP support turned off by default at runtime
  USE_UPNP=1    UPnP support turned on by default at runtime

IPv6 support may be disabled by setting:

  USE_IPV6=0    Disable IPv6 support


Compiling Berkeley DB
---------------------
You need Berkeley DB 4.8. If you have to build Berkeley DB yourself:

  ../dist/configure --enable-cxx
  make


Compiling Boost
---------------
If you need to build Boost yourself:

  sudo su
  ./bootstrap.sh
  ./bjam install


Compiling miniupnpc
-------------------
  tar -xzvf miniupnpc-1.6.tar.gz
  cd miniupnpc-1.6
  make
  sudo su
  make install


Security
--------
To help make your bitcoin installation more secure by making certain attacks impossible to
exploit even if a vulnerability is found, you can take the following measures:

* Position Independent Executable
    Build position independent code to take advantage of Address Space Layout Randomization
    offered by some kernels. An attacker who is able to cause execution of code at an arbitrary
    memory location is thwarted if he doesn't know where anything useful is located.
    The stack and heap are randomly located by default but this allows the code section to be
    randomly located as well.

    On an Amd64 processor where a library was not compiled with -fPIC, this will cause an error
    such as: "relocation R_X86_64_32 against `......' can not be used when making a shared object;"

    To build with PIE, use:

      make -f makefile.unix ... -e PIE=1

    To test that you have built PIE executable, install scanelf, part of paxutils, and use:

      scanelf -e ./bitcoin

    The output should contain:
     TYPE
    ET_DYN

* Non-executable Stack
    If the stack is executable then trivial stack based buffer overflow exploits are possible if
    vulnerable buffers are found. By default, bitcoin should be built with a non-executable stack
    but if one of the libraries it uses asks for an executable stack or someone makes a mistake
    and uses a compiler extension which requires an executable stack, it will silently build an
    executable without the non-executable stack protection.

    To verify that the stack is non-executable after compiling use:
    `scanelf -e ./bitcoin`

    the output should contain:
  STK/REL/PTL
  RW- R-- RW-

    The STK RW- means that the stack is readable and writeable but not executable.
