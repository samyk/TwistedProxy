## TwistedProxy
**TwistedProxy** is a python proxy that aims to capture, decrypt & save Clash Royale game traffic. This is an adapted version for v2.4 that use a workaround based on frida since Supercell enforced their game protection which make the serverKey patching impossible.

### Setup the proxy
The proxy need some external dependencies to run:

**If you want the frida script to be injected at proxy runtime:**

>-   Install **ADB** and add it to your path
>-   Setup **frida-server** on your device if you want to run the frida script at the proxy launch, here is a guide: [https://www.frida.re/docs/android/](https://www.frida.re/docs/android/)

1. Install the modded version of **tweetnacl**. Just run `python setup.py build_ext -b ../TCP` in TweetnaclMod directory to install it
1.  Run `python -m pip install -r requirements.txt` to install the others dependencies

### How to use it ?

To start the proxy you will just have to run the following command:
> python Main.py


However the proxy accept some optionals arguments that are:

* `-f`: the game will be automatically spawned and the frida script will be injected at proxy runtime
* `-n`: connect to frida via network rather than USB
* `-v`: the proxy will be run in verbose mode that basically output packets hexdump in terminal
* `-r`: all packets will be saved in the repository you've set in config.json (ReplayDirectory key)
* `-u`: UDP proxy will be launched too
* `-a`: optional path to adb, useful if using specific adb/Android emulator

### UDP Proxy

Before running the UDP Proxy you should set the local ip where the proxy is running in config.json (UDPHost key). 

### Credits

[Misha](https://github.com/MISHA-CRDEV) - For the crypto workaround  
[iGio](https://github.com/iGio90) - For all his amazing contribution to the RE community of the game  
**Nameless** - For the huge help and explanations about the UDP protocol

### PS

Any question or bug to report ? Feel free to contact me at @GaLaXy1036#1601 on discord