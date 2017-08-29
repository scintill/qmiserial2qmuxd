# qmiserial2qmuxd

This program's goal is to allow programs such as qmicli (libqmi), uqmi, and oFono to work with `qmuxd`. Usually such programs talk directly to a serial Qualcomm QMI interface (typically something like `/dev/cdc-wdm1` provided by `qmi_wwan` on Linux.) Some devices or configurations only have QMI access through `qmuxd`, a properietary Qualcomm daemon that provides a separate protocol over Unix domain socket. So, `qmiserial2qmuxd` emulates the serial interface and proxies requests/responses to `qmuxd`, so that the standard opensource QMI tools can work in this configuration too.

I've tested a few requests successfully on my Android phone (Samsung Galaxy S4 Mini) with qmicli. I expect other requests and devices to work as well, but haven't tested, and haven't done heavy-duty or "real-world" use yet. The code probably needs to be made more robust, safe, and convenient to use, but I think the basic function is feature-complete. The concept is simple enough that I hope there's little room for bugs.

# Usage

```sh
$ make qmiserial2qmuxd
$ sudo ./qmiserial2qmuxd
```

Something like the following is output:
```
main: connected to qmuxd and received client id 67
/dev/pts/5
```

Give that printed path to your QMI tool (this example should show your phone number):
```
$ sudo qmicli -d /dev/pts/5 --dms-get-msisdn
[/dev/pts/5] Device MSISDN retrieved:
	MSISDN: 'XXXXXXX'
```

# Building for Android

You can get an Android toolchain using the NDK, e.g.:

```
$ ~/android-ndk/build/tools/make-standalone-toolchain.sh --arch=arm --install-dir=./android-toolchain --platform=android-21
$ export PATH $PATH:$PWD/android-toolchain
$ make qmiserial2qmuxd.android
```

# Design

There are two threads. One takes a message from the serial interface and immediately writes the translated form to the qmuxd socket, then waits for the next message again. The other reads from the qmuxd socket and writes to the serial device. We don't track any state about the messages (like transaction IDs) or much about what they mean, we just pass them through.

# Issues and Development

Please let me know by Github issue or email if you have any questions or problems -- it's only been tested on my one device after all. Code review and improvement suggestions by pull request or email are welcome!

# Resources on the interface and protocol

* GobiAPI from https://portland.source.codeaurora.org/patches/quic/gobi/ (also included in libqmi source tree). Has qmuxd structs and logic, as well as the serial structs (e.g. struct sQMUXHeader), but they seem to be unused in it.
* GobiNet from https://portland.source.codeaurora.org/patches/quic/gobi/Gobi_Linux/ (also included in this repository in the "aux/reference" branch). Has serial structs e.g. struct sQMUX and logic.
* [libqmi](https://www.freedesktop.org/wiki/Software/libqmi/), [uqmi](git.openwrt.org/?p=project/uqmi.git;a=summary), and [oFono](https://01.org/ofono) (projects that are clients to the qmi_wwan serial interface)
* libqmi_client_qmux.so and qmuxd - properietary Qualcomm qmuxd client and server implementations
* Look at qmuxd logs (`adb logcat -b radio` on Android)

# License

> Copyright (C) 2017 Joey Hewitt <joey@joeyhewitt.com>
>
> qmiserial2qmuxd is free software: you can redistribute it and/or modify
> it under the terms of the GNU General Public License as published by
> the Free Software Foundation, either version 3 of the License, or
> (at your option) any later version.
>
> qmiserial2qmuxd is distributed in the hope that it will be useful,
> but WITHOUT ANY WARRANTY; without even the implied warranty of
> MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
> GNU General Public License for more details.
>
> You should have received a copy of the GNU General Public License
> along with qmiserial2qmuxd.  If not, see <http://www.gnu.org/licenses/>.

# TODO

* Make qmuxd socket path configurable - maybe follow GobiAPI's naming convention. In the source right now it is defined for Android.
* Check if indications/unsolicited messages work
* Does anything bad happen if multiple programs access us at once? (Is this one of the reasons for the existence of qmuxd and libqmi's proxy mode?) We could set the pty to exclusive mode if needed.
* Do endianness conversions, so we'll work on a big-endian system (assuming the wire protocols are always little-endian)
* Write an implementation in something like Python? I've started with C because it's probably best for my needs, but a higher-level language might make it clearer how this works, and have less possibility of memory bugs and crashes.
* Is there a good reason qmuxd wants you to do control operations through it? (e.g. eQMUXD_MSG_ALLOC_QMI_CLIENT_ID and eQMUXD_MSG_RELEASE_QMI_CLIENT_ID in GobiAPI, several others I see in libqmi_client_qmux.so.) I found a way to do raw control requests for simplicity, but maybe qmuxd wants us to use its extra layer so it can manage something important...
* Add symlinking feature, where a user-specified symlink is created to point to the pty allocated, so that a constant path can be used with the consuming tools.
