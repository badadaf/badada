## Badada Frida Client

This tool was developed to help during the security assessment of Android applications.
It implements some commonly used Frida scripts and offer them via a simple command line interface.

#### Requirements

- Python 3.0
- Frida (pip3 install -U frida)
- Frida Server for rooted devices (https://github.com/frida/frida/releases)
- Frida Gadget for non-rooted devices (https://github.com/badadaf/apkpatcher)
- ADB

#### Before you use Badada!

If your device is rooted, download Frida Server for your device's architecture put it in /data/local/tmp/frida-server and set the proper permission to the binary
```
adb push ~/Downloads/frida-server-12.6.1-android-arm64 /data/local/tmp/frida-server
adb shell chmod +x /data/local/tmp/frida-server
```

Badada will automatically start frida-server's daemon.

In some devices frida may fail because it doesn't know exactly how to patch device-specific SELinux rules.
If you found some `avc: denied` messages in logcat after starting frida-server, you can try completely disable SELinux by running the following command before running frida-server:
```
adb shell setenforce 0
```

#### How to use Badada
This section will explain how to perform the first step of using Badada. After this first step you will be able to use the Badada Command Line Interface to run other commands.

After installing badada and placing frida-server in **/data/local/tmp/frida-server**, you can:
- **Hook running Android apps by specifying its name**
    ```
    badada com.example.app
    ```

- **Hook running Android apps by specifying its PID**
    ```
    badada 14719
    ```

- **Hook a running Android app that has embedded a Frida Gadget**
    When you start the app it will become freezed waiting for Frida Client connection.
    You can specify the name "Gadget" to perform the hook
    ```
    badada Gadget
    ```

- **Load a hook script in the target running app**
    ```
    badada com.example.app -j hook-script.js
    ```

- **Monitor new started apps**
    Here the things starts to become more interesting. By using Frida's Child Gating API we can attach into a process and monitor for every time it forks.
    After the fork you will be able to choose if you want to attach into the child process or not.

    An interesting process to monitor is `zygote` and `zygote64`. Every time you start an application in Android, it will be a fork of `zygote` or `zygote64`

    You can watch every new 32-bit started application by hooking `zygote` and 64-bit apps by hooking `zygote64`, as in the following example:
    ```
    badada zygote64 --child-gating --verbose
    ```

- **Load hook scripts in started apps before they run any instruction**
    You can use this technique to load Frida scripts in new started apps before they effectively run its instructions
    ```
    badada zygote64 --child-gating --child-gating-args='com.example.app1=hook-script-1.js com.example.app2=hook-script-2.js'
    ```

- **Avoid hooking grandchildren**
    You may want to hook a process children, but not its grandchildren
    ```
    badada zygote --child-gating --child-gating-args "com.example.app1=hook-script-1.js" -v --enable-jit --avoid-grandchildren-gating
    ```

#### Command Line features
After hooking a process badada will show a cmd. You can use some built-in commands to help you to reverse engineer an application.
*We do recommend using the below commands only if you are not using child gating.*

- **List loaded classes**
    ```
    classes
    ```

- **List loaded classes with filter**
    ```
    classes keystore
    ```

- **List methods of a class**
    ```
    methods java.security.KeyStore
    ```

- **List methods of a class with filter**
    ```
    methods java.security.KeyStore load
    ```

- **Search for a method in application classes**
    Note that this can take long time, since badada search for the method name in all application classes
    ```
    searchmethod isDeviceRooted
    ```

- **Generate a Frida's hooks for all methods**
    You can use badada to generate a hook script skeleton for all methods of a specified class
    ```
    generatehooks java.security.KeyStore
    ```