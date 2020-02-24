#!/usr/bin/env python3
import frida
import sys
import pickle
import struct

# This script is based on the examples of Frida to use on_message
# https://frida.re/docs/examples/android/
# And the tutorial to spawn a process from Python
# https://awakened1712.github.io/hacking/hacking-frida/

# This is the JavaScript piece of code that will be injected in the running process
ss = """
Java.perform(function () {
    // Based on https://awakened1712.github.io/hacking/hacking-frida/
    // Example called: Android: Hook constructor method of SecretKeySpec to print out the key byte array
    // Thanks a lot!
    var ZstdDictDecompress = Java.use('com.github.luben.zstd.ZstdDictDecompress');
    ZstdDictDecompress.$init.overload('[B').implementation = function(p0) {
        console.log('ZstdDictDecompress.$init("' + bytes2hex(p0) + '")');
        return this.$init(p0);
    };
});
function bytes2hex(array) {
    var result = '';
    var arrayresult = [];
    console.log('len = ' + array.length);
    for(var i = 0; i < array.length; ++i){
        if(i%500 == 0){
            console.log('Progress: ' + i/array.length * 100.0 + ' %');
        }
        // result += ('0' + (array[i] & 0xFF).toString(16)).slice(-2);
        // Faster version (the ever-increasing string took forever)
        // Just pushing to an array and joining it together in the end
        // Note the & 0xff because of: https://reverseengineering.stackexchange.com/questions/17835/print-b-byte-array-in-frida-js-script
        arrayresult.push(String.fromCharCode(array[i] & 0xff));
    }
    console.log("Sending results...");
    send(arrayresult)
    result = arrayresult.join("");

    return result;
}
"""

# Called get_usb_device, but in reality we are connecting to the emulator
# Needs that we have done 'adb connect 192.168.0.15' (or your IP)
# to your VM, the VM, if using VirtualBox, needs to have the network setup as bridging
# to have an IP we can access
device = frida.get_usb_device()
# We spawn the Mario Kart app, I found the name of the app when opening it
# and doing frida-ps -U | grep nintendo
pid = device.spawn(["com.nintendo.zaka"])
session = device.attach(pid)
script = session.create_script(ss)


def on_message(message, data):
    # This will be the callback when in JS code we use the function 'send'
    # To send the dictionary in raw bytes back here
    try:
        if message:
            print(message)

            # To be able to play with the raw message offline
            pickle.dump(message, open('message.pickle', 'wb'))
            pickle.dump(data, open('data.pickle', 'wb'))
            # Write the dictionary file
            with open('zdict', 'wb') as f:
                for byte in message['payload']:
                    f.write(struct.pack('B', ord(byte)))
            print("Done")

    except Exception as e:
        print("Exception: " + e)


# Setting up the callback
script.on('message', on_message)
script.load()
# Letting the app run
device.resume(pid)
# Keeping the script alive so we can receive the callback
sys.stdin.read()