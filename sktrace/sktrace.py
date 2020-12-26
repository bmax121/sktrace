
"""
A instruction trace script based on Frida-Stalker.
"""

import argparse
import binascii
import json
import os
import frida

from sktracemgr import TraceMgr

__version__ = "1.0.0"

def _finish(args, device, pid, scripts):
    print('Stopping application (name={}, pid={})...'.format(
        args.target,
        pid
    ), end="")
    try:
        if args.append:
            scripts["append"].unload()
        scripts["script"].unload()
        if args.prepend:
            scripts["prepend"].unload()
        device.kill(pid)
    except frida.InvalidOperationError:
        pass
    finally:
        print("stopped.")


def _custom_script_on_message(message, data):
    print(message, data)


def _parse_args():
    parser = argparse.ArgumentParser(usage="sktrace [options] -l libname -i symbol|hexaddr target")
    parser.add_argument("-m", "--inject-method", choices=["spawn", "attach"],
                        default="spawn",
                        help="Specify how frida should inject into the process.")
    parser.add_argument("-l", "--libname", required=True, 
                        help="Specify a native library like libnative-lib.so")
    parser.add_argument("-i", "--interceptor", required=True, 
                        help="Specity a function (symbol or a hex offset address) to trace.")
    parser.add_argument("-p", "--prepend", type=argparse.FileType("r"),
                        help="Prepend a Frida script to run before sktrace does.")
    parser.add_argument("-a", "--append", type=argparse.FileType("r"),
                        help="Append a Frida script to run after sktrace has started.")
    parser.add_argument("-v", "--version", action='version',
                        version="%(prog)s " + __version__,
                        help="Show the version.")
    parser.add_argument("target",
                        help="The name of the application to trace.")
    args = parser.parse_args()

    return args



def main():
    script_file = os.path.join(os.path.dirname(__file__), "sktrace.js")
    try:
        script = open(script_file, encoding='utf-8').read()
    except:
        raise Exception("Read script error.")

    trace_mgr = TraceMgr()

    args = _parse_args()

    config = {
        "type": "config",
        "payload": {}
    }

    config["payload"]["libname"] = args.libname

    if args.interceptor.startswith("0x") or args.interceptor.startswith("0X"):
        config["payload"]["offset"] = int(args.interceptor, 16)
    else:
        config["payload"]["symbol"] = args.interceptor
    
    device = frida.get_usb_device(1)
    if args.inject_method == "spawn":
        raise Exception("working for this ...")
        pid = device.spawn([args.target])
        config["payload"]["spawn"] = True
    else:
        pid = device.get_process(args.target).pid
        config["payload"]["spawn"] = False

    session = device.attach(pid)
    scripts = {}

    if args.prepend:
        prepend = session.create_script(args.prepend.read())
        prepend.on("message", _custom_script_on_message)
        prepend.load()
        args.prepend.close()
        scripts["prepend"] = prepend

    script = session.create_script(script)
    script.on("message", trace_mgr.on_message)
    script.load()
    scripts["script"] = script

    script.post(config)

    if args.append:
        append = session.create_script(args.append.read())
        append.on("message", _custom_script_on_message)
        append.load()
        args.append.close()
        scripts["append"] = append

    if args.inject_method == "spawn":
        device.resume(pid)

    print("Tracing. Press any key to quit...")

    try:
        input()
    except KeyboardInterrupt:
        pass

    # _finish(args, device, pid, scripts)

if __name__ == '__main__':
    main()






