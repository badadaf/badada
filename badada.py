#!/usr/bin/env python
# -*- coding: utf-8 -*- 

import argparse
import frida
import sys
import time
import subprocess
import os
import signal
import cmd

class FridaProcess():
    def __init__(self, args = ['adb shell /data/local/tmp/frida-server', 'adb shell killall frida-server']):
        self.start_args = args[0]
        self.stop_args = args[1]
        self.process = None

    def run(self):
        print '[*] Starting Frida server'
        self.process = subprocess.Popen(self.start_args, stdin=subprocess.PIPE, shell=True, preexec_fn=os.setsid)
        time.sleep(1)
        
    def terminate(self):
        os.killpg(os.getpgid(self.process.pid), signal.SIGTERM)
        time.sleep(1)
        print '[*] Terminated Frida server.'

    def pool(self):
        if self.process is not None:
            return self.process.pool()
        
        return None

class BadadaShell(cmd.Cmd):

    defaultRPCMethods = None
    args = None
    session = None
    script = None
    log = None
    usbDevice = None

    def __init__(self):

        cmd.Cmd.__init__(self)

        self.aliases = {
            'exit'  : self.do_quit
        }

        parser = argparse.ArgumentParser(description='Badada arguments')
        parser.add_argument('processToHook', help='Name of the process to be attached')
        parser.add_argument('--javascript', help='Path to javascript code file to inject')
        parser.add_argument('--log', help='Save output to path')
        parser.add_argument('--gadget', action='store_true', help='Search for the gadget instead of frida-server')
        self.args = parser.parse_args()
        self.log = self.args.log

        print '\033[1m' + '\033[94m' + """                 ____          _____          _____          
                |  _ \   /\   |  __ \   /\   |  __ \   /\    
                | |_) | /  \  | |  | | /  \  | |  | | /  \   
                |  _ < / /\ \ | |  | |/ /\ \ | |  | |/ /\ \  
                | |_) / ____ \| |__| / ____ \| |__| / ____ \ 
                |____/_/    \_\_____/_/    \_\_____/_/    \_\\        
            """ + '\033[0m'

        print '[*] Ensuring adb server is running'    
        subprocess.call(['adb', 'start-server'])
  
        if not self.args.gadget:
            if subprocess.check_output(['adb shell "[ -f /data/local/tmp/frida-server ]; echo \\$?"'], shell=True).strip() is not '0':
                print '[-] frida-server does not exist in /data/local/tmp/frida-server'
                sys.exit(0)

            self.frida_server = FridaProcess()
            self.frida_server.run()
        
        print '[*] Attaching USB Device'

        try:
            self.usbDevice = frida.get_usb_device(2) # timeout = 2

        except frida.TimedOutError:
            print '[-] Failed to attach to USB Device.'
            sys.exit(1)

        if(not self.usbDevice):
            print '[-] Failed to attach to USB Device.'
            sys.exit(1)
        
        try:
            # If is digit, attach to pid
            if self.args.processToHook.isdigit():
                print '[*] Attaching to ' + self.args.processToHook + " pid"
                self.session = self.usbDevice.attach(int(self.args.processToHook))
            else:
                print '[*] Attaching to ' + self.args.processToHook + " process"
                self.session = self.usbDevice.attach(self.args.processToHook)

        except frida.ServerNotRunningError:
            print '[-] Unable to connect to frida-server.'
            sys.exit(1)

        except frida.ProcessNotFoundError:
            print '[-] Unable to find ' + self.args.processToHook + ' to attach.'
            sys.exit(1)


        print '[*] Loading default RPC methods'
        self.defaultRPCMethods = self.loadScript(os.path.join(os.path.dirname(__file__), 'scripts/', 'scriptsRPC.js'), self.session)
        self.script = None

        if self.args.javascript:
            print '[*] Loading %s' %(self.args.javascript) 
            try:
                self.script = self.loadScript(self.args.javascript, self.session)
            except IOError as e:
                print '[-] Unable to load script "' + self.args.javascript + '": file not found.'
                self.script = None
                self.args.javascript = None


    def startOrStopFridaServer(self, status):
        if status is 'start':
            subprocess.call(['adb', 'shell', '"/data/local/tmp/frida-server"', '"&"'])
        elif status is 'stop':
            subprocess.call("adb shell kill -9 \`pidof frida-server\`")

    def emptyline(self):
        pass

    def default(self, line):
        command, arg, line = self.parseline(line)
        if command in self.aliases:
            self.aliases[command](arg)
        else:
            print '[-] Command not found'

    def getFileContents(self, fileName):
        f = open(fileName)
        content = f.read()
        f.close()

        return content

    def onMessage(self, message, data):
        if 'payload' in message.keys():
            if self.log:
                logF = file("logs/" + self.log, 'a')
                logF.write(str(time.asctime()))
                logF.write(" ---> ")
                logF.write(str(message['payload']) + '\n')
                logF.close()
            sys.stdout.write(str(message['payload']) + '\n')
        else:
            if self.log:
                logF = file("logs/" + self.log, 'a')
                logF.write(str(time.asctime()))
                logF.write(" ---> ")
                logF.write(str(message) + '\n')
                logF.close()
            sys.stdout.write(str(message) + '\n')

    def loadScript(self, fileName, session):
        hookSource = self.getFileContents(fileName)
        self.script = self.session.create_script(hookSource)
        self.script.on('message', self.onMessage)
        self.script.load()

        return self.script

    def getClasses(self, containsText, defaultRPCMethods):
        self.defaultRPCMethods.exports.getclasses(containsText)

    def getMethodsWithSignature(self, className, containsText, defaultRPCMethods):
        self.defaultRPCMethods.exports.getmethods(className, containsText)

    def searchMethod(self, methodName, defaultRPCMethods):
        self.defaultRPCMethods.exports.searchmethod(methodName)

    def do_quit(self, inArgs):
        if self.defaultRPCMethods:
            print '[*] Unloading default RPC methods'
            self.defaultRPCMethods.unload()
            self.defaultRPCMethods = None

        if self.script:
            print '[*] Unloading current script...'
            self.script.unload()
            self.script = None

        print '[*] Detaching current session.'
        self.session.detach()
        
        if not self.args.gadget:
            self.frida_server.terminate()
    
        print '[*] Exiting...\n' + '[*] Thanks for using Badada! ' + 'Bye \\o/'
        raise SystemExit

    def help_quit(self):
        print '\n'.join(['Exit Frida'])

    def do_reload(self, inArgs):
        if not self.args.javascript:
            print '[*] There is no script to reload.'
            return
        
        if self.script:
            print '[*] Unloading current script...'
            self.script.unload()
            self.script = None

        print '[*] Reloading %s' %(self.args.javascript)
        try:
            self.script = self.loadScript(self.args.javascript, self.session)
        except IOError as e:
            print '[-] Unable load script "' + self.args.javascript + '": file not found.'
            self.script = None

    def help_reload(self):
        print '\neloads current script for changes\n'

    def do_ls(self, inArgs):
        os.system('ls ' + inArgs)

    def do_load(self, inArgs):
        args = inArgs.strip().split(" ")
        if(len(args) != 1 or len(args[0]) == 0):
            print '\n[-] Usage load [<script.js>]\n'

        else:
            if self.args.javascript:
                print '[*] Unloading current script...'
                self.script.unload()
                self.script = None
            
            print '[*] Loading new script...'
            self.args.javascript = args[0]
            
            try:
                self.script = self.loadScript(self.args.javascript, self.session)
            except IOError as e:
                print '[-] Unable load script "' + self.args.javascript + '": file not found.'
                self.script = None

    def help_load(self):
        print '\nLoads a javascript code to be injected.\n'

    def do_getclasses(self, inArgs):
        args = inArgs.strip().split(" ")
        if(len(args) > 1):
                print '\n[-] Usage getclasses [<contains_this>]'

        elif(len(args) == 0):
            self.getClasses('', self.defaultRPCMethods)

        else:
            self.getClasses(args[0], self.defaultRPCMethods)

    def help_getclasses(self):
        print '\n'.join(['Show all classes filtered by [<contains_this>]'])

    def do_getmethods(self, inArgs):
        args = inArgs.strip().split(" ")
        if(len(args) < 1):
            print '\n[-] Usage: getmethods <className> [<contains_this>]\n'

        elif(len(args) == 1):
           self.getMethodsWithSignature(args[0], "", self.defaultRPCMethods)
        else:
            self.getMethodsWithSignature(args[0], args[1], self.defaultRPCMethods)

    def help_getmethods(self):
        print '\n'.join(['Show all methods from <class_name> [<contains_this>]'])

    def do_clear(self, inArgs):
        os.system('cls||clear')

    def help_clear(self):
        print '\n'.join(['Clears the terminal screen.'])

    def do_hook(self, inArgs):
        args = inArgs.strip().split(" ")
        if(len(args) < 1 or len(args[0]) == 0):
            print '\n[-] Usage hook <process_to_hook>\n'

        else:
            
            if self.defaultRPCMethods:
                print '[*] Unloading default RPC methods'
                self.defaultRPCMethods.unload()
                self.defaultRPCMethods = None

            if self.args.javascript:
                print '[*] Unloading current script...'
                self.script.unload()
                self.script = None

            print '[*] Detaching current session.'
            self.session.detach()

            print '[*] Attaching to ' + args[0] + '.'

            try:
                self.session = self.usbDevice.attach(args[0])
                self.defaultRPCMethods = self.loadScript(os.path.join(os.path.dirname(__file__), 'scripts/', 'scriptsRPC.js'), self.session)
                self.args.javascript = None
            except frida.ServerNotRunningError:
                print '[-] Unable to connect to frida-server.'
                sys.exit(1)
            except frida.ProcessNotFoundError:
                print '[-] Unable to find the process to attach.'

    def help_hook(self):
        print '\n'.join(['Hooks a new process'])


if __name__ == '__main__':
    prompt = BadadaShell()
    prompt.prompt = '\033[1m' + '\033[92m' + 'badada> ' + '\033[0m'
    try:
        prompt.cmdloop()
    except KeyboardInterrupt as e:
        print ''
        prompt.do_quit(None)
