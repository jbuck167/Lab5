#
# MODIFIED TO HACK CRACKME2 BY JOSH BUCK 2017
#


#---------------------------------------------------------------------
# Debug notification hook test
#
# This script start the executable and steps through the first five
# instructions. Each instruction is disassembled after execution.
#
# Author: Gergely Erdelyi <dyce@d-dome.net>
#---------------------------------------------------------------------
from idaapi import *

class MyDbgHook(DBG_Hooks):
    """ Own debug hook class that implementd the callback functions """


# Want to modify that jz (0x74) instruction to be jnz (0x75)
#
# Use PatchByte(ea, value)
# Change value of a program byte
# If debugger was active then the debugged process memory will be patched too
#
# @param ea: linear address
# @param value: new value of the byte
# @return: 1 if the database has been modified,
#          0 if either the debugger is running and the process' memory has value
#          'value' at address 'ea', or the debugger is not running, and the IDB has
#           value 'value' at address 'ea already.
#
#
    def dbg_process_start(self, pid, tid, ea, name, base, size):
        print "Process started, pid=%d tid=%d name=%s" % (pid, tid, name)
        PatchByte(0x401241, 0x75)
        return 0


    def dbg_process_exit(self, pid, tid, ea, code):
        print "Process exited pid=%d tid=%d ea=0x%x code=%d" % (pid, tid, ea, code)
        return 0

    def dbg_library_load(self, pid, tid, ea, name, base, size):
        print "Library loaded: pid=%d tid=%d name=%s base=%x" % (pid, tid, name, base)

# Need to print the entered password
#
# Going to have to set another break point somewhere where the password will be in a register
# Then read register to obtain password.
#
    def dbg_bpt(self, tid, ea):
        print "Break point at 0x%x pid=%d" % (ea, tid)
        # If the breakpoint is the one set at the password entry point
        if ea == 0x00401370:
            # esi contains the address of the entered password string
            esi = GetRegValue("esi")
            
            # use GetString(esi, -1, 0) to get the actual entered password
            entered_password = GetString(esi, -1, 0)
            
            # Print the Entered Password
            print("Entered Password is %s\n" % (entered_password))
        
        return 0

    def dbg_trace(self, tid, ea):
        print tid, ea
        return 0

    def dbg_step_into(self):
        print "Step into"
        return self.dbg_step_over()

    def dbg_step_over(self):
        eip = GetRegValue("EIP")
        print "0x%x %s" % (eip, GetDisasm(eip))

        self.steps += 1
        if self.steps >= 5:
            request_exit_process()
        else:
            request_step_over()
        return 0

# Remove an existing debug hook
try:
    if debughook:
        print "Removing previous hook ..."
        debughook.unhook()
except:
    pass

# Install the debug hook
debughook = MyDbgHook()
debughook.hook()
debughook.steps = 0

# Per instructions, must use a breakpoint. Chosen point is at the jump instruction leading to success or failure at address 0x401241
AddBpt(0x401241) # AddBpt should enable breakpoint to

AddBpt(0x00401370) # Address where ESI contains the address of the password string

# Stop at the break point
# ep = GetLongPrm(INF_START_IP)
request_run_to(0x401241)

# Step one instruction
request_step_over()

# Start debugging
run_requests()
