from idaapi import *
from vm import *

start = 0x5a8383
ptr_bb = None

fc = idaapi.FlowChart(idaapi.get_func(start))
for bb in fc:
  if bb.startEA == start:
    ptr_bb = bb

if ptr_bb == None:
  print "Impossible to locate the BB"


vm = VM(ptr_bb)
vm.readInst()
vm.readInst()
vm.readInst()
vm.readInst()
vm.readInst()
vm.readInst()
vm.readInst()
vm.readInst()
vm.readInst()
vm.readInst()
vm.readInst()
vm.readInst()
vm.readInst()
vm.readInst()
vm.info_registers()

'''
start = 0x005A8383
print "begin_tab"

jmp_table = 0x54f184
for i in string.printable:
  print hex(Dword(jmp_table+ord(i)*4))

'''
