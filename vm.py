from idaapi import *
from idautils import *
from idc import *

TYPE_GENERAL_REGISTER = 1
TYPE_IMMEDIATE = 5

class VM(object):

  def info_registers(self):
    print "eax = ", hex(self.eax)
    print "ebx = ", hex(self.ebx)
    print "ecx = ", hex(self.ecx)
    print "edx = ", hex(self.edx)
    print "esi = ", hex(self.esi)
    print "edi = ", hex(self.edi)
    print "ebp = ", hex(self.ebp)
    print "esp = ", hex(self.esp)
    print "eip = ", hex(self.eip)
    print "efl = ", hex(self.efl)

  def set_reg(self, reg, value):
    if reg == "eax":
      self.eax = value
    if reg == "ax":
      self.eax = (self.eax & 0xFFFF0000) + (value & 0x0000FFFF)
    if reg == "ah":
      self.eax = (self.eax & 0xFFFF0000) + ((value & 0xFF) << 8) + self.eax & 0xFF
    if reg == "al":
      self.eax = (self.eax & 0xFFFFFF00) +  value & 0xFF
    if reg == "ebx":
      self.ebx = value
    if reg == "bx":
      self.ebx = (self.ebx & 0xFFFF0000) + (value & 0x0000FFFF)
    if reg == "bh":
      self.ebx = (self.ebx & 0xFFFF0000) + ((value & 0xFF) << 8) + self.ebx & 0xFF
    if reg == "bl":
      self.ebx = (self.ebx & 0xFFFFFF00) +  value & 0xFF
    if reg == "ecx":
      self.ecx = value
    if reg == "cx":
      self.ecx = (self.ecx & 0xFFFF0000) + (value & 0x0000FFFF)
    if reg == "ch":
      self.ecx = (self.ecx & 0xFFFF0000) + ((value & 0xFF) << 8) + self.ecx & 0xFF
    if reg == "cl":
      self.ecx = (self.ecx & 0xFFFFFF00) +  value & 0xFF
    if reg == "edx":
      self.edx = value
    if reg == "dx":
      self.edx = (self.edx & 0xFFFF0000) + (value & 0x0000FFFF)
    if reg == "dh":
      self.edx = (self.edx & 0xFFFF0000) + ((value & 0xFF) << 8) + self.edx & 0xFF
    if reg == "dl":
      self.edx = (self.edx & 0xFFFFFF00) +  value & 0xFF
    if reg == "esi":
      self.esi = value 
    if reg == "si":
      self.esi = (self.esi & 0xFFFF0000) + (value & 0x0000FFFF)
    if reg == "edi":
      self.edi = value
    if reg == "di":
      self.edi = (self.edi & 0xFFFF0000) + (value & 0x0000FFFF)
    if reg == "ebp":
      self.ebp = value 
    if reg == "bp":
      self.ebp = (self.ebp & 0xFFFF0000) + (value & 0x0000FFFF)
    if reg == "esp":
      self.esp = value 
    if reg == "sp":
      self.esp = (self.esp & 0xFFFF0000) + (value & 0x0000FFFF)
    if reg == "eip":
      self.eip = value 
    if reg == "ip":
      self.eip = (self.eip & 0xFFFF0000) + (value & 0x0000FFFF)

  def get_reg(self, reg):
    if reg == "eax":
      return self.eax
    if reg == "ax":
      return self.eax & 0xFFFF
    if reg == "ah":
      return self.eax & 0xFF00
    if reg == "al":
      return self.eax & 0x00FF
    if reg == "ebx":
      return self.ebx
    if reg == "bx":
      return self.ebx & 0xFFFF
    if reg == "bh":
      return self.ebx & 0xFF00
    if reg == "bl":
      return self.ebx & 0x00FF
    if reg == "ecx":
      return self.ecx
    if reg == "cx":
      return self.ecx & 0xFFFF
    if reg == "ch":
      return self.ecx & 0xFF00
    if reg == "cl":
      return self.ecx & 0x00FF
    if reg == "edx":
      return self.edx
    if reg == "dx":
      return self.edx & 0xFFFF
    if reg == "dh":
      return self.edx & 0xFF00
    if reg == "dl":
      return self.edx & 0x00FF
    if reg == "esi":
      return self.esi
    if reg == "si":
      return self.esi & 0xFFFF
    if reg == "edi":
      return self.edi
    if reg == "di":
      return self.edi & 0xFFFF
    if reg == "ebp":
      return self.ebp
    if reg == "bp":
      return self.ebp & 0xFFFF
    if reg == "esp":
      return self.esp
    if reg == "sp":
      return self.esp & 0xFFFF
    if reg == "eip":
      return self.eip
    if reg == "ip":
      return self.eip & 0xFFFF


  def get_val_opnd2(self, opnd2):
    if GetOpType(self.eip, 1) == TYPE_GENERAL_REGISTER:
      opnd2val = self.get_reg(opnd2)
    elif GetOpType(self.eip, 1) == TYPE_IMMEDIATE:
      opnd2val = GetOperandValue(self.eip, 1)

    return opnd2val

  def MOV(self, opnd1, opnd2):
    opnd2val = self.get_val_opnd2(opnd2)

    self.set_reg(opnd1, opnd2val)

  def NOT(self, opnd1):
    self.set_reg(opnd1, int(~self.get_reg(opnd1) & self.mask_32))

  def ADD(self, opnd1, opnd2):
    opnd2val = self.get_val_opnd2(opnd2)
    res = (self.get_reg(opnd1) + opnd2val) & self.mask_32
    self.set_reg(opnd1, res)

  def SUB(self, opnd1, opnd2):
    opnd2val = self.get_val_opnd2(opnd2)
    res = (self.get_reg(opnd1) - opnd2val) & self.mask_32
    self.set_reg(opnd1, res)

  def XOR(self, opnd1, opnd2):
    opnd2val = self.get_val_opnd2(opnd2)
    res = (self.get_reg(opnd1) ^ opnd2val) & self.mask_32
    self.set_reg(opnd1, res)

  def readInst(self):
    inst = GetMnem(self.eip)
    opnd1 = GetOpnd(self.eip, 0)
    opnd2 = GetOpnd(self.eip, 1)

    print "[0x%x] %s %s %s" % (self.eip, inst, opnd1, opnd2) 

    if inst == "mov":
      self.MOV(opnd1, opnd2)
    elif inst == "not":
      self.NOT(opnd1)
    elif inst == "add":
      self.ADD(opnd1, opnd2)
    elif inst == "sub": 
      self.SUB(opnd1, opnd2)
    elif inst == "xor":
      self.XOR(opnd1, opnd2)


    self.eip = NextHead(self.eip, self.current_bb.endEA)


  def __init__(self, bb):
    self.const_null = 0x00000000
    self.current_bb = bb
    self.eip = bb.startEA
    self.eax = self.const_null
    self.ebx = self.const_null
    self.ecx = self.const_null
    self.edx = self.const_null
    self.esi = self.const_null
    self.edi = self.const_null
    self.ebp = self.const_null
    self.esp = self.const_null
    self.efl = self.const_null
    self.mask_32 = 0xFFFFFFFF
    
