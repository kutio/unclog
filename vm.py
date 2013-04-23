from idaapi import *
from idautils import *
from idc import *
from struct import *
import re

TYPE_GENERAL_REGISTER = 1
TYPE_MEMORY_REFERENCE = 2
TYPE_BASE_INDEX = 3
TYPE_IMMEDIATE = 5

class VM(object):

  def little_endian_to_big_endian(self, value):
    return unpack(">I", pack("<I", value))[0]

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
      old_value = self.eax
      self.eax = (old_value & 0xFFFF0000) + (value & 0x0000FFFF)
    if reg == "ah":
      old_value = self.eax
      self.eax = (old_value & 0xFFFF0000) + ((value & 0xFF) << 8) + old_value & 0xFF
    if reg == "al":
      old_value = self.eax
      self.eax = (old_value & 0xFFFFFF00) +  value & 0xFF
    if reg == "ebx":
      self.ebx = value
    if reg == "bx":
      old_value = self.ebx
      self.ebx = (old_value & 0xFFFF0000) + (value & 0x0000FFFF)
    if reg == "bh":
      old_value = self.ebx
      self.ebx = (old_value & 0xFFFF0000) + ((value & 0xFF) << 8) + old_value & 0xFF
    if reg == "bl":
      old_value = self.ebx
      self.ebx = (old_value & 0xFFFFFF00) +  value & 0xFF
    if reg == "ecx":
      self.ecx = value
    if reg == "cx":
      old_value = self.ecx
      self.ecx = (old_value & 0xFFFF0000) + (value & 0x0000FFFF)
    if reg == "ch":
      old_value = self.ecx
      self.ecx = (old_value & 0xFFFF0000) + ((value & 0xFF) << 8) + (old_value & 0xFF)
    if reg == "cl":
      old_value = self.ecx
      self.ecx = (old_value & 0xFFFFFF00) +  value & 0xFF
    if reg == "edx":
      self.edx = value
    if reg == "dx":
      old_value = self.edx
      self.edx = (old_value & 0xFFFF0000) + (value & 0x0000FFFF)
    if reg == "dh":
      old_value = self.edx
      self.edx = (old_value & 0xFFFF0000) + ((value & 0xFF) << 8) + old_value & 0xFF
    if reg == "dl":
      old_value = self.edx
      self.edx = (old_value & 0xFFFFFF00) +  value & 0xFF
    if reg == "esi":
      self.esi = value 
    if reg == "si":
      old_value = self.esi
      self.esi = (old_value & 0xFFFF0000) + (value & 0x0000FFFF)
    if reg == "edi":
      self.edi = value
    if reg == "di":
      old_value = self.edi
      self.edi = (old_value & 0xFFFF0000) + (value & 0x0000FFFF)
    if reg == "ebp":
      self.ebp = value 
    if reg == "bp":
      old_value = self.ebp
      self.ebp = (old_value & 0xFFFF0000) + (value & 0x0000FFFF)
    if reg == "esp":
      self.esp = value 
    if reg == "sp":
      old_value = self.esp
      self.esp = (old_value & 0xFFFF0000) + (value & 0x0000FFFF)
    if reg == "eip":
      self.eip = value 
    if reg == "ip":
      old_value = self.eip
      self.eip = (old_value & 0xFFFF0000) + (value & 0x0000FFFF)

  def get_reg(self, reg):
    if reg == "eax":
      return self.eax
    if reg == "ax":
      return self.eax & 0xFFFF
    if reg == "ah":
      return (self.eax & 0xFF00) >> 8
    if reg == "al":
      return self.eax & 0x00FF
    if reg == "ebx":
      return self.ebx
    if reg == "bx":
      return self.ebx & 0xFFFF
    if reg == "bh":
      return (self.ebx & 0xFF00) >> 8
    if reg == "bl":
      return self.ebx & 0x00FF
    if reg == "ecx":
      return self.ecx
    if reg == "cx":
      return self.ecx & 0xFFFF
    if reg == "ch":
      return (self.ecx & 0xFF00) >> 8
    if reg == "cl":
      return self.ecx & 0x00FF
    if reg == "edx":
      return self.edx
    if reg == "dx":
      return self.edx & 0xFFFF
    if reg == "dh":
      return (self.edx & 0xFF00) >> 8
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

    return None

  def parse_mem(self, opnd2):
    addr = GetOperandValue(self.eip, 1)
    m = re.search(r"\[(.*?)\]+", opnd2)
    final_addr = addr
    if m != None:
      sub_opnd2 = m.group(1)
      # get reg and displacement
      m = re.split(r"\*", sub_opnd2)
      reg =  m[0]
      displacement = m[1]
      final_addr = (addr + self.get_reg(reg) * int(displacement))

    return final_addr
 
    
  def parse_phrase(self, opnd2):
    reg = re.sub(r"\[|\]", "", opnd2)
    val = self.get_reg(reg)
    if val == None:
      # index is memory
      val = int(new_opnd2, 16)
    return val
 
  def get_val_opnd2(self, opnd2):
    if GetOpType(self.eip, 1) == o_reg:
      opnd2val = self.get_reg(opnd2)
    elif GetOpType(self.eip, 1) == o_mem:
      opnd2val = self.parse_mem(opnd2)
    elif GetOpType(self.eip, 1) == o_phrase: 
      val = self.parse_phrase(opnd2)
      opnd2val = Dword(val)
    elif GetOpType(self.eip, 1) == o_imm:
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

  def DEC(self, opnd1):
    self.set_reg(opnd1, int((self.get_reg(opnd1) - 1) & self.mask_32))

  def LEA(self, opnd1, opnd2):
    opnd2val = self.get_val_opnd2(opnd2)
    self.set_reg(opnd1, int(opnd2val & self.mask_32))

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
    elif inst == "dec":
      self.DEC(opnd1)
    elif inst == "lea":
      self.LEA(opnd1, opnd2)

    self.eip = NextHead(self.eip, self.current_bb.endEA)


  def __init__(self, bb):
    self.current_bb = bb
    self.eip = bb.startEA
    self.eax = 0x1
    self.ebx = 0x6
    self.ecx = 0x0
    self.edx = 0x31
    self.esi = 0x1
    self.edi = 0x0
    self.ebp = 0x0018FA18
    self.esp = 0x0018F9C4
    self.efl = 0x202

    self.mask_32 = 0xFFFFFFFF
    
