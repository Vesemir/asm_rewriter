import pefile
import capstone as cs
import sys
import os
import struct
import copy


from collections import OrderedDict

MACHINE_WORD_SIZE = 4


# maps address to library function name and library name
IMPORT_SECTION_FUNCS = {}

# maps address to function assembler code and pseudoname
# e.g. {0x11000: {'name': 'sub_11000', 'code': {0x11111: ['mov', 'eax, ebx']}}}
KNOWN_FUNCS = {}

X86_REGS = ('eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp')



def print_asm(outfile, asm_description):
    with open(outfile, 'wb') as outp:
        for func in IMPORT_SECTION_FUNCS.values():
            outp.write('extern {}\n'.format(func['name']))
            outp.write('import {} {}\n'.format(func['name'], func['lib']))
        outp.write('section .text \n')
        for func in asm_description.values():
            outp.write('\n global {}\n\n{}:\n{}'.format(
                func['name'], func['name'],
                '\n'.join(' '.join(each for each in line) for line in func['code'].values()))
            )
    print('[+] Done dumping asm !')


def postproces_defs(func_arr):
    inst_with_labels = {}
    for func in func_arr.values():
        for addr, inst in copy.deepcopy(func['code'].items()):
            if inst[0] == 'call':
                try:
                    # try handling local functions in ".text"
                    call_target = int(inst[1], 16)
                    if call_target in KNOWN_FUNCS:
                        func['code'][addr][1] = KNOWN_FUNCS[call_target]['name']
                except Exception as ex:
                    #todo handle import calls
                    pass
            elif inst[0].startswith('j'):
                addr_to_jump = int(inst[1], 16)
                if addr_to_jump in func['code']:
                    lbl_name = 'loc_{}'.format(hex(addr_to_jump)[2:])
                    if addr_to_jump not in inst_with_labels:
                        # create label on target instruction
                        inst_with_labels[addr_to_jump] = lbl_name
                        func['code'][addr_to_jump].insert(0, '{}:\n'.format(lbl_name))
                    func['code'][addr][1] = lbl_name
                else:
                    # only happens on cross-functions jump ; for now just jump on return
                    addr_to_jump = func['code'].keys()[-1]
                    if addr_to_jump not in inst_with_labels:
                        lbl_name = 'loc_{}'.format(hex(addr_to_jump)[2:])
                        inst_with_labels[addr_to_jump] = lbl_name
                        func['code'][addr_to_jump].insert(0, '{}:\n'.format(lbl_name))
                    func['code'][addr][1] = lbl_name
                    
        #  just wanna print readable text for now
        #  can't do it in earlier cycle cause we potentially put labels on earlier addresses
        for addr, inst in func['code'].items():
            real_pos = 1 if addr in inst_with_labels else 0
            func['code'][addr][real_pos] = 4 * ' ' + func['code'][addr][real_pos]
            #if real_pos:
            #    assert False, func['code'][addr]
                   
                
class FuncDisasm:
    def __init__(self, binary, entry_point, image_base,
                 sections_arr):
        self.disasmer = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_32)
        self.disasmer.detail = True
        self.binary = binary
        self.entry_point = entry_point
        self.image_base = image_base
        self.regs = {each: 0 for each in X86_REGS}
        self.sections_arr = sections_arr

    def handle_possible_args(self, inst):
        found_arg = False
        new_op_str = None
        
        for idx, oper in enumerate(inst.operands):
            if oper.type == cs.x86.X86_OP_MEM and\
               oper.value.mem.base == cs.x86.X86_REG_EBP and\
               not oper.value.mem.index and oper.value.mem.disp > 0:
                new_opers = [None, None]
                found_arg = True
                new_opers[idx] = '[{} + arg_{}]'.format(
                        inst.reg_name(oper.value.mem.base),
                        oper.value.mem.disp - 2 * MACHINE_WORD_SIZE # one for saved ebp, two for saved eip
                        )
                if len(inst.operands) > 1:
                    new_opers[(idx + 1) % 2] = inst.reg_name(inst.operands[1-idx].reg)
                    new_op_str = ', '.join(new_opers)
                else:
                    new_op_str = new_opers[0]

        if not found_arg:
            return inst.op_str
        # should never be none
        assert new_op_str is not None
        return new_op_str

    def in_proper_data_section(self, addr):
        for section_name, section_start, section_size in self.sections_arr:
            if section_start + self.image_base <= addr <= section_start + section_size + self.image_base:
                print('[!] Found in section "{}"'.format(section_name))
                return True
        return False

    def run(self):
        function_code = OrderedDict()
        for inst in self.disasmer.disasm(self.binary[self.entry_point:],
                                         self.image_base + self.entry_point):
            addr, mnemonic, op_string = hex(inst.address)[:-1], inst.mnemonic, inst.op_str
            # nasm-specific preprocessing cause we gonna use it to compile again
            if mnemonic == 'lea':
                op_string = op_string.replace('dword', '')
            # generated disasm code for string instructions is too verbose and not understood
            if any(mnemonic.startswith(prefix) for prefix in ('rep', 'movs')):
                op_string = ''
            function_code[inst.address] = [mnemonic, op_string.replace('ptr', '')]
            op_string = self.handle_possible_args(inst)
            print addr, mnemonic, op_string

            if inst.mnemonic == 'jmp':
                ops = inst.operands
                for each in inst.operands:
                    if each.type == cs.x86.X86_OP_MEM:
                        if each.value.mem.disp in IMPORT_SECTION_FUNCS:
                            print('call {}'.format(
                                IMPORT_SECTION_FUNCS[each.value.mem.disp]['name']
                                )
                            )
                        else:
                            print('jump to unknown constant memory displacement : {}'.format(
                                hex(each.value.mem.disp)
                                )
                            )
                        return # because we are inside dumb inst cycle
                #assert False
            if inst.mnemonic == 'mov':
                if inst.operands[0].type == cs.x86.X86_OP_REG:
                    first_reg_name = inst.reg_name(inst.operands[0].value.reg)
                    if inst.operands[1].type == cs.x86.X86_OP_REG:
                        self.regs[first_reg_name] = self.regs[inst.reg_name(inst.operands[1].value.reg)]
                    elif inst.operands[1].type == cs.x86.X86_OP_MEM and not inst.operands[1].value.mem.base and not inst.operands[1].value.mem.index:
                        if self.in_proper_data_section(inst.operands[1].value.mem.disp + self.image_base):                                           
                            # mem in data section
                            value = struct.unpack('<I',
                                                  self.binary[inst.operands[1].value.mem.disp - self.image_base:
                                                              inst.operands[1].value.mem.disp - self.image_base + MACHINE_WORD_SIZE]
                                                  )[0]
                            self.regs[first_reg_name] = value
                                                        
                    # else some arg/var or whatever manipulations, not gonna do this now
                    
            if inst.mnemonic == 'ret':
                break
            elif inst.mnemonic == 'call':
                if inst.operands[0].type == cs.x86.X86_OP_MEM:
                    external_call_addr = inst.operands[0].value.mem.disp
                    if external_call_addr in IMPORT_SECTION_FUNCS:
                        print('call {}'.format(
                                IMPORT_SECTION_FUNCS[external_call_addr]['name']
                                )
                            )
                    else:
                        print('call to unknown addresss : {}'.format(hex(external_call_addr)))
                elif inst.operands[0].type == cs.x86.X86_OP_REG:
                    reg_val = self.regs[inst.reg_name(inst.operands[0].value.reg)]
                    if reg_val in IMPORT_SECTION_FUNCS:
                        print('call {}'.format(
                                IMPORT_SECTION_FUNCS[reg_val]['name']
                                )
                            )
                    else:
                        assert False, 'call by register using not-imported function'
                else:
                    # some local function we didn't disassemble yet
                    new_ep = int(inst.op_str, 16) - self.image_base
                    if self.image_base + new_ep not in KNOWN_FUNCS:
                        nested_func = FuncDisasm(self.binary, new_ep, self.image_base,
                                                 self.sections_arr)
                        print('[!] Inside nested function!')
                        nested_func.run()
                        print('[!] Outside nested function')
                    else:
                        print('[!] call {}'.format(KNOWN_FUNCS[new_ep + self.image_base]['name']))
        KNOWN_FUNCS[self.entry_point + self.image_base] = {
            'code': function_code,
            'name': 'sub_{}'.format(hex(self.entry_point + self.image_base)[2:])
        }

file_location = r"D:\Job\2017_crack\crackme"
mydriver = pefile.PE(file_location)
assert mydriver.is_driver()

required_function_rva = 0xda

text_base_address = -1
sections_triplet = []
print('[!] Section info: ')
for section in mydriver.sections:
    print section.Name,\
          hex(mydriver.OPTIONAL_HEADER.ImageBase + section.VirtualAddress),\
          hex(section.Misc_VirtualSize)
    sections_triplet.append((
        section.Name,
        mydriver.OPTIONAL_HEADER.ImageBase + section.VirtualAddress,
        section.Misc_VirtualSize
    ))
    if section.Name.startswith('.text'):
        text_base_address = section.VirtualAddress
    

whole_image = bytearray(mydriver.get_memory_mapped_image())

for entry in mydriver.DIRECTORY_ENTRY_IMPORT:
    print 'Parsing imports from "{}"'.format(entry.dll)
    for imp in entry.imports:
        print('[!] Took "{}" on {}'.format(imp.name, hex(imp.address)))
        IMPORT_SECTION_FUNCS[imp.address] = {'name': imp.name, 'lib': entry.dll}
        whole_image[imp.address - mydriver.OPTIONAL_HEADER.ImageBase:
                    imp.address - mydriver.OPTIONAL_HEADER.ImageBase + MACHINE_WORD_SIZE] = \
                    struct.pack('<I', imp.address)
        
if text_base_address < 0 :
    print('[-] Couldn\'t find text section!')
    sys.exit(1)
print('[!] Text section  base address: {}'.format(hex(text_base_address)))

start_disas_addr = text_base_address + required_function_rva
assert whole_image[start_disas_addr:start_disas_addr+4] == '\x8b\xff\x55\x8b'

func_disasm = FuncDisasm(binary=bytes(whole_image), entry_point=start_disas_addr,
                         image_base=mydriver.OPTIONAL_HEADER.ImageBase,
                         sections_arr=sections_triplet)
func_disasm.run()
postproces_defs(KNOWN_FUNCS)

print_asm('myresult_result.asm', KNOWN_FUNCS)
