import pefile
import capstone as cs
import sys
import os
import struct
import string
import copy
import argparse
import logging


from collections import OrderedDict

MACHINE_WORD_SIZE = 4
PRINTABLE_CHARS = set(string.printable)

# maps address to library function name and library name
IMPORT_SECTION_FUNCS = {}
USED_IMPORT_FUNCS = set()

# maps address to function assembler code and pseudoname
# e.g. {0x11000: {'name': 'sub_11000', 'code': {0x11111: ['mov', 'eax, ebx']}}}
KNOWN_FUNCS = {}
KNOWN_STRINGS = {}

X86_REGS = ('eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp')

extra_extern = '''
extern _VirtualAlloc@16
extern _VirtualFree@12
extern _RtlFillMemory@12
extern _RtlMoveMemory@12
'''

extra_trampoline_functions = '''
global pop1_pre_malloc
global pop1_post_free
global rtl_fill_trampoline
global rtl_move_trampoline
global start_func

start_func:
    lea eax, [password]
    push eax
    lea eax, [login]
    push eax
    call sub_110da

login: db 'XXXXXXXXX@XXXXXX.XX',0
password: db '12345678901234567890123456789012',0


pop1_pre_malloc:
    pop edx
    pop ecx
    pop ecx
    
    mov eax, 0x40 ; RWX
    push eax
    
    mov eax, 0x3000; MEM_COMMIT | MEM_RESERVER
    push eax

    push ecx ; should be size
       
    xor eax, eax
    push eax ; allocation_target
    push edx
        
    jmp _VirtualAlloc@16
pop1_post_free:
    pop edx
    pop ecx
    pop eax
    mov eax, 0x8000
    push eax
    xor eax, eax
    push eax
    push ecx
    push edx
    jmp _VirtualFree@12
rtl_fill_trampoline:
    mov eax, [esp-0x8]
    mov ecx, [esp-0xc]
    xor eax, ecx
    xor ecx, eax
    xor eax, ecx
    mov [esp-0x8], eax
    mov [esp-0xc], ecx
    jmp _RtlFillMemory@12
rtl_move_trampoline:
    pop eax
    mov [temp_var], eax
    call _RtlMoveMemory@12
    sub esp, 0xc
    mov ecx, [temp_var]
    push ecx
    ret
'''

extra_data = '''
section .data
    temp_var: db 'AAAA',0
    str_12068 db 128,{}
'''.format(','.join('0' * 63))

func_to_replace = {
    'ExAllocatePool': 'pop1_pre_malloc',
    'ExFreePoolWithTag': 'pop1_post_free',
    'memset': 'rtl_fill_trampoline',
    'memcpy': 'rtl_move_trampoline'
}


def cut_string_from_dump(data, string_start):
    start = string_start
    idx = 0
    while True:
        next_byte = data[start + idx]
        if next_byte == '\x00':
            break
        idx += 1
    return data[start:start + idx]


def print_asm(outfile, asm_description, logger):
    with open(outfile, 'wb') as outp:
        for name, contents in KNOWN_STRINGS.items():
            outp.write("{}: db '{}',0\n".format(name, contents))
        for addr, func in IMPORT_SECTION_FUNCS.items():
            if addr in USED_IMPORT_FUNCS and func['name'] not in func_to_replace.values():
                outp.write('extern {}\n'.format(func['name']))
                # need to use -f win32 and it works without import with external linker
                #outp.write('import {} {}\n'.format(func['name'], func['lib']))
        outp.write(extra_extern)
        outp.write('section .text \n')
        outp.write(extra_trampoline_functions)
        for func in asm_description.values():
            outp.write('\n global {}\n'.format(func['name']))
        # separate cycle so all global declarations are together for convenience
        for func in asm_description.values():
            outp.write('\n{}:\n{}'.format(
                func['name'],
                '\n'.join(' '.join(each for each in line) for line in func['code'].values()))
            )
        outp.write(extra_data)
    logger.info('[+] Done dumping asm !')


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
                    # todo handle import calls
                    pass
            elif inst[0].startswith('j'):
                addr_to_jump = int(inst[1], 16)
                if addr_to_jump in func['code']:
                    lbl_name = 'loc_{}'.format(hex(addr_to_jump)[2:])
                    if addr_to_jump not in inst_with_labels:
                        # create label on target instruction
                        inst_with_labels[addr_to_jump] = lbl_name
                        func['code'][addr_to_jump].insert(
                            0, '{}:\n'.format(lbl_name))
                    func['code'][addr][1] = lbl_name
                else:
                    # only happens on cross-functions jump ; for now just jump on return
                    addr_to_jump = func['code'].keys()[-1]
                    if addr_to_jump not in inst_with_labels:
                        lbl_name = 'loc_{}'.format(hex(addr_to_jump)[2:])
                        inst_with_labels[addr_to_jump] = lbl_name
                        func['code'][addr_to_jump].insert(
                            0, '{}:\n'.format(lbl_name))
                    func['code'][addr][1] = lbl_name

        #  just wanna print readable text for now
        #  can't do it in earlier cycle cause we potentially put labels on earlier addresses
        for addr, inst in func['code'].items():
            real_pos = 1 if addr in inst_with_labels else 0
            func['code'][addr][real_pos] = 4 * \
                ' ' + func['code'][addr][real_pos]


def fill_imports(mydriver, whole_image, logger):
    for entry in mydriver.DIRECTORY_ENTRY_IMPORT:
        print 'Parsing imports from "{}"'.format(entry.dll)
        for imp in entry.imports:
            logger.info('[!] Took "{}" on {}'.format(imp.name, hex(imp.address)))
            IMPORT_SECTION_FUNCS[imp.address] = {
                'name': func_to_replace.get(imp.name, imp.name),
                'lib': entry.dll
            }
            whole_image[imp.address - mydriver.OPTIONAL_HEADER.ImageBase:
                        imp.address - mydriver.OPTIONAL_HEADER.ImageBase + MACHINE_WORD_SIZE] = \
                struct.pack('<I', imp.address)


def get_section_info(mydriver, logger):
    sections_info = {}
    
    logger.info('[!] Section info: ')
    for section in mydriver.sections:
        logger.info('{} {} {}'.format(
            section.Name,
            hex(mydriver.OPTIONAL_HEADER.ImageBase + section.VirtualAddress),
            hex(section.Misc_VirtualSize)
            )
        )
        sections_info[section.Name] = (
            section.VirtualAddress,
            section.Misc_VirtualSize
        )
            
    if '.text\x00\x00\x00' not in sections_info:
        print('[-] Couldn\'t find text section!')
        sys.exit(1)
    return sections_info


class FuncDisasm:
    def __init__(self, binary, entry_point, image_base,
                 sections_arr, logger):
        self.disasmer = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_32)
        self.disasmer.detail = True
        self.binary = binary
        self.entry_point = entry_point
        self.image_base = image_base
        self.regs = {each: 0 for each in X86_REGS}
        self.sections_arr = sections_arr
        self.logger = logger

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
                    # one for saved ebp, two for saved eip
                    oper.value.mem.disp - 2 * MACHINE_WORD_SIZE
                )
                if len(inst.operands) > 1:
                    new_opers[(idx + 1) %
                              2] = inst.reg_name(inst.operands[1 - idx].reg)
                    new_op_str = ', '.join(new_opers)
                else:
                    new_op_str = new_opers[0]

        if not found_arg:
            return inst.op_str
        # should never be none
        assert new_op_str is not None
        return new_op_str

    def in_proper_data_section(self, addr):
        for section_name, (start_rva, size) in self.sections_arr.items():
            section_start = start_rva + self.image_base
            if section_start <= addr <= section_start + size:
                self.logger.debug('[!] Found in section "{}"'.format(section_name))
                return True
        return False

    def run(self):
        function_code = OrderedDict()
        for inst in self.disasmer.disasm(self.binary[self.entry_point:],
                                         self.image_base + self.entry_point):
            addr, mnemonic, op_string = hex(
                inst.address)[:-1], inst.mnemonic, inst.op_str
            # nasm-specific preprocessing cause we gonna use it to compile again
            if mnemonic == 'lea':
                op_string = op_string.replace('dword', '')
            # generated disasm code for string instructions is too verbose and not understood
            if any(mnemonic.startswith(prefix) for prefix in ('rep', 'movs')):
                op_string = ''

            if inst.mnemonic == 'jmp':
                ops = inst.operands
                for each in inst.operands:
                    if each.type == cs.x86.X86_OP_MEM:
                        displacement = each.value.mem.disp
                        if displacement in IMPORT_SECTION_FUNCS:
                            called_func = IMPORT_SECTION_FUNCS[displacement]['name']
                            self.logger.debug('call {}'.format(called_func))
                            USED_IMPORT_FUNCS.add(displacement)
                            return called_func
                        else:
                            self.logger.debug('jump to unknown constant memory displacement : {}'.format(
                                hex(each.value.mem.disp)
                            )
                            )
                        return  # because we are inside dumb inst cycle

            function_code[inst.address] = [
                mnemonic, op_string.replace('ptr', '')]
            self.logger.debug('{} {} {}'.format(addr, mnemonic, self.handle_possible_args(inst)))
            if inst.mnemonic == 'push' and inst.operands[0].value.imm == 0x12068:
                function_code[inst.address][1] = 'str_12068'
            if inst.mnemonic == 'mov':
                if inst.operands[0].type == cs.x86.X86_OP_REG:
                    first_reg_name = inst.reg_name(inst.operands[0].value.reg)
                    if inst.operands[1].type == cs.x86.X86_OP_REG:
                        self.regs[first_reg_name] = self.regs[inst.reg_name(
                            inst.operands[1].value.reg)]
                    elif inst.operands[1].type == cs.x86.X86_OP_MEM\
                            and not inst.operands[1].value.mem.base \
                            and not inst.operands[1].value.mem.index:
                        if self.in_proper_data_section(inst.operands[1].value.mem.disp):
                            # mem in data section
                            value = struct.unpack('<I',
                                                  self.binary[inst.operands[1].value.mem.disp - self.image_base:
                                                              inst.operands[1].value.mem.disp - self.image_base + MACHINE_WORD_SIZE]
                                                  )[0]
                            self.regs[first_reg_name] = value
                            if self.in_proper_data_section(value):
                                string_data = cut_string_from_dump(
                                    self.binary, value - self.image_base)
                                if set(string_data).issubset(PRINTABLE_CHARS):
                                    string_name = 'str_' + string_data[:7]
                                    KNOWN_STRINGS[string_name] = string_data
                                    function_code[inst.address][1] = '{}, {}'.format(
                                        inst.reg_name(
                                            inst.operands[0].value.reg),
                                        string_name
                                    )
                    elif inst.operands[1].type == cs.x86.X86_OP_IMM:
                        if self.in_proper_data_section(inst.operands[1].value.imm):
                            string_data = cut_string_from_dump(self.binary,
                                                               inst.operands[1].value.imm - self.image_base)
                            if set(string_data).issubset(PRINTABLE_CHARS):
                                string_name = 'str_' + string_data[:7]
                                # use string references
                                KNOWN_STRINGS[string_name] = string_data
                                function_code[inst.address][1] = '{}, {}'.format(
                                    inst.reg_name(inst.operands[0].value.reg),
                                    string_name
                                )

                    # else some arg/var or whatever manipulations, not gonna do this now

            if inst.mnemonic == 'ret':
                break
            elif inst.mnemonic == 'call':
                if inst.operands[0].type == cs.x86.X86_OP_MEM:
                    external_call_addr = inst.operands[0].value.mem.disp
                    if external_call_addr in IMPORT_SECTION_FUNCS:
                        USED_IMPORT_FUNCS.add(external_call_addr)
                        func_name = IMPORT_SECTION_FUNCS[external_call_addr]['name']
                        self.logger.debug('call {}'.format(func_name))
                        function_code[inst.address][1] = func_name
                    else:
                        self.logger.debug('call to unknown addresss : {}'.format(
                            hex(external_call_addr)))
                elif inst.operands[0].type == cs.x86.X86_OP_REG:
                    reg_val = self.regs[inst.reg_name(
                        inst.operands[0].value.reg)]
                    if reg_val in IMPORT_SECTION_FUNCS:
                        USED_IMPORT_FUNCS.add(reg_val)
                        func_name = IMPORT_SECTION_FUNCS[reg_val]['name']
                        self.logger.debug('call {}'.format(func_name))
                        function_code[inst.address][1] = func_name
                    else:
                        assert False, 'call by register using not-imported function'
                else:
                    # some local function we didn't disassemble yet
                    new_ep = int(inst.op_str, 16) - self.image_base
                    if self.image_base + new_ep not in KNOWN_FUNCS:
                        nested_func = FuncDisasm(self.binary, new_ep, self.image_base,
                                                 self.sections_arr, self.logger)
                        self.logger.debug('[!] Start nested function')
                        rewrite_import_call = nested_func.run()
                        if rewrite_import_call:
                            self.logger.debug(
                                '[!] Patching last call instruction to imported function')
                            function_code[function_code.keys(
                            )[-1]][1] = rewrite_import_call
                        self.logger.debug('[!] End nested function')
                    else:
                        self.logger.debug('[!] call {}'.format(
                            KNOWN_FUNCS[new_ep + self.image_base]['name']))
        KNOWN_FUNCS[self.entry_point + self.image_base] = {
            'code': function_code,
            'name': 'sub_{}'.format(hex(self.entry_point + self.image_base)[2:])
        }


def main():
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument('-f', '--file', help='file destination to act on', required=True)
    arg_parser.add_argument('-r', '--rva', help='RVA of a function inside file to rewrite', required=True)
    arg_parser.add_argument('--verbose', action='store_true', help='Print verbose asm output in stdout')
    args = arg_parser.parse_args()


    logger = logging.getLogger('asm_re')

    hdler = logging.StreamHandler()
    logger.addHandler(hdler)
    if args.verbose:
        cur_log_level = logger.setLevel(logging.DEBUG)
    else:
        cur_log_level = logger.setLevel(logging.INFO)

    file_location, required_function_rva = args.file, int(args.rva, 16)
    if not os.path.exists(file_location):
        print('[-] Specified file {} not found'.format(file_location))
        sys.exit(1)

    mydriver = pefile.PE(file_location)
    sections_info = get_section_info(mydriver, logger)
    text_base_address = sections_info['.text\x00\x00\x00'][0]
    logger.info('[!] Text section rva address: {}'.format(hex(text_base_address)))

    whole_image = bytearray(mydriver.get_memory_mapped_image())

    fill_imports(mydriver, whole_image, logger)
    
    start_disas_addr = text_base_address + required_function_rva
    func_disasm = FuncDisasm(binary=bytes(whole_image), entry_point=start_disas_addr,
                             image_base=mydriver.OPTIONAL_HEADER.ImageBase,
                             sections_arr=sections_info,
                             logger=logger)
    func_disasm.run()
    postproces_defs(KNOWN_FUNCS)

    print_asm('myresult_result.asm', KNOWN_FUNCS, logger)


if __name__ == '__main__':
    main()
