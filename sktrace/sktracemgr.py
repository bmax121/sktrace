
import sys
import json

class Block:
    def __init__(self, addr):
        self.addr = addr
        self.size = -1
        self.insts = []
    
    def append_inst(self, inst):
        self.insts.append(inst)
        self.size += inst.size

    def __str__(self):
        insts_addr = [inst.addr for inst in self.insts]
        insts_addr_str = ",".join(insts_addr)
        block_line = "{}\t{}\t{}".format("block", self.addr, hex(self.size))
        # block_line = "{}\t{}\t{}\t{}".format("block", self.addr, hex(self.size), insts_addr_str)
        return block_line


class Inst:
    def __init__(self, addr, block, size, mnem, op):
        self.addr = addr
        self.block = block
        self.size = size
        self.mnem = mnem
        self.op = op
        self.execed_ctxs = []
        self.changed_regs_dict = {}
        self.try_strings_set = set()
    
    def add_execed_ctx(self, ctx):
        self.execed_ctxs.append(ctx)

    def add_changed_regs(self, changed_regs_arr):
        if changed_regs_arr and len(changed_regs_arr) > 0:
            for reg_val in changed_regs_arr:
                if reg_val.keys[0] in self.changed_regs_dict:
                    self.changed_regs_dict[reg_val.keys[0]].append(reg_val.values[0])
                else:
                    self.changed_regs_dict[reg_val.keys[0]] = (reg_val.values[0])

    def cal_regs_change(self, pre_ctx, ctx):
        print_every_change = True
        eveny_change_str = None
        # ignore pc
        if not pre_ctx:
            for i in range(31):
                self.changed_regs_dict["x"+str(i)] = [ctx.general_regs[i]]
        else:
            if pre_ctx.sp != ctx.sp:
                if "sp" not in self.changed_regs_dict:
                    self.changed_regs_dict["sp"] = []
                    self.changed_regs_dict["sp"].append(ctx.sp)
                    if print_every_change:
                        eveny_change_str = ("{}\t; sp={}->{}".format(self.simple_str(), pre_ctx.sp, ctx.sp))
            for i in range(31):
                if pre_ctx.general_regs[i] != ctx.general_regs[i]:
                    if "x"+str(i) not in self.changed_regs_dict:
                        self.changed_regs_dict["x"+str(i)] = []
                    self.changed_regs_dict["x"+str(i)].append(ctx.general_regs[i])
                    if print_every_change:
                        if eveny_change_str:
                            eveny_change_str += (", x{}={}->{}".format(str(i), pre_ctx.general_regs[i], ctx.general_regs[i]))
                        else:
                            eveny_change_str = ("{}\t; x{}={}->{}".format(self.simple_str(), str(i), pre_ctx.general_regs[i], ctx.general_regs[i]))

        if print_every_change and eveny_change_str:
            print(eveny_change_str)
        pass

    def try_strings(self):
        if not self.changed_regs_dict:
            return
        # 等于多于4个字符
        char_time_threshold = 4
        for reg in self.changed_regs_dict:
            try_str = ""
            change_val_arr = self.changed_regs_dict[reg]
            for val in change_val_arr:
                val_int = int(val, 16)
                if val_int < 0x7f and val_int >= 0x20:
                    try_str += chr(val_int)
                else:
                    if len(try_str) >= 4:
                        self.try_strings_set.add(try_str)
                    try_str = ""
            if len(try_str) >= char_time_threshold:
                self.try_strings_set.add(try_str)

        if self.try_strings_set:
            # print("strs\t" + str(self.try_strings_set))
            print("strings\t" + ",".join(self.try_strings_set))

    def statistics_changed_regs(self):
        if self.changed_regs_dict:
            change_line = "statistics"
            for reg in self.changed_regs_dict:
                change_reg = "\t{}:{}".format(reg, ",".join(self.changed_regs_dict[reg]))
                change_line += change_reg
            print(change_line)
    
    def simple_str(self):
        inst_line = "{}\t{}\t{}".format(self.addr, self.mnem, self.op)
        return inst_line

    def __str__(self):
        inst_line = "{}\t{}\t{}\t{}\t{}\t{}".format("instruction", self.addr, self.block, self.size, self.mnem, self.op)
        return inst_line

class Arm64Ctx:
        def __init__xxx(self, pc, sp, 
                x0, x1, x2, x3, x4, x5, x6, x7, x8, x9,
                x10, x11, x12, x13, x14, x15, x16, x17, x18, x19,
                x20, x21, x22, x23, x24, x25, x26, x27, x28,
                fp, lr
                ):
            self.pc = pc
            self.sp = sp
            self.general_regs = [int(x0,16), int(x1,16), int(x2,16), int(x3,16), int(x4,16), int(x5,16), int(x6,16), int(x7,16), int(x8,16), int(x9,16),
                int(x10,16), int(x11,16), int(x12,16), int(x13,16), int(x14,16), int(x15,16), int(x16,16), int(x17,16), int(x18,16), int(x19,16),
                int(x20,16), int(x21,16), int(x22,16), int(x23,16), int(x24,16), int(x25,16), int(x26,16), int(x27,16), int(x28,16),
                int(fp,16), int(lr,16)]
            self.fp = self.general_regs[29]
            self.lr = self.general_regs[30]
            self.changed_regs = []

        def __init__(self, pc, sp, 
                x0, x1, x2, x3, x4, x5, x6, x7, x8, x9,
                x10, x11, x12, x13, x14, x15, x16, x17, x18, x19,
                x20, x21, x22, x23, x24, x25, x26, x27, x28,
                fp, lr
                ):
            self.pc = pc
            self.sp = sp
            self.general_regs = [x0, x1, x2, x3, x4, x5, x6, x7, x8, x9,
                                    x10, x11, x12, x13, x14, x15, x16, x17, x18, x19,
                                    x20, x21, x22, x23, x24, x25, x26, x27, x28,
                                    fp, lr]
            self.fp = self.general_regs[29]
            self.lr = self.general_regs[30]
            self.changed_regs = []
        
        def __str__(self):
            ctx_line = ",".join([hex(r) for r in self.general_regs])
            return ctx_line




class TraceMgr:

    def __init__(self):
        self.tid_trace_dict = {}
        pass

    def trace_symbol(self, lib, symbol):
        pass

    def trace_offset(self, lib, offset):
        pass

    def on_message(self, msg, data):
        if msg['type'] == 'error':
            print(msg)
            return
        if msg['type'] == 'send':
            payload = msg['payload']
            tid = payload['tid']
            if tid not in self.tid_trace_dict:
                self.tid_trace_dict[tid] = Arm64TraceLog(tid)
    
            self.tid_trace_dict[tid].on_message(payload)


class Arm64TraceLog:
    def __init__(self, tid):
        self.tid = tid
        self.block_dict = {}
        self.inst_dict = {}
        self.pre_ctx = None

    def on_message(self, payload):
        # tid = payload['tid']
        type = payload['type']
        if type == 'inst':
            # print(payload)
            val = json.loads(payload['val'])
            inst = Inst(val["address"], payload["block"], val["size"], val["mnemonic"], val["opStr"])
            if inst.block not in self.block_dict:
                self.block_dict[inst.block] = Block(inst.block)
            self.block_dict[inst.block].append_inst(inst)
            self.inst_dict[inst.addr] = inst
            # print(inst)
            pass
        elif type == 'ctx':
            # print(payload)
            val = json.loads(payload['val'])            
            ctx = Arm64Ctx(val["pc"], val["sp"], 
                val["x0"], val["x1"], val["x2"], val["x3"], val["x4"], val["x5"], val["x6"], val["x7"], val["x8"], val["x9"], 
                val["x10"], val["x11"], val["x12"], val["x13"], val["x14"], val["x15"], val["x16"], val["x17"], val["x18"], val["x19"],
                val["x20"], val["x21"], val["x22"], val["x23"], val["x24"], val["x25"], val["x26"], val["x27"], val["x28"], 
                val["fp"], val["lr"])
            if ctx.pc not in self.inst_dict:
                raise Exception("No inst addr:{} maybe caused by Interceptor.payload:{}".format(ctx.pc, payload))
            self.inst_dict[ctx.pc].add_execed_ctx(ctx)
            self.inst_dict[ctx.pc].cal_regs_change(self.pre_ctx, ctx)
            self.pre_ctx = ctx
            pass
        elif type == "fin":
            self.statistics()
            pass

# statistics
# '''
# tid  block  addr   size   inst_addrs
# tid  inst   block  size   mnemonic  op
# tid  chng   {reg:val_list}
# tid  strs   (guess_strs_set)
# '''
    def statistics(self):
        print('''==================== Statistic Start =====================''')
        for block_addr in self.block_dict:
            block = self.block_dict[block_addr]
            print(block)
            for inst in block.insts:
                print(inst)
                inst.statistics_changed_regs()
                inst.try_strings()
        print('''==================== Statistic End =====================''')
            

