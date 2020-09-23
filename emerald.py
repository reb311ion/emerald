# Import Drcov code coverage data
# @author @reb311ion
# @keybinding shift I
# @category Analysis
# @toolbar emerald.png


from ghidra.program.model.symbol.SourceType import USER_DEFINED
from ghidra.app.tablechooser import AddressableRowObject
from ghidra.app.tablechooser import StringColumnDisplay
from ghidra.app.tablechooser import TableChooserExecutor
from ghidra.program.model.symbol import FlowType
from ghidra.app.plugin.core.colorizer import ColorizingService
from ghidra.app.script import GhidraScript
from ghidra.program.model.address import Address
from ghidra.program.model.address import AddressSet
from java.awt import Color
from utility.function import Callback
from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.framework.plugintool.util import OptionsService
from ghidra.util.task import TaskMonitor

service = state.getTool().getService(ColorizingService)

# ------------------------------------------------------------------------------
# Table UI initialization
# ------------------------------------------------------------------------------

TABLE_DIALOG = None
FINAL_MATCH_DICT = {}


class Exec(TableChooserExecutor):
    def getButtonName(self):
        return "select covered"

    def execute(self, rowObject):
        global TABLE_DIALOG
        global FINAL_MATCH_DICT
        function = getFunctionAt(rowObject.getAddress())
        ranges = service.getBackgroundColorAddresses(service.getBackgroundColor(function.getEntryPoint()))
        setCurrentSelection(function.getBody())
        setCurrentSelection(ranges)
        return False


class FunctionName(StringColumnDisplay):
    def getColumnName(self):
        return "Function Name"

    def getColumnValue(self, value):
        return value


class CovRate(StringColumnDisplay):
    def getColumnName(self):
        return "Cov Rate"

    def getColumnValue(self, value):
        global FINAL_MATCH_DICT
        return FINAL_MATCH_DICT[str(value)][1]


class BlockHit(StringColumnDisplay):
    def getColumnName(self):
        return "Block Hit"

    def getColumnValue(self, value):
        global FINAL_MATCH_DICT
        return FINAL_MATCH_DICT[str(value)][2]


class Initializer(AddressableRowObject):
    head = ""
    function_address = 0

    def getAddress(self):
        return self.function_address

    def toString(self):
        return self.head


# ------------------------------------------------------------------------------
# Drcov Parser
# ------------------------------------------------------------------------------

# !/usr/bin/env python

from struct import unpack
from os.path import basename


def detect_format(filename):
    enough_bytes = 256
    with open(filename, 'rb') as f:
        data = f.read(enough_bytes)
    if isinstance(data, bytes):
        data = data.decode(errors='replace')

    if data.startswith('DRCOV VERSION: 2'):
        return 'drcov'
    if '+' in data:
        first_line = data.split('\n')[0]
        pieces = first_line.split('+')
        if len(pieces) == 2:
            try:
                hex_int = int(pieces[1], 16)
                return 'module+offset'
            except ValueError:
                pass
    raise Exception('[!] File "%s" doesn\'t appear to be drcov or module+offset format')


def parse_coverage_file(filename, module_base=0, module_blocks=[], debug=True):
    file_format = detect_format(filename)
    if file_format == 'drcov':
        block_dict = parse_drcov_file(filename, module_base, module_blocks)
    elif file_format == 'module+offset':
        module_name = ""
        block_dict = parse_mod_offset_file(filename, module_name, module_base, module_blocks)
    return block_dict


def parse_mod_offset_file(filename, module_name, module_base, module_blocks, debug=True):
    blocks = set()
    modules_seen = set()
    with open(filename, 'r') as f:
        for line in f.readlines():
            pieces = line.split('+')
            if len(pieces) != 2:
                continue
            name, offset = pieces
            if debug:
                if module_name != name and name not in modules_seen:
                    modules_seen.add(name)
            block_offset = int(offset, 16)
            block_addr = module_base + block_offset
            if block_addr in module_blocks:
                blocks.add(block_addr)
    return blocks


def parse_drcov_header(header, filename, debug):
    module_table_start = False
    module_ids = []
    module_dict = {}
    for i, line in enumerate(header.split("\n")):
        if line.startswith("BB Table"):
            break
        if line.strip().startswith("0"):
            module_table_start = True
        if module_table_start:
            columns = line.split(",")
            mline = line.strip().split(",")
            module_dict[mline[-1]] = mline[0]
    if not module_table_start:
        raise Exception('[!] No module table found in "%s"' % filename)

    return module_dict


def parse_drcov_binary_blocks(block_data, filename, module_ids, module_base, module_blocks, debug):
    blocks = set()
    block_data_len = len(block_data)
    blocks_seen = 0
    offset_dict = {}

    remainder = block_data_len % 8
    if remainder != 0:
        block_data = block_data[:-remainder]
    if debug:
        module_dict = {}

    for i in range(0, block_data_len, 8):
        block_module_id = unpack("<H", block_data[i + 6:i + 8])[0]

        if block_module_id == module_ids:
            block_offset = unpack("<I", block_data[i:i + 4])[0]
            block_size = unpack("<H", block_data[i + 4:i + 6])[0]
            block_addr = module_base + block_offset
            blocks_seen += 1
            offset_dict[block_offset] = block_size
            module_dict[block_module_id] = module_dict.get(block_module_id, 0) + 1
            if block_module_id == module_ids:
                cur_addr = block_addr
                while cur_addr < block_addr + block_size:
                    if cur_addr in module_blocks:
                        blocks.add(cur_addr)
                        cur_addr += module_blocks[cur_addr]
                    else:
                        cur_addr += 1

    return offset_dict


def parse_drcov_ascii_blocks(block_data, filename, module_ids, module_base, module_blocks, debug):
    blocks = set()
    blocks_seen = 0
    int_base = 0
    offset_dict = {}

    for line in block_data.split(b"\n"):
        left_bracket_index = line.find(b'[')
        right_bracket_index = line.find(b']')
        if left_bracket_index == -1 or right_bracket_index == -1:
            continue
        block_module_id = int(line[left_bracket_index + 1: right_bracket_index])
        block_offset, block_size = line[right_bracket_index + 2:].split(b',')

        if int_base:
            block_offset = int(block_offset, int_base)
        else:
            if b'x' in block_offset:
                int_base = 16
            else:
                int_base = 10
            block_offset = int(block_offset, int_base)

        block_size = int(block_size)
        block_addr = module_base + block_offset
        blocks_seen += 1
        offset_dict[block_offset] = block_size
        module_dict[block_module_id] = module_dict.get(block_module_id, 0) + 1
        if block_module_id == module_ids:
            cur_addr = block_addr
            while cur_addr < block_addr + block_size:
                if cur_addr in module_blocks:
                    blocks.add(cur_addr)
                    cur_addr += module_blocks[cur_addr]
                else:
                    cur_addr += 1

    return offset_dict


def parse_drcov_file(filename, module_base, module_blocks, debug=True):
    with open(filename, 'rb') as f:
        data = f.read()

    if not data.startswith(b"DRCOV VERSION: 2"):
        raise Exception("[!] File %s does not appear to be a drcov format file, " % filename +
                        "it doesn't start with the expected signature: 'DRCOV VERSION: 2'")

    header_end_pattern = b"BB Table: "
    header_end_location = data.find(header_end_pattern)
    if header_end_location == -1:
        raise Exception("[!] File %s does not appear to be a drcov format file, " % filename +
                        "it doesn't contain a header for the basic block table'")
    header_end_location = data.find(b"\n", header_end_location) + 1  # +1 to skip the newline

    # Check for ascii vs binary drcov version (binary is the default)
    binary_file = True
    ascii_block_header = b"module id, start, size:"

    block_header_candidate = data[header_end_location:header_end_location + len(ascii_block_header)]
    if block_header_candidate == ascii_block_header:
        binary_file = False
        header_end_location = data.find(b"\n", header_end_location) + 1

    header = data[:header_end_location].decode()
    block_data = data[header_end_location:]

    module_dict = parse_drcov_header(header, filename, debug)
    main_module = ""
    for key in module_dict.keys():
        if key.endswith(".exe"):
            main_module = key
            break

    module_ids = askChoice("Module List", "Please Choose Module", module_dict.keys(), main_module)
    module_ids = int(module_dict[module_ids])

    if binary_file:
        parse_blocks = parse_drcov_binary_blocks
    else:
        parse_blocks = parse_drcov_ascii_blocks
    block_dict = parse_blocks(block_data, filename, module_ids, module_base, module_blocks, debug)
    return block_dict


# ------------------------------------------------------------------------------
# Emerald main class
# ------------------------------------------------------------------------------

class Emerald():
    program_base = int(getFirstData().getAddress().toString(), 16)
    cov_functions = {}

    def __init__(self):
        file_path = askFile("Import Drcov", "Import").toString()
        self.basic_blocks = parse_coverage_file(file_path)

    def set_basic_block_colors(self, start_addr, size):
        service.setBackgroundColor(start_addr, start_addr.add(size), Color(0, 255, 172))

    def decolorize_blocks(self):
        start()
        for bb in self.basic_blocks.keys():
            start_addr = toAddr(bb + self.program_base)
            block_size = self.basic_blocks[bb] - 1
            service.clearBackgroundColor(start_addr, start_addr.add(block_size))
        end(True)

    def colorize_blocks(self):
        global FINAL_MATCH_DICT
        global TABLE_DIALOG

        decompInterface = DecompInterface()
        decompInterface.openProgram(currentProgram)

        start()  # starting a database transition
        cov_block_list = []
        for bb in self.basic_blocks.keys():
            start_addr = toAddr(bb + self.program_base)
            block_size = self.basic_blocks[bb] - 1
            function = getFunctionContaining(start_addr)
            self.set_basic_block_colors(start_addr, block_size)
            if function and not function in cov_block_list:
                cov_block_list.append(function)

        end(True)  # ending the db transition started before and setting Commit to true

        for function in cov_block_list:
            hfunction = decompInterface.decompileFunction(function, 30, TaskMonitor.DUMMY).getHighFunction()
            basic_blocks = hfunction.getBasicBlocks()
            basic_block_len = len(basic_blocks)
            total_block_size = 0
            function_size = 0
            total_cov_size = 0
            for block in basic_blocks:
                block_size = int(block.getStop().toString(), 16) - int(block.getStart().toString(), 16)
                function_size += block_size
                bg_color = service.getBackgroundColor(block.getStart())
                if bg_color and bg_color.getRGB() == -16711764:
                    total_block_size += 1
                    total_cov_size += block_size

            block_hit = str(total_block_size) + "/" + str(basic_block_len)

            if total_cov_size > 0:
                total_cov_size = str(int(100 * float(total_cov_size) / float(function_size))) + "%"
            elif total_block_size == basic_block_len:
                total_cov_size = "100%"
            else:
                total_cov_size = "0%"

            FINAL_MATCH_DICT[function.getName()] = [function.getName(), total_cov_size, block_hit,
                                                    function.getEntryPoint()]

        for key in FINAL_MATCH_DICT.keys():
            init_obj = Initializer()
            init_obj.head = key
            init_obj.function_address = FINAL_MATCH_DICT[key][3]
            FINAL_MATCH_DICT[key].append(init_obj)
            TABLE_DIALOG.add(init_obj)

        save_csv = askYesNo("Export", "Export coverage information as CSV?")
        if not save_csv:
            return
        export_path = askFile("Where to store the export?", "Choose File")
        if not export_path:
            return
        with open(export_path.getAbsolutePath(), 'w') as csv_file:
            writer = csv.writer(csv_file)
            writer.writerow(["Function Name", "Coverage Rate", "Blocks Hit", "Function Entry Point"])
            for key in FINAL_MATCH_DICT.keys():
                writer.writerow(FINAL_MATCH_DICT[key][:-1])


class OnCloseCallback(Callback):
    def __init__(self, emerald):
        self.emerald = emerald

    def call(self):
        decolorize = askYesNo("Decolorizing?", "Do you want to undo colorization?")
        if decolorize:
            print("Decolorizing... ")
            self.emerald.decolorize_blocks()
            print("done")


if __name__ == '__main__':
    execute = Exec()
    TABLE_DIALOG = createTableChooserDialog(currentProgram.getName() + " Functions", execute)
    TABLE_DIALOG.addCustomColumn(FunctionName())
    TABLE_DIALOG.addCustomColumn(CovRate())
    TABLE_DIALOG.addCustomColumn(BlockHit())

    emerald = Emerald()
    emerald.colorize_blocks()

    TABLE_DIALOG.setClosedListener(OnCloseCallback(emerald))

    TABLE_DIALOG.show()
