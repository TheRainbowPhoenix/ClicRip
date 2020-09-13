import os
import pefile
import struct
import zlib

from src.gui import open_file_dialog, show_message_dialog


class InvalidPeException(Exception):
    def __init__(self, msg):
        super.__init__(msg)


class S:
    UINT8  = 'B'
    INT8   = 'b'
    UINT16 = 'H'
    INT16  = 'h'
    UINT32 = 'I'
    INT32  = 'i'

    @classmethod
    def sizeof(cls, s):
        if s == S.UINT8 or s == S.INT8:
            return 1
        if s == S.UINT16 or s == S.INT16:
            return 2
        if s == S.UINT32 or s == S.INT32:
            return 4
        return 0


class ResourceEntry:
    def __init__(self):
        self.data_length = 0

    @property
    def ID(self):
        return 0

    @property
    def Data(self):
        pass

    @property
    def DataLength(self):
        return self.data_length

    def __len__(self):
        return self.data_length

    @DataLength.setter
    def DataLength(self, value):
        self.data_length = value


class ClicRip:
    FLAG = b'PAMU'

    def __init__(self, game_path):
        self.game_path: str = game_path
        self.game_buffer = None
        self.game_dir = None
        self.file = None

        self.res_entries: list = []

        self.adding_textures = False
        self.adding_sounds = False

        self.game_size = 0
        self.cursor = 0

        self.init_dir()

    def init_dir(self):
        self.game_dir = os.path.dirname(os.path.realpath(self.game_path))
        print(self.game_dir)

    def load_game(self):
        self.file = open(self.game_path, 'rb')
        self.game_buffer = self.file.read()
        self.file.close()
        self.game_size = len(self.game_buffer)

        pe_header_reader = PeHeaderReader(self.game_buffer)
        pe_header_reader.read_headers()
        headers = pe_header_reader.get_headers()
        if len(headers) == 0:
            raise InvalidPeException("Invalid PE Headers")
        last_header = headers[-1]
        flag = False
        self.cursor = last_header.PointerToRawData + last_header.SizeOfRawData
        while self.cursor < len(self.game_buffer) - 4:
            if self.game_buffer[self.cursor:self.cursor + 4] == self.FLAG:
                print(self.cursor)
                flag = True
                break
            self.cursor += 1

        if not flag:
            show_message_dialog(message="Flag not found !!", title="Error")
        else:
            self.seek(self.cursor)
            self.read_entries()

    def seek(self, pos):
        self.cursor = pos

    def read(self, length):
        self.cursor += length

        if self.cursor + length >= self.game_size:
            return None

        data = self.game_buffer[self.cursor: self.cursor+length]
        return data

    @property
    def EOF(self):
        return self.cursor >= self.game_size

    def read_entries(self):
        i, = struct.unpack(S.UINT32, self.read(S.sizeof(S.UINT32)))
        print(i)
        while True:
            re = self.read_entry()

            if self.EOF:
                break
        # TODO: read entries

    def read_entry(self):
        num, = struct.unpack(S.UINT16, self.read(S.sizeof(S.UINT16)))
        flag, = struct.unpack(S.UINT16, self.read(S.sizeof(S.UINT16)))

        print(num, flag)

        res_entry = ResourceEntry()

        if num in [21845]:
            self.adding_textures = False
        elif num in [21847]:
            self.adding_sounds = False

        if num in [13107, 32639]:
            pass  # new res(num, file.pos, read(4), hasData=false)
        elif num in [8768]:
            pass  # new res(num, file.pos, read(4), hasData=false)
        elif num in [8745, 8748, 8770, 8774, 13127, 26214, 26215, 26216]:
            pass  # new res(num, file.pos, read(8), hasData=false)
        elif num in [8781]:
            pass  # new res(num, file.pos, read(12), hasData=false)
        else:
            if flag <= 0:
                if num in [17477]:
                    pass  # new obj(file.pos, read(INT32), inPreData=true)
                elif num in [13109]:
                    pass  # new frame(file.pos, read(INT32), inPreData=true)
            num2 = self.find_until_next([120, 218])
            if num2 < 0:
                return None
            pre_data = self.read(max(0, num2 - 8))
            if self.adding_textures:
                pass  # new texture(num, file.pos, pre_data)
            elif self.adding_sounds:
                pass  # new sound(num, file.pos, pre_data)
            else:
                if num in [17477]:
                    pass  # obj(file.pos, pre_data)
                elif num in [13109]:
                    pass  # frame(file.pos, pre_data)
                elif num in [8740]:
                    pass  # meta(file.pos, pre_data)
                elif num in [8763]:
                    pass  # meta(file.pos, pre_data)
                elif num in [8751]:
                    pass  # meta(file.pos, pre_data)
                elif num in [8750]:
                    pass  # meta(file.pos, pre_data)
                else:
                    pass  # res(num, file.pos, pre_data)

        if res_entry.ID in [8450, 8751]:
            self.read_compressed()
        else:
            array = self.read_compressed(decompress=False)
            res_entry.DataLength = len(array) if array is not None else 0
            pass  # res_entry.dataLength = len(readCompressed(decomrpess=false))

        return res_entry

    def find_until_next(self, param):
        return -1  # TODO

    def read_compressed(self, decompress=True):
        i, = struct.unpack(S.UINT32, self.read(S.sizeof(S.UINT32)))
        print(i)

        count, = struct.unpack(S.UINT32, self.read(S.sizeof(S.UINT32)))
        print(f"read_compressed :{count}")
        array = self.read(count)
        if not decompress:
            return array
        return self._uncompress(array)

    def _uncompress(self, array):
        return zlib.decompress(array)


class PeHeaderReader:
    def __init__(self, game_buffer):
        self.game_buffer = game_buffer
        self.image_section_headers = []

    def read_headers(self):
        pe = pefile.PE(data=self.game_buffer, fast_load=True)

        print("Machine : " + hex(pe.FILE_HEADER.Machine))

        # Check if it is a 32-bit or 64-bit binary
        if hex(pe.FILE_HEADER.Machine) == '0x14c':
            print("This is a 32-bit binary")
        else:
            print("This is a 64-bit binary")

        print("TimeDateStamp : " + pe.FILE_HEADER.dump_dict()['TimeDateStamp']['Value'].split('[')[1][:-1]
              )

        print("NumberOfSections : " + hex(pe.FILE_HEADER.NumberOfSections))

        print("Characteristics flags : " + hex(pe.FILE_HEADER.Characteristics))

        self.image_section_headers = pe.sections

        for section in pe.sections:
            print(f"{section.Name.decode().rstrip()}  Chrtcs: {section.Characteristics}  VSize: {section.Misc_VirtualSize} VAddr:{section.VirtualAddress} PtrRaw: {section.PointerToRawData} RawSz:{section.SizeOfRawData}")

    def get_headers(self) -> list:
        return self.image_section_headers



if __name__ == '__main__':
    file_path_variable = open_file_dialog(file_filter='Game file (.exe)\0*.exe\0')

    if file_path_variable is not None:
        clicrip = ClicRip(file_path_variable)
        clicrip.load_game()

    else:
        print("Invalid file chosen.")
