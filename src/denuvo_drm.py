import json
import struct

import pefile


class DenuvoDRM:

    def __init__(self, config_path: str, pe_path: str):
        self._config = self._load_config(config_path)
        self._pe = pefile.PE(pe_path, fast_load=True)


    def save_pe(self, new_pe_path: str) -> None:
        self._pe.OPTIONAL_HEADER.CheckSum = self._pe.generate_checksum()
        self._pe.write(new_pe_path)


    def fix_imports(self) -> None:
        denuvo_sections: list[str] = self._config['denuvo_sections']
        
        imports = self._map_denuvo_to_original_imports()
        for section in self._pe.sections:
            denuvo_name = section.Name.rstrip(b'\x00').decode()
            if denuvo_name in denuvo_sections:
                self._replace_imports_in_section(imports, section)
    

    def fix_pe_header(self) -> None:
        optional_header: dict[str, str] = self._config['optional_header']
        data_directories: dict[str, dict[str, str]] = self._config['data_directories']

        self._pe.OPTIONAL_HEADER.AddressOfEntryPoint = int(optional_header['entry_point'], 16)
        self._pe.OPTIONAL_HEADER.BaseOfData = int(optional_header['base_of_data'], 16)

        for name, address_and_size in data_directories.items():
            data_directory = self._get_pe_data_directory(name)
            data_directory.VirtualAddress = int(address_and_size['address'], 16)
            data_directory.Size = int(address_and_size['size'], 16)


    def rename_sections(self) -> None:
        sections: dict[str, str] = self._config['sections']
        denuvo_sections: list[str] = self._config['denuvo_sections']

        index = 1
        for section in self._pe.sections:
            denuvo_name = section.Name.rstrip(b'\x00').decode()
            original_name = sections.get(denuvo_name)
            if original_name:
                section.Name = original_name.encode().ljust(8, b'\x00')
            elif denuvo_name in denuvo_sections:
                section.Name = f'.denuvo{index}'.encode()
                index += 1


    def _load_config(self, config_path: str) -> dict:
        with open(config_path, 'r', encoding='utf-8') as config_file:
            return json.load(config_file)
        

    def _get_pe_data_directory(self, name: str) -> pefile.Structure:
        index = pefile.DIRECTORY_ENTRY[name]
        return self._pe.OPTIONAL_HEADER.DATA_DIRECTORY[index]
    

    def _map_denuvo_to_original_imports(self) -> dict[int, int]:
        data_directories: dict[str, dict[str, str]] = self._config['data_directories']

        denuvo_import_directory_entry = self._get_pe_data_directory('IMAGE_DIRECTORY_ENTRY_IMPORT')
        original_import_directory_entry = data_directories['IMAGE_DIRECTORY_ENTRY_IMPORT']

        denuvo_imports = {}
        denuvo_import_directory = self._pe.parse_import_directory(
            rva=denuvo_import_directory_entry.VirtualAddress,
            size=denuvo_import_directory_entry.Size,
        )
        for denuvo_import_descriptor in denuvo_import_directory:
            for denuvo_import in denuvo_import_descriptor.imports:
                dll = denuvo_import_descriptor.dll.lower()
                function = denuvo_import.ordinal if denuvo_import.import_by_ordinal else denuvo_import.name.lower()
                denuvo_imports[denuvo_import.address] = (dll, function)

        original_imports = {}
        original_import_directory = self._pe.parse_import_directory(
            rva=int(original_import_directory_entry['address'], 16),
            size=int(original_import_directory_entry['size'], 16),
        )
        for original_import_descriptor in original_import_directory:
            for original_import in original_import_descriptor.imports:
                dll = original_import_descriptor.dll.lower()
                function = original_import.ordinal if original_import.import_by_ordinal else original_import.name.lower()
                original_imports[(dll, function)] = original_import.address

        imports = {}
        for denuvo_address, (dll, function) in denuvo_imports.items():
            original_address = original_imports.get((dll, function))
            if original_address is not None:
                imports[denuvo_address] = original_address

        return imports
    

    def _replace_imports_in_section(self, imports: dict[int, int], section: pefile.Structure) -> None:
        fmt = '<L' # TODO: or '<Q'
        size = 4 # TODO: or 8
        
        data = bytearray(self._pe.get_data(section.VirtualAddress, section.SizeOfRawData))
        
        for i in range(len(data) - (size - 1)):
            pointer = struct.unpack(fmt, data[i:i + size])[0]
            if pointer in imports:
                data[i:i + size] = struct.pack(fmt, imports[pointer])

        self._pe.set_bytes_at_rva(section.VirtualAddress, bytes(data))
