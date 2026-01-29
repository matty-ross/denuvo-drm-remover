import json

import pefile


class DenuvoDRM:

    def __init__(self, config_path: str, pe_path: str, ):
        self._config = self._load_config(config_path)
        self._pe = pefile.PE(pe_path, fast_load=True)


    def save_pe(self, new_pe_path: str) -> None:
        self._pe.OPTIONAL_HEADER.CheckSum = self._pe.generate_checksum()
        self._pe.write(new_pe_path)


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
        
        for section in self._pe.sections:
            denuvo_name = section.Name.rstrip(b'\x00').decode()
            original_name = sections.get(denuvo_name)
            if original_name:
                section.Name = original_name.encode().ljust(8, b'\x00')


    def _load_config(self, config_path: str) -> dict:
        with open(config_path, 'r', encoding='utf-8') as config_file:
            return json.load(config_file)
        

    def _get_pe_data_directory(self, name: str) -> pefile.Structure:
        index = pefile.DIRECTORY_ENTRY[name]
        return self._pe.OPTIONAL_HEADER.DATA_DIRECTORY[index]
