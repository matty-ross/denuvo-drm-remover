import struct

import pefile

from denuvo_drm_config import DenuvoDrmConfig


def fix_imports(pe: pefile.PE, config: DenuvoDrmConfig) -> None:
    imports = _map_denuvo_to_original_imports(pe, config)

    for section in pe.sections:
        denuvo_section_name = _decode_pe_section_name(section.Name)
        if denuvo_section_name in config.denuvo_section_names:
            _replace_imports_in_section(pe, section, imports)


def fix_pe_header(pe: pefile.PE, config: DenuvoDrmConfig) -> None:
    pe.OPTIONAL_HEADER.AddressOfEntryPoint = config.original_entry_point
    pe.OPTIONAL_HEADER.BaseOfData = config.original_base_of_data

    for data_directory_name, original_data_directory in config.original_data_directories.items():
        data_directory = _get_pe_data_directory(pe, data_directory_name)
        data_directory.VirtualAddress = original_data_directory['address']
        data_directory.Size = original_data_directory['size']


def rename_sections(pe: pefile.PE, config: DenuvoDrmConfig) -> None:
    index = 1

    for section in pe.sections:
        denuvo_section_name = _decode_pe_section_name(section.Name)
        original_section_name = config.original_section_names.get(denuvo_section_name)

        if original_section_name:
            section.Name = _encode_pe_section_name(original_section_name)
        elif denuvo_section_name in config.denuvo_section_names:
            section.Name = _encode_pe_section_name(f'.denuvo{index}')
            index += 1


def _map_denuvo_to_original_imports(pe: pefile.PE, config: DenuvoDrmConfig) -> dict[int, int]:
    denuvo_imports: dict[int, tuple[str, str | int]] = {}
    denuvo_import_directory = _get_pe_data_directory(pe, 'IMAGE_DIRECTORY_ENTRY_IMPORT')
    denuvo_import_descriptors = pe.parse_import_directory(
        rva=denuvo_import_directory.VirtualAddress,
        size=denuvo_import_directory.Size,
    )
    for denuvo_import_descriptor in denuvo_import_descriptors:
        dll = denuvo_import_descriptor.dll.lower()
        for denuvo_import in denuvo_import_descriptor.imports:
            function = denuvo_import.ordinal if denuvo_import.import_by_ordinal else denuvo_import.name
            denuvo_imports[denuvo_import.address] = (dll, function)

    original_imports: dict[tuple[str, str | int], int] = {}
    original_import_directory = config.original_data_directories['IMAGE_DIRECTORY_ENTRY_IMPORT']
    original_import_descriptors = pe.parse_import_directory(
        rva=original_import_directory['address'],
        size=original_import_directory['size'],
    )
    for original_import_descriptor in original_import_descriptors:
        dll = original_import_descriptor.dll.lower()
        for original_import in original_import_descriptor.imports:
            function = original_import.ordinal if original_import.import_by_ordinal else original_import.name
            original_imports[(dll, function)] = original_import.address

    imports = {}
    for denuvo_address, (dll, function) in denuvo_imports.items():
        original_address = original_imports.get((dll, function))
        if original_address is not None:
            imports[denuvo_address] = original_address

    return imports


def _replace_imports_in_section(pe: pefile.PE, section: pefile.Structure, imports: dict[int, int]) -> None:
    match pe.OPTIONAL_HEADER.Magic:
        case pefile.OPTIONAL_HEADER_MAGIC_PE:
            pointer_format = '<L'
            pointer_size = 4
        case pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS:
            pointer_format = '<Q'
            pointer_size = 8
        case _:
            return

    data = bytearray(pe.get_data(section.VirtualAddress, section.SizeOfRawData))

    for offset in range(len(data) - pointer_size + 1):
        pointer = struct.unpack_from(pointer_format, data, offset)[0]
        if pointer in imports:
            struct.pack_into(pointer_format, data, offset, imports[pointer])

    pe.set_bytes_at_rva(section.VirtualAddress, bytes(data))


def _get_pe_data_directory(pe: pefile.PE, data_directory_name: str) -> pefile.Structure:
    data_directory_index = pefile.DIRECTORY_ENTRY[data_directory_name]
    return pe.OPTIONAL_HEADER.DATA_DIRECTORY[data_directory_index]


def _decode_pe_section_name(section_name: bytes) -> str:
    return section_name.rstrip(b'\x00').decode('ascii')


def _encode_pe_section_name(section_name: str) -> bytes:
    return section_name.encode('ascii').ljust(8, b'\x00')
