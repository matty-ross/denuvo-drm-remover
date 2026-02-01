import tomllib
from dataclasses import dataclass


@dataclass
class DenuvoDrmConfig:
    original_entry_point: int
    original_base_of_data: int
    denuvo_section_names: list[str]
    original_data_directories: dict[str, dict]
    original_section_names: dict[str, str]


def load(file_path: str) -> DenuvoDrmConfig:
    with open(file_path, 'rb') as file:
        config = tomllib.load(file)

    return DenuvoDrmConfig(**config)
