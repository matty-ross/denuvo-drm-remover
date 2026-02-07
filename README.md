# Denuvo DRM Remover

![](https://img.shields.io/badge/Python-3670A0?style=for-the-badge&logo=python&logoColor=FFDD54)

A tool to partially remove Denuvo DRM from PE files.

Note that it doesn't fully remove the DRM, only some parts of it, so the PE file is easier to analyze.


## Config file

This tool requires a config file in TOML format:

```toml
# Most of this info can be obtained from IMAGE_DEBUG_TYPE_POGO data
# NOTE: This config is for Burnout Paradise Remastered

# Original entry point RVA
original_entry_point = 0x45BDB3

# Original base of data RVA
original_base_of_data = 0x8AE000

# List of section names added by Denuvo
denuvo_section_names = [
    ".trace",
    ".srdata",
    ".text1",
    ".rsrc",
]

# Original data directories (their RVAs and sizes)
[original_data_directories]
IMAGE_DIRECTORY_ENTRY_EXPORT = { address = 0xB1BEF0, size = 0x6C00 }
IMAGE_DIRECTORY_ENTRY_IMPORT = { address = 0xB22AF0, size = 0x2D0 }
IMAGE_DIRECTORY_ENTRY_DEBUG = { address = 0xB0E620, size = 0x70 }
IMAGE_DIRECTORY_ENTRY_IAT = { address = 0x8AE000, size = 0x9F8 }

# Mapping from Denuvo to original section names
[original_section_names]
".code" = ".text"
".link" = ".rdata"
".sdata" = ".data"
".text" = ".tls"
".rdata" = "CONST"
".edata" = ".gfids"
".data" = "_RDATA"
".sbss" = ".rsrc"
```


## Usage

```
python .\src\main.py
```

1. Choose the game's PE file (`*.exe`)
1. Choose the config file (`*.toml`)
1. Choose where to save the new PE file
