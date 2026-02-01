from tkinter import filedialog

import pefile

import denuvo_drm_config
import denuvo_drm


def main() -> None:
    pe_file_path = filedialog.askopenfilename(title="PE file")
    pe = pefile.PE(pe_file_path, fast_load=True)

    config_file_path = filedialog.askopenfilename(title="Denuvo DRM config file")
    config = denuvo_drm_config.load(config_file_path)

    print("Processing...")
    denuvo_drm.fix_imports(pe, config)
    denuvo_drm.fix_pe_header(pe, config)
    denuvo_drm.rename_sections(pe, config)

    new_pe_file_path = filedialog.asksaveasfilename(title="New PE file", defaultextension='exe')
    print("Saving...")
    pe.OPTIONAL_HEADER.CheckSum = pe.generate_checksum()
    pe.write(new_pe_file_path)

    print("Done")


if __name__ == '__main__':
    main()
