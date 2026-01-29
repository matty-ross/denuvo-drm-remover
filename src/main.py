from tkinter import filedialog

from denuvo_drm import DenuvoDRM


def main() -> None:
    config_path = filedialog.askopenfilename(title="Config file")
    pe_path = filedialog.askopenfilename(title="PE file")
    new_pe_path = filedialog.asksaveasfilename(title="New PE file", defaultextension='exe')
    
    denuvo_drm = DenuvoDRM(config_path, pe_path)
    denuvo_drm.fix_pe_header()
    denuvo_drm.rename_sections()
    denuvo_drm.save_pe(new_pe_path)


if __name__ == '__main__':
    main()
