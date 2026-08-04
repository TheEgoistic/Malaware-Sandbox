import pefile

def analyze_pe(file_path):
    """Extract key information from a PE file."""
    pe_info = {
        "is_pe": False,
        "sections": [],
        "imports": [],
        "entry_point": None,
        "timestamp": None
    }
    try:
        pe = pefile.PE(file_path)
        pe_info['is_pe'] = True
        pe_info['entry_point'] = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        pe_info['timestamp'] = pe.FILE_HEADER.TimeDateStamp

        for section in pe.sections:
            section_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
            pe_info['sections'].append({
                "name": section_name,
                "virtual_size": section.Misc_VirtualSize,
                "entropy": section.get_entropy() # Built-in pefile entropy
            })

        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8', errors='ignore')
                for imp in entry.imports:
                    pe_info['imports'].append(f"{dll_name}:{imp.name.decode('utf-8', errors='ignore')}")

    except pefile.PEFormatError:
        pe_info['error'] = "Not a valid PE file or file is corrupted."
    except Exception as e:
        pe_info['error'] = f"PE analysis failed: {e}"

    return pe_info
