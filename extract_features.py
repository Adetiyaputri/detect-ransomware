import pefile
import re

def extract_bitcoin_addresses(pe):
    """Ekstrak alamat Bitcoin dari file PE jika ada"""
    bitcoin_addresses = []
    for section in pe.sections:
        if section.Name.strip():
            section_data = section.get_data()
            addresses = re.findall(r'([13][a-km-zA-HJ-NP-Z1-9]{25,34})', section_data.decode(errors='ignore'))
            bitcoin_addresses.extend(addresses)
    return bitcoin_addresses

def extract_characteristics(file_path):
    characteristics = {}
    
    try:
        pe = pefile.PE(file_path)
        
        characteristics['machine'] = pe.FILE_HEADER.Machine
        characteristics['major_image_version'] = pe.OPTIONAL_HEADER.MajorImageVersion
        characteristics['major_os_version'] = pe.OPTIONAL_HEADER.MajorOperatingSystemVersion
        characteristics['major_linker_version'] = pe.OPTIONAL_HEADER.MajorLinkerVersion
        characteristics['minor_linker_version'] = pe.OPTIONAL_HEADER.MinorLinkerVersion
        characteristics['number_of_sections'] = pe.FILE_HEADER.NumberOfSections
        characteristics['size_of_stack_reserve'] = pe.OPTIONAL_HEADER.SizeOfStackReserve
        characteristics['dll_characteristics'] = pe.OPTIONAL_HEADER.DllCharacteristics
        
        if hasattr(pe, 'DIRECTORY_ENTRY_DEBUG') and len(pe.DIRECTORY_ENTRY_DEBUG) > 0:
            debug_entry = pe.DIRECTORY_ENTRY_DEBUG[0]
            characteristics['DebugSize'] = getattr(debug_entry.struct, 'SizeOfData', 0)
            characteristics['DebugRVA'] = getattr(debug_entry.struct, 'AddressOfRawData', 0)
        else:
            characteristics['DebugSize'] = 0
            characteristics['DebugRVA'] = 0

        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') and pe.DIRECTORY_ENTRY_EXPORT:
            characteristics['ExportRVA'] = getattr(pe.DIRECTORY_ENTRY_EXPORT.struct, 'VirtualAddress', 0)
            characteristics['ExportSize'] = getattr(pe.DIRECTORY_ENTRY_EXPORT.struct, 'Size', 0)
        else:
            characteristics['ExportRVA'] = 0
            characteristics['ExportSize'] = 0

        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') and pe.DIRECTORY_ENTRY_IMPORT:
            iat_entry = pe.DIRECTORY_ENTRY_IMPORT[0]  # Ambil entri pertama dari daftar impor
            characteristics['IatVRA'] = getattr(iat_entry.struct, 'OriginalFirstThunk', 0)
        else:
            characteristics['IatVRA'] = 0

        if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE') and pe.DIRECTORY_ENTRY_RESOURCE:
            resource_entry = pe.DIRECTORY_ENTRY_RESOURCE.struct
            characteristics['ResourceSize'] = getattr(resource_entry, 'Size', 0)
        else:
            characteristics['ResourceSize'] = 0

        addresses = extract_bitcoin_addresses(pe)
        characteristics['BitcoinAddresses'] = 1 if addresses else 0
        
    except Exception as e:
        characteristics['error'] = str(e)
        print("An error occurred while processing the PE file.")

    return characteristics