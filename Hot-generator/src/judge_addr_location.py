import bisect


def is_address_in_hot_function(address, function_text_info):

    first_column = [row[0] for row in function_text_info]
    index = bisect.bisect_right(first_column, address) - 1

    if index >= 0 and (
        function_text_info[index][0]
        <= address
        < (function_text_info[index][0] + function_text_info[index][1])
    ):
        print(
            f"relocation_offset:{hex(address)},fun_start:{hex(function_text_info[index][0])},fun_end:{hex((function_text_info[index][0] + function_text_info[index][1]))}"
        )
        return function_text_info[index][2]

    return None


def is_address_in_text(text_sections, r_target):
    text_offset = None
    for section in text_sections:
        text_offset = section["sh_addr"]
        text_end = text_offset + section["sh_size"]
        if (r_target >= text_offset) & (r_target < text_end):
            return True
    return False


def is_address_in_readonly_segment(segments, address):
    for segm in segments:
        if (address >= segm["p_vaddr"]) & (
            address < (segm["p_vaddr"] + segm["p_memsz"])
        ):
            return True
    return False


def is_address_in_load_write_segment(segments, address):
    for segm in segments:
        if (address >= segm["p_vaddr"]) & (
            address < (segm["p_vaddr"] + segm["p_memsz"])
        ):
            return True
    return False
