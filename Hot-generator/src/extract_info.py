import numpy as np


def get_dso_baseaddr(dso_baseaddr):
    content = []
    save_content = False
    with open(dso_baseaddr, "r") as file:
        for line in file:
            line = line.strip()
            if line.startswith("baseaddr"):
                save_content = True
            if line.startswith("baseaddr end"):
                save_content = False
                break
            if save_content:
                content.append(line)
    content = content[1:]

    dso_info = []
    for item in content:
        parts = item.split(" ", 2)
        pointer = np.uint64(int(parts[1], 16))

        parts[1] = pointer
        parts[2] = pointer

        dso_info.append(parts)
    dso_info = sorted(dso_info, key=lambda x: x[1])
    dso_info = [item for item in dso_info if "vdso" not in item[0]]
    return dso_info


hot_dso = [
    # "/home/ning/Desktop/Ning/smart_gloader/lib/libsqueezenet.so",
    "/home/ning/Desktop/Ning/smart_gloader/lib/libc.so.6",
]


file = "/home/ning/Desktop/TEST_APP/APP/ffmpeg/log0529"
dso_info = get_dso_baseaddr(file)
for item in dso_info:
    if item[0] not in hot_dso:
        print(f"'{item[0]}',")
