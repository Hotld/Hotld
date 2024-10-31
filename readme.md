# Hotld
Hotld is a method aimed at optimizing the code layout of dynamic libraries from a global perspective. It merges hot code from different dynamic libraries into a single hot library and rewrites the indirect call instructions in the hot library to bypass the execution of PLT trampoline code.
## Download Hotld for rocksdb
```bash
git clone https://github.com/Hotld/Hotld.git
```
## Install Hot-linker

```bash
mkdir build 
cd build
LDFLAGS+="-Wl,--emit-relocs " ../glibc-2.35/configure --prefix=/usr/smart_glibc
make LDFLAGS+="-Wl,--emit-relocs " -j32
sudo make install
```

-Wl,--emit-relocs: Specify that the linker retains relocation information in the output file.

## Install BOTL
To use llvm-bolt and perf2bolt utilities, BOLT needs to be installed.
BOLT installation can be referenced in the official documentation: https://github.com/llvm/llvm-project.git

## Use BOTL
* collect profile 

```bash
# For Applications
perf record -e cycles:u -j any,u -o perf.data -- <executable> <args> ...

# For Services
perf record -e cycles:u -j any,u -a -o perf.data -- sleep 180

# With instrumentation
llvm-bolt <executable> -instrument -o <instrumented-executable>
```

* Convert Profile to BOLT Format
```bash
perf2bolt -p perf.data -o perf.fdata <executable>
```
* Get the reordered function sequence and control flow graph (CFG).
```bash
llvm-bolt instrumented-executable -o instrumented-executable.bolt \
--generate-function-order=instrumented-executable.order -data=perf.fdata \
--reorder-blocks=none --reorder-functions=hfsort --print-cfg >instrumented-executable.cfg
```


## Hot-generator

- dso_infos: The path of the executable file and the paths of frequently used dynamic libraries.
- merge_type: The methods for merging different dynamic libraries' code are as follows: 
    - 1: merging the execution segments of different dynamic libraries
    - 2: merging the code segments of different dynamic libraries
    - 3: merging the hot code of different dynamic libraries. Currently, only option 3 is stable.
- ht_savepath: Path for storing generated Hot-library.
- hf_cfgs: Directory for storing CFG information.
- hf_order: Directory for storing the rearrangement order of hot library functions.

<pre>
python3 main.py --dso_infos ../register_file/db_bench.json --merge_type 3 --ht_savepath ../hot_template/db_bench.ht --hf_cfgs=../cfg_information/rocksdb/ --hf_order=../cfg_information/rocksdb/
</pre>


## Test Rocksdb
### Install Rocksdb