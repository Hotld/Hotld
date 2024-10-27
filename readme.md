# glibc install

<pre>
    mkdir build 
    cd build
    LDFLAGS+="-Wl,--emit-relocs " ../glibc-2.35/configure --prefix=/usr/smart_glibc
    make LDFLAGS+="-Wl,--emit-relocs " -j32
    sudo make install
</pre>

-Wl,--emit-relocs: Specify that the linker retains relocation information in the output file.

# llvm-bolt
## install


# hot-generator

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


