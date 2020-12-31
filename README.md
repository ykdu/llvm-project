# Orion静态分析工具

### 安装
```bash
mkdir build
cd build
cmake -DLLVM_ENABLE_PROJECTS=clang -DCMAKE_BUILD_TYPE=Release -D CMAKE_C_COMPILER=gcc -D CMAKE_CXX_COMPILER=g++ -G "Unix Makefiles" ../llvm
make clang -j30
make install clang -j30
```

### 检测项 & 检测方法

| 单个编译单元检测项           | 含义                  | 检测方法                                                     |
| ---------------------------- | --------------------- | ------------------------------------------------------------ |
| Missing \_\_rpc\_\_          | 缺少\__rpc__          | 某路径中，在遇到\__rpc__前先遇到了其他RPC APIs               |
| Missing \_\_end\_\_          | 缺少\__end__          | 函数的分析出口处，某路径依然没有遇到\__end__                 |
| Nested RPC                   | 嵌套的RPC块           | 进入\_\_rpc\_\_后，退出\_\_end\_\_前遇到了\_\_rpc\_\_        |
| Unexpected rpc_send_X_length | 不应出现send_X_length | 见代码注释，DFA                                              |
| Missing rpc_send_X_length    | 缺少了send_X_len      | 用一个dict记录出现过的send_X_length，每次遇到send_X都在dict中对该表项的value减1 |

| 跨编译单元检测项                                        | 含义                                   | 检测方法 |
| ------------------------------------------------------- | -------------------------------------- | -------- |
| Undefined RPC, not found in server                      | client中有而server中没有该RPC          |          |
| Unique client path, has no corresponding path in server | server中该路径在client中没有对应的路径 |          |
| Unique server path, has no corresponding path in client | client中该路径在server中没有对应的路径 |          |

###  [User Guide](doc/user_guide.md)

使用Orion静态分析工具发现问题

###  [Internal](doc/internal.md)

开发人员手册
