# Orion静态分析工具

### 架构

<img src="arch.png" alt="架构" width=50%/>

**符号化**：目的是尽可能在用户代码层面提前删除掉多余代码，避免CSA分析时遇到太多分支等信息。RPC函数重定义为仅包含side effect的等价函数，并记录下后续分析所需的参数信息（包括：RPC块名、RPC API名、RPC调用签名型实参名、RPC调用可选实参名）。模块化为一个单独的头文件，尽量不侵入原应用程序代码。

**路径仿真器**：由CSA（Clang Static Analyzer）提供，负责给出所有可能的执行路径。path-sensitive指各个分支均会被考虑，而且CSA会利用其约束求解器尽可能计算出哪些分支一定不会进入，从而剪枝掉。

**编译单元内检查器**：在路径仿真的过程中，通过在explored节点中记录相关信息，从而检测出问题。

**跨编译单元检查器**：先分析单元1，将其路径信息保存在磁盘文件中；再分析单元2，从磁盘文件中读入单元1的路径信息，再结合路径仿真器分析出的单元2的路径信息，综合检测跨编译单元问题。

### 后续

1. ​	循环的处理
2. ​	当前暂时不支持send buf等

### for 开发者

对CSA开发文档基于新版Clang进行了一些更新，文档中解决了一些接口变化导致的用例不可用问题。 https://github.com/ykdu/clang-analyzer-guide

### 代码仓同步步骤

```bash
# in github repo（开发）
    git push
# in gitlab repo（同步）
    git remote add upstream https://github.com/ykdu/llvm-project
    git pull upstream master
    git push origin master
```

### QA

1. 为什么不在EndFunction时检测\_\_end\_\_缺失，反而把visitedRPC保存为map，并用其value作为判断？

   提前return也是合法情况，前者回把这种情况识别为错误。所以不应要求所有路径都被关闭，而从另一个角度想，每个不缺少\_\_end\_\_的rpc块都至少有一条路径能走到\_\_end\_\_，因此判断是否确实的条件应是：被关闭过一次就ok。
   
2. 为什么副作用要定义为malloc的形式？

   为了使得这里是一个随机值。反之，size_t len{}的话，编译器会知道这里len==0，进而影响后续的分支判断。

3. make CC="clang++ -###" 2>&1 >/dev/null | python ../../check.py -save 的含义

   生成编译日志，并传入脚本中执行
