### demo

##### demo1 单个编译单元内检测

1. 根据make long，获取编译命令（已获取好，在csa.sh）

   ```bash
   make
   clang -### ... -DSTATIC_ANALYSIS -analyze -analyzer-checker=core.RPC -analyzer-config ipa=none
   ```

   注意到其中的编译选项

   ```bash
   -DSTATIC_ANALYSIS # 一方面注释掉业务代码中直接使用的gcc pragma，从而避免使用clang时报warning；另一方面使能符号化头文件。
   -analyze -analyzer-checker=core.RPC # 开启检查。
   -analyzer-config ipa=none # 因为我们的case中不需要过程间分析，所以关闭以加速。
   ```

2. 检测构造的错误用例

   ```bash
   # 解开ut
   ./csa.sh
   ```

   应报出5个warning。

3. 尝试多分支场景下路径分析是否正确

   ```shell
   # 解开ut-branch
   ./csa.sh
   ```

   注意到其中额外的两个编译选项

   ```bash
   -analyzer-config core.RPC:SavePathLocation="/tmp/csa"	 # 表明把路径信息写入到/tmp/csa中
   -analyzer-config core.RPC:SavePathMode="trunc"  		 # 表明以追加模式写入
   ```

   应在/tmp/csa文件中打印出5条RPC路径

4. 检测libapp

   ```bash
   # 解开libapp
   ./csa.sh
   ```

   应报出3个warning。（其中assert所带来的提前return问题在TODO中）

##### demo2 跨编译单元检测

 1. 检测并保存client的路径

    ```bash
    # 解开libapp
    ./csa.sh
    ```

 2. 手动添加一个bug

    ```bash
    #比如，注释掉一个recv()
    ```

 3. 跨单元检测server

    ```bash
    cd server_engine
    ./csa.sh
    ```

    注意到其中的编译选项，用于读入其他编译单元的路径

    ```bash
    -analyzer-config core.RPC:LoadPathLocation="/tmp/csa"
    ```



### 架构

<img src="https://github.com/ykdu/llvm-project/blob/master/arch.png" alt="架构" style="zoom:24%;" />

**符号化**：目的是尽可能在用户代码层面提前删除掉多余代码，避免CSA分析时遇到太多分支等信息。RPC函数重定义为仅包含side effect的等价函数，并记录下后续分析所需的参数信息（包括：RPC块名、RPC API名、RPC调用签名型实参名、RPC调用可选实参名）。模块化为一个单独的头文件，尽量不侵入原应用程序代码。

**路径仿真器**：由CSA（Clang Static Analyzer）提供，负责给出所有可能的执行路径。path-sensitive指各个分支均会被考虑，而且CSA会利用其约束求解器尽可能计算出哪些分支一定不会进入，从而剪枝掉。

**编译单元内检查器**：在路径仿真的过程中，通过在explored节点中记录相关信息，从而检测出问题。

**跨编译单元检查器**：先分析单元1，将其路径信息保存在磁盘文件中；再分析单元2，从磁盘文件中读入单元1的路径信息，再结合路径仿真器分析出的单元2的路径信息，综合检测跨编译单元问题。



### 检测项 & 检测方法

| 单个编译单元检测项        | 含义                  | 检测方法                                                     |
| ------------------------- | --------------------- | ------------------------------------------------------------ |
| BT_MISSING_RPC            | 缺少\__rpc__          | 某路径中，在遇到\__rpc__前先遇到了其他RPC APIs               |
| BT_MISSING_END            | 缺少\__end__          | 函数的分析出口处，某路径依然没有遇到\__end__                 |
| BT_NESTED_RPC             | 嵌套的RPC块           | 进入\_\_rpc\_\_后，退出\_\_end\_\_前遇到了\_\_rpc\_\_        |
| BT_REDEFINED_RPC          | 重复定义的RPC块       | 记录遇到过的RPC名，遇到了同名RPC                             |
| BT_UNEXPECTED_SEND_LENGTH | 不应出现send_X_length | 见代码注释，DFA                                              |
| BT_MISSING_SEND_LENGTH    | 缺少了send_X_len      | 用一个dict记录出现过的send_X_length，每次遇到send_X都在dict中对该表项的value减1 |

| 跨编译单元检测项              | 含义                                   | 检测方法 |
| ----------------------------- | -------------------------------------- | -------- |
| BT_CCU_MISSING_CLIENT         | server中有而client中没有该RPC          |          |
| BT_CCU_MISSING_SERVER         | client中有而server中没有该RPC          |          |
| BT_CCU_INDIVIDUAL_SERVER_PATH | server中该路径在client中没有对应的路径 |          |
| BT_CCU_INDIVIDUAL_CLIENT_PATH | client中该路径在server中没有对应的路径 |          |



### 使用方法

#TODO待完善

```bash
-DSTATIC_ANALYSIS 侵入式过滤掉应用程序中gcc强相关的代码
-analyzer-config core.RPC:SavePathLocation="/tmp/csa"	 # 表明把路径信息写入到/tmp/csa中
-analyzer-config core.RPC:SavePathMode="trunc"
-analyzer-config core.RPC:LoadPathLocation="/tmp/csa"
-O0	#（可选）可加快检测
```

### 后续

1. ​	循环的处理
2. ​	当前暂时不支持send buf等

### for 开发者

对CSA开发文档基于新版Clang进行了一些更新，文档中解决了一些接口变化导致的用例不可用问题。 https://github.com/ykdu/clang-analyzer-guide

