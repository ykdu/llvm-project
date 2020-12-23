# Orion静态分析工具

### 单独使用demo

前置：在/duyunkai/llvm-project仓库下，编译出clang。或者进入已经编好clang的docker镜像orion-compile:cuda-universal。

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

### 单独使用方法

#TODO待完善

```bash
-analyze -analyzer-checker=core.RPC
-analyzer-config ipa=none
-DSTATIC_ANALYSIS 		#侵入式过滤掉应用程序中gcc强相关的代码
```

可选配置

```bash
-analyzer-config core.RPC:SavePathLocation="/tmp/csa"	 # 表明把路径信息写入到/tmp/csa中
-analyzer-config core.RPC:SavePathMode="trunc"
-analyzer-config core.RPC:LoadPathLocation="/tmp/csa"
-O0	#（可选）可加快检测
```

### 在orion_arch中使用方法

当需要静态检查一个新的arch模块时，须按如下步骤操作（具体可以参考cuda模块）：

1. 拿到检查工具的docker镜像 orion-compile:cuda-universal

2. 新增check.sh

   1. 其中重点在于对client/server分别make时对CC、CFLAGS、CXXFLAGS的重定义。

3. 直接运行

   ```bash
   ./check.sh
   ```

   或者，在Makefile中加入check命令，然后

   ```bash
   make check
   ```
