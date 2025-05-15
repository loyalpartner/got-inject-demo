# GOT Hook Injection Demo

这个项目演示了如何通过修改 GOT (Global Offset Table) 来钩取一个正在运行的进程中的函数调用。

## 项目结构

```
got_inject_demo/
├── hook.so       # 我们的 hook 库（负责 GOT Hook）
├── injector      # 注入器（使用 ptrace + dlopen 注入 hook.so）
├── target        # 被注入的目标进程（演示用）
```

## 编译

使用以下命令编译所有组件：

```bash
make
```

或者单独编译：

```bash
# 编译目标程序
gcc target.c -o target -no-pie -fno-pie

# 编译 Hook 库
gcc -shared -fPIC -o hook.so hook.c -ldl

# 编译注入器
gcc injector.c -o injector -ldl
```

## 运行流程

1. 启动目标程序：

```bash
./target
```

2. 在另一个终端中，查找目标进程的 PID：

```bash
pgrep target
```

3. 注入 Hook 库：

```bash
sudo ./injector <pid> $(realpath ./hook.so)
```

4. 观察目标程序的输出变化，puts 函数已被钩取。

## 技术说明

### target

一个简单的循环程序，每隔 2 秒调用一次 puts 函数。编译时关闭 PIE 以简化注入流程。

### hook.so

这个共享库通过以下步骤钩取 puts 函数：
1. 使用 `dl_iterate_phdr` 遍历加载的共享对象
2. 在动态段中寻找 GOT 表和相关的符号表
3. 找到 puts 函数对应的 GOT 条目
4. 保存原始函数指针并替换为自己的实现

### injector

注入器使用 ptrace 附加到目标进程，然后：
1. 保存寄存器状态
2. 在目标进程中分配内存以存储共享库路径
3. 定位目标进程中 `dlopen` 函数的地址
4. 重写寄存器以调用 `dlopen` 加载 hook.so
5. 恢复原始寄存器状态并分离

## 安全提示

此代码仅用于教育目的，在实际系统上使用时请注意：
- 需要 root 权限才能使用 ptrace
- 注入陌生进程可能导致不稳定或安全问题