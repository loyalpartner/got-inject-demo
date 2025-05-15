#!/bin/bash

# simple_inject.sh - 使用LD_PRELOAD简单注入hook.so

if [ $# -lt 1 ]; then
    echo "Usage: $0 <pid> [hook_so_path]"
    echo "  pid: 目标进程ID"
    echo "  hook_so_path: 钩子库路径 (默认: ./hook.so)"
    exit 1
fi

PID=$1
HOOK_PATH=${2:-"$(realpath ./hook.so)"}

if [ ! -f "$HOOK_PATH" ]; then
    echo "错误: 钩子库文件不存在: $HOOK_PATH"
    exit 1
fi

if [ ! -d "/proc/$PID" ]; then
    echo "错误: 进程 $PID 不存在"
    exit 1
fi

echo "目标进程: $PID"
echo "钩子库路径: $HOOK_PATH"

# 获取进程的环境变量
ENV_FILE="/proc/$PID/environ"
if [ ! -r "$ENV_FILE" ]; then
    echo "错误: 无法读取进程环境变量 (需要root权限)"
    exit 1
fi

# 获取当前LD_PRELOAD值
CURRENT_PRELOAD=$(tr '\0' '\n' < "$ENV_FILE" | grep "^LD_PRELOAD=" | cut -d= -f2)

# 获取进程可执行文件路径
EXE_PATH=$(readlink -f "/proc/$PID/exe")
echo "可执行文件: $EXE_PATH"

# 检查是否已经注入
if [[ "$CURRENT_PRELOAD" == *"$HOOK_PATH"* ]]; then
    echo "钩子库已经被注入!"
    exit 0
fi

# 构建新的LD_PRELOAD值
if [ -z "$CURRENT_PRELOAD" ]; then
    NEW_PRELOAD="$HOOK_PATH"
else
    NEW_PRELOAD="$HOOK_PATH:$CURRENT_PRELOAD"
fi

echo "注入LD_PRELOAD: $NEW_PRELOAD"

# 使用gdb注入LD_PRELOAD环境变量
GDB_SCRIPT=$(mktemp)
cat > "$GDB_SCRIPT" << EOF
attach $PID
call setenv("LD_PRELOAD", "$NEW_PRELOAD", 1)
call dlopen("$HOOK_PATH", 2)
detach
quit
EOF

echo "使用GDB执行注入..."
gdb -batch -x "$GDB_SCRIPT"
rm "$GDB_SCRIPT"

echo "注入完成，检查进程的内存映射..."
grep "$HOOK_PATH" "/proc/$PID/maps" || echo "警告: 在内存映射中未找到钩子库!"

echo "尝试重新执行程序的关键函数以触发钩子..."
GDB_TRIGGER=$(mktemp)
cat > "$GDB_TRIGGER" << EOF
attach $PID
call puts("GDB_TRIGGER_MESSAGE")
detach
quit
EOF

gdb -batch -x "$GDB_TRIGGER"
rm "$GDB_TRIGGER"

echo "注入过程完成!"