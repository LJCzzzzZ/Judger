package tracer

var (
	// defaultAllows 列出允许的系统调用（syscalls）
	defaultAllows = []string{
		"read",       // 从文件描述符中读取数据
		"write",      // 向文件描述符中写入数据
		"readv",      // 从多个缓冲区中读取数据
		"writev",     // 将多个缓冲区中的数据写入文件描述符
		"open",       // 打开文件并返回文件描述符
		"unlink",     // 删除文件系统中的文件
		"close",      // 关闭文件描述符
		"readlink",   // 读取符号链接的目标路径
		"openat",     // 相对于目录文件描述符打开文件
		"unlinkat",   // 相对于目录文件描述符删除文件
		"readlinkat", // 相对于目录文件描述符读取符号链接的目标
		"stat",       // 获取文件状态信息
		"fstat",      // 获取打开文件的状态信息
		"lstat",      // 类似于 stat，但专门处理符号链接
		"lseek",      // 调整文件描述符的读/写偏移
		"access",     // 检查文件的访问权限

		"dup",   // 复制文件描述符
		"dup2",  // 复制文件描述符并指定新的描述符编号
		"dup3",  // 复制文件描述符并指定标志
		"ioctl", // 用于设备的控制操作
		"fcntl", // 对文件描述符进行控制操作（例如设置锁）

		"mmap",     // 将文件或设备映射到内存
		"mprotect", // 设置内存区域的保护（读、写、执行权限）
		"munmap",   // 解除内存映射
		"brk",      // 调整数据段的大小
		"mremap",   // 重新映射内存区域
		"msync",    // 将内存映射的文件内容同步到磁盘
		"mincore",  // 检查内存页是否驻留在内存中
		"madvise",  // 提供关于内存使用的建议

		"rt_sigaction",   // 更改信号处理的动作
		"rt_sigprocmask", // 改变信号掩码，控制哪些信号被阻塞
		"rt_sigreturn",   // 从信号处理程序中返回并恢复之前的信号掩码
		"rt_sigpending",  // 检查当前未决的信号
		"sigaltstack",    // 配置信号处理的备用栈

		"getcwd", // 获取当前工作目录

		"exit",       // 终止当前进程
		"exit_group", // 终止进程组中的所有线程

		"arch_prctl", // 设置与架构相关的线程状态信息（例如，x86-64）

		"gettimeofday",  // 获取当前时间
		"getrlimit",     // 获取资源限制（如文件描述符的最大数量）
		"getrusage",     // 获取进程或线程的资源使用情况
		"times",         // 返回进程时间信息
		"time",          // 获取当前的日历时间
		"clock_gettime", // 从指定时钟获取时间

		"restart_syscall", // 重新启动被信号中断的系统调用
	}

	// defaultTraces 列出需要跟踪的系统调用
	defaultTraces = []string{
		// should be traced
		"execve",

		// file open
		"open",
		"openat",

		// file delete
		"unlink",
		"unlinkat",

		// soft link
		"readlink",
		"readlinkat",

		// permission check
		"lstat",
		"stat",
		"access",
	}
)
