# 问题
## 问题1：run.sh: ./autogen.sh: /bin/sh^M: bad interpreter: No such file or directory
> [参考](https://blog.csdn.net/kwu_ganymede/article/details/54134104)
1. 安装dos2unix：`sudo apt install dos2unix`
2. 运行命令：`dos2unix autogen.sh`

## 问题2：.ibtoolize:   error: AC_CONFIG_MACRO_DIRS([build-aux/m4]) conflicts with ACLOCAL_AMFLAGS=-I build-aux/m4
1. 运行命令：`dos2unix Makefile.am`