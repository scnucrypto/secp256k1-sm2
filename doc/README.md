# 问题
## 问题1：run.sh: ./autogen.sh: /bin/sh^M: bad interpreter: No such file or directory
> [参考](https://blog.csdn.net/kwu_ganymede/article/details/54134104)
1. 安装dos2unix：`sudo apt install dos2unix`
2. 运行命令：`dos2unix autogen.sh`

## 问题2：.ibtoolize:   error: AC_CONFIG_MACRO_DIRS([build-aux/m4]) conflicts with ACLOCAL_AMFLAGS=-I build-aux/m4
1. 运行命令：`dos2unix Makefile.am`

## 问题3：$'\r': command not found
1. 详细的报错信息
```bash
(base) chase@DESKTOP-D3FEH7R:~/code_2023/secp256k1-sm2$ bash run.sh
run.sh: line 2: $'\r': command not found
run.sh: line 7: $'\r': command not found
run.sh: line 22: syntax error near unexpected token `elif'
'un.sh: line 22: `elif [ $1 = "enc" ]; then
```
2. 解决方法：修改换行符格式为LF，而不是windows的CRLF