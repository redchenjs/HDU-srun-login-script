# 概述

本仓库修改自北京理工大学深澜校园网登录脚本，用于实现命令行登录杭州电子科技大学iHDU校园网。

# 运行依赖

```
python3
python3-requests
```

# 使用说明

登录操作需要两步：

1. 修改`login.py`文件填入数字杭电的帐号和密码
2. 执行`login.py`或`python3 login.py`命令即可登录iHDU校园网

注意：确保`HduSrunLogin`文件夹与`login.py`位于同一目录中。

# 参考链接

* [北京理工大学深澜校园网登录脚本](https://github.com/coffeehat/BIT-srun-login-script)
* [深澜校园网登录的分析与python实现-北京理工大学版](https://zhuanlan.zhihu.com/p/122556315)
