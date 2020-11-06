
## usage

这是一个 wireshark 包解析插件.

安装方法: 放到 wireshark lua plugin 目录里, 重新加载 lua 插件.

NOTE1: 目录位置 wireshark 菜单 -> 帮助 -> 关于 -> 文件夹: `个人 Lua 插件` 或 `全局 Lua 插件`
NOTE2: 重新加载 lua 插件: ctrl+shift+l 或 菜单 -> 分析 -> `重新载入 Lua 插件`

使用方法:
wireshark 报文解析(分组详情 窗口) 会多出 package direction 的项, 其中子项 可以显示为列.

