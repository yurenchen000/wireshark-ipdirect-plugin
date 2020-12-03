
## usage

这是一个 wireshark 包解析插件.

- 安装方法: 放到 wireshark lua plugin 目录里, 重新加载 lua 插件.

  - NOTE1: 目录位置 wireshark 菜单 -> 帮助 -> 关于 -> 文件夹: `个人 Lua 插件` 或 `全局 Lua 插件`.
  - NOTE2: 重新加载 lua 插件: `Ctrl+Shift+L` 或 菜单 -> 分析 -> `重新载入 Lua 插件`.

- 使用方法:
wireshark 报文解析(分组详情窗口) 会多出 `package direction` 的项, 其中子项 可以右键 `显示为列`.

  - NOTE3: 其中右键 -> 协议首选项 -> open ..: 可以设置 `local mac` //插件通过 mac 区分报文 是收是发


- 使用效果:
主要为了提高包列表 的可读性

![preview1.png](plugin_preview1.png)


color rules highlight for recv:

    ip.direction.direct == "<--"

## profile
预前配置好的 columns, layout, color rules (直接导入 可避免手动在 GUI 里再配置一遍)

用法:

    cp -pvrT profile_chen ~/.config/wireshark/profiles/chen

// win 系统 参见 NOTE1, 找 configuration 目录