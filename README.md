# 基于Pyqt和scapy实现的简单抓包软件
## 环境
Windows 64位
```
PyQt5~=5.15.4
scapy~=2.4.5
geoip2~=4.5.0
pyecharts~=1.9.1
QtPy~=2.0.1
pcap-ct==1.2.3b12
```
*本来是用pypcap，但是windows安装太麻烦，而且pcap-ct的api更好一些。而且是纯python库，直接pip install安装，不用配置Wincap等等。*

### 第三方资源

使用geoip2解析IP地理位置和城市，从https://dev.maxmind.com/geoip?lang=en 来获取资源

项目本身已经包含所需的资源和解析数据资料。

### UI

UI使用Qt designer设计并使用qtuic生成python文件，UI源文件在目录*res/ui/*下。

## 功能

主界面：

![](https://s2.loli.net/2022/05/05/SjVOMD3faRgBi64.png)

抓包：

![](https://s2.loli.net/2022/05/05/yGYeJgAanNVkjQ4.png)

保存和读取pcap文件：

![](https://s2.loli.net/2022/05/07/7gsrmU6hLHvMxVK.png)

协议统计：

![](https://s2.loli.net/2022/05/07/34bunaJCmQ5hHd1.png)

流量统计：

![](https://s2.loli.net/2022/05/07/vMudx1GXIQ8l7Rr.png)

![](https://s2.loli.net/2022/05/07/bSFp9QqhZuo1UCI.png)

![](https://s2.loli.net/2022/05/07/UTPLHQWy1jmneEz.png)

归属地：

![](https://s2.loli.net/2022/05/07/6KRIHe3ALhBVjw1.png)
## 使用
```
git clone https://github.com/ShenTiao/PyNetSniffer
pip install requirements.txt
python sniffer_main.py
```
### 参考
***
[scapyshark](https://github.com/bannsec/scapyshark)
[Pcap-Analyzer](https://github.com/HatBoy/Pcap-Analyzer)
