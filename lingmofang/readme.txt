IndexNow Auto 1.0
=================

适用环境
--------
Debian 12、宝塔面板、Nginx、PHP 8.2。脚本自身仅使用 Python 3 标准库。

固定逻辑
--------
1. 读取 /opt/indexnow_auto/domain.txt；兼容 domian.txt。
2. 每个基础域名生成 @、www、m、3g、wap 五个 host。
3. 检查各 host 首页是否可访问。
4. 在 /www/wwwroot/基础域名/ 写入统一 IndexNow 密钥文件。
5. 只扫描站点根目录第一层 PHP 文件。
6. index.php 只代表首页，不生成 index.html。
7. 其他非敏感 PHP 文件转换为同名 .html。
8. 不生成 article-数字.html、纯数字/纯字母/混合字符泛页面。
9. 每个可访问 host 都推送首页 + 全部固定内页。
10. 每天全量重复推送，不做增量状态判断。

Sitemap 文件
------------
Sitemap 协议要求一个文件只包含一个 host，因此脚本在同一站点根目录生成：
- 裸域名：sitemap.xml
- www：sitemap-www.xml
- m：sitemap-m.xml
- 3g：sitemap-3g.xml
- wap：sitemap-wap.xml

例如：
https://example.com/sitemap.xml
https://www.example.com/sitemap-www.xml
https://m.example.com/sitemap-m.xml

每份文件都包含对应 host 的首页 + 固定内页。

部署
----
1. 上传整个目录到服务器，例如 /root/indexnow_auto_package/
2. 执行：
   chmod +x /root/indexnow_auto_package/install.sh
   bash /root/indexnow_auto_package/install.sh
3. 编辑：
   nano /opt/indexnow_auto/domain.txt
4. 首次演练：
   python3 /opt/indexnow_auto/main.py --dry-run --verbose
5. 只生成 Sitemap 和密钥，不推送：
   python3 /opt/indexnow_auto/main.py --no-push --verbose
6. 正式运行：
   python3 /opt/indexnow_auto/main.py --verbose

常用命令
--------
只处理一个域名：
python3 /opt/indexnow_auto/main.py --domain example.com --verbose

检查语法：
python3 -m py_compile /opt/indexnow_auto/main.py

查看日志：
tail -f /opt/indexnow_auto/logs/run.log

查看报告：
column -s, -t < /opt/indexnow_auto/reports/latest.csv | less -S

宝塔计划任务
------------
任务类型：Shell 脚本
执行周期：每天一次，例如 03:20
脚本内容：

/usr/bin/python3 /opt/indexnow_auto/main.py >> /opt/indexnow_auto/logs/cron.log 2>&1

建议设置任务超时时间足够长。脚本使用 /opt/indexnow_auto/state/run.lock 防止重复执行。

注意事项
--------
- 根目录 PHP 文件会被视为公开固定页，务必维护 config.ini 的 exclude 和 exclude_name_contains。
- 由于站点存在泛路由，任意 .html 可能返回 200，所以默认不会用 HTTP 200 判断固定内页真假。
- 如果某些公开 PHP 文件没有对应 .html 伪静态规则，请将它加入 exclude。
- 如果 HTTPS 证书不完整，会先失败；允许时脚本会回退 HTTP。生产环境建议修复证书，不建议关闭 verify_tls。
- IndexNow HTTP 200 表示已接收；202 表示已接收但密钥验证待完成，不代表一定收录。
