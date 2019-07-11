# xhprof的安装和使用

## 简介

​	xhprof 是一个分层PHP性能分析工具。

## 安装

### Php Version

​	>=7.0  &&  <= 7.3

### Installation

```
git clone https://github.com/longxinH/xhprof.git ./xhprof
cd xhprof/extension/
/usr/local/Cellar/php@7.2/7.2.18/bin/phpize
./configure --with-php-config=/usr/local/Cellar/php@7.2/7.2.18/bin/php-config
make && sudo make install
```

### Edit Php.ini

```
extension = xhprof.so
xhprof.output_dir = /data/www/xhprof/output
```

### Checked

```
//重启php
brew services restart php@7.2
//查看是否安装上
php -m | grep xhprof
```

### Configure Xhprof Domain

```
//创建输出文件
	mkdir -p /data/www/xhprof/output
//创建xhprof文件
	mkdir /data/www/pxhprof
	cp -R /usr/local/etc/xhprof/* /data/www/pxhprof
	cd /data/www/phprof
//Xhprof域名配置
	server {
        listen 80;
        server_name xhprof.xin.com;
        #access_log logs/xhprof.access.log;
        autoindex on;
        location / {
                root /data/www/pxhprof;
                index index.html index.htm index.php;
                try_files $uri $uri/ /index.php?$query_string;
         }
        location ~ \.php$ {
                root /data/www/pxhprof;
                fastcgi_pass 127.0.0.1:9000;
                fastcgi_index index.php;
                fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
                fastcgi_intercept_errors on; include fastcgi_params;
        }
	}
//修改hosts
	127.0.0.1       xhprof.xin.com
```

### Reload Nginx

```
//重启nginx
	brew services restart nginx
//再安装一个插件 graphviz 可以看生成的图片
	brew install graphviz
```

## 使用

#### 代码改动

关于xhprof的使用有两种方式

1.在入口文件(即：Public/index.php)文件加入

```
xhprof_enable(XHPROF_FLAGS_MEMORY | XHPROF_FLAGS_CPU);
register_shutdown_function(function() {
    $xhprof_data = xhprof_disable();
    if (function_exists('fastcgi_finish_request')){
        fastcgi_finish_request();
    }
    include_once "/data/www/pxhprof/xhprof_lib/utils/xhprof_lib.php";
    include_once "/data/www/pxhprof/xhprof_lib/utils/xhprof_runs.php";
    $xhprof_runs = new XHProfRuns_Default();
    $run_id = $xhprof_runs->save_run($xhprof_data, 'xhprof');
});
```

2.添加两个方法 enableXhprof() 和 disableXhprof()，然后再要执行的方法片段加上两个方法名

```
function enableXhprof()
{
    xhprof_enable(XHPROF_FLAGS_MEMORY | XHPROF_FLAGS_CPU);
}
function disableXhprof()
{
    $xhprof_data = xhprof_disable();
    include_once "/data/www/pxhprof/xhprof_lib/utils/xhprof_lib.php";
    include_once "/data/www/pxhprof/xhprof_lib/utils/xhprof_runs.php";
    $xhprof_runs = new \XHProfRuns_Default();
    $run_id = $xhprof_runs->save_run($xhprof_data, "xhprof_foo");
    #echo $run_id;
}
```

#### 具体展示图

![image-20190711173740994](/Users/zyy/Library/Application Support/typora-user-images/image-20190711173740994.png)

![image-20190711174430970](/Users/zyy/Library/Application Support/typora-user-images/image-20190711174430970.png)



![image-20190711174501977](/Users/zyy/Library/Application Support/typora-user-images/image-20190711174501977.png)
