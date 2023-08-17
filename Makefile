
default:	build

clean:
	rm -rf Makefile objs

.PHONY:	default clean

build:
	$(MAKE) -f objs/Makefile

install:
	$(MAKE) -f objs/Makefile install

modules:
	$(MAKE) -f objs/Makefile modules

upgrade:
	/home/thatcher/projects/ja4_nginx/nginx/nginx_local/sbin/nginx -t

	kill -USR2 `cat /home/thatcher/projects/ja4_nginx/nginx/nginx_local/logs/nginx.pid`
	sleep 1
	test -f /home/thatcher/projects/ja4_nginx/nginx/nginx_local/logs/nginx.pid.oldbin

	kill -QUIT `cat /home/thatcher/projects/ja4_nginx/nginx/nginx_local/logs/nginx.pid.oldbin`

.PHONY:	build install modules upgrade
