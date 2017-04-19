#!/bin/sh -e

j2 --format=env /opt/nginx/conf/nginx.conf.j2 >/opt/nginx/conf/nginx.conf
j2 --format=env /opt/nginx/conf.d/default.conf.j2 >/opt/nginx/conf.d/default.conf

echo "Starting Nginx ${NGINX_VERSION}"
/opt/nginx/sbin/nginx -V
exec /opt/nginx/sbin/nginx
