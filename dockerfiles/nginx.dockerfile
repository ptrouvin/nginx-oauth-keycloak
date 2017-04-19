FROM openshift/base-centos7

EXPOSE 8080

LABEL maintainer "sebastien.rohaut@axa-tech.com" \
version "0.2.0" \
description "nginx image to interface with contento4 sail app"

# Default values
ENV NGINX_VERSION=1.10.3 \
    NGINX_LISTEN_PORT=8080 \
    NGINX_LOG_ACCESS=/dev/stdout \
    NGINX_LOG_ERROR=/dev/stderr \
    NGINX_LOG_FORMAT=main \
    NGINX_SERVER_TOKENS=off \
    NGINX_WORKER_PROCESSES=1 \
    NGINX_WORKER_CONNECTIONS=1024 \
    NGINX_PROXY_WEBSOCKET_ENABLED=false \
    NGINX_PROXYPASS='http://127.0.0.1:1337' \
    NGINX_GZIP_ENABLED=true \
    NGINX_ALLOW_UPLOAD=false \
    NGINX_MAX_BODY_SIZE=10 \
    NGINX_ADD_HEADERS='X-Frame-Options SAMEORIGIN|X-XSS-Protection "1; mode=block"|X-Content-Type-Options nosniff' \
	NGINX_AUTH_KEYCLOAK_LUAPATH='/opt/nginx/lua' \
	NGINX_AUTH_METHOD='keycloak' \
	NGINX_AUTH_DEBUG='false' \
	NGINX_URL='https://nginx-noauth.apps-wh.axaxx.nu'

RUN echo "Install EPEL reprository ..." \
 && yum install -y  https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm \
 && yum clean all

RUN echo "Installing dependencies ..." \
 && yum install -y python2-pip luajit luajit-devel libffi libffi-devel \
 && yum clean all \
 && pip install j2cli[yaml]

COPY usr/local/bin/ /usr/local/bin/

RUN chmod a+x /usr/local/bin/*

# Build nginx
RUN /usr/local/bin/build_nginx.sh

RUN mkdir -p /opt/nginx/conf.d $NGINX_AUTH_KEYCLOAK_LUAPATH/resty \
 && chown -R nginx:0 /opt/nginx \
 && chmod -R g+rw /opt/nginx \
 && yum -y update \
 && yum clean all

USER nginx

COPY nginx/nginx.conf.j2 /opt/nginx/conf
COPY nginx/conf.d/default.conf.j2 /opt/nginx/conf.d
COPY html/50x.html /opt/nginx/html/

COPY oauth-keycloak/* $NGINX_AUTH_KEYCLOAK_LUAPATH/ 
COPY oauth-keycloak/resty/* $NGINX_AUTH_KEYCLOAK_LUAPATH/resty/ 

CMD ["start-nginx.sh"]
