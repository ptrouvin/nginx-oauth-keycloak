
#!/bin/sh

# Default variables
NGINX_VERSION=${NGINX_VERSION:-1.10.3}
NGINX_FILENAME=nginx-${NGINX_VERSION}.tar.gz
NGINX_DL_URL=https://nginx.org/download/${NGINX_FILENAME}
NGINX_SRC_DIR=/usr/src/nginx
NGINX_DIR=/opt/nginx
NGINX_MORE_MODULES_DIR=${NGINX_SRC_DIR}/more_modules

# Note : the trust key delivered by nginx was revoked in June, 2016

# && ( useradd -u 998 -g 996 -s /sbin/nologin -c 'nginx user' -d /var/cache/nginx nginx || : ) \

(groupadd -g 996 nginx || :) \
&& ( useradd -g 996 -s /sbin/nologin -c 'nginx user' -d /var/cache/nginx nginx || : ) \
&& curl -fSL "${NGINX_DL_URL}" -o "${NGINX_FILENAME}" \
&& mkdir -p ${NGINX_SRC_DIR} \
&& mkdir -p ${NGINX_MORE_MODULES_DIR} \
&& tar xvzf ${NGINX_FILENAME} -C ${NGINX_SRC_DIR} --strip-components=1 \
&& rm ${NGINX_FILENAME} \
&& git clone https://github.com/simpl/ngx_devel_kit ${NGINX_MORE_MODULES_DIR}/ngx_devel_kit \
&& git clone https://github.com/openresty/lua-nginx-module ${NGINX_MORE_MODULES_DIR}/lua-nginx-module \
&& git clone https://github.com/openresty/headers-more-nginx-module.git ${NGINX_MORE_MODULES_DIR}/headers-more-nginx-module \
&& cd ${NGINX_SRC_DIR} \
&& ./configure --prefix=${NGINX_DIR} \
  --user=nginx \
  --group=nginx \
  --with-file-aio \
  --with-threads \
  --with-ipv6 \
  --http-client-body-temp-path=${NGINX_DIR}/cache/client_temp \
  --http-proxy-temp-path=${NGINX_DIR}/cache/proxy_temp \
  --with-http_addition_module \
  --with-http_auth_request_module \
  --with-http_gunzip_module \
  --with-http_gzip_static_module \
  --with-http_mp4_module \
  --with-http_realip_module \
  --with-http_ssl_module \
  --with-http_stub_status_module \
  --with-http_sub_module \
  --with-http_v2_module \
  --with-http_realip_module \
  --with-poll_module \
  --without-http_charset_module \
  --without-http_ssi_module \
  --without-http_userid_module \
  --without-http_split_clients_module \
  --without-http_fastcgi_module \
  --without-http_uwsgi_module \
  --without-http_scgi_module \
  --without-http_memcached_module \
  --without-http_empty_gif_module \
  --add-module=${NGINX_MORE_MODULES_DIR}/lua-nginx-module \
  --add-module=${NGINX_MORE_MODULES_DIR}/ngx_devel_kit \
  --add-module=${NGINX_MORE_MODULES_DIR}/headers-more-nginx-module \
  --with-cc-opt='-O2 -g -pipe -Wall -Wp,-D_FORTIFY_SOURCE=2 -fexceptions -fstack-protector-strong --param=ssp-buffer-size=4 -grecord-gcc-switches -m64 -mtune=generic -fPIC' \
  --with-ld-opt='-Wl,-z,relro -Wl,-z,now -pie' \
&& make \
&& make install \
&& strip /opt/nginx/sbin/nginx \
&& mkdir -p ${NGINX_DIR}/cache \
&& true \ # yum -y lua-devel openldap-devel \
&& true \ # git clone https://github.com/ptrouvin/lualdap.git ${NGINX_SRC_DIR}/lualdap \
&& true \ # cd ${NGINX_SRC_DIR}/lualdap \
&& true \ # LUA_INC=/usr/include/lua50 OPENLDAP_INC=/usr/include make -e \
&& true \ # make install \
&& true \ # yum clean all \
&& rm -f ${NGINX_DIR}/conf/*.default \
&& cd - \
&& rm -rf ${NGINX_SRC_DIR}

