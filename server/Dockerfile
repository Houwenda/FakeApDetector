FROM registry.docker-cn.com/richarvey/nginx-php-fpm
MAINTAINER houwenda < houwd123@126.com >

#RUN apt-get update
#RUN apt-get upgrade
RUN mkdir /var/www/html/upload/

COPY php.ini /user/local/php/php.ini
COPY index.php /var/www/html/
COPY analysis.py /var/www/html/
COPY install.sh /tmp/

RUN chmod +x /tmp/install.sh
RUN /tmp/install.sh
RUN chmod +x /var/www/html/upload
RUN chmod +x /var/www/html/index.php

EXPOSE 80 9000
CMD ["/start.sh"]
