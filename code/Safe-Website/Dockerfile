FROM php:7.2-apache
RUN docker-php-ext-install mysqli
RUN docker-php-ext-enable mysqli
RUN groupadd -r app && useradd -g app app
RUN chown -R app:app .
USER app
COPY src/ /var/www/html/
EXPOSE 80
VOLUME [ "/data" ]