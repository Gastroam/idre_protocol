#!/bin/bash
set -e

echo "Applying fixed Nginx config..."
cp /tmp/nginx-multi.conf /etc/nginx/sites-available/idre
ln -sf /etc/nginx/sites-available/idre /etc/nginx/sites-enabled/idre
rm -f /etc/nginx/sites-enabled/default

echo "Updating IDRE landing page..."
mkdir -p /var/www/idre
sed -n "/<html/,/<\/html>/p" /tmp/deploy_ec2.sh > /var/www/idre/index.html
chown -R www-data:www-data /var/www/idre

echo "Updating MTI-EVO website files..."
mkdir -p /var/www/mti-evo
cp -r /home/ubuntu/website/* /var/www/mti-evo/
chown -R www-data:www-data /var/www/mti-evo

echo "Testing and reloading Nginx..."
nginx -t
systemctl reload nginx
echo "Nginx multi-site config active"

echo "Checking HIVE services status..."
systemctl is-active idre-node-a idre-node-b idre-demo

echo "Done!"
