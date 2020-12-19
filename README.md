# Server setup guide

This is a guide to setting up and installing PHP and Apache or Nginx on an Ubuntu 20.04.1 LTS system running on an AWS EC2 instance (though it's probably almost exactly the same elsewhere). It should probably work more-or-less the same on other Ubuntu releases too, which was already successfully attempted - for example, this guide was more or less identical while Ubuntu 18.04.3 LTS was the latest LTS release, as well as even Ubuntu 16.04.3 LTS - which is good, because it means the guide is pretty stable over time, and will likely remain like that.

It's recommended to read through this guide before attempting to follow it, so you'd know what to expect, and which alternative options might be suggested for certain steps.

Not everything here is absolutely required for setting up a system - as always, it depends on the specific situation. This just documents the most common stuff I've personally needed when setting up servers, so that I could easily refer to it when needed.

The projects I usually deployed on these servers are Laravel applications, either running directly on the server in an Apache+PHP setup, or within a Docker container, proxied through NGINX.

This guide went through many updates and iterations over the years, but I've just now gotten to managing it in a [GitHub repo](https://github.com/levacic/server-setup-guide) (it previously lived within a private Gist for a very long time).

There is also a mirror of this guide [on my blog](https://blog.levacic.net/2020/12/19/server-setup-guide/).

All right, let's go.

## Updates

Before doing anything else, update all packages on the system:

```sh
sudo apt-get update
sudo apt-get upgrade
```

Sometimes, you might get a message regarding GRUB, which I've yet to figure out why and when it happens - but just ignoring it and skipping reinstalling GRUB seems to work.

## Editor

Most Ubuntu images on EC2 use `nano` as the default editor. If you'd like to change it to `vim` instead, run the following:

```sh
sudo update-alternatives --config editor
```

You'll be presented with several choices, including `vim.basic`, which is the one you want.

## Fail2ban

Fail2ban is a security tool which monitors log files for common services running on servers, and when it detects suspicious behavior from specific IP addresses (e.g. too many consecutive failed login attempts), it bans those IP addresses for a certain amount of time.

This is needed almost always on any publicly accessible servers as an important security precaution - but might be applicable in other situations as well, depending on the vulnerability profile. In cloud hosting setups specifically, this is a must, as the available IP addresses are almost guaranteed to be reused and publicly known, and thus a common target for brute force hacking attempts.

To install, just run the following:

```sh
sudo apt-get install fail2ban
```

Fail2ban's configuration is located in `/etc/fail2ban`, and by default on Debian-based distributions, includes SSHD monitoring, which you can confirm by checking the contents of `/etc/fail2ban/jail.d/defaults-debian.conf`, which should look something like this:

```ini
[sshd]
enabled = true
```

Monitoring can be enabled for other services as well, but this is a baseline security precaution. In a setup with a bastion SSH proxy server, the bastion _should_ have Fail2ban installed and configured to monitor SSH connections.

In this case, Fail2ban will monitor `/var/log/auth.log` (which is where SSHD logs SSH actions and logins) and track the IP addresses attempting to login.

Fail2ban has its own log file in `/var/log/fail2ban.log` where it's possible to review what it's doing.

## iptables

Depending on the hosting environment, it might be possible to filter traffic using platform-provided features, such as Security Groups, which is a common mechanism available on cloud platforms.

It's possible to setup a similar traffic filtering mechanism within the server itself by using `iptables`.

The following command can be used at any moment to view the current `iptables` configuration:

```sh
sudo iptables --list --verbose
```

Or its shorter version:

```sh
sudo iptables -L -v
```

At a minimum, you want the following configuration:

```sh
# Accept incoming localhost connections.
sudo iptables --append INPUT --in-interface lo --jump ACCEPT

# Accept existing connections, to avoid dropping the current SSH connection in
# cases of misconfiguration.
sudo iptables --append INPUT --match conntrack --ctstate RELATED,ESTABLISHED --jump ACCEPT

# Accept incoming SSH, HTTP, and HTTPS connections.
sudo iptables --append INPUT --protocol tcp --dport 22 --jump ACCEPT
sudo iptables --append INPUT --protocol tcp --dport 80 --jump ACCEPT
sudo iptables --append INPUT --protocol tcp --dport 443 --jump ACCEPT

# Drop all other traffic.
sudo iptables --append INPUT --jump DROP
```

It's possible to insert a rule at a specific position like this:

```sh
sudo iptables --insert chain [rule-num] rule-specification
```

For example, to add a rule to accept MySQL traffic to position 6, you can do this:

```sh
sudo iptables --insert INPUT 6 --protocol tcp --dport 3306 --jump ACCEPT
```

To delete a rule in a specific position, you can do:

```sh
sudo iptables --delete chain rule-num
```

For example, to delete the rule in position 6:

```sh
sudo iptables --delete INPUT 6
```

### Persisting iptables rules

By default, the `iptables` configuration will clear after a server restart. To persist it, you want to install `iptables-persistent`, or `netfilter-persistent` (which is the new name for the same program).

```sh
sudo apt-get install netfilter-persistent
```

During installation, you will be prompted to persist the current IPv4 and IPv6 rules, which will be saved into `/etc/iptables/rules.v4` and `/etc/iptables/rules.v6` respectively.

To update the rules, you can use:

```sh
sudo iptables-save | sudo tee /etc/iptables/rules.v4
```

Finally, you can restart the service:

```sh
sudo service iptables restart
```

To check the service status, run:

```sh
sudo service iptables status
```

### NFT

Finally, you might want to use the newer NFT tool instead of `iptables` - which is the recommended default firewall today. See the following links for installation and configuration info:

- https://wiki.debian.org/nftables
- https://wiki.nftables.org/wiki-nftables/index.php/Moving_from_iptables_to_nftables

## Dotfiles

> **Note:** Specific to my personal setup, feel free to skip.

So assuming that you're logged into the server, the first thing you want is to set up an SSH key so we could later clone the repos you need. If you don't already have a public/private key pair (e.g. `id_rsa` and `id_rsa.pub` in `~/.ssh`), generate them:

```sh
ssh-keygen -t rsa -b 4096
```

Clone the dotfiles repo (add the public key `cat ~/.ssh/id_rsa.pub` to the approved access keys for that repo), and configure it as per the instructions in the repo's README file. This helps have a more readable prompt, and provides some useful project-administration-related commands.

Logout and login to get a nicer prompt.

## Bash history per-user logging

> **Note:** This section of the guide differentiates between a "user" (an account on the server, such as the default `ubuntu` user on Ubuntu systems) and a "person"/"people" (which are actual humans, most often developers or system administrators, who need access to the server).

Most of the time, we have a single user with root permissions doing the setup (usually `ubuntu` in the context of this guide - other non-AWS providers might use a different default user in their base images), which multiple people are authorized to login as, using their SSH keys - which is accomplished by adding such people's keys into the `ubuntu` user's `~/.ssh/authorized_keys` file.

A useful setup is to have each person's Bash commands logged into a different Bash history file, so it would be easy to track _who did what_ on the server - this is not a foolproof solution, nor is it meant to be - these still need to be people who are trusted not to act maliciously on the server, and with this setup, they have the opportunity to delete any traces of their activity on the server.

If you're looking for a full-blown solution, what you need is a logging/auditing bastion host, and there are both free and paid enteprise-grade solutions to accomplish this. One such free solution can be implemented by following this guide:

- https://aws.amazon.com/blogs/security/how-to-record-ssh-sessions-established-through-a-bastion-host/

So, in order to log SSH history separately for each person who logs into the server as the `ubuntu` user, we first need to configure the SSH server to allow users to set their own environment variables while SSH sessions are being established - which is a potential security risk when access restrictions are limited (e.g. if we were setting up a bastion host with limited access), but doesn't really change anything in a root-login scenario like we have here (where people can already do everything once logged into the server).

This is achieved by editing the `/etc/ssh/sshd_config` file and configuring:

```plaintext
PermitUserEnvironment yes
```

After this you need to restart the SSH daemon (a reload probably works as well):

```sh
sudo service sshd restart
```

What this allows you is to add pre-configured environment variables into the `authorized_keys` file, e.g. instead of the file looking like this:

```plaintext
# user-foo
ssh-rsa AAAAB3NzaC1y...

# user-bar
ssh-rsa AAAAB3NzaC1y...
```

you can do this:

```plaintext
# user-foo
environment="LOGGED_IN_USER=user-foo" ssh-rsa AAAAB3NzaC1y...

# user-bar
environment="LOGGED_IN_USER=user-bar" ssh-rsa AAAAB3NzaC1y...
```

after which any times a person logs in with a specific key, the respective `LOGGED_IN_USER` environment variable will be set accordingly. This further allows us to configure a custom Bash-history file by adding the following into the `~/.bashrc` file:

```sh
# Enable timestamps in history, and format them nicely for display.
HISTTIMEFORMAT="%F %T "

# Append history, and update it after every command.
shopt -s histappend
PROMPT_COMMAND="history -a;$PROMPT_COMMAND"

# Track SSH logins and per-key history.
if [ "$LOGGED_IN_USER" != "" ]
then
  logger -ip auth.notice -t sshd "Accepted publickey for $LOGGED_IN_USER"
  HISTFILE="$HOME/.$LOGGED_IN_USER.bash_history"
fi
```

The above configures a few additional things, to make the history more reliable and easier to use.

## AWS CloudWatch Agent

If you're in an AWS environment and want your server to send additional metrics to CloudWatch (which is recommended in order to track some additional metrics not included by default, e.g. disk and memory usage), you need to install the CloudWatch Agent.

The server running the agent needs to have an IAM role assigned, which has the `CloudWatchAgentServerPolicy` policy attached - so add that, in addition to any other policies the server's role needs. The alternative options is to create an IAM user with this policy, and configure the user's access key ID and secret access key when setting up the CloudWatch Agent - however, this is out of the scope of this guide, and not the recommended way of setting stuff up anyway.

Note that monitoring a server using the CloudWatch Agent will incurr additional costs - consult the AWS pricing pages and documentation for more info on that.

### Installation

For Ubuntu AMD64 you want to download the following installation:

```sh
wget https://s3.amazonaws.com/amazoncloudwatch-agent/ubuntu/amd64/latest/amazon-cloudwatch-agent.deb
```

You can also use a region-specific URL, e.g. `s3.{region}.amazonaws.com` to potentially speed up the download - although it's not a major difference anyway.

For other systems, review the AWS documentation.

Install the agent like this:

```sh
sudo dpkg -i -E ./amazon-cloudwatch-agent.deb
```

### Configuration

Before configuring and running the agent, you must ensure the correct region will be in use - by default, the agent will publish the metrics to the same region in which the EC2 instance is located. The `region` entry in the `[default]` section of your AWS configuration file (ie. `~/.aws/config`) will take precedence over that default, and the `region` entry in the `[AmazonCloudWatchAgent]` section of the AWS configuration file (if it exist) will have the highest precedence.

You can run the configuration wizard by entering the following:

```sh
sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-config-wizard
```

This will ask a series of questions, based on which a configuration will be created and stored in `/opt/aws/amazon-cloudwatch-agent/bin/config.json`.

Alternatively, you can just create that file manually with the following configuration which makes sensible assumptions about the logging requirements:

```json
{
    "agent": {
        "metrics_collection_interval": 60,
        "run_as_user": "root"
    },
    "metrics": {
        "append_dimensions": {
            "AutoScalingGroupName": "${aws:AutoScalingGroupName}",
            "ImageId": "${aws:ImageId}",
            "InstanceId": "${aws:InstanceId}",
            "InstanceType": "${aws:InstanceType}"
        },
        "aggregation_dimensions": [
            [
                "InstanceId"
            ]
        ],
        "metrics_collected": {
            "cpu": {
                "measurement": [
                    "cpu_usage_idle",
                    "cpu_usage_iowait",
                    "cpu_usage_user",
                    "cpu_usage_system"
                ],
                "metrics_collection_interval": 60,
                "totalcpu": false
            },
            "disk": {
                "measurement": [
                    "used_percent",
                    "inodes_free"
                ],
                "metrics_collection_interval": 60,
                "resources": [
                    "*"
                ]
            },
            "diskio": {
                "measurement": [
                    "io_time",
                    "write_bytes",
                    "read_bytes",
                    "writes",
                    "reads"
                ],
                "metrics_collection_interval": 60,
                "resources": [
                    "*"
                ]
            },
            "mem": {
                "measurement": [
                    "mem_used_percent"
                ],
                "metrics_collection_interval": 60
            },
            "netstat": {
                "measurement": [
                    "tcp_established",
                    "tcp_time_wait"
                ],
                "metrics_collection_interval": 60
            },
            "swap": {
                "measurement": [
                    "swap_used_percent"
                ],
                "metrics_collection_interval": 60
            }
        }
    }
}
```

Feel free to adapt this configuration to your own needs.

### Running the agent

The following command starts the CloudWatch Agent on an EC2 instance running Linux:

```sh
sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -c file:/opt/aws/amazon-cloudwatch-agent/bin/config.json -s
```

The agent should automatically start after system reboots as well, but in case you encounter issues with that, you might want to configure this command to run on reboot. Note that _this should not be necessary_, but if it is, the easiest way to do that is to add it to the `root` account's crontab:

```sh
sudo crontab -e
```

Add the following:

```plaintext
@reboot /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -c file:/opt/aws/amazon-cloudwatch-agent/bin/config.json -s
```

If setting up an automated system installation via tools like Puppet or something else, you'll probably prefer to configure a new file under `/etc/cron.d/` or something similar, however that's also out of the scope of this guide.

## Apache

Most likely you want Apache. If not, an alternative setup with an NGINX reverse proxy is provided further below.

```sh
sudo apt-get update
sudo apt-get install apache2
```

Allow traffic through firewall (not needed usually but just in case; more info on this later):

```sh
sudo ufw app list
```

This should show a few options including "Apache Full". Enable that:

```sh
sudo ufw allow in "Apache Full"
```

That's it for now, we'll configure it later.

## MySQL

If you're using AWS, you're probably going to use RDS as a database without installing MySQL on the server instance.

In that case, you'll usually want at least the client-side MySQL programs `mysql` and `mysqldump`, as they're useful for obvious reasons.

To install them, just run:

```sh
sudo apt-get install mysql-client
```

If, however, you do need the MySQL server installed on the instance, you should skip installing only the client, and run something like:

```sh
sudo apt-get install mysql-server
```

Note that this will automatically install the client as well.

Following this, run the secure MySQL setup program:

```sh
mysql_secure_installation
```

Most of the steps to secure the installation should be obvious, use your best judgement and security awareness - be sure to also store the root password somewhere safe.

If you need to create a database for the project, here's a quick four-liner:

```sql
CREATE DATABASE example CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'example'@'localhost' IDENTIFIED BY 'randomthirtytwocharacterpassword';
GRANT ALL PRIVILEGES ON example.* TO 'example'@'localhost';
FLUSH PRIVILEGES;
```

If connecting to an external database, such as RDS, you want to use `%` instead of `localhost` (ie. allow all hosts for that user, unless you know the exact IP address from where the client will connect, which you probably don't). Here's that version, for easier copy-pasting:

```sql
CREATE DATABASE example CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'example'@'%' IDENTIFIED BY 'randomthirtytwocharacterpassword';
GRANT ALL PRIVILEGES ON example.* TO 'example'@'%';
FLUSH PRIVILEGES;
```

You're welcome.

## PHP 7.4/8.0

If we're installing PHP, we want the latest version. On Ubuntu 20.04.1 LTS you need to add additional repos for this:

```sh
sudo add-apt-repository ppa:ondrej/php
sudo apt-get update
```

Now install PHP and a bunch of extensions we might need:

```sh
sudo apt-get -y install \
    php7.4 \
    php7.4-apc \
    php7.4-cli \
    php7.4-bcmath \
    php7.4-curl \
    php7.4-dom \
    php7.4-gd \
    php7.4-gmp \
    php7.4-imagick \
    php7.4-imap \
    php7.4-intl \
    php7.4-json \
    php7.4-ldap \
    php7.4-mailparse \
    php7.4-mbstring \
    php7.4-memcached \
    php7.4-mysql \
    php7.4-opcache \
    php7.4-pgsql \
    php7.4-pspell \
    php7.4-redis \
    php7.4-soap \
    php7.4-sqlite3 \
    php7.4-tidy \
    php7.4-xml \
    php7.4-xmlrpc \
    php7.4-xsl \
    php7.4-zip \
    unzip
```

Some of these packages will be installed by default, some might overlap a bit with their dependencies, but in general, this should cover you pretty well with most commonly used packages - or at least the ones I personally used in different environments and for different projects.

The command also installs the `unzip` program, which is recommeded as it makes Composer install dependencies faster.

One thing you should *NOT* install in your production environment is `xdebug` because it can slow down everything.

For PHP 8.0, everything should probably work just as well by simply replacing `php7.4` with `php8.0` in all of the packages listed in the install command above.

## Project

> *NOTE:* This part of the guide is specific to the projects and setup I used on the projects my team and I worked on, and relies on some internal knowledge about directory structure. I might add that documentation later in case it could be useful for someone. It also relies on some commands from a custom set of scripts. For the most part, you can skip this if you're only interested in the server setup itself.

Clone your project. We like to use `~/apps`, but feel free to decide what you would like to use - for the rest of this guide but we'll assume it's `~/apps`.

Let's say your project is "Example". Create your project folder within `~/apps`:

```sh
mkdir -p ~/apps/example
```

Within it, recreate the structure we commonly use that relies on symlinking, e.g. `data` and `repo` folders, and a `production` folder within `repo` - and any other environments you might want to deploy.

Add the server's public key into the project repo's access keys and clone it with `clone-project`.

### Docker-based project folder structure

If we're doing a Docker-based setup behind an NGINX proxy, we don't need the repo folder and the symlink to a specific checkout, we just want to clone the project into e.g. `~/apps/example/repo` - because our usual workflow with this is not to run the project from the host system's filesystem, but rather build a fully-contained Docker image and run that instead - optionally mounting volumes from the host filesystem for some common files we might need to retain, such as logs or file uploads (though we would usually stream logs into an external service, and use a cloud-based file storage mechanism such as S3).

Project updates in that scenario would be done by just doing a `git pull` and triggering a rebuild/restart of the Docker images/containers - the latter of which would usually be performed by a script provided along with the project.

## Apache part 2

### Additional modules

So now that we have everything ready, we need to configure the virtual host for the project.

Let's first enable a few modules we'll need:

```sh
sudo a2enmod \
    headers \
    rewrite \
    ssl
```

You don't need the `ssl` module if your server is running behind a Load Balancer (which it almost certainly should) that performs SSL termination.

Restart the server:

```sh
sudo service apache2 restart
```

### Directory permissions

Configure the directory permissions:

```sh
sudo vim /etc/apache2/apache2.conf
```

Find the `<Directory /var/www/>` entry and below that block add a new one:

```apache
<Directory /home/ubuntu/apps>
    AllowOverride all
    Require all granted
</Directory>
```

If deploying the websites from a different directory, specify that one instead.

### Logging behind an AWS load balancer

If running the server behind a load balancer, by default Apache will log the load balancer's IP address, which will be fairly useless when reviewing log files. To override this, you want to change the default `LogFormat` to include the header containing the actual client IP address. In an AWS environment, you need to edit the `/etc/apache2/apache2.conf` file and find these lines:

```apache
LogFormat "%h %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\"" combined
LogFormat "%h %l %u %t \"%r\" %>s %O" common
```

and replace them with:

```apache
LogFormat "%{X-Forwarded-For}i %h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"" combined
LogFormat "%h %l %u %t \"%r\" %>s %b" common
```

This basically prepends the value of the `X-Forwarded-For` header, which is the one used by AWS load balancers, to each log entry, and also replaces `%O` (the total bytes sent, including headers) with `%b` (the total bytes sent, excluding headers).

This assumes you will use either the `combined` or `common` log formats when configuring a specific Virtual Host's `CustomLog` configuration.

More information about configuring Apache's `LogFormat`s can be found here:

- http://httpd.apache.org/docs/current/mod/mod_log_config.html

More information about configuring Apache's `LogFormat` to correctly handle operating behind an AWS load balancer can be found here:

- https://aws.amazon.com/premiumsupport/knowledge-center/elb-capture-client-ip-addresses/

Note that this is potentially dangerous in non-AWS setups, as it depends on the exact header which the load balancer uses to pass the client's real IP address, and this may not be the same in other setups.

After updating the configuration, you need to reload Apache:

```sh
sudo service apache2 reload
```

### Default virtual hosts

Edit the default virtual host to return a 404 instead of the Apache welcome page:

```sh
sudo vim /etc/apache2/sites-available/000-default.conf
```

The contents should be something like:

```apache
<VirtualHost *:80>
    RedirectMatch 204 /healthcheck
    Redirect 404 /
</VirtualHost>
```

Yes, these are the only two directives you want - the `RedirectMatch 204 /healthcheck` responds with a `204 No Content` status for requests to `/healthcheck`, and the `Redirect 404 /` returns a `404 Not Found` for everything else - comment out the rest if you're worried about losing the original/default configuration.

You don't even need the healthcheck directive if you're not using some kind of a load balancer that needs to be able to check if the server is up and running.

This is needed so that requests to the server that don't match any virtual host defined later (e.g. the one for `example.com` you're about to setup) fall back to the first virtual host defined - which will usually be `000-default` - and you don't want these requests to return anything except a 404 page. This situation could occur when someone accesses the server's IP address directly, or points their own domain to the server's IP address - since we don't want to respond to hosts other than those we explicitly define as virtual hosts, a 404 makes sense for those requests.

You might require this if either your server is directly serving internet traffic - ie. not behind a load balancer - or is behind a load balancer configured to proxy all requests to the server (as opposed to explicitly configuring the hostnames you want to match and only proxying those requests - which is generally a much better idea anyway).

To do the same for the default SSL website (in case you're actually serving SSL traffic from this server; if your load balancer is doing SSL termination, just skip this), rename the `default-ssl.conf` file:

```sh
sudo mv /etc/apache2/sites-available/default-ssl.conf /etc/apache2/sites-available/000-default-ssl.conf
```

Now edit it:

```sh
sudo vim /etc/apache2/sites-available/000-default-ssl.conf
```

The contents should look mostly like:

```apache
<IfModule mod_ssl.c>
    <VirtualHost _default_:443>
        #ServerAdmin webmaster@localhost

        #DocumentRoot /var/www/html

        # Nothing to see here.
        Redirect 404 /

        # Available loglevels: trace8, ..., trace1, debug, info, notice, warn,
        # error, crit, alert, emerg.
        # It is also possible to configure the loglevel for particular
        # modules, e.g.
        #LogLevel info ssl:warn

        #ErrorLog ${APACHE_LOG_DIR}/error.log
        #CustomLog ${APACHE_LOG_DIR}/access.log combined

        # For most configuration files from conf-available/, which are
        # enabled or disabled at a global level, it is possible to
        # include a line for only one particular virtual host. For example the
        # following line enables the CGI configuration for this host only
        # after it has been globally disabled with "a2disconf".
        #Include conf-available/serve-cgi-bin.conf

        #   SSL Engine Switch:
        #   Enable/Disable SSL for this virtual host.
        SSLEngine on

        #   A self-signed (snakeoil) certificate can be created by installing
        #   the ssl-cert package. See
        #   /usr/share/doc/apache2/README.Debian.gz for more info.
        #   If both key and certificate are stored in the same file, only the
        #   SSLCertificateFile directive is needed.
        SSLCertificateFile  /etc/ssl/certs/ssl-cert-snakeoil.pem
        SSLCertificateKeyFile /etc/ssl/private/ssl-cert-snakeoil.key

        #   Server Certificate Chain:
        #   Point SSLCertificateChainFile at a file containing the
        #   concatenation of PEM encoded CA certificates which form the
        #   certificate chain for the server certificate. Alternatively
        #   the referenced file can be the same as SSLCertificateFile
        #   when the CA certificates are directly appended to the server
        #   certificate for convinience.
        #SSLCertificateChainFile /etc/apache2/ssl.crt/server-ca.crt

        #   Certificate Authority (CA):
        #   Set the CA certificate verification path where to find CA
        #   certificates for client authentication or alternatively one
        #   huge file containing all of them (file must be PEM encoded)
        #   Note: Inside SSLCACertificatePath you need hash symlinks
        #        to point to the certificate files. Use the provided
        #        Makefile to update the hash symlinks after changes.
        #SSLCACertificatePath /etc/ssl/certs/
        #SSLCACertificateFile /etc/apache2/ssl.crt/ca-bundle.crt

        #   Certificate Revocation Lists (CRL):
        #   Set the CA revocation path where to find CA CRLs for client
        #   authentication or alternatively one huge file containing all
        #   of them (file must be PEM encoded)
        #   Note: Inside SSLCARevocationPath you need hash symlinks
        #        to point to the certificate files. Use the provided
        #        Makefile to update the hash symlinks after changes.
        #SSLCARevocationPath /etc/apache2/ssl.crl/
        #SSLCARevocationFile /etc/apache2/ssl.crl/ca-bundle.crl

        #   Client Authentication (Type):
        #   Client certificate verification type and depth.  Types are
        #   none, optional, require and optional_no_ca.  Depth is a
        #   number which specifies how deeply to verify the certificate
        #   issuer chain before deciding the certificate is not valid.
        #SSLVerifyClient require
        #SSLVerifyDepth  10

        #   SSL Engine Options:
        #   Set various options for the SSL engine.
        #   o FakeBasicAuth:
        #    Translate the client X.509 into a Basic Authorisation.  This means that
        #    the standard Auth/DBMAuth methods can be used for access control.  The
        #    user name is the `one line' version of the client's X.509 certificate.
        #    Note that no password is obtained from the user. Every entry in the user
        #    file needs this password: `xxj31ZMTZzkVA'.
        #   o ExportCertData:
        #    This exports two additional environment variables: SSL_CLIENT_CERT and
        #    SSL_SERVER_CERT. These contain the PEM-encoded certificates of the
        #    server (always existing) and the client (only existing when client
        #    authentication is used). This can be used to import the certificates
        #    into CGI scripts.
        #   o StdEnvVars:
        #    This exports the standard SSL/TLS related `SSL_*' environment variables.
        #    Per default this exportation is switched off for performance reasons,
        #    because the extraction step is an expensive operation and is usually
        #    useless for serving static content. So one usually enables the
        #    exportation for CGI and SSI requests only.
        #   o OptRenegotiate:
        #    This enables optimized SSL connection renegotiation handling when SSL
        #    directives are used in per-directory context.
        #SSLOptions +FakeBasicAuth +ExportCertData +StrictRequire
        <FilesMatch "\.(cgi|shtml|phtml|php)$">
                SSLOptions +StdEnvVars
        </FilesMatch>
        <Directory /usr/lib/cgi-bin>
                SSLOptions +StdEnvVars
        </Directory>

        #   SSL Protocol Adjustments:
        #   The safe and default but still SSL/TLS standard compliant shutdown
        #   approach is that mod_ssl sends the close notify alert but doesn't wait for
        #   the close notify alert from client. When you need a different shutdown
        #   approach you can use one of the following variables:
        #   o ssl-unclean-shutdown:
        #    This forces an unclean shutdown when the connection is closed, i.e. no
        #    SSL close notify alert is send or allowed to received.  This violates
        #    the SSL/TLS standard but is needed for some brain-dead browsers. Use
        #    this when you receive I/O errors because of the standard approach where
        #    mod_ssl sends the close notify alert.
        #   o ssl-accurate-shutdown:
        #    This forces an accurate shutdown when the connection is closed, i.e. a
        #    SSL close notify alert is send and mod_ssl waits for the close notify
        #    alert of the client. This is 100% SSL/TLS standard compliant, but in
        #    practice often causes hanging connections with brain-dead browsers. Use
        #    this only for browsers where you know that their SSL implementation
        #    works correctly.
        #   Notice: Most problems of broken clients are also related to the HTTP
        #   keep-alive facility, so you usually additionally want to disable
        #   keep-alive for those clients, too. Use variable "nokeepalive" for this.
        #   Similarly, one has to force some clients to use HTTP/1.0 to workaround
        #   their broken HTTP/1.1 implementation. Use variables "downgrade-1.0" and
        #   "force-response-1.0" for this.
        # BrowserMatch "MSIE [2-6]" \
        #       nokeepalive ssl-unclean-shutdown \
        #       downgrade-1.0 force-response-1.0

    </VirtualHost>
</IfModule>
```

What we did was comment out the `ServerAdmin`, `DocumentRoot`, `ErrorLog`, and `CustomLog` directives and added another `Redirect 404 /` directive.

We should of course enable that site and reload the Apache configuration:

```sh
sudo a2ensite 000-default-ssl
sudo service apache2 reload
```

## Project-specific virtual hosts

Now create a new virtual host for the project:

```sh
sudo cp /etc/apache2/sites-available/000-default.conf /etc/apache2/sites-available/example.com.conf
sudo vim /etc/apache2/sites-available/example.com.conf
```

The file oughta look something like this:

```apache
<VirtualHost *:80>
    ServerName example.com
    ServerAlias www.example.com

    ServerAdmin admin@example.com
    DocumentRoot /home/ubuntu/apps/example/production/public

    ErrorLog ${APACHE_LOG_DIR}/example.com.error.log
    CustomLog ${APACHE_LOG_DIR}/example.com.access.log combined
</VirtualHost>
```

Now enable it:

```sh
sudo a2ensite example.com
```

And reload Apache:

```sh
sudo service apache2 reload
```

### Additional permission configuration

Now here's the deal - Apache (usually, by default) runs under `www-data` which doesn't have permissions to access `ubuntu`'s home folder. To fix this you need to grant the correct permissions. However, don't do something crazy and irresponsible like `chmod 777 all-the-things` - instead, use `setfacl` (instructions courtesy of WebFaction mostly), while logged in as the `ubuntu` user:

```sh
# Allow www-data to access ubuntu's home folder
setfacl -m u:www-data:--x $HOME

# Grant read/write/execute access to the apps folder
setfacl -R -m u:www-data:rwx $HOME/apps

# Grant default read/write/execute access for any future files/folders here
setfacl -R -m d:u:www-data:rwx $HOME/apps

# Make sure ubuntu's group is the owner of any future files/folders
chmod g+s $HOME/apps

# Grant ubuntu full access to any future files/folders
setfacl -R -m d:u:ubuntu:rwx $HOME/apps
```

You should now be able to open your website assuming the DNS records are configured correctly (if not, edit your local `/etc/hosts` file so you can try it out). You'll probably get a styled 500 error from the application but you can go ahead and view the log file in order to debug the app - you probably need to configure your application's `.env` file correctly, maybe migrate the database etc.

Of course, if the server runs behind a load balancer, you'll want to configure the load balancer's proxying configuration accordingly.

## NGINX

Another common setup we've used in our team is to run Docker containers through an NGINX reverse proxy - either directly from the instance or through an AWS ALB.

The first step is installing NGINX:

```sh
sudo apt-get update
sudo apt-get install nginx
```

Then we want to adjust the firewall, which is similar to how we would do it for Apache. First run:

```sh
sudo ufw app list
```

This should show a few options including "Nginx Full", "Nginx HTTP", and "Nginx HTTPS". If the instance is directly serving public traffic, we want to enable "Nginx Full", otherwise if it's behind an AWS ALB, we would usually do SSL termination on the load balancer, and do plain HTTP between the load balancer and the instance. Either way, we want to allow access through the firewall, which would be accomplished, e.g. in the former case, by running:

```sh
sudo ufw allow in "Nginx Full"
```

After that you can run the following to check the configuration:

```sh
sudo ufw status
```

> *NOTE:* The official Ubuntu AMIs available via AWS usually have the firewall disabled completely - which is probably fine, as we'll have a sensible networking/security group configuration anyway.

You can check that Nginx is runing properly:

```sh
systemctl status nginx
```

### Virtual host setup

We won't be providing instructions on running projects directly via NGINX here, only a reverse proxy configuration.

In short, you want to have an `/etc/nginx/includes/proxy.conf` file (that file most likely doesn't exist yet at this point, nor its parent `includes` folder - so just create them; if the file exists, pick a different name and reference that in the server configuration files documented further below) with something like this:

```nginx
proxy_http_version 1.1;
proxy_set_header Upgrade $http_upgrade;
proxy_set_header Connection 'upgrade';
proxy_set_header Host $host;
proxy_set_header X-Forwarded-Host $host;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_cache_bypass $http_upgrade;
```

This particular configuration is applicable when running the server behind a load balancer, due to the included `X-Forwarded-For` header configuration (which might be a vulnerability in other setups, e.g. when NGINX is directly serving internet traffic).

Backup the default website configuration `/etc/nginx/sites-available/default` and change it so it looks like this:

```nginx
server {
    listen 80 default_server;
    listen [::]:80 default_server;

    root /var/www/html;

    # Add index.php to the list if you are using PHP
    index index.html index.htm index.nginx-debian.html;

    server_name _;

    # Respond with a 204 on this endpoint, for AWS target group
    # health checks.
    location /healthcheck {
        return 204;
    }

    location / {
        return 404;
    }
}
```

Similar to the previously documented default Apache configuration, this just always returns 404s by default (ie. if a request doesn't specify a hostname for which we have a specific configuration block), except for a `204` response on the `/healthcheck` URL that can be used for AWS target group health checks - feel free to remove this if you don't need it.

Finally, for a specific project such as `example-website`, which should be served at `example.com` and `www.example.com`, which is handled by a Docker container running on the local system on port `8080`, you want this configuration:

```nginx
upstream example-website {
    server localhost:8080;
}

server {
    listen 80;
    server_name www.example.com example.com;

    location / {
        include /etc/nginx/includes/proxy.conf;
        proxy_pass http://example-website;
    }

    access_log /var/log/nginx/example-website.access.log combined;
    error_log /var/log/nginx/example-website.error.log error;
}
```

Adapt to your local use-case, sudo-symlink it into the `/etc/nginx/sites-enabled/` folder, and reload NGINX:

```sh
sudo service nginx reload
```

You're done.

## Docker

If you need Docker, it's best to follow the official instructions found here: https://docs.docker.com/engine/install/ubuntu/ (in case this link changes in the future, it shouldn't be hard to just find the new URL). In short, these are the steps:

```sh
# Ensure no older Docker versions are on the system - this shouldn't be
# necessary in most cases on a fresh system, but it really depends on where your
# base system image comes from and how it was installed - if you're not sure,
# just run this.
sudo apt-get remove docker docker-engine docker.io containerd runc

# Install dependencies required for installation.
sudo apt-get update
sudo apt-get install \
    apt-transport-https \
    ca-certificates \
    curl \
    gnupg-agent \
    software-properties-common

# Import Docker's official GPG key - this is potentially dangerous so best to
# check with the official installation guide if this is still the correct way to
# do this.
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -

# Make sure the key's fingerprint is:
#
#     9DC8 5822 9FC7 DD38 854A  E2D8 8D81 803C 0EBF CD88
#
# This is the correct fingerprint at the time this tutorial was written, but
# again, best to check the official guide for this one as well.
sudo apt-key fingerprint 0EBFCD88

# Add the stable repository.
sudo add-apt-repository \
   "deb [arch=amd64] https://download.docker.com/linux/ubuntu \
   $(lsb_release -cs) \
   stable"

# Install Docker Engine.
sudo apt-get update
sudo apt-get install docker-ce docker-ce-cli containerd.io

# Make sure it works. This should download an example image an run it, which
# should result in sensible output.
sudo docker run hello-world

# Check if running Docker as a non-root user works - it shouldn't.
docker run hello-world

# You want it to work, so you also want to run the following commands (the first
# one will probably report that the `docker` group already exists - that's fine
# and you should run the second command anyway):
sudo groupadd docker
sudo usermod -aG docker $USER

#
# Logout of the system and log back in for the group changes to take effect.
#

# This should work now:
docker run hello-world

# We almost certainly want Docker Compose too, which can be installed like this:
sudo apt-get install docker-compose

# Make sure Docker will start on boot:
sudo systemctl enable docker
```

You now have a working Docker Engine on your system.

## Let's Encrypt

If you're not behind a load balancer (which I strongly suggest you should be within an AWS setup), and you want to set up Let's Encrypt for certificates, that's easy-peasy!

The best choice is to follow the official instructions for configuring Certbot, which are available [https://certbot.eff.org/#ubuntuxenial-apache](here) for the setup we're working with. In short, however, we need to perform the steps outlined below.

Install Certbot:

```sh
sudo apt-get update
sudo apt-get install software-properties-common
sudo add-apt-repository ppa:certbot/certbot
sudo apt-get update
sudo apt-get install python-certbot-apache
```

After that, if using Apache, run:

```sh
sudo certbot --apache
```

If using NGINX, you should run this instead:

```sh
sudo certbot --nginx
```

This will guide you through step-by-step instructions for configuring an SSL certificate for one of the available Apache websites. That's it!

Automatic renewals are performed by a Cron job that runs:

```sh
sudo certbot renew
```

This needs to run as root though, and isn't trivial to setup manually. Luckily, this gets configured automatically during Certbot installation - on Ubuntu 20.04.1 LTS, you should be able to find the Cron configuration in the following file:

```sh
cat /etc/cron.d/certbot
```

You don't need to do anything here, it's just to confirm that renewals will be automated.

## Additional users

If you need to add a new user `username` with passwordless `sudo` permissions, you should generally follow the steps outlined below.

First, create the new user:

```sh
sudo adduser username
```

When prompted for the password, enter any random password - we'll lock it later so it won't be usable anyway unless unlocked - but that is only doable by a user with `sudo` permissions, and if someone already has that, there's worse things they can do anyway.

You'll be prompted for the new user's information, which you most likely want to just leave blank. After that, lock the user's password so it cannot be used:

```sh
sudo passwd -l username
```

Now, add the user to the sudo group:

```sh
sudo usermod -aG sudo username
```

Next, in order to enable passwordless `sudo`, open the `/etc/sudoers` file using the special `visudo` program which validates the syntax and makes sure stuff will work after making changes - unlike if you were to use a regular text editor such as `vim` or `nano`:

```sh
sudo visudo
```

At the **end** of the file, add the following line:

```plaintext
username ALL=(ALL) NOPASSWD:ALL
```

Finally, in order for this user to be able to login via SSH, you want to edit their `authorized_keys` file and add a public SSH key to it.

The easiest way to do this is to switch into the new user's account and set everything up:

```sh
sudo su - username
```

Next, create the necessary path and file:

```sh
# Create the `.ssh` path in `$HOME` if it doesn't already exist, and assign the
# correct permissions to it.
mkdir --parents --mode=700 "$HOME/.ssh"

# Create an `authorized_keys` file.
touch "$HOME/.ssh/authorized_keys"

# Assign the correct permissions to it.
chmod 600 "$HOME/.ssh/authorized_keys"
```

Finally, edit the file with your favorite editor and add your public key of choice, to enable the user to login via SSH.

Don't forget to do

```sh
exit
```

after you're done, in order to switch back to your own user account.
