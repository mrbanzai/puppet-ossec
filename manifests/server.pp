# Main ossec server config
class ossec::server (
  $mailserver_ip,
  $ossec_emailto,
  $ossec_emailfrom                     = "ossec@${::domain}",
  $ossec_active_response               = true,
  $ossec_rootcheck                     = true,
  $ossec_global_host_information_level = 8,
  $ossec_global_stat_level             = 8,
  $ossec_email_alert_level             = 7,
  $ossec_ignorepaths                   = [],
  $ossec_emailnotification             = 'yes',
  $ossec_check_frequency               = 79200,
  $use_mysql                           = false,
  $manage_repos                        = false
) {
  validate_bool(
    $ossec_active_response, $ossec_rootcheck,
    $use_mysql, $manage_repos
  )
  # This allows arrays of integers, sadly
  # (commented due to stdlib version requirement)
  #validate_integer($ossec_check_frequency, undef, 1800)
  validate_array($ossec_ignorepaths)

  class { 'ossec::packages':
    manage_repos => $manage_repos
  }

  if $use_mysql {
    include mysql::client
  }

  $ossec_local_files = {}

  # install package
  case $::osfamily {
    'Debian' : {
      $ossec_local_files = {
        '/var/log/syslog'             => 'syslog',
        '/var/log/auth.log'           => 'syslog',
        '/var/log/mail.log'           => 'syslog',
        '/var/log/dpkg.log'           => 'syslog',
        '/var/log/apache2/access.log' => 'apache',
        '/var/log/apache2/error.log'  => 'apache'
      }
      package { $ossec::common::hidsserverpackage:
        ensure  => installed,
        require => Apt::Source['alienvault'],
      }
    }
    'RedHat' : {
      $ossec_local_files = {
        '/var/log/messages'         => 'syslog',
        '/var/log/secure'           => 'syslog',
        '/var/log/maillog'          => 'syslog',
        '/var/log/yum.log'          => 'syslog',
        '/var/log/httpd/access_log' => 'apache',
        '/var/log/httpd/error_log'  => 'apache'
      }
      case $::operatingsystem {
        'RedHat', 'CentOS', 'OracleLinux' : {
          case $::operatingsystemmajrelease {
            '7' : {
              if $use_mysql {
                package { 'mariadb': ensure => present }
                package { 'ossec-hids':
                  ensure   => installed,
                }
                package { $ossec::common::hidsserverpackage:
                  ensure  => installed,
                  require => Package['mariadb'],
                }
              } else {
                package { 'ossec-hids':
                  ensure   => installed,
                }
                package { $ossec::common::hidsserverpackage:
                  ensure  => installed,
                }
              }
            }
            default: {
              if $use_mysql {
                package { 'mysql': ensure => present }
                package { 'ossec-hids':
                  ensure   => installed,
                }
                package { $ossec::common::hidsserverpackage:
                  ensure  => installed,
                  require => Package['mysql'],
                }
              } else {
                package { 'ossec-hids':
                  ensure   => installed,
                }
                package { $ossec::common::hidsserverpackage:
                  ensure  => installed,
                }
              }
            }
          }
        }
      }
    }
    default: { fail('OS family not supported') }
  }

  service { $ossec::common::hidsserverservice:
    ensure    => running,
    enable    => true,
    hasstatus => $ossec::common::servicehasstatus,
    pattern   => $ossec::common::hidsserverservice,
    require   => Package[$ossec::common::hidsserverpackage],
  }

  # configure ossec
  concat { '/var/ossec/etc/ossec.conf':
    owner   => 'root',
    group   => 'ossec',
    mode    => '0440',
    require => Package[$ossec::common::hidsserverpackage],
    notify  => Service[$ossec::common::hidsserverservice]
  }
  concat::fragment { 'ossec.conf_10' :
    target  => '/var/ossec/etc/ossec.conf',
    content => template('ossec/10_ossec.conf.erb'),
    order   => 10,
    notify  => Service[$ossec::common::hidsserverservice]
  }
  concat::fragment { 'ossec.conf_90' :
    target  => '/var/ossec/etc/ossec.conf',
    content => template('ossec/90_ossec.conf.erb'),
    order   => 90,
    notify  => Service[$ossec::common::hidsserverservice]
  }

  concat { '/var/ossec/etc/client.keys':
    owner   => 'root',
    group   => 'ossec',
    mode    => '0640',
    notify  => Service[$ossec::common::hidsserverservice],
    require => Package[$ossec::common::hidsserverpackage],
  }
  concat::fragment { 'var_ossec_etc_client.keys_end' :
    target  => '/var/ossec/etc/client.keys',
    order   => 99,
    content => "\n",
    notify  => Service[$ossec::common::hidsserverservice]
  }
  Ossec::Agentkey<<| |>>

}
