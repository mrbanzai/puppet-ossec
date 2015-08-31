# Setup for ossec client
class ossec::client(
  $ossec_active_response   = true,
  $ossec_rootcheck         = true,
  $ossec_server_ip,
  $ossec_emailnotification = 'yes',
  $ossec_ignorepaths       = [],
  $ossec_check_frequency   = 79200,
  $selinux                 = false,
  $manage_repos            = false
) {
  validate_bool(
    $ossec_active_response, $ossec_rootcheck,
    $selinux, $manage_repos
  )
  # This allows arrays of integers, sadly
  validate_integer($ossec_check_frequency, undef, 1800)
  validate_array($ossec_ignorepaths)

  class { 'ossec::packages':
    manage_repos => $manage_repos
  }

  case $::osfamily {
    'Debian' : {
      package { $ossec::common::hidsagentpackage:
        ensure  => installed,
        require => $manage_repos ? {
          true    => Apt::Source['alienvault'],
          default => []
        }
      }
    }
    'RedHat' : {
      package { $ossec::common::hidsagentpackage:
        ensure  => installed,
        require => $manage_repos ? {
          true    => Yumrepo['ossec'],
          default => []
        }
      }
    }
    default: { fail('OS family not supported') }
  }

  service { $ossec::common::hidsagentservice:
    ensure    => running,
    enable    => true,
    hasstatus => $ossec::common::servicehasstatus,
    pattern   => $ossec::common::hidsagentservice,
    require   => Package[$ossec::common::hidsagentpackage],
  }

  concat { '/var/ossec/etc/ossec.conf':
    owner   => 'root',
    group   => 'ossec',
    mode    => '0440',
    require => Package[$ossec::common::hidsagentpackage],
    notify  => Service[$ossec::common::hidsagentservice]
  }
  concat::fragment { 'ossec.conf_10' :
    target  => '/var/ossec/etc/ossec.conf',
    content => template('ossec/10_ossec_agent.conf.erb'),
    order   => 10,
    notify  => Service[$ossec::common::hidsagentservice]
  }
  concat::fragment { 'ossec.conf_99' :
    target  => '/var/ossec/etc/ossec.conf',
    content => template('ossec/99_ossec_agent.conf.erb'),
    order   => 99,
    notify  => Service[$ossec::common::hidsagentservice]
  }

  concat { '/var/ossec/etc/client.keys':
    owner   => 'root',
    group   => 'ossec',
    mode    => '0640',
    notify  => Service[$ossec::common::hidsagentservice],
    require => Package[$ossec::common::hidsagentpackage]
  }
  ossec::agentkey{ "ossec_agent_${::fqdn}_client":
    agent_id         => $::uuid,
    agent_name       => $::fqdn,
    agent_ip_address => $::ipaddress,
  }
  @@ossec::agentkey{ "ossec_agent_${::fqdn}_server":
    agent_id         => $::uuid,
    agent_name       => $::fqdn,
    agent_ip_address => $::ipaddress
  }

  # Set log permissions properly to fix
  # https://github.com/djjudas21/puppet-ossec/issues/20
  file { '/var/ossec/logs':
    ensure  => directory,
    require => Package[$ossec::common::hidsagentpackage],
    owner   => 'ossec',
    group   => 'ossec',
    mode    => '0755',
  }

  # SELinux
  if ($::osfamily == 'RedHat' and $selinux == true) {
    selinux::module { 'ossec-logrotate':
      ensure => 'present',
      source => 'puppet:///modules/ossec/ossec-logrotate.te',
    }
  }
}
