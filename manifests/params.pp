class ossec::params {
  case $::kernel {
    'Linux': {

      $base_dir = '/var/ossec'

      $config_file = "${base_dir}/etc/ossec.conf"
      $config_mode = '0440'
      $config_owner = 'root'
      $config_group = 'ossec'

      $keys_file = "${base_dir}/etc/client.keys"
      $keys_mode = '0440'
      $keys_owner = 'root'
      $keys_group = 'ossec'

      $local_rules_file = "${base_dir}/rules/local_rules.xml"
      $local_rules_mode = '0440'
      $local_rules_owner = 'root'
      $local_rules_group = 'ossec'

      $local_decoders_file = "${base_dir}/etc/local_decoder.xml"
      $local_decoders_mode = '0440'
      $local_decoders_owner = 'root'
      $local_decoders_group = 'ossec'

      # These might require configuration changes to support, but
      # the directories are setup by the Atomicorp OSSEC RPM

      $local_rules_dir = "${base_dir}/etc/rules.d"
      $local_rules_dir_mode = '0550'
      $local_rules_dir_owner = 'root'
      $local_rules_dir_group = 'ossec'

      $local_decoders_dir = "${base_dir}/etc/decoders.d"
      $local_decoders_dir_mode = '0550'
      $local_decoders_dir_owner = 'root'
      $local_decoders_dir_group = 'ossec'

      case $::osfamily {
        'Debian': {

          $agent_service  = 'ossec'

          $agent_package  = 'ossec-hids-agent'

          $service_has_status  = false

          $default_local_files = {
            '/var/log/syslog'             => 'syslog',
            '/var/log/auth.log'           => 'syslog',
            '/var/log/mail.log'           => 'syslog',
            '/var/log/dpkg.log'           => 'syslog',
            '/var/log/apache2/access.log' => 'apache',
            '/var/log/apache2/error.log'  => 'apache'
          }

          case $::lsbdistcodename {
            /(lucid|precise|trusty)/: {
              $server_service = 'ossec-hids-server'
              $server_package = 'ossec-hids-server'
            }
            /^(jessie|wheezy)$/: {
              $server_service = 'ossec'
              $server_package = 'ossec-hids'
            }
            default: { fail('This ossec module has not been tested on your distribution (or lsb package not installed)') }
          }

        }
        'Redhat': {

          $agent_service  = 'ossec-hids'

          $agent_package  = 'ossec-hids-client'

          $server_service = 'ossec-hids'

          $server_package = 'ossec-hids-server'

          $service_has_status  = true

          $default_local_files = {
            '/var/log/messages'         => 'syslog',
            '/var/log/secure'           => 'syslog',
            '/var/log/maillog'          => 'syslog',
            '/var/log/yum.log'          => 'syslog',
            '/var/log/httpd/access_log' => 'apache',
            '/var/log/httpd/error_log'  => 'apache'
          }

        }
      }
    }
    'windows': {
      $config_file = regsubst(sprintf('%s/%s', getvar('env_programfiles(x86)'), 'ossec-agent/ossec.conf'), '\\', '/')
      $config_mode = '0440'
      $config_owner = 'Administrator'
      $config_group = 'Administrators'

      $keys_file = regsubst(sprintf('%s/%s', getvar('env_programfiles(x86)'), 'ossec-agent/client.keys'), '\\', '/')
      $keys_mode = '0440'
      $keys_owner = 'Administrator'
      $keys_group = 'Administrators'

      $agent_service  = 'OssecSvc'

      $agent_package  = 'OSSEC HIDS 2.8'

      $server_service = ''

      $server_package = ''

      $service_has_status  = true

      # Pushed by shared agent config now
      $default_local_files = {}

    }
    default: { fail('This ossec module has not been tested on your distribution') }
  }
}