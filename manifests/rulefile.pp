define ossec::rulefile(
  $content = undef,
  $source = undef,
  $order = 10
) {
  require ossec::params

  if $::osfamily == 'windows' {
    fail('The ossec module does not yet support installing the OSSEC HIDS server on Windows')
  }

  file { "${ossec::params::local_rules_dir}/${order}_${name}.xml":
    content => $content,
    source  => $source,
    mode    => $ossec::params::local_rules_mode,
    owner   => $ossec::params::local_rules_owner,
    group   => $ossec::params::local_rules_group,
    notify  => Service[$ossec::params::server_service]
  }

}
