define ossec::rulefragment(
  $content = undef,
  $source = undef,
  $order = 10
) {
  require ossec::params

  if $::osfamily == 'windows' {
    fail('The ossec module does not yet support installing the OSSEC HIDS server on Windows')
  }

  concat::fragment { $name:
    target  => $ossec::params::local_rules_file,
    content => $content,
    source  => $source,
    order   => $order,
    notify  => Service[$ossec::params::server_service]
  }

}
