#!/usr/bin/perl
# Request a new SSL cert using Let's Encrypt

use strict;
use warnings;
no warnings 'redefine';
no warnings 'uninitialized';

require "./webmin-lib.pl";
our %text;
our %miniserv;
our %in;
our $config_directory;
our %config;
our $module_name;
our $letsencrypt_cmd;
&error_setup($text{'letsencrypt_err'});

# Parse inputs first, as this script also handles events maintenance actions.
&ReadParse();
if ($in{'event_action'} || $in{'clearall'} || $in{'confirm_clear_all'}) {
	&handle_letsencrypt_events_action();
	exit;
	}

# Re-check if let's encrypt is available
my $err = &check_letsencrypt();
&error($err) if ($err);

# Validate inputs
my @doms = split(/\s+/, $in{'dom'});
foreach my $dom (@doms) {
	$dom =~ /^(\*\.)?[a-z0-9\-\.\_]+$/i || &error($text{'letsencrypt_edom'});
	}
$in{'renew_def'} || $in{'renew'} =~ /^[1-9][0-9]*$/ ||
	&error($text{'letsencrypt_erenew'});
$in{'size_def'} || $in{'size'} =~ /^\d+$/ ||
	&error($text{'newkey_esize'});
my $size = $in{'size_def'} ? undef : $in{'size'};
my $acme_server_mode = $in{'acme_server_mode'};
if ($acme_server_mode !~ /^(public|custom)$/) {
	$acme_server_mode = $config{'letsencrypt_server_mode'};
	}
if ($acme_server_mode !~ /^(public|custom)$/) {
	$acme_server_mode = ($config{'letsencrypt_server'} ||
			     $config{'letsencrypt_directory_url'}) ?
			    "custom" : "public";
	}
$in{'acme_server'} = &trim($in{'acme_server'});
$in{'acme_eab_kid'} = &trim($in{'acme_eab_kid'});
$in{'acme_eab_hmac'} = &trim($in{'acme_eab_hmac'});
my $acme_server = length($in{'acme_server'}) ? $in{'acme_server'} : undef;
my $acme_eab_kid = length($in{'acme_eab_kid'}) ? $in{'acme_eab_kid'} : undef;
my $acme_eab_hmac = length($in{'acme_eab_hmac'}) ? $in{'acme_eab_hmac'} : undef;
if ($acme_server_mode eq "custom") {
	$acme_server || &error($text{'letsencrypt_eacmeserverreq'});
	$acme_server =~ /^https?:\/\/\S+$/i ||
		&error($text{'letsencrypt_eacmeserver'});
	}
elsif ($acme_server_mode ne "public") {
	&error($text{'letsencrypt_eacmeservermode'});
	}
my $request_server = $acme_server_mode eq "custom" ? $acme_server : undef;
if ($acme_server_mode eq "custom" && ($acme_eab_kid || $acme_eab_hmac)) {
	$acme_eab_kid && $acme_eab_hmac ||
		&error($text{'letsencrypt_eeabpair'});
	$letsencrypt_cmd || &error($text{'letsencrypt_eeabnative'});
	}
my $request_eab_kid = $acme_server_mode eq "custom" ? $acme_eab_kid : undef;
my $request_eab_hmac = $acme_server_mode eq "custom" ? $acme_eab_hmac : undef;
my $acme_email_mode = $in{'acme_email_mode'};
if ($acme_email_mode !~ /^(none|webmin|custom)$/) {
	$acme_email_mode = $config{'letsencrypt_email_mode'};
	}
if ($acme_email_mode !~ /^(none|webmin|custom)$/) {
	$acme_email_mode = $config{'letsencrypt_email'} ? "custom" : "none";
	}
my $acme_email;
my $acme_email_webmin_raw;
my $acme_email_webmin_fallback;
if ($acme_email_mode eq "custom") {
	$acme_email = $in{'acme_email'};
	$acme_email =~ s/^\s+//;
	$acme_email =~ s/\s+$//;
	$acme_email || &error($text{'letsencrypt_eacmeemailreq'});
	if ($acme_email !~ /^[^\s\@]+\@[^\s\@]+$/) {
		&error($text{'letsencrypt_eacmeemail'});
		}
	}
elsif ($acme_email_mode eq "webmin") {
	$acme_email_webmin_raw = &get_letsencrypt_webmin_email_raw();
	if ($acme_email_webmin_raw &&
	    &is_usable_letsencrypt_acme_email($acme_email_webmin_raw)) {
		$acme_email = $acme_email_webmin_raw;
		}
	else {
		$acme_email = undef;
		$acme_email_webmin_fallback = $acme_email_webmin_raw ? 1 : 0;
		}
	}
elsif ($acme_email_mode ne "none") {
	&error($text{'letsencrypt_eacmeemailmode'});
	}
my $force = defined($in{'force'}) ? ($in{'force'} ? 1 : 0)
				  : defined($config{'letsencrypt_force'}) ?
				      $config{'letsencrypt_force'} : 1;
my $webroot;
my $mode = "web";
if ($in{'webroot_mode'} == 3) {
	# Validation via DNS
	$mode = "dns";
	}
elsif ($in{'webroot_mode'} == 4) {
	# Validation via Certbot webserver, unless Webmin is already handling
	# HTTP on port 80 (fall back to webroot mode in that case)
	&get_miniserv_config(\%miniserv);
	my @fallback_webroots = grep { $_ && $_ =~ /^\/\S+/ && -d $_ } (
		$in{'webroot'},
		$config{'letsencrypt_webroot'},
		$miniserv{'root'}
		);
	my %done;
	@fallback_webroots = grep { !$done{$_}++ } @fallback_webroots;
	if ($miniserv{'port'} =~ /(^|\s)80($|\s)/ &&
	    $miniserv{'root'} && -d $miniserv{'root'}) {
		$mode = "web";
		$webroot = $miniserv{'root'};
		}
	elsif (!&can_bind_local_port(80)) {
		if (@fallback_webroots) {
			$mode = "web";
			$webroot = $fallback_webroots[0];
			}
		else {
			&error(&text('letsencrypt_ecertbotport', 80));
			}
		}
	else {
		$mode = "certbot";
		}
	}
elsif ($in{'webroot_mode'} == 2) {
	# Some directory
	$in{'webroot'} =~ /^\/\S+/ && -d $in{'webroot'} ||
		&error($text{'letsencrypt_ewebroot'});
	$webroot = $in{'webroot'};
	}
else {
	# Apache domain
	&foreign_require("apache");
	my $conf = &apache::get_config();
	foreach my $virt (&apache::find_directive_struct(
				"VirtualHost", $conf)) {
		my $sn = &apache::find_directive(
			"ServerName", $virt->{'members'});
		my @sa = &apache::find_directive(
			"ServerAlias", $virt->{'members'});
		my $match = 0;
		if ($in{'webroot_mode'} == 0 &&
		    &indexof($doms[0], $sn, @sa) >= 0) {
			# Based on domain name
			$match = 1;
			}
		elsif ($in{'webroot_mode'} == 1 && $sn eq $in{'vhost'}) {
			# Specifically selected domain
			$match = 1;
			}
		my @ports;
		foreach my $w (@{$virt->{'words'}}) {
			if ($w =~ /:(\d+)$/) {
				push(@ports, $1);
				}
			else {
				push(@ports, 80);
				}
			}
		if ($match && &indexof(80, @ports) >= 0) {
			# Get document root
			$webroot = &apache::find_directive(
				"DocumentRoot", $virt->{'members'}, 1);
			$webroot || &error(&text('letsencrypt_edroot', $sn));
			last;
			}
		}
	$webroot || &error(&text('letsencrypt_evhost', $doms[0]));
	}

if ($in{'save'} || $in{'savecfg'}) {
	# Just update renewal
	&save_renewal_only(\@doms, $webroot, $mode, $size,
			   $in{'subset'}, $in{'use'}, $acme_server_mode,
			   $acme_server, $acme_eab_kid, $acme_eab_hmac,
			   $acme_email_mode, $acme_email, $force);
	&redirect("edit_ssl.cgi?mode=lets");
	}
else {
	# Save renewal and request options even if certificate issuance fails,
	# so cron/email/server settings can be updated independently.
	&save_renewal_only(\@doms, $webroot, $mode, $size,
			   $in{'subset'}, $in{'use'},
			   $acme_server_mode, $acme_server,
			   $acme_eab_kid, $acme_eab_hmac,
			   $acme_email_mode, $acme_email, $force);

	# Request the cert
	&ui_print_unbuffered_header(undef, $text{'letsencrypt_title'}, "");

	print &text($mode eq 'dns' ? 'letsencrypt_doingdns' :
		    $mode eq 'certbot' ? 'letsencrypt_doingcertbot' :
					 'letsencrypt_doing',
		    "<tt>".&html_escape(join(", ", @doms))."</tt>",
		    "<tt>".&html_escape($webroot)."</tt>"),"<p>\n";
	if ($acme_email_webmin_fallback) {
		&webmin_log("letsencrypt_email_fallback", undef, join(" ", @doms),
			    { 'domains' => join(", ", @doms),
			      'email' =>
				&clean_letsencrypt_event_value($acme_email_webmin_raw),
			      'context' => 'request' });
		}
	my ($ok, $cert, $key, $chain) = &request_letsencrypt_cert(
		\@doms, $webroot, $acme_email, $size, $mode, $in{'staging'},
		undef, undef, undef, $request_server, $request_eab_kid,
		$request_eab_hmac, $in{'subset'},
		$force);
	if (!$ok) {
		my $logerr = &clean_letsencrypt_event_value($cert);
		&webmin_log("letsencrypt_failed", undef, join(" ", @doms),
			    { 'domains' => join(", ", @doms),
			      'mode' => $mode,
			      'error' => $logerr,
			      'server' => $request_server || "" });
		&save_letsencrypt_event(0, "request", \@doms, $mode, $webroot,
					$request_server, $cert);
		print &text('letsencrypt_failed', $cert),"<p>\n";
		}
	else {
		# Worked, now copy to Webmin
		print $text{'letsencrypt_done'},"<p>\n";

		# Copy cert, key and chain to Webmin
		if ($in{'use'}) {
			print $text{'letsencrypt_webmin'},"<br>\n";
			&lock_file($ENV{'MINISERV_CONFIG'});
			&get_miniserv_config(\%miniserv);

			$miniserv{'keyfile'} = $config_directory.
					       "/letsencrypt-key.pem";
			&lock_file($miniserv{'keyfile'});
			&copy_source_dest($key, $miniserv{'keyfile'}, 1);
			&unlock_file($miniserv{'keyfile'});

			$miniserv{'certfile'} = $config_directory.
						"/letsencrypt-cert.pem";
			&lock_file($miniserv{'certfile'});
			&copy_source_dest($cert, $miniserv{'certfile'}, 1);
			&unlock_file($miniserv{'certfile'});

			if ($chain) {
				$miniserv{'extracas'} = $config_directory.
							"/letsencrypt-ca.pem";
				&lock_file($miniserv{'extracas'});
				&copy_source_dest($chain, $miniserv{'extracas'}, 1);
				&unlock_file($miniserv{'extracas'});
				}
			else {
				delete($miniserv{'extracas'});
				}
			&put_miniserv_config(\%miniserv);
			&unlock_file($ENV{'MINISERV_CONFIG'});

			&restart_miniserv(1);
			print $text{'letsencrypt_wdone'},"<p>\n";
			}

		&webmin_log("letsencrypt", undef, join(" ", @doms),
			    { 'domains' => join(", ", @doms),
			      'mode' => $mode,
			      'use_webmin' => $in{'use'} ? 1 : 0,
			      'server' => $request_server || "" });

		# Tell the user what was done
		print $text{'letsencrypt_show'},"<p>\n";
		my @grid = ( $text{'letsencrypt_cert'}, $cert,
			     $text{'letsencrypt_key'}, $key );
		push(@grid, $text{'letsencrypt_chain'}, $chain) if ($chain);
		print &ui_grid_table(\@grid, 2);
		&save_letsencrypt_event(
			1, "request", \@doms, $mode, $webroot, $request_server,
			$in{'use'} ? "Certificate requested and applied to Webmin"
				   : "Certificate requested successfully");
		}

	&ui_print_footer("edit_ssl.cgi?mode=lets", $text{'ssl_tablets'});
	}

# save_renewal_only(&doms, webroot, mode, size, subset-mode, used-by-webmin,
#		    [acme-server-mode], [custom-acme-server], [eab-kid],
#		    [eab-hmac], [acme-email-mode], [acme-account-email],
#		    [force-renew])
# Save for future renewals
sub save_renewal_only
{
my ($doms, $webroot, $mode, $size, $subset, $usewebmin, $acme_server_mode,
    $acme_server, $acme_eab_kid, $acme_eab_hmac,
    $acme_email_mode, $acme_email, $force) = @_;
my $has_webmincron = &foreign_check("webmincron");
if ($acme_server_mode !~ /^(public|custom)$/) {
	$acme_server_mode = $config{'letsencrypt_server_mode'};
	}
if ($acme_server_mode !~ /^(public|custom)$/) {
	$acme_server_mode = ($config{'letsencrypt_server'} ||
			     $config{'letsencrypt_directory_url'}) ?
			    "custom" : "public";
	}
if ($acme_email_mode !~ /^(none|webmin|custom)$/) {
	$acme_email_mode = $config{'letsencrypt_email_mode'};
	}
if ($acme_email_mode !~ /^(none|webmin|custom)$/) {
	$acme_email_mode = $config{'letsencrypt_email'} ? "custom" : "none";
	}
my %old = (
	'doms' => $config{'letsencrypt_doms'},
	'webroot' => $config{'letsencrypt_webroot'},
	'mode' => $config{'letsencrypt_mode'},
	'size' => $config{'letsencrypt_size'},
	'subset' => $config{'letsencrypt_subset'} ? 1 : 0,
	'usewebmin' => !$config{'letsencrypt_nouse'} ? 1 : 0,
	'server_mode' => $config{'letsencrypt_server_mode'} =~
			 /^(public|custom)$/ ?
			 $config{'letsencrypt_server_mode'} :
			 (($config{'letsencrypt_server'} ||
			   $config{'letsencrypt_directory_url'}) ?
			  "custom" : "public"),
	'server' => $config{'letsencrypt_server'} ||
		    $config{'letsencrypt_directory_url'},
	'eab_kid' => $config{'letsencrypt_eab_kid'},
	'eab_hmac_set' => $config{'letsencrypt_eab_hmac'} ? 1 : 0,
	'email_mode' => $config{'letsencrypt_email_mode'} =~
			/^(none|webmin|custom)$/ ?
			$config{'letsencrypt_email_mode'} :
			($config{'letsencrypt_email'} ? "custom" : "none"),
	'email' => $config{'letsencrypt_email'},
	'force' => defined($config{'letsencrypt_force'}) ?
		   ($config{'letsencrypt_force'} ? 1 : 0) : 1,
	'renew' => undef,
	);
if ($has_webmincron) {
	my $oldjob = &find_letsencrypt_cron_job();
	$old{'renew'} = $oldjob && $oldjob->{'months'} =~ /^\*\/(\d+)$/ ? $1
									: undef;
	}

my %new = (
	'doms' => join(" ", @$doms),
	'webroot' => $webroot,
	'mode' => $mode,
	'size' => $size,
	'subset' => $subset ? 1 : 0,
	'usewebmin' => $usewebmin ? 1 : 0,
	'server_mode' => $acme_server_mode,
	'server' => undef,
	'eab_kid' => undef,
	'eab_hmac_set' => 0,
	'email_mode' => $acme_email_mode,
	'email' => $acme_email_mode eq "custom" ? $acme_email : undef,
	'force' => defined($force) ? ($force ? 1 : 0) : 1,
	'renew' => $has_webmincron ? ($in{'renew_def'} ? undef : $in{'renew'})
				   : $old{'renew'},
	);
my $stored_server = $config{'letsencrypt_server'} ||
		    $config{'letsencrypt_directory_url'};
if ($acme_server_mode eq "custom" && $acme_server) {
	$stored_server = $acme_server;
	}
my $stored_eab_kid = $config{'letsencrypt_eab_kid'};
my $stored_eab_hmac = $config{'letsencrypt_eab_hmac'};
if ($acme_server_mode eq "custom") {
	$stored_eab_kid = $acme_eab_kid;
	$stored_eab_hmac = $acme_eab_hmac;
	}
$new{'server'} = $stored_server;
$new{'eab_kid'} = $stored_eab_kid;
$new{'eab_hmac_set'} = $stored_eab_hmac ? 1 : 0;

$config{'letsencrypt_doms'} = join(" ", @$doms);
$config{'letsencrypt_webroot'} = $webroot;
$config{'letsencrypt_mode'} = $mode;
$config{'letsencrypt_size'} = $size;
$config{'letsencrypt_subset'} = $subset;
$config{'letsencrypt_nouse'} = $usewebmin ? 0 : 1;
$config{'letsencrypt_server_mode'} = $acme_server_mode;
if (defined($stored_server) && length($stored_server)) {
	$config{'letsencrypt_server'} = $stored_server;
	$config{'letsencrypt_directory_url'} = $stored_server;
	}
else {
	delete($config{'letsencrypt_server'});
	delete($config{'letsencrypt_directory_url'});
	}
if (defined($stored_eab_kid) && length($stored_eab_kid)) {
	$config{'letsencrypt_eab_kid'} = $stored_eab_kid;
	}
else {
	delete($config{'letsencrypt_eab_kid'});
	}
if (defined($stored_eab_hmac) && length($stored_eab_hmac)) {
	$config{'letsencrypt_eab_hmac'} = $stored_eab_hmac;
	}
else {
	delete($config{'letsencrypt_eab_hmac'});
	}
if ($acme_email_mode ne "none") {
	$config{'letsencrypt_email_mode'} = $acme_email_mode;
	}
else {
	delete($config{'letsencrypt_email_mode'});
	}
if ($acme_email_mode eq "custom" && $acme_email) {
	$config{'letsencrypt_email'} = $acme_email;
	}
else {
	delete($config{'letsencrypt_email'});
	}
$force = 1 if (!defined($force));
$config{'letsencrypt_force'} = $force ? 1 : 0;
&save_module_config();
if ($has_webmincron) {
	my $job = &find_letsencrypt_cron_job();
	if ($in{'renew_def'}) {
		&webmincron::delete_webmin_cron($job) if ($job);
		}
	else {
		my @tm = localtime(time() - 60);
		$job ||= { 'module' => $module_name,
			   'func' => 'renew_letsencrypt_cert' };
		$job->{'mins'} ||= $tm[1];
		$job->{'hours'} ||= $tm[2];
		$job->{'days'} ||= $tm[3];
		$job->{'months'} = '*/'.$in{'renew'};
		$job->{'weekdays'} = '*';
		&webmincron::create_webmin_cron($job);
		}
	}

my @changes = &collect_letsencrypt_setting_changes(\%old, \%new);
if (@changes) {
	&webmin_log("letsencrypt_settings", undef, scalar(@changes),
		    { 'changes' => join(" ; ", @changes) });
	}
}

# handle_letsencrypt_events_action()
# Handles delete-selected / clear-all requests from SSL Let's Encrypt events UI.
sub handle_letsencrypt_events_action
{
my $action = $in{'event_action'};
$action = "clear_all" if (!$action && $in{'clearall'});
$action = "confirm_clear_all" if (!$action && $in{'confirm_clear_all'});
my $event_days = $in{'event_days'};
$event_days = undef if (!defined($event_days) ||
			$event_days !~ /^\d+$/ || $event_days < 1);
my $return = "edit_ssl.cgi?mode=lets".
	     ($event_days ? "&event_days=".$event_days : "");

if ($action eq "clear_all" || $action eq "confirm" ||
       $action eq "confirm_clear_all") {
	if ($action ne "confirm_clear_all" && $action ne "confirm") {
		&ui_print_header(undef, $text{'ssl_letsevents_clear_title'}, "");
		print &ui_form_start("letsencrypt.cgi", "post");
		print &ui_hidden("event_action", "confirm_clear_all"),"\n";
		print &ui_hidden("event_days", $event_days),"\n" if ($event_days);
		print "<center>\n";
		print $text{'ssl_letsevents_clear_confirm'},"<p>\n";
		print &ui_submit($text{'ssl_letsevents_clear'}),"\n";
		print "</center>\n";
		print &ui_form_end();
		&ui_print_footer($return, $text{'index_return'});
		return;
		}
	&clear_letsencrypt_events();
	&webmin_log("letsencrypt_events_clear");
	&redirect($return);
	return;
	}
else {
	&redirect($return);
	return;
	}
}

# collect_letsencrypt_setting_changes(\%old, \%new)
# Returns human-readable list of "field: old -> new" entries.
sub collect_letsencrypt_setting_changes
{
my ($old, $new) = @_;
my @fields = (
	[ 'Domains', 'doms' ],
	[ 'Validation mode', 'mode' ],
	[ 'Webroot', 'webroot' ],
	[ 'Key size', 'size' ],
	[ 'Skip unverifiable', 'subset' ],
	[ 'Copy to Webmin', 'usewebmin' ],
	[ 'ACME server mode', 'server_mode' ],
	[ 'Custom ACME server', 'server' ],
	[ 'EAB key ID', 'eab_kid' ],
	[ 'EAB HMAC key set', 'eab_hmac_set' ],
	[ 'ACME email mode', 'email_mode' ],
	[ 'ACME email', 'email' ],
	[ 'Force renewal', 'force' ],
	[ 'Renewal months', 'renew' ],
	);
my @changes;
foreach my $f (@fields) {
	my ($name, $key) = @$f;
	my $ov = defined($old->{$key}) ? $old->{$key} : "";
	my $nv = defined($new->{$key}) ? $new->{$key} : "";
	next if ($ov eq $nv);
	push(@changes, "$name: ".&format_letsencrypt_setting_value($ov).
		       " -> ".&format_letsencrypt_setting_value($nv));
	}
return @changes;
}

# format_letsencrypt_setting_value(value)
# Formats a setting value for action log display.
sub format_letsencrypt_setting_value
{
my ($v) = @_;
$v = &clean_letsencrypt_event_value($v);
return length($v) ? $v : "-";
}

# can_bind_local_port(port)
# Returns 1 if this process can bind to a local TCP port.
sub can_bind_local_port
{
my ($port) = @_;
my $sock;
eval {
	require IO::Socket::INET;
	$sock = IO::Socket::INET->new(
		'Proto' => 'tcp',
		'LocalAddr' => '0.0.0.0',
		'LocalPort' => $port,
		'Listen' => 5,
		'ReUseAddr' => 0,
		);
	};
return 0 if ($@ || !$sock);
close($sock);
return 1;
}
