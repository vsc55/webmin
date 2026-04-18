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

# Re-check if let's encrypt is available
my $err = &check_letsencrypt();
&error($err) if ($err);

# Validate inputs
&ReadParse();
my @doms = split(/\s+/, $in{'dom'});
foreach my $dom (@doms) {
	$dom =~ /^(\*\.)?[a-z0-9\-\.\_]+$/i || &error($text{'letsencrypt_edom'});
	}
$in{'renew_def'} || $in{'renew'} =~ /^[1-9][0-9]*$/ ||
	&error($text{'letsencrypt_erenew'});
$in{'size_def'} || $in{'size'} =~ /^\d+$/ ||
	&error($text{'newkey_esize'});
my $size = $in{'size_def'} ? undef : $in{'size'};
my $acme_server = $in{'acme_server'};
$acme_server =~ s/^\s+//;
$acme_server =~ s/\s+$//;
$acme_server = undef if (!length($acme_server));
$acme_server =~ /^https?:\/\/\S+$/i ||
	&error($text{'letsencrypt_eacmeserver'}) if ($acme_server);
if ($acme_server && !$letsencrypt_cmd) {
	&error($text{'letsencrypt_eacmeservercmd'});
	}
my $acme_email = $in{'acme_email'};
$acme_email =~ s/^\s+//;
$acme_email =~ s/\s+$//;
$acme_email = undef if (!length($acme_email));
if ($acme_email && $acme_email !~ /^[^\s\@]+\@[^\s\@]+$/) {
	&error($text{'letsencrypt_eacmeemail'});
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
			   $in{'subset'}, $in{'use'}, $acme_server,
			   $acme_email, $force);
	&redirect("edit_ssl.cgi?mode=lets");
	}
else {
	# Save renewal and request options even if certificate issuance fails,
	# so cron/email/server settings can be updated independently.
	&save_renewal_only(\@doms, $webroot, $mode, $size,
			   $in{'subset'}, $in{'use'},
			   $acme_server, $acme_email, $force);

	# Request the cert
	&ui_print_unbuffered_header(undef, $text{'letsencrypt_title'}, "");

	print &text($mode eq 'dns' ? 'letsencrypt_doingdns' :
		    $mode eq 'certbot' ? 'letsencrypt_doingcertbot' :
					 'letsencrypt_doing',
		    "<tt>".&html_escape(join(", ", @doms))."</tt>",
		    "<tt>".&html_escape($webroot)."</tt>"),"<p>\n";
	my ($ok, $cert, $key, $chain) = &request_letsencrypt_cert(
		\@doms, $webroot, $acme_email, $size, $mode, $in{'staging'},
		undef, undef, undef, $acme_server, undef, undef, $in{'subset'},
		$force);
	if (!$ok) {
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

			&webmin_log("letsencrypt");
			&restart_miniserv(1);
			print $text{'letsencrypt_wdone'},"<p>\n";
			}

		# Tell the user what was done
		print $text{'letsencrypt_show'},"<p>\n";
		my @grid = ( $text{'letsencrypt_cert'}, $cert,
			     $text{'letsencrypt_key'}, $key );
		push(@grid, $text{'letsencrypt_chain'}, $chain) if ($chain);
		print &ui_grid_table(\@grid, 2);
		}

	&ui_print_footer("", $text{'index_return'});
	}

# save_renewal_only(&doms, webroot, mode, size, subset-mode, used-by-webmin,
#		    [custom-acme-server], [acme-account-email], [force-renew])
# Save for future renewals
sub save_renewal_only
{
my ($doms, $webroot, $mode, $size, $subset, $usewebmin, $acme_server,
    $acme_email, $force) = @_;
$config{'letsencrypt_doms'} = join(" ", @$doms);
$config{'letsencrypt_webroot'} = $webroot;
$config{'letsencrypt_mode'} = $mode;
$config{'letsencrypt_size'} = $size;
$config{'letsencrypt_subset'} = $subset;
$config{'letsencrypt_nouse'} = $usewebmin ? 0 : 1;
if ($acme_server) {
	$config{'letsencrypt_server'} = $acme_server;
	}
else {
	delete($config{'letsencrypt_server'});
	}
if ($acme_email) {
	$config{'letsencrypt_email'} = $acme_email;
	}
else {
	delete($config{'letsencrypt_email'});
	}
$force = 1 if (!defined($force));
$config{'letsencrypt_force'} = $force ? 1 : 0;
&save_module_config();
if (&foreign_check("webmincron")) {
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
