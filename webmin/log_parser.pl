# log_parser.pl
# Functions for parsing this module's logs

do 'webmin-lib.pl';

# parse_webmin_log(user, script, action, type, object, &params)
# Converts logged information from this module into human-readable form
sub parse_webmin_log
{
my ($user, $script, $action, $type, $object, $p) = @_;
if ($action eq 'install') {
	return &text('log_install', "<i>$p->{'desc'}</i>");
	}
elsif ($action eq 'tinstall') {
	return &text('log_tinstall', "<i>$p->{'desc'}</i>");
	}
elsif ($action eq 'clone') {
	return &text('log_clone', "<i>$p->{'desc'}</i>",
				  "<i>$p->{'dstdesc'}</i>");
	}
elsif ($action eq 'delete') {
	return &text('log_delete', "<i>$p->{'desc'}</i>");
	}
elsif ($action eq 'upgrade') {
	return &text('log_upgrade', $p->{'version'});
	}
elsif ($action eq 'theme') {
	return $p->{'theme'} ? &text('log_theme', "<tt>$p->{'theme'}</tt>")
			     : $text{'log_theme_def'};
	}
elsif ($action eq 'deletecache') {
	return &text('log_deletecache', $object);
	}
elsif ($action eq 'letsencryptdns' || $action eq 'letsencryptcleanup') {
	return &text('log_'.$action, $object);
	}
elsif ($action eq 'letsencrypt_failed' ||
       $action eq 'letsencrypt_renew_failed') {
	my $doms = (ref($p) ? $p->{'domains'} : undef) || $object;
	my $err = (ref($p) ? $p->{'error'} : undef) || "";
	return $err ? &text('log_'.$action, "<tt>$doms</tt>", "<tt>$err</tt>")
		    : &text('log_'.$action, "<tt>$doms</tt>");
	}
elsif ($action eq 'letsencrypt_renew') {
	my $doms = (ref($p) ? $p->{'domains'} : undef) || $object;
	return &text('log_'.$action, "<tt>$doms</tt>");
	}
elsif ($action eq 'letsencrypt_email_fallback') {
	my $doms = (ref($p) ? $p->{'domains'} : undef) || $object;
	my $email = (ref($p) ? $p->{'email'} : undef) || "";
	return $email ? &text('log_'.$action, "<tt>$doms</tt>", "<tt>$email</tt>")
		      : &text('log_'.$action, "<tt>$doms</tt>", "<tt>-</tt>");
	}
elsif ($action eq 'letsencrypt_settings') {
	my $changes = (ref($p) ? $p->{'changes'} : undef) || "";
	$changes = &html_escape($changes);
	return $changes ? &text('log_'.$action, "<tt>$changes</tt>")
			: $text{'log_'.$action};
	}
elsif ($type eq 'webmincron') {
	return &text('log_'.$action.'_webmincron', $object);
	}
elsif ($text{"log_$action"}) {
	return $text{"log_$action"};
	}
else {
	return undef;
	}
}

