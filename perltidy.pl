#!/usr/bin/env perl
use strict;
use warnings;

use Perl::Tidy;
use PPI;

# Formats a Perl file using an embedded Webmin perltidy profile and then
# applies a few Webmin-specific cleanup passes that perltidy cannot express
# on its own.
#
# Usage:
#   perltidy.pl path/to/file.pl
#
# The perltidy profile is embedded below so this script is self-contained and
# behaves the same regardless of the current working directory.

my $file = shift or die "usage: $0 file.pl\n";
my $embedded_perltidyrc = <<'END_PERLTIDYRC';
# Webmin perltidy configuration used by perltidy.pl
#
# Key characteristics:
#   - 8-column hard tabs for indentation
#   - Ratliff/Banner brace style (closing brace at body indentation)
#   - Sub opening brace on its own line
#   - Uncuddled else/elsif
#   - Logical operators (|| &&) at end of line, not start of continuation
#   - No spaces around string concatenation operator (.)
#
# Wrapper post-processing:
#   - Restore named sub body indentation to Webmin style
#   - Rewrite empty arrayrefs from [] to [ ]
#   - Preserve alignment in multiline qw(...) lists
#
# Notes:
#   - Line length is set to 88 so code inside named subs ends up near an
#     effective 80 columns after the sub-body unindent pass runs.
#   - Deeply nested UI helper calls (ui_table_row, ui_select, etc.) may
#     still reflow differently than the hand-formatted originals. The
#     -lp (line-up-parens) option was considered but produces worse
#     results with Webmin's deeply nested call patterns.

# Indentation
-i=8            # 8 columns per indent level
-ci=4           # Continuation indent (half of indent level)
-et=8           # Entab leading whitespace, 8-column tab stops

# Line length
-l=88          # Max line length: 88 (includes 80 + 8 from sub-body unindent fix)

# Brace placement
-nbl            # Control-structure opening brace stays on same line
-sbl            # Sub opening brace goes on a new line by itself
-icb            # Indent closing brace to body level (Ratliff/Banner)

# else / elsif
-nce            # Uncuddled: else/elsif on its own line, not after }

# Container tightness
-pt=2           # Parens: keep all parens tight, like f($x) and ($a + $b)
-sbt=2          # Brackets: $a[0]    not  $a[ 0 ]
-bt=2           # Braces:   $h{key}  not  $h{ key }

# Blank lines
-bbs            # Blank line before subs
-mbl=2          # Max 2 consecutive blank lines
-kbl=1          # Keep existing blank lines
-nbboc          # Don't add a blank line before opening comments in blocks

# Spacing
-nvc            # Don't vertically align code like consecutive assignments
-nwls="."       # No space to the left of . (concat)
-nwrs="."       # No space to the right of . (concat)

# Line break positions
-wba="&& || and or ."  # Break after these operators (keep at end of line)

# Other
-nolq           # Don't outdent long quoted strings
END_PERLTIDYRC

my $source = read_source_file($file);
my $tidied = run_perltidy($source);
my $out = apply_webmin_post_tidy_fixes($source, $tidied, "\t");

write_source_file($file, $out);

# read_source_file(file)
# Reads a source file into memory.
sub read_source_file
{
my ($file) = @_;

open my $fh, '<', $file or die "open($file): $!";
local $/;
return <$fh>;
}

# write_source_file(file, code)
# Writes the final formatted source back to disk.
sub write_source_file
{
my ($file, $code) = @_;

open my $fh, '>', $file or die "write($file): $!";
print {$fh} $code;
close $fh or die "close($file): $!";
}

# run_perltidy(source)
# Runs perltidy with the embedded Webmin profile.
sub run_perltidy
{
my ($source) = @_;

my $tidied = '';
my $err = '';

my $rc = Perl::Tidy::perltidy(
	source => \$source,
	destination => \$tidied,
	stderr => \$err,
	# Feed the embedded profile directly to perltidy.
	perltidyrc => \$embedded_perltidyrc,
);

die "perltidy failed:\n$err\n" if $rc;

return $tidied;
}

# apply_webmin_post_tidy_fixes(source, code, indent-unit)
# Applies all Webmin-specific post-processing passes.
sub apply_webmin_post_tidy_fixes
{
my ($source, $code, $indent_unit) = @_;

# Webmin's style keeps named sub bodies flush with the "sub" keyword, and
# prefers a space inside empty anonymous arrayrefs. Some hand-aligned
# multi-line qw(...) lists should also keep their original continuation
# columns.
$code = apply_webmin_sub_unindent($code, $indent_unit);
$code = apply_webmin_empty_array_spacing($code);
$code = apply_webmin_multiline_qw_alignment($source, $code);

return $code;
}

# apply_webmin_sub_unindent(code, indent-unit)
# Removes one body-indent level from named subroutines.
sub apply_webmin_sub_unindent
{
my ($code, $indent_unit) = @_;
$indent_unit //= "\t";

# Split with a negative limit so we preserve any trailing newline exactly.
my @lines = split /\n/, $code, -1;
my $doc = PPI::Document->new(\$code) or die "PPI parse failed\n";

my $subs = $doc->find(
	sub {
		my ($top, $node) = @_;
		return 0 unless $node->isa('PPI::Statement::Sub');
		return defined $node->name;    # named subs only
		}
);

return $code unless $subs && @$subs;

# Each named sub contributes one indentation level that perltidy adds but
# Webmin does not want. Track that per line so nested named subs are handled
# correctly even if they share lines with other code.
my %unindent_count;

for my $sub (@$subs) {
	my $block = $sub->block or next;

	my $start = $block->location or next;    # opening brace line/col
	my $finish = $block->last_token or next;
	my $finish_loc = $finish->location or next;

	# Start after the opening brace line and include the closing brace line.
	my $start_line = $start->[0] + 1;
	my $end_line = $finish_loc->[0];
	next if $start_line > $end_line;

	for my $line_no ($start_line .. $end_line) {
		$unindent_count{$line_no}++;
		}
	}

for my $line_no (sort { $a <=> $b } keys %unindent_count) {
	my $idx = $line_no - 1;
	next if $idx < 0 || $idx > $#lines;

	# Remove exactly one leading indent unit per containing named sub.
	for (1 .. $unindent_count{$line_no}) {
		if ($indent_unit eq "\t") {
			$lines[$idx] =~ s/^\t//;
			}
		else {
			my $q = quotemeta($indent_unit);
			$lines[$idx] =~ s/^$q//;
			}
		}
	}

return join "\n", @lines;
}

# apply_webmin_empty_array_spacing(code)
# Rewrites empty arrayrefs from [] to [ ].
sub apply_webmin_empty_array_spacing
{
my ($code) = @_;

my @lines = split /\n/, $code, -1;
my $doc = PPI::Document->new(\$code) or die "PPI parse failed\n";

my $constructors = $doc->find(
	sub {
		my ($top, $node) = @_;
		return 0 unless $node->isa('PPI::Structure::Constructor');

	     # perltidy keeps empty arrayrefs as "[]"; Webmin style wants "[ ]".
		return $node->content eq '[]';
		}
);

return $code unless $constructors && @$constructors;

my %replacements;

for my $constructor (@$constructors) {
	my $start = $constructor->start or next;
	my $finish = $constructor->finish or next;
	my $start_loc = $start->location or next;
	my $finish_loc = $finish->location or next;

	# Empty constructors are a single token pair on one line. Skip anything
	# more complex rather than guessing.
	next if $start_loc->[0] != $finish_loc->[0];
	next if $finish_loc->[1] != $start_loc->[1] + 1;

	push @{$replacements{$start_loc->[0]}}, [$start_loc->[1], 2];
	}

for my $line_no (keys %replacements) {
	my $idx = $line_no - 1;
	next if $idx < 0 || $idx > $#lines;

	# Rewrite from right to left so earlier column offsets stay valid.
	for my $edit (sort { $b->[0] <=> $a->[0] } @{$replacements{$line_no}}) {
		my ($column, $length) = @$edit;
		substr($lines[$idx], $column - 1, $length, '[ ]');
		}
	}

return join "\n", @lines;
}

# apply_webmin_multiline_qw_alignment(source, code)
# Restores original alignment for multiline qw(...) lists.
sub apply_webmin_multiline_qw_alignment
{
my ($source, $code) = @_;

my $source_doc = PPI::Document->new(\$source) or die "PPI parse failed\n";
my $code_doc = PPI::Document->new(\$code) or die "PPI parse failed\n";

my @source_tokens = find_multiline_qw_tokens($source_doc);
my @code_tokens = find_multiline_qw_tokens($code_doc);

return $code unless @source_tokens && @code_tokens;
return $code unless @source_tokens == @code_tokens;

my $line_offsets = build_line_offsets($code);
my @replacements;

for my $i (0 .. $#code_tokens) {
	my $source_token = $source_tokens[$i];
	my $code_token = $code_tokens[$i];

	next if $source_token->content eq $code_token->content;
	next
	    unless normalize_qw_token($source_token->content) eq
	    normalize_qw_token($code_token->content);

	my $start_loc = $code_token->location or next;
	my $offset = location_to_offset($line_offsets, $start_loc);

	push @replacements,
	    [$offset, length($code_token->content), $source_token->content];
	}

return $code unless @replacements;

# Apply from the end of the file so earlier offsets remain valid.
for my $edit (sort { $b->[0] <=> $a->[0] } @replacements) {
	my ($offset, $length, $replacement) = @$edit;
	substr($code, $offset, $length, $replacement);
	}

return $code;
}

# find_multiline_qw_tokens(doc)
# Returns quote-like word tokens that span multiple lines.
sub find_multiline_qw_tokens
{
my ($doc) = @_;

return
    grep { $_->content =~ /\n/ }
    grep { $_->isa('PPI::Token::QuoteLike::Words') } $doc->tokens;
}

# normalize_qw_token(content)
# Normalizes qw(...) token whitespace for comparisons.
sub normalize_qw_token
{
my ($content) = @_;

$content =~ s/\s+/ /g;
$content =~ s/^\s+//;
$content =~ s/\s+$//;

return $content;
}

# build_line_offsets(code)
# Builds 1-based line-start offsets for substring replacement.
sub build_line_offsets
{
my ($code) = @_;

my @lines = split /\n/, $code, -1;
my @offsets = (undef);
my $offset = 0;

for my $i (0 .. $#lines) {
	$offsets[$i + 1] = $offset;
	$offset += length($lines[$i]) + 1;
	}

return \@offsets;
}

# location_to_offset(line-offsets, location)
# Converts a PPI line and column to a string offset.
sub location_to_offset
{
my ($line_offsets, $location) = @_;

my ($line, $column) = @$location;
return $line_offsets->[$line] + ($column - 1);
}
