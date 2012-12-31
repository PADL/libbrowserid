#ident $Id: cvslib.pl,v 1.5 1999/04/05 01:38:26 lukeh Exp $

$CVSVERSIONDIR = $ENV{'CVSVERSIONDIR'};

$INFOFILE = $CVSVERSIONDIR ne "" ? $CVSVERSIONDIR."/CVSVersionInfo.txt" : "CVSVersionInfo.txt";

$DISTDIR = $ENV{'HOME'} . "/dist";

sub getSGSFile
{
	if (-f "version.h") { return "version.h"; }
	elsif (-f "vers.c") { return "vers.c"; }
	else { return; }
}

sub nameToTag
{
	local($tag) = shift;
	$tag =~ s/\./\~/g;
	return ($tag);
}

sub getCVSRepository
{
	if (!(-d "CVS"))
	{
		return;
	}

	open(ROOT, "CVS/Root") || return;
	open(REPOSITORY, "CVS/Repository") || return;
	local ($CVSROOT) = <ROOT>;
	chop ($CVSROOT);
	if ($CVSROOT =~ '^:') {
		local(@C) = split(/:/, $CVSROOT);
		$CVSROOT = $C[3];
	}
	local ($CVSREPOSITORY) = <REPOSITORY>;
	chop ($CVSREPOSITORY);
	close(ROOT);
	close(REPOSITORY);

	if ($CVSREPOSITORY =~ /^\//)
	{
		$CVSREPOSITORY =~ s/^$CVSROOT\///g;
	}
	return($CVSREPOSITORY);
}

sub getCVSVersionInfo
{
	local ($VERSION, $PROJECT);

	local $gitVersion = `git describe --tags`;
	if ($gitVersion ne "")
	{
		chop($gitVersion);
		return $gitVersion;
	}

	if (-f $INFOFILE)
	{
		open(INFOFILE, $INFOFILE) || return;
		while(<INFOFILE>)
		{
			if (/^#/) { next; }

			local ($key, $value) = split(/:\s+/);
			chop($value);

			if ($key eq "ProjectVersion")
			{
			        $VERSION = $value;
			}
			elsif ($key eq "ProjectName")
			{
			        $PROJECT = $value;
			}
		}
	}
	close(INFOFILE);
	return "$PROJECT-$VERSION";
}
