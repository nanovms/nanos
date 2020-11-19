#!/usr/bin/awk -f

BEGIN {
	FS=","
	format_string="%s,%s,%s,%s\n"
	if (ARGV[1] == "-t") {
		format_string="%-30s\t%s\t%13s\t%13s\n"
		delete ARGV[1]
	}
	printf format_string, "function", "count", "tot lat", "self lat"
}
{
	if (NR==0) { next }
	names[$1] = $1
	counts[$1] += 1
	fnlat[$1] += $3 / 1000
	selflat[$1] += $4 / 1000
}
END {
	for (n in names) {
		f = fnlat[n]
		s = selflat[n]
		printf format_string, n, counts[n], f, s
	}
}

