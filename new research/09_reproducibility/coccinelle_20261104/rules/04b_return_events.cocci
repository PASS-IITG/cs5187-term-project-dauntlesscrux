// Enumerate every return statement. Pair with 04a allocations by parsed C
// function range and require allocation line < return line.
@return_event@
position site;
@@
return@site ...;

@script:python@
site << return_event.site;
@@
for i in range(len(site)):
    coccilib.report.print_report(site[i], "return_event")
