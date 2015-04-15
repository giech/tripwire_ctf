# Originally given as a hint:
# https://twitter.com/tripwirevert/status/581837157742059520
# Reposted from http://pastebin.com/rwxeyunY (now expired)

dnfc = decode(ZFT)
if not (dnfc.startswith(dname) and dnfc.endswith(dname)):
    show_error=true
else:
    PerformNextCheck()
	