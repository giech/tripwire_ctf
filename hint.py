dnfc = decode(ZFT)
if not (dnfc.startswith(dname) and dnfc.endswith(dname)):
    show_error=true
else:
    PerformNextCheck()
	