# Assignment 7 - Automated Log Analyzer

**Student:** Eng. Dhafer Alyaari  
**Language:** Python

## English
This program reads a text log file line by line. It looks for common indicators of SQL Injection and Path Traversal using regular expressions. It prints the line number, IP address, attack type, and matching log line, followed by a short summary.

**Run:**
```bash
python log_analyzer.py sample_security.log
```

**Save the report:**
```bash
python log_analyzer.py sample_security.log --report result.txt
```

**Run tests:**
```bash
python -m unittest -v test_log_analyzer
```

**Example result:** 10 lines checked, 4 suspicious lines: 2 SQL Injection and 2 Path Traversal. See `Example_Output.txt`.

## العربية
هذا البرنامج يقرأ ملف السجل سطرًا بسطر، ويبحث عن علامات **SQL Injection** و**Path Traversal** باستخدام `re`. يعرض رقم السطر وعنوان IP ونوع التنبيه والسطر المكتشف، ثم يطبع ملخص النتائج.

**التشغيل:** `python log_analyzer.py sample_security.log`  
**حفظ التقرير:** `python log_analyzer.py sample_security.log --report result.txt`  
**الاختبار:** `python -m unittest -v test_log_analyzer`

يمكن تشغيل `Run_Demo.bat` أو `Run_Tests.bat` على ويندوز بعد تثبيت Python. ملف `Run_EXE.bat` يعمل بعد إنشاء `Log_Analyzer.exe`.

## Files / الملفات
- `log_analyzer.py` — Python source code / كود البرنامج
- `test_log_analyzer.py` — automated tests / الاختبارات
- `sample_security.log` — sample web log / سجل تجريبي
- `Example_Output.txt` — actual sample report / مثال النتيجة
- `Test_Report.txt` — local test results / نتائج الاختبار
- `Run_Demo.bat`, `Run_Tests.bat`, `Run_EXE.bat` — Windows shortcuts
- `.github/workflows/build-windows.yml` — builds and checks a Windows EXE on GitHub

**Note:** Matching lines are *possible indicators*, not proof of a real attack. A line containing both types is counted once as a suspicious line and once in each category. IP detection uses the first valid IPv4 address found in each log line.
