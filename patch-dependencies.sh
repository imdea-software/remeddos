#!/bin/bash

echo "Patching trans_real.py" >&2
patch /srv/venv/lib/python2.7/site-packages/django/utils/translation/trans_real.py <<END
--- aaa/trans_real.py	2019-02-20 09:46:40.973999000 -0500
+++ bbb/trans_real.py	2019-02-20 09:50:24.480000000 -0500
@@ -143,7 +143,7 @@
         # doesn't affect en-gb), even though they will both use the core "en"
         # translation. So we have to subvert Python's internal gettext caching.
         base_lang = lambda x: x.split('-', 1)[0]
-        if base_lang(lang) in [base_lang(trans) for trans in _translations]:
+        if res and base_lang(lang) in [base_lang(trans) for trans in _translations]:
             res._info = res._info.copy()
             res._catalog = res._catalog.copy()
 
END

echo "Patching widgets.py" >&2
patch /srv/venv/lib/python2.7/site-packages/tinymce/widgets.py <<END
--- aaa/widgets.py	2018-11-12 16:46:37.006000000 -0500
+++ bbb/widgets.py	2018-11-12 16:46:58.576000000 -0500
@@ -13,7 +13,11 @@
 from django import forms
 from django.conf import settings
 from django.contrib.admin import widgets as admin_widgets
-from django.forms.utils import flatatt
+try:
+    from django.forms.utils import flatatt
+except ImportError:
+    from django.forms.util import flatatt   # Django <1.9
+
 from django.utils.encoding import force_text
 from django.utils.html import escape
 from django.utils.safestring import mark_safe
END

echo "Finished patching."

