from django.urls import re_path, path
from golem import views
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [ 
    path('list/',views.display,name="attack-list"),
]