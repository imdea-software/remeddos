from django.urls import re_path, path
from accounts import views

urlpatterns = [
    re_path(r'^profile/token/$', views.generate_token, name="user-profile-token"),
    

]