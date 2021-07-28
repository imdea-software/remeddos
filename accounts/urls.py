from django.urls import re_path
from accounts import views

urlpatterns = [
    re_path(r'^profile/token/$', views.generate_token, name="user-profile-token"),
    re_path(r'^accounts/activate/(?P<activation_key>\w+)/$', views.activate, name='activate_account'),

]