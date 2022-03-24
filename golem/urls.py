from django.urls import re_path, path
from golem import views
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [ 
    path('list/',views.display,name="attack-list"),
    path('routes/<str:golem_name>',views.display_routes,name="golem-routes"),
    path('updates/<str:golem_id>/',views.display_golem_updates,name="golem-updates"),
]