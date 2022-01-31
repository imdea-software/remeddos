from django.urls import re_path, path
from flowspec import views
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [ 
    path('',views.group_routes, name="group-routes"),
    re_path(r'^routes_ajax/?$', views.group_routes_ajax, name="group-routes-ajax"),
    re_path(r'^overview_ajax/?$', views.overview_routes_ajax, name="overview-ajax"),
    re_path(r'^dashboard/$', views.dashboard, name="dashboard"),
    re_path(r'^profile/?$', views.user_profile, name="user-profile"),
    re_path(r'^add/?$', views.verify_add_user, name="add-route"),
    path('addroute',views.add_route,name="add"),
    re_path(r'^addport/?$', views.add_port, name="add-port"),
    path('editroute/<slug:route_slug>/',views.verify_edit_user,name="edit-route"),
    path('edit/<slug:route_slug>/',views.edit_route,name="edit"),
    path('deleteroute/<slug:route_slug>/',views.verify_delete_user,name="delete-route"),
    path('delete/<slug:route_slug>/',views.delete_route,name="delete"),
    path('display_graphs/<slug:route_slug>/',views.display_graphs,name="display-graphs"),
    re_path(r'^welcome/?', views.welcome, name="welcome"),
    re_path(r'^selectinst/?$', views.selectinst, name="selectinst"),
    path('load_js/<str:file>', views.load_jscript, name="load-js"),
    re_path(r'^overview/?$', views.overview, name="overview"),
    path('routes_sync/', views.routes_sync, name="rsync"),
    path('sync_router/', views.sync_router, name="router-sync"),
    path('backup/',views.backup,name="backup"),
    path('restore/',views.restore_backup,name="restore"),
    path('edit/<slug:route_slug>/',views.routedetails,name="route-details"),
    re_path(r'^routestats/(?P<route_slug>[\w-]+)/$', views.routestats, name="routestats"),
    re_path(r'^setup/', views.setup, name='setup'),
    path('ajax_graphs/',views.ajax_graphs, name='ajax-graphs'),
]

