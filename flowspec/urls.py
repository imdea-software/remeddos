from django.urls import re_path, path
from flowspec import views
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('', views.dashboard, name="dashboard"),
    path('group_routes/',views.group_routes, name="group-routes"),
    path('pending_routes/',views.pending_routes, name="pending-routes"),
    re_path(r'^routes_ajax/?$', views.group_routes_ajax, name="group-routes-ajax"),
    re_path(r'^overview_ajax/?$', views.overview_routes_ajax, name="overview-ajax"),    
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
    path('details/<slug:route_slug>/',views.routedetails,name="route-details"),
    re_path(r'^routestats/(?P<route_slug>[\w-]+)/$', views.routestats, name="routestats"),
    re_path(r'^setup/', views.setup, name='setup'),
    path('ajax_graphs/',views.ajax_graphs, name='ajax-graphs'),
    path('createdbackup/',views.create_db_backup, name='db-backup'),
    path('restoredb/',views.restore_complete_db, name='db-restore'),
    path('route_update/<slug:route_slug>',views.routes_update,name='route-updates'),
    path('delete_route/<slug:route_slug>',views.exterminate_route, name="exterminate"),
    path('commit_route/<slug:route_slug>',views.commit_to_router, name="commit"),
]

