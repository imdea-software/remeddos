from django.urls import re_path, path
from flowspec import views
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('', views.dashboard, name="dashboard"),
    path('group_routes',views.group_routes, name="group-routes"),
    path('pending_routes/',views.pending_routes, name="pending-routes"),
    re_path(r'^overview_ajax/?$', views.overview_routes_ajax, name="overview-ajax"),    
    re_path(r'^profile/?$', views.user_profile, name="user-profile"),
    re_path(r'^add/?$', views.verify_add_user, name="add-route"),
    path('addroute',views.add_route,name="add"),
    re_path(r'^addport/?$', views.add_port, name="add-port"),
    path('editroute/<str:route_slug>/',views.verify_edit_user,name="edit-route"),
    path('edit/<str:route_slug>/',views.edit_route,name="edit"),
    path('deleteroute/<str:route_slug>/',views.verify_delete_user,name="delete-route"),
    path('delete/<str:route_slug>/',views.delete_route,name="delete"),
    re_path(r'^welcome/?', views.welcome, name="welcome"),
    re_path(r'^selectinst/?$', views.selectinst, name="selectinst"),
    path('load_js/<str:file>', views.load_jscript, name="load-js"),
    re_path(r'^overview/?$', views.overview,  name="overview"),
    re_path(r'^setup/', views.setup, name='setup'),
    # Graphs or more details
    path('route_details/<str:route_slug>/',views.display_graphs,name="display-graphs"),
    path('ajax_graphs/',views.ajax_graphs, name='ajax-graphs'),
    path('details/<str:route_slug>/',views.display_graphs,name="route-details"),
    path('get_net/',views.ajax_networks, name='ajax-networks'),
    # storage and sync options
    path('backup/',views.backup,name="backup"),
    path('restore/',views.restore_backup,name="restore"),
    path('createdbackup/',views.create_db_backup, name='db-backup'),
    path('restoredb/',views.restore_complete_db, name='db-restore'),
    path('route_update/<str:route_slug>',views.routes_update,name='route-updates'),
    path('check_sync/<str:route_slug>',views.check_sync,name='check-sync'),
    path('delete_route/<str:route_slug>',views.exterminate_route, name="exterminate"),
    path('storage_dashboard/',views.storage_dashboard,name='storage-dashboard'),
    path('sync_routers/',views.sync_routers,name="sync-routers"),
] + static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)

